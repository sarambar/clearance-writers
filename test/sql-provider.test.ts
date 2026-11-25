// Copyright 2026 Sarambar
// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import { describe, it } from "node:test";

import {
  AZURE_SQL_RULE_PROVIDER_ACTIONS,
  MemoryAuditSink,
  createAzureSqlRuleProvider,
  isSbcRuleName,
  parseSbcRuleName,
  type HttpTransport,
} from "../src/index.js";
import type { HttpRequest, HttpResponse } from "../src/azure/http.js";
import { SQL_ID, TOKEN } from "./helpers.js";

const IP = "8.8.8.8";

const SBC_RULE = "sbc-1700000600-01HF7YAT00S5WARN4TQ5A8XEWP";
const SBC_RULE_SAME_ULID = "sbc-1700000900-01HF7YAT00S5WARN4TQ5A8XEWP";
const SBC_RULE_EXPIRED = "sbc-1699999000-01HF7YAT00S5WARN4TQ5A8XEWQ";
const PIN_SHA = "0123456789abcdef0123456789abcdef01234567";

class StrictSqlArm implements HttpTransport {
  readonly rules = new Map<string, { startIpAddress: string; endIpAddress: string }>();
  readonly requests: Array<{ method: string; path: string; body?: string }> = [];
  rateLimitQueue: Array<{ method: string; status: number; retryAfter: string; applyAnyway?: boolean }> = [];
  listOverride?: (name: string, props: { startIpAddress: string; endIpAddress: string }) => {
    startIpAddress: string;
    endIpAddress: string;
  };
  deleteLeavesRule = false;

  async send(request: HttpRequest): Promise<HttpResponse> {
    const url = new URL(request.url);
    const path = url.pathname;
    this.requests.push({ method: request.method, path, body: request.body });

    const collection = `${SQL_ID}/firewallRules`;
    if (this.rateLimitQueue.length > 0 && this.rateLimitQueue[0]?.method === request.method) {
      const rl = this.rateLimitQueue.shift()!;
      if (rl.applyAnyway && request.method === "PUT" && path.startsWith(`${collection}/`)) {
        const rule = decodeURIComponent(path.slice(collection.length + 1));
        const parsed = JSON.parse(request.body ?? "{}") as {
          properties: { startIpAddress: string; endIpAddress: string };
        };
        this.rules.set(rule, { ...parsed.properties });
      }
      return {
        status: rl.status,
        headers: { "retry-after": rl.retryAfter },
        body: JSON.stringify({ error: { code: "TooManyRequests", message: "throttled" } }),
      };
    }

    if (path === collection && request.method === "GET") {
      const value = Array.from(this.rules.entries()).map(([name, props]) => ({
        name,
        properties: this.listOverride !== undefined ? this.listOverride(name, props) : props,
      }));
      return {
        status: 200,
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ value }),
      };
    }

    if (!path.startsWith(`${collection}/`)) {
      throw new Error(`forbidden_endpoint:${request.method}:${path}`);
    }
    const rule = decodeURIComponent(path.slice(collection.length + 1));

    if (request.method === "GET") {
      const existing = this.rules.get(rule);
      if (existing === undefined) {
        return { status: 404, headers: {}, body: JSON.stringify({ error: { code: "ResourceNotFound" } }) };
      }
      return {
        status: 200,
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ name: rule, properties: existing }),
      };
    }

    if (request.method === "PUT") {
      const parsed = JSON.parse(request.body ?? "{}") as {
        properties: { startIpAddress: string; endIpAddress: string };
      };
      this.rules.set(rule, { ...parsed.properties });
      return {
        status: 200,
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ name: rule, properties: parsed.properties }),
      };
    }

    if (request.method === "DELETE") {
      if (!this.deleteLeavesRule) {
        this.rules.delete(rule);
      }
      return { status: 200, headers: {}, body: "" };
    }

    return { status: 405, headers: {}, body: "" };
  }
}

function makeProvider(arm: StrictSqlArm, audit = new MemoryAuditSink(), sleepCalls: number[] = []) {
  return {
    audit,
    sleepCalls,
    provider: createAzureSqlRuleProvider({
      transport: arm,
      tokenProvider: { async getToken() { return TOKEN; } },
      audit,
      now: () => new Date("2026-11-25T00:00:00.000Z"),
      sleep: async (ms) => {
        sleepCalls.push(ms);
      },
      writersCommitSha: PIN_SHA,
    }),
  };
}

describe("azure sql single-rule provider (Slice 2)", () => {
  it("exports least-privilege actions without Microsoft.Sql/servers/read", () => {
    assert.deepEqual([...AZURE_SQL_RULE_PROVIDER_ACTIONS], [
      "Microsoft.Sql/servers/firewallRules/read",
      "Microsoft.Sql/servers/firewallRules/write",
      "Microsoft.Sql/servers/firewallRules/delete",
    ]);
  });

  it("validates sbc-<expiry>-<ulid> rule names strictly", () => {
    assert.equal(isSbcRuleName(SBC_RULE), true);
    const parsed = parseSbcRuleName(SBC_RULE);
    assert.equal(parsed.ok, true);
    if (parsed.ok) {
      assert.equal(parsed.value.expiresAtSeconds, 1700000600);
      assert.equal(parsed.value.ulid, "01HF7YAT00S5WARN4TQ5A8XEWP");
    }
    for (const bad of [
      "clearance-01HF7YAT00S5WARN4TQ5A8XEWP",
      "AllowAllWindowsAzureIps",
      "customer-office",
      "sbc-0-01HF7YAT00S5WARN4TQ5A8XEWP",
      "sbc-1700000600-lowercaseulid00000000000000",
    ]) {
      assert.equal(isSbcRuleName(bad), false);
    }
  });

  it("opens and closes using firewallRules/{read,write,delete} only, stamps writersCommitSha without process.env, and allows legitimate customer range rules untouched/unreported", async () => {
    const arm = new StrictSqlArm();
    arm.rules.set("customer-office-vpn", { startIpAddress: "198.51.100.0", endIpAddress: "198.51.100.255" });
    const { provider, audit } = makeProvider(arm);

    const opened = await provider.openRule({
      ledgerOwned: true,
      resourceId: SQL_ID,
      ruleName: SBC_RULE,
      ipv4: IP,
      ttlSeconds: 300,
    });
    assert.equal(opened.ok, true);
    assert.equal(arm.requests.some((r) => r.path === SQL_ID), false);
    assert.deepEqual(
      arm.requests.map((r) => `${r.method} ${r.path.slice(SQL_ID.length)}`),
      [
        `GET /firewallRules/${SBC_RULE}`,
        `PUT /firewallRules/${SBC_RULE}`,
        "GET /firewallRules",
      ],
    );

    const closed = await provider.closeRule({
      ledgerOwned: true,
      resourceId: SQL_ID,
      ruleName: SBC_RULE,
    });
    assert.equal(closed.ok, true);
    assert.equal(arm.rules.has(SBC_RULE), false);
    assert.deepEqual(arm.rules.get("customer-office-vpn"), {
      startIpAddress: "198.51.100.0",
      endIpAddress: "198.51.100.255",
    });
    for (const event of audit.events) {
      assert.equal(event.writersCommitSha, PIN_SHA);
      assert.equal(JSON.stringify(event).includes("customer-office-vpn"), false);
      assert.equal(JSON.stringify(event).includes("198.51.100.255"), false);
    }
  });

  it("open read-back (B-T5 & B-T6) fails closed on allow-all and allow-Azure-services, removes OUR rule, audits violation, and never modifies or reports customer rules", async () => {
    const cases: Array<{
      label: string;
      customerName: string;
      customerProps: { startIpAddress: string; endIpAddress: string };
      expectedCode: string;
      expectedDetail: string;
    }> = [
      {
        label: "allow-all 0.0.0.0-255.255.255.255",
        customerName: "customer-wide-open",
        customerProps: { startIpAddress: "0.0.0.0", endIpAddress: "255.255.255.255" },
        expectedCode: "verify_failed",
        expectedDetail: "readback_allow_all",
      },
      {
        label: "allow-Azure-services 0.0.0.0-0.0.0.0",
        customerName: "AllowAllWindowsAzureIps",
        customerProps: { startIpAddress: "0.0.0.0", endIpAddress: "0.0.0.0" },
        expectedCode: "server_allows_azure_services",
        expectedDetail: "server_allows_azure_services",
      },
    ];

    for (const testCase of cases) {
      const arm = new StrictSqlArm();
      arm.rules.set(testCase.customerName, { ...testCase.customerProps });
      const { provider, audit } = makeProvider(arm);

      const res = await provider.openRule({
        ledgerOwned: true,
        resourceId: SQL_ID,
        ruleName: SBC_RULE,
        ipv4: IP,
        ttlSeconds: 300,
      });
      assert.equal(res.ok, false, testCase.label);
      if (!res.ok) {
        assert.equal(res.error.code, testCase.expectedCode, testCase.label);
        assert.equal(res.error.ruleApplied, false, testCase.label);
        assert.equal(res.error.removalVerified, true, testCase.label);
        assert.equal(res.error.message.includes(testCase.customerName), false, testCase.label);
      }
      assert.equal(arm.rules.has(SBC_RULE), false, `${testCase.label}: our rule must be deleted`);
      assert.deepEqual(arm.rules.get(testCase.customerName), testCase.customerProps, `${testCase.label}: customer rule untouched`);
      assert.equal(
        audit.events.some((e) => e.detailCode === testCase.expectedDetail && e.outcome === "failed"),
        true,
        testCase.label,
      );
      assert.equal(JSON.stringify(audit.events).includes(testCase.customerName), false, testCase.label);
    }
  });

  it("open read-back fails closed and removes OUR rule when our sbc- rule has a range, wrong IP, or an extra sbc- rule exists for the same lease", async () => {
    const armRange = new StrictSqlArm();
    armRange.listOverride = (name, props) =>
      name === SBC_RULE ? { startIpAddress: IP, endIpAddress: "8.8.8.20" } : props;
    const { provider: providerRange } = makeProvider(armRange);
    const resRange = await providerRange.openRule({
      ledgerOwned: true,
      resourceId: SQL_ID,
      ruleName: SBC_RULE,
      ipv4: IP,
      ttlSeconds: 300,
    });
    assert.equal(resRange.ok, false);
    if (!resRange.ok) {
      assert.equal(resRange.error.code, "verify_failed");
      assert.equal(resRange.error.removalVerified, true);
    }
    assert.equal(armRange.rules.has(SBC_RULE), false);

    const armExtra = new StrictSqlArm();
    armExtra.rules.set(SBC_RULE_SAME_ULID, { startIpAddress: "1.1.1.1", endIpAddress: "1.1.1.1" });
    const { provider: providerExtra } = makeProvider(armExtra);
    const resExtra = await providerExtra.openRule({
      ledgerOwned: true,
      resourceId: SQL_ID,
      ruleName: SBC_RULE,
      ipv4: IP,
      ttlSeconds: 300,
    });
    assert.equal(resExtra.ok, false);
    if (!resExtra.ok) {
      assert.equal(resExtra.error.code, "verify_failed");
      assert.equal(resExtra.error.removalVerified, true);
    }
    assert.equal(armExtra.rules.has(SBC_RULE), false);
  });

  it("collision fails closed with rule_conflict and zero PUTs regardless of existing IP", async () => {
    for (const existingIp of ["1.1.1.1", IP]) {
      const arm = new StrictSqlArm();
      arm.rules.set(SBC_RULE, { startIpAddress: existingIp, endIpAddress: existingIp });
      const { provider } = makeProvider(arm);

      const res = await provider.openRule({
        ledgerOwned: true,
        resourceId: SQL_ID,
        ruleName: SBC_RULE,
        ipv4: IP,
        ttlSeconds: 300,
      });
      assert.equal(res.ok, false);
      if (!res.ok) {
        assert.equal(res.error.code, "rule_conflict");
        assert.equal(res.error.ruleApplied, false);
      }
      assert.equal(arm.requests.some((r) => r.method === "PUT"), false);
      assert.deepEqual(arm.rules.get(SBC_RULE), { startIpAddress: existingIp, endIpAddress: existingIp });
    }
  });

  it("429 on PUT verifies absence via read-back before setting removalVerified=true, and treats unverified 429 or any 503 PUT as possibly applied", async () => {
    // 429 on PUT + 404 read-back -> confirmed absent (ruleApplied=false, removalVerified=true), zero inline sleep.
    const arm429Absent = new StrictSqlArm();
    arm429Absent.rateLimitQueue.push({ method: "PUT", status: 429, retryAfter: "45" });
    const { provider: pAbsent, sleepCalls } = makeProvider(arm429Absent);
    const resAbsent = await pAbsent.openRule({
      ledgerOwned: true,
      resourceId: SQL_ID,
      ruleName: SBC_RULE,
      ipv4: IP,
      ttlSeconds: 300,
    });
    assert.equal(resAbsent.ok, false);
    if (!resAbsent.ok) {
      assert.equal(resAbsent.error.code, "throttled");
      assert.equal(resAbsent.error.retryAfterSeconds, 45);
      assert.equal(resAbsent.error.ruleApplied, false);
      assert.equal(resAbsent.error.removalVerified, true);
    }
    assert.deepEqual(sleepCalls, []);
    assert.equal(arm429Absent.requests.filter((r) => r.method === "GET").length, 2);

    // 429 on PUT where rule WAS applied (or read-back throttled) -> ruleApplied=true, removalVerified=false.
    const arm429Applied = new StrictSqlArm();
    arm429Applied.rateLimitQueue.push({ method: "PUT", status: 429, retryAfter: "45", applyAnyway: true });
    const { provider: pApplied } = makeProvider(arm429Applied);
    const resApplied = await pApplied.openRule({
      ledgerOwned: true,
      resourceId: SQL_ID,
      ruleName: SBC_RULE,
      ipv4: IP,
      ttlSeconds: 300,
    });
    assert.equal(resApplied.ok, false);
    if (!resApplied.ok) {
      assert.equal(resApplied.error.code, "throttled");
      assert.equal(resApplied.error.ruleApplied, true);
      assert.equal(resApplied.error.removalVerified, false);
    }

    // 503 on PUT -> ALWAYS treated as possibly applied (ruleApplied=true, removalVerified=false) even if absent right now.
    const arm503 = new StrictSqlArm();
    arm503.rateLimitQueue.push({ method: "PUT", status: 503, retryAfter: "30" });
    const { provider: p503 } = makeProvider(arm503);
    const res503 = await p503.openRule({
      ledgerOwned: true,
      resourceId: SQL_ID,
      ruleName: SBC_RULE,
      ipv4: IP,
      ttlSeconds: 300,
    });
    assert.equal(res503.ok, false);
    if (!res503.ok) {
      assert.equal(res503.error.code, "throttled");
      assert.equal(res503.error.retryAfterSeconds, 30);
      assert.equal(res503.error.ruleApplied, true);
      assert.equal(res503.error.removalVerified, false);
    }
  });

  it("refuses non-sbc- rule deletes with zero ARM calls and detects leftover after delete", async () => {
    const arm = new StrictSqlArm();
    arm.rules.set("customer-vpn", { startIpAddress: "1.1.1.1", endIpAddress: "1.1.1.1" });
    arm.rules.set(SBC_RULE, { startIpAddress: IP, endIpAddress: IP });
    const { provider } = makeProvider(arm);

    const refused = await provider.closeRule({
      ledgerOwned: true,
      resourceId: SQL_ID,
      ruleName: "customer-vpn",
    });
    assert.equal(refused.ok, false);
    if (!refused.ok) {
      assert.equal(refused.error.code, "invalid_rule_name");
    }
    assert.equal(arm.requests.length, 0);

    arm.deleteLeavesRule = true;
    const leftover = await provider.closeRule({
      ledgerOwned: true,
      resourceId: SQL_ID,
      ruleName: SBC_RULE,
    });
    assert.equal(leftover.ok, false);
    if (!leftover.ok) {
      assert.equal(leftover.error.code, "delete_not_verified");
      assert.equal(leftover.error.ruleApplied, true);
    }
  });

  it("listSbcRules returns only sbc- rules with parsed expiry and hides customer rules", async () => {
    const arm = new StrictSqlArm();
    arm.rules.set("customer-secret-rule", { startIpAddress: "1.1.1.1", endIpAddress: "1.1.1.1" });
    arm.rules.set(SBC_RULE, { startIpAddress: IP, endIpAddress: IP });
    arm.rules.set(SBC_RULE_EXPIRED, { startIpAddress: "9.9.9.9", endIpAddress: "9.9.9.9" });
    const { provider, audit } = makeProvider(arm);

    const listed = await provider.listSbcRules({ resourceId: SQL_ID });
    assert.equal(listed.ok, true);
    if (listed.ok) {
      assert.deepEqual(
        listed.value.rules.map((r) => ({ name: r.ruleName, exp: r.expiresAtSeconds })),
        [
          { name: SBC_RULE, exp: 1700000600 },
          { name: SBC_RULE_EXPIRED, exp: 1699999000 },
        ],
      );
      assert.equal(JSON.stringify(listed.value).includes("customer-secret-rule"), false);
    }
    assert.equal(JSON.stringify(audit.events).includes("customer-secret-rule"), false);
  });
});

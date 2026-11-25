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
const SBC_RULE_EXPIRED = "sbc-1699999000-01HF7YAT00S5WARN4TQ5A8XEWQ";
const PIN_SHA = "0123456789abcdef0123456789abcdef01234567";

class StrictSqlArm implements HttpTransport {
  readonly rules = new Map<string, { startIpAddress: string; endIpAddress: string }>();
  readonly requests: Array<{ method: string; path: string; body?: string }> = [];
  nextRateLimit: { status: number; retryAfter: string } | null = null;
  deleteLeavesRule = false;

  async send(request: HttpRequest): Promise<HttpResponse> {
    const url = new URL(request.url);
    const path = url.pathname;
    this.requests.push({ method: request.method, path, body: request.body });

    if (this.nextRateLimit !== null && (request.method === "PUT" || request.method === "DELETE")) {
      const rl = this.nextRateLimit;
      this.nextRateLimit = null;
      return {
        status: rl.status,
        headers: { "retry-after": rl.retryAfter },
        body: JSON.stringify({ error: { code: "TooManyRequests", message: "throttled" } }),
      };
    }

    const collection = `${SQL_ID}/firewallRules`;
    if (path === collection && request.method === "GET") {
      const value = Array.from(this.rules.entries()).map(([name, props]) => ({
        name,
        properties: props,
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

  it("opens and closes using firewallRules/{read,write,delete} only, stamps writersCommitSha without process.env, and leaves customer single-host rules untouched", async () => {
    const arm = new StrictSqlArm();
    arm.rules.set("customer-single-host", { startIpAddress: "1.1.1.1", endIpAddress: "1.1.1.1" });
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
    assert.deepEqual(arm.rules.get("customer-single-host"), { startIpAddress: "1.1.1.1", endIpAddress: "1.1.1.1" });
    for (const event of audit.events) {
      assert.equal(event.writersCommitSha, PIN_SHA);
      assert.equal(JSON.stringify(event).includes("customer-single-host"), false);
    }
  });

  it("open read-back (B-T5 & B-T6) fails closed, removes OUR rule, audits violation, and never modifies or reports customer rules", async () => {
    const cases: Array<{
      label: string;
      customerName: string;
      customerProps: { startIpAddress: string; endIpAddress: string };
      expectedDetail: string;
    }> = [
      {
        label: "allow-all 0.0.0.0-255.255.255.255",
        customerName: "customer-wide-open",
        customerProps: { startIpAddress: "0.0.0.0", endIpAddress: "255.255.255.255" },
        expectedDetail: "readback_allow_all",
      },
      {
        label: "allow-Azure-services 0.0.0.0-0.0.0.0",
        customerName: "AllowAllWindowsAzureIps",
        customerProps: { startIpAddress: "0.0.0.0", endIpAddress: "0.0.0.0" },
        expectedDetail: "readback_azure_services",
      },
      {
        label: "range rule start != end",
        customerName: "customer-office-range",
        customerProps: { startIpAddress: "8.8.8.1", endIpAddress: "8.8.8.254" },
        expectedDetail: "readback_range_rule",
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
        assert.equal(res.error.code, "verify_failed", testCase.label);
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

  it("returns 429 Retry-After immediately with zero inline sleep and ruleApplied=false on throttled PUT", async () => {
    const arm = new StrictSqlArm();
    arm.nextRateLimit = { status: 429, retryAfter: "45" };
    const { provider, sleepCalls } = makeProvider(arm);

    const res = await provider.openRule({
      ledgerOwned: true,
      resourceId: SQL_ID,
      ruleName: SBC_RULE,
      ipv4: IP,
      ttlSeconds: 300,
    });
    assert.equal(res.ok, false);
    if (!res.ok) {
      assert.equal(res.error.code, "throttled");
      assert.equal(res.error.retryAfterSeconds, 45);
      assert.equal(res.error.ruleApplied, false);
    }
    assert.deepEqual(sleepCalls, []);
    assert.equal(arm.requests.filter((r) => r.method === "PUT").length, 1);
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

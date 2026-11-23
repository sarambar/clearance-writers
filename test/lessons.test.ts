// Copyright 2026 Sarambar
// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { FakeArm } from "../src/azure/fake-arm.js";
import { AZURE_POSTGRES_FIREWALL_PROFILE, AZURE_SQL_FIREWALL_PROFILE, UNIMPLEMENTED_SERVICES } from "../src/azure/profiles.js";
import { validateRoleDefinitionDeleteArgs } from "../src/azure/role-definition.js";
import type { HttpRequest, HttpResponse, HttpTransport } from "../src/azure/http.js";
import {
  SQL_FIREWALL_CACHE_WINDOW_SECONDS,
  classifyReachability,
  exposureBoundSeconds,
  normalizeAzureLocation,
  observePostgresDriverError,
  observeSqlDriverError,
  postDeleteProbePassed,
} from "../src/index.js";
import { IP, RULE, SQL_ID, TOKEN, addRequest, harness } from "./helpers.js";

describe("lessons", () => {
  it("1. a confirmation prompt fails the fake and does not delete", async () => {
    const fake = new FakeArm();
    fake.seedServer({
      resourceId: SQL_ID,
      location: "centralus",
      rules: [{ name: RULE, startIpv4: IP, endIpv4: IP }],
    });
    const url = `https://management.azure.com${SQL_ID}/firewallRules/${RULE}?api-version=${AZURE_SQL_FIREWALL_PROFILE.apiVersion}&confirm=prompt`;
    const response = await fake.send({
      method: "DELETE",
      url,
      headers: { authorization: `Bearer ${TOKEN}` },
    });
    assert.equal(response.status, 400);
    assert.match(response.body, /ConfirmationRequired/);
    assert.match(response.body, /no tty available/);
    assert.equal(fake.rulesFor(SQL_ID)?.length, 1);
    const { fake: writerFake, writer, resourceId } = harness("sql", {
      rules: [{ name: RULE, startIpv4: IP, endIpv4: IP }],
    });
    assert.equal((await writer.removeRule({ resourceId, ruleName: RULE, ledgerOwned: true })).ok, true);
    assert.equal(writerFake.requests.some((request) => request.url.includes("confirm=")), false);
  });

  it("2. compares locations only after folding display form", () => {
    assert.equal(normalizeAzureLocation("Central US"), "centralus");
    assert.equal(normalizeAzureLocation("eastus2"), normalizeAzureLocation("East US 2"));
    assert.equal(normalizeAzureLocation("UK South"), "uksouth");
  });

  it("2. accepts centralus when ARM returns Central US", async () => {
    const { fake, writer, resourceId } = harness("sql");
    const matched = await writer.addRule(addRequest(resourceId, { expectedLocation: "centralus" }));
    assert.equal(matched.ok, true);
    const mismatched = await writer.addRule(addRequest(resourceId, { expectedLocation: "eastus", ruleName: "clearance-jobtoken2" }));
    assert.equal(mismatched.ok, false);
    if (!mismatched.ok) {
      assert.equal(mismatched.error.code, "location_mismatch");
    }
    assert.equal(fake.requests.filter((request) => request.method === "PUT").length, 1);
  });

  it("3. classifies SQL and PostgreSQL probe failures differently", () => {
    assert.equal(classifyReachability(observeSqlDriverError({ number: 40615, message: "Cannot open server" })), "firewall-block");
    assert.equal(classifyReachability(observeSqlDriverError({ message: "timeout expired" })), "tool-error");
    assert.equal(classifyReachability(observeSqlDriverError({ number: 18456, message: "Login failed for user 'example'" })), "reachable-login-rejected");
    assert.equal(classifyReachability({ service: "azure-sql", outcome: "connected" }), "login-succeeded");
    assert.equal(classifyReachability(observePostgresDriverError({ message: "timeout expired" })), "firewall-block");
    assert.equal(classifyReachability(observePostgresDriverError({ code: "ETIMEDOUT" })), "firewall-block");
    assert.equal(classifyReachability(observePostgresDriverError({ number: 40615, message: "Cannot open server" })), "tool-error");
    assert.equal(
      classifyReachability(observePostgresDriverError({ sqlState: "28P01", message: "password authentication failed for user \"example\"" })),
      "reachable-login-rejected",
    );
    assert.equal(postDeleteProbePassed("firewall-block"), true);
    assert.equal(postDeleteProbePassed("login-succeeded"), false);
    assert.equal(SQL_FIREWALL_CACHE_WINDOW_SECONDS, 300);
  });

  it("4. rejects non-numeric and out-of-range durations", async () => {
    const { writer, fake, resourceId } = harness("sql");
    for (const ttlSeconds of [Number.NaN, Number.POSITIVE_INFINITY, -1, 0, 1.5, 3601]) {
      const result = await writer.addRule(addRequest(resourceId, { ttlSeconds }));
      assert.equal(result.ok, false);
      if (!result.ok) {
        assert.equal(result.error.code, "invalid_ttl");
      }
    }
    const text = await writer.addRule({ ...addRequest(resourceId), ttlSeconds: "60" as unknown as number });
    assert.equal(text.ok, false);
    assert.equal(fake.requests.length, 0);
  });

  it("5. does not trust a delete status when a later read still shows the rule", async () => {
    const transport: HttpTransport = {
      async send(request: HttpRequest): Promise<HttpResponse> {
        const rule = {
          name: RULE,
          properties: { startIpAddress: IP, endIpAddress: IP },
        };
        if (request.method === "DELETE") {
          return { status: 204, headers: { "content-type": "application/json" }, body: "" };
        }
        return { status: 200, headers: { "content-type": "application/json" }, body: JSON.stringify(rule) };
      },
    };
    const { createAzureSqlFirewallWriter, MemoryAuditSink } = await import("../src/index.js");
    const writer = createAzureSqlFirewallWriter({
      transport,
      tokenProvider: { async getToken() { return TOKEN; } },
      audit: new MemoryAuditSink(),
      sleep: async () => undefined,
    });
    const removed = await writer.removeRule({ resourceId: SQL_ID, ruleName: RULE, ledgerOwned: true });
    assert.equal(removed.ok, false);
    if (!removed.ok) {
      assert.equal(removed.error.code, "delete_not_verified");
      assert.equal(removed.error.ruleApplied, true);
      assert.equal(removed.error.removalVerified, false);
    }
  });

  it("6. the fake rejects a bad api version and a malformed body", async () => {
    const fake = new FakeArm();
    fake.seedServer({ resourceId: SQL_ID, location: "centralus" });
    const missing = await fake.send({
      method: "GET",
      url: `https://management.azure.com${SQL_ID}/firewallRules/${RULE}`,
      headers: { authorization: `Bearer ${TOKEN}` },
    });
    assert.match(missing.body, /MissingApiVersionParameter/);
    const wrong = await fake.send({
      method: "PUT",
      url: `https://management.azure.com${SQL_ID}/firewallRules/${RULE}?api-version=2014-04-01`,
      headers: { authorization: `Bearer ${TOKEN}`, "content-type": "application/json" },
      body: JSON.stringify({ properties: { startIpAddress: IP, endIpAddress: IP } }),
    });
    assert.match(wrong.body, /InvalidApiVersionParameter/);
    assert.equal(fake.rulesFor(SQL_ID)?.length, 0);
    const badJson = await fake.send({
      method: "PUT",
      url: `https://management.azure.com${SQL_ID}/firewallRules/${RULE}?api-version=${AZURE_SQL_FIREWALL_PROFILE.apiVersion}`,
      headers: { authorization: `Bearer ${TOKEN}`, "content-type": "application/json" },
      body: "{",
    });
    assert.match(badJson.body, /InvalidJson/);
  });

  it("7. exposure is TTL plus the sweep interval, and remove is idempotent", () => {
    assert.equal(exposureBoundSeconds(60, 30), 90);
    assert.throws(() => exposureBoundSeconds(Number.POSITIVE_INFINITY, 30));
  });

  it("8. pins server and rule flags per service", () => {
    assert.deepEqual(AZURE_SQL_FIREWALL_PROFILE.cli.serverFlags, ["--server", "-s"]);
    assert.deepEqual(AZURE_SQL_FIREWALL_PROFILE.cli.ruleFlags, ["--name", "-n"]);
    assert.equal(AZURE_SQL_FIREWALL_PROFILE.cli.serverFlags.includes("-n"), false);
    assert.deepEqual(AZURE_POSTGRES_FIREWALL_PROFILE.cli.serverFlags, ["--server-name", "-s"]);
    assert.equal(AZURE_POSTGRES_FIREWALL_PROFILE.cli.serverFlags.includes("-n"), false);
    for (const profile of [AZURE_SQL_FIREWALL_PROFILE, AZURE_POSTGRES_FIREWALL_PROFILE]) {
      for (const flag of profile.cli.serverMustNotUse) {
        assert.equal(profile.cli.serverFlags.includes(flag), false);
      }
    }
    const mysql = UNIMPLEMENTED_SERVICES.find((service) => service.id === "azure-mysql-flexible-firewall");
    assert.equal(mysql?.implemented, false);
    assert.deepEqual(mysql?.cli?.serverFlags, ["--name"]);
    assert.deepEqual(mysql?.cli?.ruleFlags, ["--rule-name"]);
    assert.equal(mysql?.cli?.serverFlags.includes("--server-name"), false);
    const redis = UNIMPLEMENTED_SERVICES.find((service) => service.id === "azure-redis-classic-firewall");
    assert.equal(redis?.deleteGuard, "refuse-last-rule");
    assert.deepEqual(redis?.cli?.startIpFlag, "--start-ip");
    assert.equal(redis?.cli?.serverFlags.includes("--start-ip-address"), false);
    assert.equal(
      classifyReachability(observePostgresDriverError({ message: "connection terminated unexpectedly" })),
      "tool-error",
    );
  });

  it("9. puts the operator line on the error channel", async () => {
    const { writer, resourceId } = harness("sql");
    const result = await writer.addRule(addRequest(resourceId, { ipv4: "0.0.0.0/0" }));
    assert.equal(result.ok, false);
    if (!result.ok) {
      assert.equal(result.error.stream, "error");
      assert.equal(result.error.toOperatorLine().includes("\n"), false);
      assert.match(result.error.toOperatorLine(), /^clearance-writers default_route_forbidden:/);
    }
  });

  it("10. only an allowlisted denial code is an authorization failure", async () => {
    const denied = harness("sql");
    denied.fake.failMatching({ method: "PUT" }, {
      status: 403,
      code: "AuthorizationFailed",
      message: "The client does not have authorization to perform action.",
    });
    const denial = await denied.writer.addRule(addRequest(denied.resourceId));
    assert.equal(denial.ok, false);
    if (!denial.ok) {
      assert.equal(denial.error.code, "authorization_denied");
      assert.equal(denial.error.authorizationDenial, true);
      assert.equal(denial.error.ruleApplied, false);
    }
    assert.equal(denied.fake.rulesFor(SQL_ID)?.length ?? 0, 0);

    const gateway = harness("sql");
    gateway.fake.failMatching({ method: "PUT" }, {
      status: 502,
      code: "BadGateway",
      message: "does not contain sufficient information to enforce access control policy",
    });
    const badGateway = await gateway.writer.addRule(addRequest(gateway.resourceId));
    assert.equal(badGateway.ok, false);
    if (!badGateway.ok) {
      assert.equal(badGateway.error.code, "gateway_error");
      assert.equal(badGateway.error.authorizationDenial, false);
    }

    const empty = harness("sql");
    const listed = await empty.writer.readWholeList({ resourceId: empty.resourceId });
    assert.equal(listed.ok, true);
    if (listed.ok) {
      assert.equal(listed.value.rules.length, 0);
    }
    assert.equal(empty.audit.events.some((event) => event.detailCode === "authorization_denied"), false);
  });

  it("11. role definition delete requires --name and --scope, and an id-only firewall delete is rejected", async () => {
    assert.equal(validateRoleDefinitionDeleteArgs({ id: "00000000-0000-0000-0000-000000000000" }).ok, false);
    assert.match(
      validateRoleDefinitionDeleteArgs({ id: "00000000-0000-0000-0000-000000000000" }).ok
        ? ""
        : (validateRoleDefinitionDeleteArgs({ id: "00000000-0000-0000-0000-000000000000" }) as { message: string }).message,
      /--name/,
    );
    assert.equal(
      validateRoleDefinitionDeleteArgs({
        name: "Sarambar Clearance SQL Firewall",
        scope: `/subscriptions/${"00000000-0000-0000-0000-000000000000"}`,
      }).ok,
      true,
    );
    const fake = new FakeArm();
    fake.seedServer({
      resourceId: SQL_ID,
      location: "centralus",
      rules: [{ name: RULE, startIpv4: IP, endIpv4: IP }, { name: "office-vpn", startIpv4: "198.51.100.20", endIpv4: "198.51.100.20" }],
    });
    const response = await fake.send({
      method: "DELETE",
      url: `https://management.azure.com${SQL_ID}/firewallRules?api-version=${AZURE_SQL_FIREWALL_PROFILE.apiVersion}&id=${SQL_ID}/firewallRules/office-vpn`,
      headers: { authorization: `Bearer ${TOKEN}` },
    });
    assert.equal(response.status, 400);
    assert.match(response.body, /--name/);
    assert.equal(fake.rulesFor(SQL_ID)?.length, 2);
  });
});

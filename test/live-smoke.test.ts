// Copyright 2026 Sarambar
// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";

import { FakeArm } from "../src/azure/fake-arm.js";
import { createAzurePostgresFirewallWriter, createAzureSqlFirewallWriter } from "../src/azure/child-writer.js";
import { formatSmokeReport, liveSmokeBlockedReason, main, runLiveSmoke } from "../src/live-smoke.js";
import { MemoryAuditSink, WRITERS_VERSION } from "../src/index.js";
import { IP, PG_ID, RULE, SQL_ID, TEST_IP_POLICY } from "./helpers.js";

const root = join(dirname(fileURLToPath(import.meta.url)), "../..");

describe("live smoke guards", () => {
  it("refuses CI before any cloud call", async () => {
    assert.match(liveSmokeBlockedReason({ CI: "true" }) ?? "", /CI/);
    assert.equal(await main({ CI: "true", ARM_ACCESS_TOKEN: "test-token" }), 1);
    assert.equal(await main({}), 1);
  });

  it("runs the writer steps against the fake and leaves the foreign rule", async () => {
    const fake = new FakeArm();
    const audit = new MemoryAuditSink();
    const foreign = { name: "office-vpn", startIpv4: "198.51.100.20", endIpv4: "198.51.100.20" };
    fake.seedServer({ resourceId: SQL_ID, location: "centralus", rules: [foreign] });
    fake.seedServer({ resourceId: PG_ID, location: "centralus", rules: [foreign] });
    const options = {
      transport: fake,
      tokenProvider: { async getToken() { return "test-token"; } },
      audit,
      sleep: async () => undefined,
    };
    const report = await runLiveSmoke({
      ipv4: IP,
      ruleName: RULE,
      ipPolicy: TEST_IP_POLICY,
      expectedLocation: "centralus",
      targets: [
        { writer: createAzureSqlFirewallWriter(options), resourceId: SQL_ID },
        { writer: createAzurePostgresFirewallWriter(options), resourceId: PG_ID },
      ],
    });
    assert.equal(report.ok, true);
    assert.equal(report.rows.some((row) => row.result === "FAIL"), false);
    assert.deepEqual(fake.rulesFor(SQL_ID)?.map((rule) => rule.name), ["office-vpn"]);
    assert.deepEqual(fake.rulesFor(PG_ID)?.map((rule) => rule.name), ["office-vpn"]);
    assert.equal(report.audits.every((event) => event.writersVersion === WRITERS_VERSION), true);
    assert.match(formatSmokeReport(report), /foreign-remains \| PASS/);
  });

  it("the shell script tears down with --yes and does not pass a SQL password", () => {
    const script = readFileSync(join(root, "scripts/live-smoke.sh"), "utf8");
    assert.match(script, /az group delete/);
    assert.match(script, /--yes/);
    assert.match(script, /--no-wait/);
    assert.match(script, /api\.ipify\.org/);
    assert.match(script, /get-access-token/);
    assert.match(script, /enable-ad-only-auth/);
    assert.match(script, /password-auth Disabled/);
    assert.match(script, /Standard_B1ms/);
    assert.equal(script.includes("--admin-password"), false);
    assert.equal(script.includes("client-secret"), false);
    assert.match(script, /live-smoke refuses to run in CI/);
  });
});

// Copyright 2026 Sarambar
// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { AzureChildFirewallWriter } from "../src/azure/child-writer.js";
import {
  AZURE_POSTGRES_FIREWALL_API_VERSION,
  AZURE_SQL_FIREWALL_API_VERSION,
  AZURE_SQL_FIREWALL_PROFILE,
  UNIMPLEMENTED_SERVICES,
} from "../src/azure/profiles.js";
import {
  InMemoryFirewallWriter,
  SQL_RULE_CAP,
  type FirewallWriter,
} from "../src/index.js";
import { FOREIGN_IP, IP, OTHER_IP, OTHER_RULE, PG_ID, RULE, SQL_ID, addRequest, harness, methods } from "./helpers.js";

describe("azure sql writer", () => {
  it("adds one named child and does not replace the collection", async () => {
    const { fake, writer, audit, resourceId } = harness("sql", {
      rules: [{ name: "office-vpn", startIpv4: FOREIGN_IP, endIpv4: FOREIGN_IP }],
    });
    const added = await writer.addRule(addRequest(resourceId, { expectedLocation: "centralus" }));
    assert.equal(added.ok, true);
    if (!added.ok) {
      return;
    }
    assert.equal(added.value.replayed, false);
    assert.equal(added.value.locationRaw, "Central US");
    assert.equal(added.value.locationNormalized, "centralus");
    assert.equal(added.value.startIpv4, IP);
    assert.equal(added.value.endIpv4, IP);
    const rules = fake.rulesFor(SQL_ID);
    assert.deepEqual(
      rules?.map((rule) => rule.name).sort(),
      ["clearance-jobtoken1", "office-vpn"],
    );
    assert.equal(methods(fake).some((line) => line.startsWith("PUT") && line.endsWith("/firewallRules")), false);
    assert.equal(methods(fake).some((line) => line.endsWith(`/firewallRules/${RULE}`)), true);
    const put = fake.requests.find((request) => request.method === "PUT");
    assert.ok(put);
    assert.equal(new URL(put.url).searchParams.get("api-version"), AZURE_SQL_FIREWALL_API_VERSION);
    assert.match(put.headers["user-agent"] ?? put.headers["User-Agent"] ?? "", /clearance-writers\/0\.0\.0/);
    assert.equal(audit.events[0]?.phase, "intent");
    assert.equal(audit.events.at(-1)?.outcome, "succeeded");
    assert.equal(audit.events.every((event) => event.writersVersion === "0.0.0"), true);
  });

  it("replays the same rule without a second PUT", async () => {
    const { fake, writer, resourceId } = harness("sql");
    assert.equal((await writer.addRule(addRequest(resourceId))).ok, true);
    const before = fake.requests.filter((request) => request.method === "PUT").length;
    const again = await writer.addRule(addRequest(resourceId));
    assert.equal(again.ok, true);
    if (again.ok) {
      assert.equal(again.value.replayed, true);
    }
    assert.equal(fake.requests.filter((request) => request.method === "PUT").length, before);
  });

  it("does not overwrite a different address on the same name", async () => {
    const { fake, writer, resourceId } = harness("sql", {
      rules: [{ name: RULE, startIpv4: OTHER_IP, endIpv4: OTHER_IP }],
    });
    const result = await writer.addRule(addRequest(resourceId));
    assert.equal(result.ok, false);
    if (!result.ok) {
      assert.equal(result.error.code, "rule_conflict");
    }
    assert.equal(fake.requests.some((request) => request.method === "PUT"), false);
    assert.equal(fake.rulesFor(SQL_ID)?.[0]?.startIpv4, OTHER_IP);
  });

  it("removes only the named Clearance rule and verifies it is gone", async () => {
    const { fake, writer, resourceId } = harness("sql", {
      rules: [
        { name: "office-vpn", startIpv4: FOREIGN_IP, endIpv4: FOREIGN_IP },
        { name: RULE, startIpv4: IP, endIpv4: IP },
      ],
    });
    const removed = await writer.removeRule({ resourceId, ruleName: RULE, ledgerOwned: true });
    assert.equal(removed.ok, true);
    if (removed.ok) {
      assert.equal(removed.value.removalVerified, true);
      assert.equal(removed.value.alreadyAbsent, false);
    }
    assert.deepEqual(fake.rulesFor(SQL_ID)?.map((rule) => rule.name), ["office-vpn"]);
    const again = await writer.removeRule({ resourceId, ruleName: RULE, ledgerOwned: true });
    assert.equal(again.ok, true);
    if (again.ok) {
      assert.equal(again.value.alreadyAbsent, true);
    }
    assert.equal(fake.requests.filter((request) => request.method === "DELETE").length, 1);
  });

  it("lists owned rules separately from the whole list", async () => {
    const { writer, resourceId } = harness("sql", {
      rules: [
        { name: "office-vpn", startIpv4: FOREIGN_IP, endIpv4: FOREIGN_IP },
        { name: RULE, startIpv4: IP, endIpv4: IP },
        { name: OTHER_RULE, startIpv4: OTHER_IP, endIpv4: OTHER_IP },
      ],
    });
    const whole = await writer.readWholeList({ resourceId });
    const owned = await writer.listOwnedRules({ resourceId });
    assert.equal(whole.ok && whole.value.rules.length, 3);
    assert.equal(owned.ok && owned.value.rules.length, 2);
    if (owned.ok) {
      assert.equal(owned.value.rules.every((rule) => rule.owned), true);
    }
  });

  it("refuses a 257th SQL rule before calling PUT", async () => {
    const rules = Array.from({ length: SQL_RULE_CAP }, (_, index) => ({
      name: `customer-${index}`,
      startIpv4: FOREIGN_IP,
      endIpv4: FOREIGN_IP,
    }));
    const { fake, writer, resourceId } = harness("sql", { rules });
    const result = await writer.addRule(addRequest(resourceId));
    assert.equal(result.ok, false);
    if (!result.ok) {
      assert.equal(result.error.code, "rule_cap_exceeded");
    }
    assert.equal(fake.requests.some((request) => request.method === "PUT"), false);
    assert.equal(fake.rulesFor(SQL_ID)?.length, SQL_RULE_CAP);
  });

  it("still deletes when the server is already at the SQL cap", async () => {
    const rules = [
      { name: RULE, startIpv4: IP, endIpv4: IP },
      ...Array.from({ length: SQL_RULE_CAP - 1 }, (_, index) => ({
        name: `customer-${index}`,
        startIpv4: FOREIGN_IP,
        endIpv4: FOREIGN_IP,
      })),
    ];
    const { fake, writer, resourceId } = harness("sql", { rules });
    const removed = await writer.removeRule({ resourceId, ruleName: RULE, ledgerOwned: true });
    assert.equal(removed.ok, true);
    assert.equal(fake.rulesFor(SQL_ID)?.some((rule) => rule.name === RULE), false);
  });
});

describe("azure postgres writer", () => {
  it("polls the long-running create and delete", async () => {
    const { fake, writer, delays, resourceId } = harness("pg");
    const added = await writer.addRule(addRequest(resourceId));
    assert.equal(added.ok, true);
    assert.ok(delays.includes(30_000));
    assert.equal(new URL(fake.requests.find((request) => request.method === "PUT")?.url ?? "https://example.com").searchParams.get("api-version"), AZURE_POSTGRES_FIREWALL_API_VERSION);
    assert.equal(fake.rulesFor(PG_ID)?.length, 1);
    const removed = await writer.removeRule({ resourceId, ruleName: RULE, ledgerOwned: true });
    assert.equal(removed.ok, true);
    assert.equal(fake.rulesFor(PG_ID)?.length, 0);
    assert.equal(fake.requests.some((request) => request.url.includes("/operationResults/")), true);
  });

  it("does not invent a firewall-rule cap", async () => {
    const rules = Array.from({ length: 30 }, (_, index) => ({
      name: `customer-${index}`,
      startIpv4: FOREIGN_IP,
      endIpv4: FOREIGN_IP,
    }));
    const { fake, writer, resourceId } = harness("pg", { rules });
    const added = await writer.addRule(addRequest(resourceId));
    assert.equal(added.ok, true);
    assert.equal(fake.rulesFor(PG_ID)?.length, 31);
  });

  it("refuses a private-access server before PUT", async () => {
    const { fake, writer, resourceId } = harness("pg", { publicNetworkAccess: "Disabled" });
    const result = await writer.addRule(addRequest(resourceId));
    assert.equal(result.ok, false);
    if (!result.ok) {
      assert.equal(result.error.code, "public_access_disabled");
    }
    assert.equal(fake.requests.some((request) => request.method === "PUT"), false);
  });
});

describe("writer contract", () => {
  it("runs the same open and close calls against memory and Azure", async () => {
    async function openAndClose(writer: FirewallWriter, resourceId: string) {
      const added = await writer.addRule(addRequest(resourceId));
      const removed = await writer.removeRule({ resourceId, ruleName: RULE, ledgerOwned: true });
      return { added, removed };
    }
    const azure = harness("sql");
    const memoryAudit = new (await import("../src/index.js")).MemoryAuditSink();
    const memory = new InMemoryFirewallWriter({ audit: memoryAudit, now: () => new Date("2026-01-01T00:00:00.000Z") });
    const cloud = await openAndClose(azure.writer, azure.resourceId);
    const local = await openAndClose(memory, "memory:sql-example");
    assert.equal(cloud.added.ok && cloud.removed.ok, true);
    assert.equal(local.added.ok && local.removed.ok, true);
    assert.equal(azure.writer.descriptor.listShape, memory.descriptor.listShape);
    assert.notEqual(azure.writer.descriptor.cloud, memory.descriptor.cloud);
  });

  it("follows a same-origin nextLink and returns every rule", async () => {
    const { fake, writer, resourceId } = harness("sql", {
      rules: [
        { name: "office-vpn", startIpv4: FOREIGN_IP, endIpv4: FOREIGN_IP },
        { name: RULE, startIpv4: IP, endIpv4: IP },
        { name: OTHER_RULE, startIpv4: OTHER_IP, endIpv4: OTHER_IP },
      ],
    });
    const whole = await writer.readWholeList({ resourceId });
    assert.equal(whole.ok && whole.value.rules.length, 3);
    assert.equal(fake.requests.filter((request) => request.method === "GET" && request.url.includes("skip=")).length, 1);
  });

  it("refuses the last rule only when the profile's guard says so", async () => {
    const { fake, audit, resourceId } = harness("sql", {
      rules: [{ name: RULE, startIpv4: IP, endIpv4: IP }],
    });
    const redis = UNIMPLEMENTED_SERVICES.find((service) => service.id === "azure-redis-classic-firewall");
    assert.equal(redis?.deleteGuard, "refuse-last-rule");
    assert.equal(AZURE_SQL_FIREWALL_PROFILE.deleteGuard, "none");
    const guarded = new AzureChildFirewallWriter(
      { ...AZURE_SQL_FIREWALL_PROFILE, deleteGuard: redis?.deleteGuard ?? "none" },
      {
        transport: fake,
        tokenProvider: { async getToken() { return "test-token"; } },
        audit,
        now: () => new Date("2026-01-01T00:00:00.000Z"),
        sleep: async () => undefined,
      },
    );
    const refused = await guarded.removeRule({ resourceId, ruleName: RULE, ledgerOwned: true });
    assert.equal(refused.ok, false);
    if (!refused.ok) {
      assert.equal(refused.error.code, "last_rule_refused");
    }
    assert.equal(fake.rulesFor(SQL_ID)?.length, 1);
    assert.equal(fake.requests.some((request) => request.method === "DELETE"), false);
  });
});

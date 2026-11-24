// Copyright 2026 Sarambar
// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import { readFileSync, readdirSync, statSync } from "node:fs";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";

import { ArmClient } from "../src/azure/arm.js";
import { FakeArm } from "../src/azure/fake-arm.js";
import type { HttpRequest, HttpResponse } from "../src/azure/http.js";
import {
  AZURE_POSTGRES_FIREWALL_PROFILE,
  AZURE_SQL_FIREWALL_PROFILE,
  UNIMPLEMENTED_SERVICES,
} from "../src/azure/profiles.js";
import { containsDisallowedCharacters, sha256Hex } from "../src/codec.js";
import { CLEARANCE_RULE_PREFIX, RULE_NAME, parseRuleName } from "../src/names.js";
import { MemoryAuditSink, createAzureSqlFirewallWriter } from "../src/index.js";
import { IP, OTHER_IP, RULE, SQL_ID, TOKEN, addRequest } from "./helpers.js";

const root = join(dirname(fileURLToPath(import.meta.url)), "../..");
const CHILD = `${SQL_ID}/firewallRules/${RULE}`;

function walk(directory: string): string[] {
  const found: string[] = [];
  for (const name of readdirSync(directory)) {
    if (name === "node_modules" || name === "dist" || name === ".git") {
      continue;
    }
    const path = join(directory, name);
    if (statSync(path).isDirectory()) {
      found.push(...walk(path));
    } else {
      found.push(path);
    }
  }
  return found;
}

function ruleNameBodyMin(pattern: RegExp): number {
  const match = /\{(\d+),(\d+)\}/.exec(pattern.source);
  assert.ok(match, pattern.source);
  return Number(match[1]);
}

function armClient(handler: (request: HttpRequest) => HttpResponse) {
  const requests: HttpRequest[] = [];
  const client = new ArmClient({
    transport: {
      async send(request) {
        requests.push(request);
        return handler(request);
      },
    },
    tokenProvider: { async getToken() { return TOKEN; } },
    userAgent: "clearance-writers-test",
    sleep: async () => undefined,
  });
  return { client, requests };
}

describe("encoded constraints", () => {
  it("hashes UTF-8 and refuses non-NFC or disallowed characters", () => {
    assert.equal(sha256Hex("café"), "850f7dc43910ff890f8879c0ed26fe697c93a067ad93a7d50f466a7028a9bf4e");
    assert.equal(containsDisallowedCharacters("e\u0301"), true);
    assert.equal(containsDisallowedCharacters("é"), false);
    assert.equal(containsDisallowedCharacters("a\u200b"), true);
    assert.equal(containsDisallowedCharacters("a\u202e"), true);
    assert.equal(containsDisallowedCharacters("clearance-jobtoken1"), false);
  });

  it("does not shell out, and does not export a role-definition delete", async () => {
    for (const path of walk(join(root, "src"))) {
      const text = readFileSync(path, "utf8");
      assert.equal(/child_process/.test(text), false, path);
      assert.equal(/\bspawn(?:Sync)?\b|\bexecFile(?:Sync)?\b|\bexecSync\b/.test(text), false, path);
    }
    const role = await import("../src/azure/role-definition.js");
    assert.deepEqual(Object.keys(role).sort(), ["validateRoleDefinitionDeleteArgs"]);
  });

  it("keeps unimplemented services unimplemented, and pins lro and name floors", () => {
    assert.equal(AZURE_SQL_FIREWALL_PROFILE.lro, "sync");
    assert.equal(AZURE_POSTGRES_FIREWALL_PROFILE.lro, "async");
    const bodyMin = ruleNameBodyMin(RULE_NAME);
    assert.equal(bodyMin, 8);
    const clearanceMin = CLEARANCE_RULE_PREFIX.length + bodyMin;
    assert.equal(parseRuleName(`${CLEARANCE_RULE_PREFIX}${"a".repeat(bodyMin)}`).ok, true);
    assert.equal(parseRuleName(`${CLEARANCE_RULE_PREFIX}${"a".repeat(bodyMin - 1)}`).ok, false);
    assert.ok(clearanceMin > AZURE_SQL_FIREWALL_PROFILE.cloudRuleNameMin);
    assert.ok(clearanceMin > AZURE_POSTGRES_FIREWALL_PROFILE.cloudRuleNameMin);
    for (const service of UNIMPLEMENTED_SERVICES) {
      assert.equal(service.implemented, false, service.id);
      if (service.listShape === "whole-list") {
        assert.equal(service.cli, null, service.id);
      } else {
        assert.notEqual(service.cli, null, service.id);
      }
    }
    const redis = UNIMPLEMENTED_SERVICES.find((service) => service.id === "azure-redis-classic-firewall");
    assert.equal(redis?.deleteGuard, "refuse-last-rule");
  });

  it("exports firewall writer factories only for SQL and PostgreSQL", async () => {
    const index = await import("../src/index.js");
    const factories = Object.keys(index)
      .filter((name) => name.startsWith("create") && name.endsWith("FirewallWriter"))
      .sort();
    assert.deepEqual(factories, ["createAzurePostgresFirewallWriter", "createAzureSqlFirewallWriter"]);
  });

  it("finishes 200 and 201 writes, polls 202, and fails a 202 with no operation URL", async () => {
    const finished = armClient(() => ({ status: 201, headers: {}, body: "{}" }));
    const created = await finished.client.put(CHILD, AZURE_SQL_FIREWALL_PROFILE.apiVersion, {});
    assert.equal(created.ok, true);
    assert.equal(finished.requests.length, 1);

    const updated = armClient(() => ({ status: 200, headers: {}, body: "{}" }));
    const wrote = await updated.client.put(CHILD, AZURE_SQL_FIREWALL_PROFILE.apiVersion, {});
    assert.equal(wrote.ok, true);
    assert.equal(updated.requests.length, 1);

    const missing = armClient(() => ({ status: 202, headers: {}, body: "" }));
    const polled = await missing.client.put(CHILD, AZURE_SQL_FIREWALL_PROFILE.apiVersion, {});
    assert.equal(polled.ok, false);
    if (!polled.ok) {
      assert.equal(polled.error.code, "lro_malformed");
    }
    assert.equal(missing.requests.length, 1);

    const operation =
      "https://management.azure.com/subscriptions/00000000-0000-0000-0000-000000000000/providers/Microsoft.Sql/locations/centralus/operationResults/1";
    const asyncPut = armClient((request): HttpResponse => {
      if (request.method === "PUT") {
        return { status: 202, headers: { "azure-asyncoperation": operation }, body: "" };
      }
      return { status: 200, headers: {}, body: JSON.stringify({ status: "Succeeded" }) };
    });
    const accepted = await asyncPut.client.put(CHILD, AZURE_POSTGRES_FIREWALL_PROFILE.apiVersion, {});
    assert.equal(accepted.ok, true);
    assert.equal(asyncPut.requests.length, 2);
    assert.equal(asyncPut.requests[1]?.method, "GET");
    assert.equal(asyncPut.requests[1]?.url, operation);
  });

  it("finishes 200 and 204 deletes, polls 202, and returns 404 as not_found", async () => {
    for (const status of [200, 204]) {
      const finished = armClient(() => ({ status, headers: {}, body: "" }));
      const removed = await finished.client.delete(CHILD, AZURE_SQL_FIREWALL_PROFILE.apiVersion);
      assert.equal(removed.ok, true, String(status));
      assert.equal(finished.requests.length, 1, String(status));
    }

    const missing = armClient(() => ({
      status: 404,
      headers: {},
      body: JSON.stringify({ error: { code: "ResourceNotFound", message: "The firewall rule was not found." } }),
    }));
    const absent = await missing.client.delete(CHILD, AZURE_SQL_FIREWALL_PROFILE.apiVersion);
    assert.equal(absent.ok, false);
    if (!absent.ok) {
      assert.equal(absent.error.code, "not_found");
    }
    assert.equal(missing.requests.length, 1);

    const operation =
      "https://management.azure.com/subscriptions/00000000-0000-0000-0000-000000000000/providers/Microsoft.Sql/locations/centralus/operationResults/2";
    const asyncDelete = armClient((request): HttpResponse => {
      if (request.method === "DELETE") {
        return { status: 202, headers: { "azure-asyncoperation": operation }, body: "" };
      }
      return { status: 200, headers: {}, body: JSON.stringify({ status: "Succeeded" }) };
    });
    const accepted = await asyncDelete.client.delete(CHILD, AZURE_POSTGRES_FIREWALL_PROFILE.apiVersion);
    assert.equal(accepted.ok, true);
    assert.equal(asyncDelete.requests.length, 2);
  });

  it("treats only a clean not-found as absent after a failed add", async () => {
    async function addWithFollowUp(status: number, body: string) {
      const transport = {
        async send(request: HttpRequest): Promise<HttpResponse> {
          const path = new URL(request.url).pathname;
          if (request.method === "GET" && path.endsWith("/servers/sql-example")) {
            return {
              status: 200,
              headers: {},
              body: JSON.stringify({ location: "Central US", properties: { publicNetworkAccess: "Enabled" } }),
            };
          }
          if (request.method === "GET" && path.endsWith("/firewallRules")) {
            return { status: 200, headers: {}, body: JSON.stringify({ value: [] }) };
          }
          if (request.method === "PUT") {
            return {
              status: 400,
              headers: {},
              body: JSON.stringify({ error: { code: "Conflict", message: "no" } }),
            };
          }
          return { status, headers: {}, body };
        },
      };
      const writer = createAzureSqlFirewallWriter({
        transport,
        tokenProvider: { async getToken() { return TOKEN; } },
        audit: new MemoryAuditSink(),
        sleep: async () => undefined,
      });
      return writer.addRule(addRequest(SQL_ID));
    }

    const notFound = await addWithFollowUp(
      404,
      JSON.stringify({ error: { code: "ResourceNotFound", message: "missing" } }),
    );
    assert.equal(notFound.ok, false);
    if (!notFound.ok) {
      assert.equal(notFound.error.ruleApplied, false);
    }

    const failed = await addWithFollowUp(
      500,
      JSON.stringify({ error: { code: "InternalServerError", message: "down" } }),
    );
    assert.equal(failed.ok, false);
    if (!failed.ok) {
      assert.equal(failed.error.ruleApplied, true);
    }

    const unreadable = await addWithFollowUp(200, "{}");
    assert.equal(unreadable.ok, false);
    if (!unreadable.ok) {
      assert.equal(unreadable.error.code, "cloud_rejected");
      assert.equal(unreadable.error.ruleApplied, true);
    }
  });

  it("stores a display location, overwrites a named rule on PUT, and does not mutate on a matched failure", async () => {
    const fake = new FakeArm();
    fake.seedServer({
      resourceId: SQL_ID,
      location: "centralus",
      rules: [{ name: RULE, startIpv4: IP, endIpv4: IP }],
    });
    const parent = await fake.send({
      method: "GET",
      url: `https://management.azure.com${SQL_ID}?api-version=${AZURE_SQL_FIREWALL_PROFILE.apiVersion}`,
      headers: { authorization: `Bearer ${TOKEN}` },
    });
    assert.match(parent.body, /Central US/);

    const url = `https://management.azure.com${CHILD}?api-version=${AZURE_SQL_FIREWALL_PROFILE.apiVersion}`;
    const headers = { authorization: `Bearer ${TOKEN}`, "content-type": "application/json" };
    const put = await fake.send({
      method: "PUT",
      url,
      headers,
      body: JSON.stringify({ properties: { startIpAddress: OTHER_IP, endIpAddress: OTHER_IP } }),
    });
    assert.equal(put.status, 200);
    assert.equal(fake.rulesFor(SQL_ID)?.length, 1);
    assert.equal(fake.rulesFor(SQL_ID)?.[0]?.startIpv4, OTHER_IP);

    fake.failMatching({ method: "PUT", pathIncludes: "/firewallRules/" }, { status: 500, message: "no" });
    const failed = await fake.send({
      method: "PUT",
      url,
      headers,
      body: JSON.stringify({ properties: { startIpAddress: IP, endIpAddress: IP } }),
    });
    assert.equal(failed.status, 500);
    assert.equal(fake.rulesFor(SQL_ID)?.[0]?.startIpv4, OTHER_IP);
    assert.equal(fake.rulesFor(SQL_ID)?.length, 1);
  });
});

// Copyright 2026 Sarambar
// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import { describe, it } from "node:test";

import type { HttpRequest, HttpResponse, HttpTransport } from "../src/azure/http.js";
import type { AddRuleRequest } from "../src/index.js";
import { IP, SQL_ID, TOKEN, addRequest, harness } from "./helpers.js";

function hostileAdd(overrides: Record<string, unknown>): AddRuleRequest {
  return { ...addRequest(SQL_ID), ...overrides } as AddRuleRequest;
}

describe("hostile input", () => {
  const cases: Array<{ name: string; request: AddRuleRequest; code: string }> = [
    { name: "allow azure services", request: hostileAdd({ ipv4: "0.0.0.0" }), code: "azure_services_forbidden" },
    { name: "default route", request: hostileAdd({ ipv4: "0.0.0.0/0" }), code: "default_route_forbidden" },
    { name: "world as a hyphen range", request: hostileAdd({ ipv4: "0.0.0.0-255.255.255.255" }), code: "broad_range" },
    { name: "azure services hyphen", request: hostileAdd({ ipv4: "0.0.0.0-0.0.0.0" }), code: "broad_range" },
    { name: "broad documentation prefix", request: hostileAdd({ ipv4: "203.0.113.0/8" }), code: "broad_range" },
    { name: "private address", request: hostileAdd({ ipv4: "10.0.0.1" }), code: "not_public_unicast" },
    { name: "loopback", request: hostileAdd({ ipv4: "127.0.0.1" }), code: "not_public_unicast" },
    { name: "link local", request: hostileAdd({ ipv4: "169.254.1.1" }), code: "not_public_unicast" },
    { name: "multicast", request: hostileAdd({ ipv4: "224.0.0.1" }), code: "not_public_unicast" },
    { name: "ipv6", request: hostileAdd({ ipv4: "2001:db8::1" }), code: "invalid_input" },
    { name: "ipv4 mapped ipv6", request: hostileAdd({ ipv4: "::ffff:203.0.113.10" }), code: "invalid_input" },
    { name: "leading zero", request: hostileAdd({ ipv4: "203.0.113.010" }), code: "invalid_input" },
    { name: "ttl infinity", request: hostileAdd({ ttlSeconds: Number.POSITIVE_INFINITY }), code: "invalid_ttl" },
    { name: "ttl string", request: hostileAdd({ ttlSeconds: "inf" }), code: "invalid_ttl" },
    { name: "ttl fraction", request: hostileAdd({ ttlSeconds: 1.5 }), code: "invalid_ttl" },
    { name: "ttl zero", request: hostileAdd({ ttlSeconds: 0 }), code: "invalid_ttl" },
    { name: "ttl over the hard ceiling", request: hostileAdd({ ttlSeconds: 3601 }), code: "invalid_ttl" },
    { name: "reserved azure name", request: hostileAdd({ ruleName: "AllowAllWindowsAzureIps" }), code: "invalid_rule_name" },
    { name: "foreign rule name", request: hostileAdd({ ruleName: "office-vpn" }), code: "invalid_rule_name" },
    { name: "shell metacharacters", request: hostileAdd({ ruleName: "clearance-jobtoken;rm" }), code: "invalid_rule_name" },
    { name: "newline in the name", request: hostileAdd({ ruleName: "clearance-jobtoken1\n" }), code: "invalid_rule_name" },
    { name: "zero width in the name", request: hostileAdd({ ruleName: "clearance-jobtoken1\u200b" }), code: "invalid_rule_name" },
    { name: "path traversal in the name", request: hostileAdd({ ruleName: "clearance-../../office" }), code: "invalid_rule_name" },
    { name: "overlong name", request: hostileAdd({ ruleName: `clearance-${"a".repeat(200)}` }), code: "invalid_rule_name" },
    {
      name: "resource id traversal",
      request: hostileAdd({
        resourceId: "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-example/providers/Microsoft.Sql/servers/../other",
      }),
      code: "invalid_resource_id",
    },
    {
      name: "encoded slash",
      request: hostileAdd({ resourceId: `${SQL_ID}%2FfirewallRules` }),
      code: "invalid_resource_id",
    },
    {
      name: "key vault id",
      request: hostileAdd({
        resourceId:
          "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-example/providers/Microsoft.KeyVault/vaults/example",
      }),
      code: "invalid_resource_id",
    },
    {
      name: "managed redis id",
      request: hostileAdd({
        resourceId:
          "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-example/providers/Microsoft.Cache/redisEnterprise/example",
      }),
      code: "invalid_resource_id",
    },
    { name: "overlong resource id", request: hostileAdd({ resourceId: `/${"a".repeat(3000)}` }), code: "invalid_resource_id" },
    { name: "missing ledger assertion", request: hostileAdd({ ledgerOwned: false }), code: "ledger_required" },
  ];

  for (const item of cases) {
    it(`rejects ${item.name} before any ARM call`, async () => {
      const { fake, writer } = harness("sql");
      const result = await writer.addRule(item.request);
      assert.equal(result.ok, false);
      if (!result.ok) {
        assert.equal(result.error.code, item.code);
        assert.equal(result.error.message.includes("\n"), false);
        assert.equal(result.error.authorizationDenial, false);
      }
      assert.equal(fake.requests.length, 0);
      assert.equal(JSON.stringify(result).includes(TOKEN), false);
    });
  }

  it("sends 0.0.0.0 only when the policy explicitly allows the Azure services rule", async () => {
    const { fake, writer, resourceId } = harness("sql");
    const allowed = await writer.addRule(
      addRequest(resourceId, {
        ipv4: "0.0.0.0",
        ipPolicy: {
          minimumPrefixLength: 32,
          allowNonPublic: false,
          allowAzureServicesRule: true,
          allowDefaultRoute: false,
        },
      }),
    );
    assert.equal(allowed.ok, true);
    const put = fake.requests.find((request) => request.method === "PUT");
    assert.match(put?.body ?? "", /"startIpAddress":"0.0.0.0"/);
    assert.match(put?.body ?? "", /"endIpAddress":"0.0.0.0"/);
  });

  it("rejects a truthy non-boolean policy flag", async () => {
    const { fake, writer, resourceId } = harness("sql");
    const result = await writer.addRule(
      addRequest(resourceId, {
        ipv4: "0.0.0.0/0",
        ipPolicy: {
          minimumPrefixLength: 32,
          allowNonPublic: false,
          allowAzureServicesRule: false,
          allowDefaultRoute: "false" as unknown as boolean,
        },
      }),
    );
    assert.equal(result.ok, false);
    if (!result.ok) {
      assert.equal(result.error.code, "invalid_input");
    }
    assert.equal(fake.requests.length, 0);
  });

  it("does not delete a foreign rule even if the caller asserts ledger ownership", async () => {
    const { fake, writer, resourceId } = harness("sql", {
      rules: [{ name: "office-vpn", startIpv4: "198.51.100.20", endIpv4: "198.51.100.20" }],
    });
    const removed = await writer.removeRule({
      resourceId,
      ruleName: "office-vpn" as unknown as "clearance-jobtoken1",
      ledgerOwned: true,
    });
    assert.equal(removed.ok, false);
    if (!removed.ok) {
      assert.equal(removed.error.code, "invalid_rule_name");
    }
    assert.equal(fake.requests.length, 0);
    assert.equal(fake.rulesFor(resourceId)?.length, 1);
  });

  it("refuses a clearance-looking delete when ledger ownership is not asserted", async () => {
    const { fake, writer, resourceId } = harness("sql", {
      rules: [{ name: "clearance-please-delete", startIpv4: IP, endIpv4: IP }],
    });
    const removed = await writer.removeRule({
      resourceId,
      ruleName: "clearance-please-delete",
      ledgerOwned: false as unknown as true,
    });
    assert.equal(removed.ok, false);
    if (!removed.ok) {
      assert.equal(removed.error.code, "ledger_required");
    }
    assert.equal(fake.requests.some((request) => request.method === "DELETE"), false);
    assert.equal(fake.rulesFor(resourceId)?.length, 1);
  });

  it("does not follow a nextLink onto another host", async () => {
    const seen: string[] = [];
    const transport: HttpTransport = {
      async send(request: HttpRequest): Promise<HttpResponse> {
        seen.push(request.url);
        if (seen.length === 1) {
          return {
            status: 200,
            headers: { "content-type": "application/json", "x-ms-request-id": "00000000-0000-0000-0000-000000000000" },
            body: JSON.stringify({
              value: [],
              nextLink: "https://evil.example/latest/meta-data",
            }),
          };
        }
        return { status: 500, headers: {}, body: "should not be called" };
      },
    };
    const { createAzureSqlFirewallWriter, MemoryAuditSink } = await import("../src/index.js");
    const writer = createAzureSqlFirewallWriter({
      transport,
      tokenProvider: { async getToken() { return TOKEN; } },
      audit: new MemoryAuditSink(),
      sleep: async () => undefined,
    });
    const result = await writer.readWholeList({ resourceId: SQL_ID });
    assert.equal(result.ok, false);
    if (!result.ok) {
      assert.equal(result.error.code, "unsafe_poll_url");
    }
    assert.equal(seen.length, 1);
  });

  it("does not poll an operation URL on another host", async () => {
    const seen: string[] = [];
    const transport: HttpTransport = {
      async send(request: HttpRequest): Promise<HttpResponse> {
        seen.push(request.url);
        if (request.method === "GET" && request.url.includes("/firewallRules")) {
          return { status: 200, headers: { "content-type": "application/json" }, body: JSON.stringify({ value: [] }) };
        }
        if (request.method === "GET") {
          return {
            status: 200,
            headers: { "content-type": "application/json" },
            body: JSON.stringify({ location: "Central US", properties: { publicNetworkAccess: "Enabled" } }),
          };
        }
        return {
          status: 202,
          headers: {
            "azure-asyncoperation": "http://169.254.169.254/latest/meta-data",
            "retry-after": "0",
          },
          body: "",
        };
      },
    };
    const { createAzureSqlFirewallWriter, MemoryAuditSink } = await import("../src/index.js");
    const writer = createAzureSqlFirewallWriter({
      transport,
      tokenProvider: { async getToken() { return TOKEN; } },
      audit: new MemoryAuditSink(),
      sleep: async () => undefined,
    });
    const result = await writer.addRule(addRequest(SQL_ID));
    assert.equal(result.ok, false);
    if (!result.ok) {
      assert.equal(result.error.code, "unsafe_poll_url");
      assert.equal(result.error.ruleApplied, true);
    }
    assert.equal(seen.some((url) => url.includes("169.254.169.254")), false);
  });
});

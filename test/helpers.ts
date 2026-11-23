// Copyright 2026 Sarambar
// SPDX-License-Identifier: Apache-2.0

import { FakeArm, type FakeServerSeed } from "../src/azure/fake-arm.js";
import {
  MemoryAuditSink,
  createAzurePostgresFirewallWriter,
  createAzureSqlFirewallWriter,
  type AddRuleRequest,
  type FirewallWriter,
} from "../src/index.js";

export const SUBSCRIPTION = "00000000-0000-0000-0000-000000000000";
export const SQL_ID = `/subscriptions/${SUBSCRIPTION}/resourceGroups/rg-example/providers/Microsoft.Sql/servers/sql-example`;
export const PG_ID = `/subscriptions/${SUBSCRIPTION}/resourceGroups/rg-example/providers/Microsoft.DBforPostgreSQL/flexibleServers/pg-example`;
export const TOKEN = "test-token";
export const RULE = "clearance-jobtoken1";
export const OTHER_RULE = "clearance-jobtoken2";
export const IP = "203.0.113.10";
export const OTHER_IP = "203.0.113.11";
export const FOREIGN_IP = "198.51.100.20";
export const NOW = new Date("2026-01-01T00:00:00.000Z");

export function addRequest(resourceId: string, overrides: Partial<AddRuleRequest> = {}): AddRuleRequest {
  return {
    resourceId,
    ruleName: RULE,
    ipv4: IP,
    ttlSeconds: 60,
    ledgerOwned: true,
    ...overrides,
  };
}

export function harness(kind: "sql" | "pg" = "sql", seed: Partial<FakeServerSeed> = {}) {
  const fake = new FakeArm();
  const resourceId = kind === "sql" ? SQL_ID : PG_ID;
  fake.seedServer({
    resourceId,
    location: "centralus",
    ...seed,
  });
  const audit = new MemoryAuditSink();
  const delays: number[] = [];
  const options = {
    transport: fake,
    tokenProvider: { async getToken() { return TOKEN; } },
    audit,
    now: () => NOW,
    sleep: async (ms: number) => {
      delays.push(ms);
    },
  };
  const writer: FirewallWriter =
    kind === "sql" ? createAzureSqlFirewallWriter(options) : createAzurePostgresFirewallWriter(options);
  return { fake, audit, writer, delays, resourceId };
}

export function methods(fake: FakeArm): string[] {
  return fake.requests.map((request) => `${request.method} ${new URL(request.url).pathname}`);
}

// Copyright 2026 Sarambar
// SPDX-License-Identifier: Apache-2.0

import { MemoryAuditSink, type AuditEvent } from "./audit.js";
import { createAzurePostgresFirewallWriter, createAzureSqlFirewallWriter } from "./azure/child-writer.js";
import { createFetchTransport } from "./azure/http.js";
import type { IpPolicy } from "./ip.js";
import type { FirewallWriter } from "./writer.js";

const FOREIGN_RULE = "office-vpn";

export interface SmokeTarget {
  writer: FirewallWriter;
  resourceId: string;
}

export interface SmokeRow {
  service: string;
  step: string;
  result: "PASS" | "FAIL";
  detail: string;
}

export interface LiveSmokeReport {
  ok: boolean;
  rows: SmokeRow[];
  audits: AuditEvent[];
}

export interface LiveSmokeInput {
  targets: readonly SmokeTarget[];
  ipv4: string;
  ruleName: string;
  foreignRuleName?: string;
  ttlSeconds?: number;
  /** Omit on a live run. Unit tests set this so placeholder addresses are allowed. */
  ipPolicy?: IpPolicy;
  expectedLocation?: string;
}

/**
 * Refuse automated environments. A live smoke opens real firewall rules.
 */
export function liveSmokeBlockedReason(env: Record<string, string | undefined>): string | null {
  if (env.GITHUB_ACTIONS === "true" || env.CI === "true" || env.GITLAB_CI === "true" || env.TF_BUILD === "True" || env.BUILDKITE === "true") {
    return "live-smoke refuses to run in CI";
  }
  return null;
}

export async function runLiveSmoke(input: LiveSmokeInput): Promise<LiveSmokeReport> {
  const foreignRuleName = input.foreignRuleName ?? FOREIGN_RULE;
  const ttlSeconds = input.ttlSeconds ?? 300;
  const rows: SmokeRow[] = [];
  const audits: AuditEvent[] = [];
  for (const target of input.targets) {
    const service = target.writer.descriptor.id;
    const record = (step: string, pass: boolean, detail: string): void => {
      rows.push({ service, step, result: pass ? "PASS" : "FAIL", detail: oneLine(detail) });
    };
    const keep = (events: readonly AuditEvent[]): void => {
      audits.push(...events);
    };

    const added = await target.writer.addRule({
      resourceId: target.resourceId,
      ruleName: input.ruleName,
      ipv4: input.ipv4,
      ttlSeconds,
      ledgerOwned: true,
      ...(input.ipPolicy === undefined ? {} : { ipPolicy: input.ipPolicy }),
      ...(input.expectedLocation === undefined ? {} : { expectedLocation: input.expectedLocation }),
    });
    keep(added.audit);
    record("add", added.ok && added.value.replayed === false, added.ok ? "created" : added.error.toOperatorLine());

    const owned = await target.writer.listOwnedRules({ resourceId: target.resourceId });
    keep(owned.audit);
    const present = owned.ok && owned.value.rules.some((rule) => rule.ruleName === input.ruleName && rule.startIpv4 === input.ipv4);
    record("list-owned-present", present, present ? "rule present" : owned.ok ? "rule missing" : owned.error.toOperatorLine());

    const whole = await target.writer.readWholeList({ resourceId: target.resourceId });
    keep(whole.audit);
    const sawForeign = whole.ok && whole.value.rules.some((rule) => rule.ruleName === foreignRuleName && rule.owned === false);
    record("whole-list", sawForeign, sawForeign ? "foreign rule present" : whole.ok ? "foreign rule missing" : whole.error.toOperatorLine());

    const again = await target.writer.addRule({
      resourceId: target.resourceId,
      ruleName: input.ruleName,
      ipv4: input.ipv4,
      ttlSeconds,
      ledgerOwned: true,
      ...(input.ipPolicy === undefined ? {} : { ipPolicy: input.ipPolicy }),
      ...(input.expectedLocation === undefined ? {} : { expectedLocation: input.expectedLocation }),
    });
    keep(again.audit);
    record("re-add", again.ok && again.value.replayed === true, again.ok ? (again.value.replayed ? "idempotent" : "wrote again") : again.error.toOperatorLine());

    const removed = await target.writer.removeRule({
      resourceId: target.resourceId,
      ruleName: input.ruleName,
      ledgerOwned: true,
    });
    keep(removed.audit);
    record(
      "remove",
      removed.ok && removed.value.alreadyAbsent === false && removed.value.removalVerified === true,
      removed.ok ? "verified gone" : removed.error.toOperatorLine(),
    );

    const ownedAfter = await target.writer.listOwnedRules({ resourceId: target.resourceId });
    keep(ownedAfter.audit);
    const gone = ownedAfter.ok && !ownedAfter.value.rules.some((rule) => rule.ruleName === input.ruleName);
    record("list-owned-absent", gone, gone ? "rule absent" : ownedAfter.ok ? "rule still listed" : ownedAfter.error.toOperatorLine());

    const removedAgain = await target.writer.removeRule({
      resourceId: target.resourceId,
      ruleName: input.ruleName,
      ledgerOwned: true,
    });
    keep(removedAgain.audit);
    record(
      "re-remove",
      removedAgain.ok && removedAgain.value.alreadyAbsent === true && removedAgain.value.removalVerified === true,
      removedAgain.ok ? "idempotent" : removedAgain.error.toOperatorLine(),
    );

    const after = await target.writer.readWholeList({ resourceId: target.resourceId });
    keep(after.audit);
    const foreignRemains = after.ok && after.value.rules.some((rule) => rule.ruleName === foreignRuleName && rule.owned === false);
    const clearanceGone = after.ok && !after.value.rules.some((rule) => rule.ruleName === input.ruleName);
    record(
      "foreign-remains",
      foreignRemains && clearanceGone,
      foreignRemains && clearanceGone ? "foreign rule untouched" : after.ok ? "whole list drifted" : after.error.toOperatorLine(),
    );
  }
  return { ok: rows.every((row) => row.result === "PASS"), rows, audits };
}

export function formatSmokeReport(report: LiveSmokeReport): string {
  const lines = ["service | step | result | detail"];
  for (const row of report.rows) {
    lines.push(`${row.service} | ${row.step} | ${row.result} | ${row.detail}`);
  }
  lines.push("audit | phase | operation | outcome | version | commit");
  for (const event of report.audits) {
    lines.push(
      `${event.service} | ${event.phase} | ${event.operation} | ${event.outcome} | ${event.writersVersion} | ${event.writersCommitSha}`,
    );
  }
  return lines.join("\n");
}

export async function main(env: Record<string, string | undefined> = process.env): Promise<number> {
  const blocked = liveSmokeBlockedReason(env);
  if (blocked !== null) {
    console.error(blocked);
    return 1;
  }
  const sqlResourceId = env.SMOKE_SQL_RESOURCE_ID;
  const pgResourceId = env.SMOKE_PG_RESOURCE_ID;
  const ipv4 = env.SMOKE_IPV4;
  const ruleName = env.SMOKE_RULE_NAME;
  const token = env.ARM_ACCESS_TOKEN;
  const missing = [
    ["SMOKE_SQL_RESOURCE_ID", sqlResourceId],
    ["SMOKE_PG_RESOURCE_ID", pgResourceId],
    ["SMOKE_IPV4", ipv4],
    ["SMOKE_RULE_NAME", ruleName],
    ["ARM_ACCESS_TOKEN", token],
  ].filter((entry) => entry[1] === undefined || entry[1] === "");
  if (missing.length > 0) {
    console.error(`live-smoke is missing ${missing.map((entry) => entry[0]).join(", ")}`);
    return 1;
  }
  if (sqlResourceId === undefined || pgResourceId === undefined || ipv4 === undefined || ruleName === undefined || token === undefined) {
    return 1;
  }
  const transport = createFetchTransport(globalThis.fetch, 120_000);
  const tokenProvider = { async getToken(): Promise<string> { return token; } };
  const shared = { transport, tokenProvider, audit: new MemoryAuditSink() };
  const report = await runLiveSmoke({
    ipv4,
    ruleName,
    ...(env.SMOKE_FOREIGN_RULE === undefined || env.SMOKE_FOREIGN_RULE === "" ? {} : { foreignRuleName: env.SMOKE_FOREIGN_RULE }),
    ...(env.SMOKE_LOCATION === undefined || env.SMOKE_LOCATION === "" ? {} : { expectedLocation: env.SMOKE_LOCATION }),
    targets: [
      { writer: createAzureSqlFirewallWriter(shared), resourceId: sqlResourceId },
      { writer: createAzurePostgresFirewallWriter(shared), resourceId: pgResourceId },
    ],
  });
  console.log(formatSmokeReport(report));
  return report.ok ? 0 : 1;
}

function oneLine(value: string): string {
  return value.replace(/[\r\n]+/g, " ").slice(0, 240);
}

// Copyright 2026 Sarambar
// SPDX-License-Identifier: Apache-2.0

import { buildAuditEvent, type AuditEvent, type AuditOperation, type AuditOutcome, type AuditSink } from "../audit.js";
import { writerError, type WriterError } from "../errors.js";
import { parseAllowAddress, parseIpv4, parseTtlSeconds, STRICT_IP_POLICY } from "../ip.js";
import { parseSbcRuleName, RESERVED_FIREWALL_RULE_NAMES } from "../names.js";
import { WRITERS_VERSION } from "../provenance.js";
import { ArmClient, type ArmCall } from "./arm.js";
import type { ArmTokenProvider, HttpTransport } from "./http.js";
import {
  AZURE_SQL_FIREWALL_PROFILE,
  childPath,
  collectionPath,
  parseAzureParentId,
  type ParsedParent,
} from "./profiles.js";

/**
 * Least-privilege actions required by AzureSqlRuleProvider.
 * No Microsoft.Sql/servers/read, no database actions, no data-plane actions.
 */
export const AZURE_SQL_RULE_PROVIDER_ACTIONS = [
  "Microsoft.Sql/servers/firewallRules/read",
  "Microsoft.Sql/servers/firewallRules/write",
  "Microsoft.Sql/servers/firewallRules/delete",
] as const;

export interface AzureSqlRuleProviderOptions {
  transport: HttpTransport;
  tokenProvider: ArmTokenProvider;
  audit: AuditSink;
  endpoint?: string;
  now?: () => Date;
  sleep?: (ms: number) => Promise<void>;
  /** Pinned commit SHA for audit provenance without mutating process.env. */
  writersCommitSha?: string;
}

export interface SqlOpenRuleRequest {
  ledgerOwned: true;
  resourceId: string;
  ruleName: string;
  ipv4: string;
  ttlSeconds: number;
}

export interface SqlCloseRuleRequest {
  ledgerOwned: true;
  resourceId: string;
  ruleName: string;
}

export interface SqlListSbcRulesRequest {
  resourceId: string;
}

export interface SqlOpenRuleValue {
  resourceId: string;
  ruleName: string;
  startIpv4: string;
  endIpv4: string;
}

export interface SqlCloseRuleValue {
  resourceId: string;
  ruleName: string;
  alreadyAbsent: boolean;
  removalVerified: true;
}

export interface SbcRuleView {
  ruleName: string;
  expiresAtSeconds: number;
  ulid: string;
  startIpv4: string;
  endIpv4: string;
}

export interface SqlListSbcRulesValue {
  resourceId: string;
  rules: SbcRuleView[];
}

export type SqlRuleOutcome<T> =
  | { ok: true; value: T; audit: AuditEvent[] }
  | { ok: false; error: WriterError; audit: AuditEvent[] };

export interface AzureSqlRuleProvider {
  openRule(request: SqlOpenRuleRequest): Promise<SqlRuleOutcome<SqlOpenRuleValue>>;
  closeRule(request: SqlCloseRuleRequest): Promise<SqlRuleOutcome<SqlCloseRuleValue>>;
  listSbcRules(request: SqlListSbcRulesRequest): Promise<SqlRuleOutcome<SqlListSbcRulesValue>>;
}

interface AuditFields {
  resourceId: string | null;
  ruleName: string | null;
  ipv4: string | null;
  ttlSeconds: number | null;
}

interface ParsedFirewallRule {
  name: string;
  startIpv4: string;
  endIpv4: string;
}

function emptyFields(): AuditFields {
  return { resourceId: null, ruleName: null, ipv4: null, ttlSeconds: null };
}

function asRecord(value: unknown): Record<string, unknown> | null {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    return null;
  }
  return value as Record<string, unknown>;
}

function parseFirewallRule(body: unknown): ParsedFirewallRule | null {
  const record = asRecord(body);
  if (record === null || typeof record.name !== "string") {
    return null;
  }
  const properties = asRecord(record.properties);
  const start = typeof properties?.startIpAddress === "string" ? parseIpv4(properties.startIpAddress) : null;
  const end = typeof properties?.endIpAddress === "string" ? parseIpv4(properties.endIpAddress) : null;
  if (start === null || end === null) {
    return null;
  }
  return { name: record.name, startIpv4: start, endIpv4: end };
}

function withState(error: WriterError, ruleApplied: boolean, removalVerified = error.removalVerified): WriterError {
  return writerError({
    code: error.code,
    message: error.message,
    retryable: error.retryable,
    ruleApplied,
    removalVerified,
    authorizationDenial: error.authorizationDenial,
    cloudCode: error.cloudCode,
    cloudStatus: error.cloudStatus,
    retryAfterSeconds: error.retryAfterSeconds,
  });
}

type ReadBackViolation = "readback_allow_all" | "readback_azure_services" | "readback_range_rule" | "verify_failed";

/**
 * Inspects every firewall rule returned by ARM (B-T5) without ever reporting
 * customer rule names or IP addresses (B-T6).
 */
function inspectServerRules(
  rules: readonly ParsedFirewallRule[],
  expectedRuleName: string,
  expectedIpv4: string,
): ReadBackViolation | null {
  let matchedOwnRule = false;
  for (const rule of rules) {
    const isReservedAzure = RESERVED_FIREWALL_RULE_NAMES.some(
      (reserved) => reserved.toLowerCase() === rule.name.toLowerCase(),
    );
    if (rule.startIpv4 === "0.0.0.0" && rule.endIpv4 === "255.255.255.255") {
      return "readback_allow_all";
    }
    if ((rule.startIpv4 === "0.0.0.0" && rule.endIpv4 === "0.0.0.0") || isReservedAzure) {
      return "readback_azure_services";
    }
    if (rule.startIpv4 !== rule.endIpv4) {
      return "readback_range_rule";
    }
    if (rule.name.toLowerCase() === expectedRuleName.toLowerCase()) {
      if (rule.startIpv4 !== expectedIpv4 || rule.endIpv4 !== expectedIpv4) {
        return "verify_failed";
      }
      matchedOwnRule = true;
    }
  }
  return matchedOwnRule ? null : "verify_failed";
}

/**
 * Single-rule Azure SQL firewall provider using firewallRules/{read,write,delete} only.
 * Never reads the parent server (no Microsoft.Sql/servers/read), never sends collection PUT,
 * never modifies/deletes/reports customer rules, and returns 429/503 Retry-After immediately
 * with no inline throttle sleep so the caller coordinator persists per-server backoff.
 */
export class AzureSqlFirewallRuleProvider implements AzureSqlRuleProvider {
  private readonly arm: ArmClient;
  private readonly auditSink: AuditSink;
  private readonly now: () => Date;
  private readonly commitSha: string | undefined;

  constructor(options: AzureSqlRuleProviderOptions) {
    this.auditSink = options.audit;
    this.now = options.now ?? (() => new Date());
    this.commitSha = options.writersCommitSha;
    this.arm = new ArmClient({
      transport: options.transport,
      tokenProvider: options.tokenProvider,
      endpoint: options.endpoint,
      now: this.now,
      sleep: options.sleep,
      inlineThrottleRetry: false,
      userAgent: `clearance-writers/${WRITERS_VERSION} (${AZURE_SQL_FIREWALL_PROFILE.id})`,
    });
  }

  async openRule(request: SqlOpenRuleRequest): Promise<SqlRuleOutcome<SqlOpenRuleValue>> {
    if (request.ledgerOwned !== true) {
      return this.denied(
        "add",
        writerError({ code: "ledger_required", message: "Refusing to change a rule without an explicit ledger ownership assertion." }),
        emptyFields(),
      );
    }
    const parsedParent = parseAzureParentId(AZURE_SQL_FIREWALL_PROFILE, request.resourceId);
    if (!parsedParent.ok) {
      return this.denied("add", parsedParent.error, emptyFields());
    }
    const parsedName = parseSbcRuleName(request.ruleName);
    if (!parsedName.ok) {
      return this.denied("add", parsedName.error, emptyFields());
    }
    const parsedIp = parseAllowAddress(request.ipv4, STRICT_IP_POLICY);
    if (!parsedIp.ok) {
      return this.denied("add", parsedIp.error, { ...emptyFields(), resourceId: parsedParent.value.canonicalId, ruleName: parsedName.value.ruleName });
    }
    const parsedTtl = parseTtlSeconds(request.ttlSeconds);
    if (!parsedTtl.ok) {
      return this.denied("add", parsedTtl.error, {
        resourceId: parsedParent.value.canonicalId,
        ruleName: parsedName.value.ruleName,
        ipv4: parsedIp.value.canonical,
        ttlSeconds: null,
      });
    }

    const wantedIp = parsedIp.value.startIpv4;
    const ruleName = parsedName.value.ruleName;
    const fields: AuditFields = {
      resourceId: parsedParent.value.canonicalId,
      ruleName,
      ipv4: parsedIp.value.canonical,
      ttlSeconds: parsedTtl.value,
    };
    const events: AuditEvent[] = [];
    if (!(await this.record(events, "add", "intent", "succeeded", "ok", fields, false, null))) {
      return this.auditFailed("audit_intent_failed", events, false, false);
    }

    const path = childPath(AZURE_SQL_FIREWALL_PROFILE, parsedParent.value, ruleName);
    const existing = await this.arm.get(path, AZURE_SQL_FIREWALL_PROFILE.apiVersion);
    if (existing.ok) {
      return this.failed(
        "add",
        events,
        writerError({
          code: "rule_conflict",
          message: "A firewall rule with this name already exists and was not modified.",
          ruleApplied: false,
        }),
        fields,
        false,
        existing.requestId,
      );
    }
    if (existing.error.code !== "not_found") {
      return this.failed("add", events, withState(existing.error, false), fields, false, existing.requestId);
    }

    const put = await this.arm.put(path, AZURE_SQL_FIREWALL_PROFILE.apiVersion, {
      properties: { startIpAddress: wantedIp, endIpAddress: wantedIp },
    });
    if (!put.ok) {
      if (put.error.code === "throttled") {
        // ARM rejected the PUT before applying it; do not pin the lease as applied.
        return this.failed("add", events, withState(put.error, false), fields, false, put.requestId);
      }
      const presence = await this.rulePresence(parsedParent.value, ruleName);
      const applied = presence !== "absent";
      return this.failed("add", events, withState(put.error, applied), fields, applied, put.requestId);
    }

    // Open read-back: list server rules via firewallRules/read only (B-T5), never exposing customer rules (B-T6).
    const listed = await this.readAllRules(parsedParent.value);
    if (!listed.ok) {
      const rollback = await this.rollbackOwnRule(parsedParent.value, ruleName);
      return this.failed(
        "add",
        events,
        writerError({
          code: "verify_failed",
          message: "Firewall rule read-back list failed after create.",
          ruleApplied: !rollback.verifiedAbsent,
          removalVerified: rollback.verifiedAbsent,
          cloudCode: listed.error.cloudCode,
          cloudStatus: listed.error.cloudStatus,
          retryAfterSeconds: listed.error.retryAfterSeconds,
        }),
        fields,
        !rollback.verifiedAbsent,
        listed.requestId,
        "verify_failed",
      );
    }

    const violation = inspectServerRules(listed.rules, ruleName, wantedIp);
    if (violation !== null) {
      const rollback = await this.rollbackOwnRule(parsedParent.value, ruleName);
      return this.failed(
        "add",
        events,
        writerError({
          code: "verify_failed",
          message: "Firewall rule read-back detected a disallowed server rule state.",
          ruleApplied: !rollback.verifiedAbsent,
          removalVerified: rollback.verifiedAbsent,
        }),
        fields,
        !rollback.verifiedAbsent,
        listed.requestId,
        violation,
      );
    }

    const value: SqlOpenRuleValue = {
      resourceId: parsedParent.value.canonicalId,
      ruleName,
      startIpv4: wantedIp,
      endIpv4: wantedIp,
    };
    return this.succeeded("add", events, fields, true, value, listed.requestId);
  }

  async closeRule(request: SqlCloseRuleRequest): Promise<SqlRuleOutcome<SqlCloseRuleValue>> {
    if (request.ledgerOwned !== true) {
      return this.denied(
        "remove",
        writerError({ code: "ledger_required", message: "Refusing to change a rule without an explicit ledger ownership assertion." }),
        emptyFields(),
      );
    }
    const parsedParent = parseAzureParentId(AZURE_SQL_FIREWALL_PROFILE, request.resourceId);
    if (!parsedParent.ok) {
      return this.denied("remove", parsedParent.error, emptyFields());
    }
    const parsedName = parseSbcRuleName(request.ruleName);
    if (!parsedName.ok) {
      return this.denied(
        "remove",
        writerError({ code: "invalid_rule_name", message: "Refusing to touch a rule outside the sbc- naming pattern." }),
        { ...emptyFields(), resourceId: parsedParent.value.canonicalId },
      );
    }

    const ruleName = parsedName.value.ruleName;
    const fields: AuditFields = {
      resourceId: parsedParent.value.canonicalId,
      ruleName,
      ipv4: null,
      ttlSeconds: null,
    };
    const events: AuditEvent[] = [];
    const intentOk = await this.record(events, "remove", "intent", "succeeded", "ok", fields, false, null);

    const path = childPath(AZURE_SQL_FIREWALL_PROFILE, parsedParent.value, ruleName);
    const deleted = await this.arm.delete(path, AZURE_SQL_FIREWALL_PROFILE.apiVersion);
    let alreadyAbsent = false;
    if (!deleted.ok) {
      if (deleted.error.code === "not_found") {
        alreadyAbsent = true;
      } else if (deleted.error.code === "throttled") {
        return this.failed("remove", events, withState(deleted.error, true), fields, true, deleted.requestId);
      } else {
        const presence = await this.rulePresence(parsedParent.value, ruleName);
        if (presence === "absent") {
          alreadyAbsent = true;
        } else {
          return this.failed("remove", events, withState(deleted.error, true), fields, true, deleted.requestId);
        }
      }
    }

    const after = await this.arm.get(path, AZURE_SQL_FIREWALL_PROFILE.apiVersion);
    if (after.ok) {
      return this.failed(
        "remove",
        events,
        writerError({
          code: "delete_not_verified",
          message: "The firewall rule was still present after delete.",
          ruleApplied: true,
        }),
        fields,
        true,
        after.requestId,
      );
    }
    if (after.error.code !== "not_found") {
      return this.failed("remove", events, withState(after.error, true), fields, true, after.requestId);
    }

    const value: SqlCloseRuleValue = {
      resourceId: parsedParent.value.canonicalId,
      ruleName,
      alreadyAbsent,
      removalVerified: true,
    };
    const outcome = await this.succeeded("remove", events, fields, false, value, after.requestId);
    if (!intentOk && outcome.ok) {
      return {
        ok: false,
        audit: outcome.audit,
        error: writerError({
          code: "audit_intent_failed",
          message: "The audit sink did not accept the intent event. Cleanup was not skipped.",
          ruleApplied: false,
          removalVerified: true,
        }),
      };
    }
    return outcome;
  }

  async listSbcRules(request: SqlListSbcRulesRequest): Promise<SqlRuleOutcome<SqlListSbcRulesValue>> {
    const parsedParent = parseAzureParentId(AZURE_SQL_FIREWALL_PROFILE, request.resourceId);
    if (!parsedParent.ok) {
      return this.denied("list_owned", parsedParent.error, emptyFields());
    }
    const fields: AuditFields = {
      resourceId: parsedParent.value.canonicalId,
      ruleName: null,
      ipv4: null,
      ttlSeconds: null,
    };
    const events: AuditEvent[] = [];
    const listed = await this.readAllRules(parsedParent.value);
    if (!listed.ok) {
      return this.failed("list_owned", events, listed.error, fields, false, listed.requestId);
    }
    const sbcRules: SbcRuleView[] = [];
    for (const rule of listed.rules) {
      const parsed = parseSbcRuleName(rule.name);
      if (parsed.ok) {
        sbcRules.push({
          ruleName: parsed.value.ruleName,
          expiresAtSeconds: parsed.value.expiresAtSeconds,
          ulid: parsed.value.ulid,
          startIpv4: rule.startIpv4,
          endIpv4: rule.endIpv4,
        });
      }
    }
    return this.succeeded(
      "list_owned",
      events,
      fields,
      false,
      { resourceId: parsedParent.value.canonicalId, rules: sbcRules },
      listed.requestId,
    );
  }

  private async rollbackOwnRule(parent: ParsedParent, ruleName: string): Promise<{ verifiedAbsent: boolean }> {
    const path = childPath(AZURE_SQL_FIREWALL_PROFILE, parent, ruleName);
    const deleted = await this.arm.delete(path, AZURE_SQL_FIREWALL_PROFILE.apiVersion);
    if (!deleted.ok && deleted.error.code !== "not_found") {
      return { verifiedAbsent: false };
    }
    const after = await this.arm.get(path, AZURE_SQL_FIREWALL_PROFILE.apiVersion);
    return { verifiedAbsent: !after.ok && after.error.code === "not_found" };
  }

  private async readAllRules(
    parent: ParsedParent,
  ): Promise<
    | { ok: true; rules: ParsedFirewallRule[]; requestId: string | null }
    | { ok: false; error: WriterError; requestId: string | null }
  > {
    const rules: ParsedFirewallRule[] = [];
    const seen = new Set<string>();
    let call: ArmCall = await this.arm.get(
      collectionPath(AZURE_SQL_FIREWALL_PROFILE, parent),
      AZURE_SQL_FIREWALL_PROFILE.apiVersion,
    );
    let lastRequestId: string | null = null;
    for (let page = 0; page < 512; page += 1) {
      lastRequestId = call.requestId;
      if (!call.ok) {
        return { ok: false, error: call.error, requestId: lastRequestId };
      }
      const record = asRecord(call.body);
      const value = record?.value;
      if (!Array.isArray(value)) {
        return {
          ok: false,
          requestId: lastRequestId,
          error: writerError({
            code: "cloud_response_invalid",
            message: "Firewall rule list did not contain a value array.",
          }),
        };
      }
      for (const item of value) {
        const rule = parseFirewallRule(item);
        if (rule === null) {
          return {
            ok: false,
            requestId: lastRequestId,
            error: writerError({
              code: "cloud_response_invalid",
              message: "A firewall rule in the list could not be parsed.",
            }),
          };
        }
        rules.push(rule);
      }
      const nextLink = record?.nextLink;
      if (nextLink === undefined || nextLink === null) {
        return { ok: true, rules, requestId: lastRequestId };
      }
      if (typeof nextLink !== "string" || seen.has(nextLink)) {
        return {
          ok: false,
          requestId: lastRequestId,
          error: writerError({
            code: "unsafe_poll_url",
            message: "The firewall rule list returned a nextLink that will not be followed.",
          }),
        };
      }
      seen.add(nextLink);
      call = await this.arm.getAbsolute(nextLink);
    }
    return {
      ok: false,
      requestId: lastRequestId,
      error: writerError({ code: "cloud_response_invalid", message: "The firewall rule list exceeded the page limit." }),
    };
  }

  private async rulePresence(parent: ParsedParent, ruleName: string): Promise<"present" | "absent" | "unknown"> {
    const response = await this.arm.get(
      childPath(AZURE_SQL_FIREWALL_PROFILE, parent, ruleName),
      AZURE_SQL_FIREWALL_PROFILE.apiVersion,
    );
    if (!response.ok) {
      return response.error.code === "not_found" ? "absent" : "unknown";
    }
    return "present";
  }

  private async denied(
    operation: AuditOperation,
    error: WriterError,
    fields: AuditFields,
  ): Promise<SqlRuleOutcome<never>> {
    const events: AuditEvent[] = [];
    const recorded = await this.record(events, operation, "result", "denied", error.code, fields, false, error.cloudCode);
    if (!recorded) {
      return this.auditFailed("audit_intent_failed", events, false, false);
    }
    return { ok: false, error, audit: events };
  }

  private async failed(
    operation: AuditOperation,
    events: AuditEvent[],
    error: WriterError,
    fields: AuditFields,
    ruleApplied: boolean,
    requestId: string | null = null,
    detailCode: string = error.code,
  ): Promise<SqlRuleOutcome<never>> {
    const ok = await this.record(
      events,
      operation,
      "result",
      "failed",
      detailCode,
      fields,
      ruleApplied,
      error.cloudCode,
      requestId,
    );
    if (!ok) {
      return this.auditFailed("audit_completion_failed", events, ruleApplied, error.removalVerified);
    }
    return { ok: false, error: withState(error, ruleApplied, error.removalVerified), audit: events };
  }

  private async succeeded<T>(
    operation: AuditOperation,
    events: AuditEvent[],
    fields: AuditFields,
    ruleApplied: boolean,
    value: T,
    requestId: string | null,
  ): Promise<SqlRuleOutcome<T>> {
    const ok = await this.record(events, operation, "result", "succeeded", "ok", fields, ruleApplied, null, requestId);
    if (!ok) {
      return this.auditFailed("audit_completion_failed", events, ruleApplied, operation === "remove");
    }
    return { ok: true, value, audit: events };
  }

  private auditFailed(
    code: "audit_intent_failed" | "audit_completion_failed",
    events: AuditEvent[],
    ruleApplied: boolean,
    removalVerified: boolean,
  ): SqlRuleOutcome<never> {
    return {
      ok: false,
      audit: events,
      error: writerError({
        code,
        message: "The audit sink did not accept the event. An add is not sent when the intent cannot be recorded.",
        ruleApplied,
        removalVerified,
      }),
    };
  }

  private async record(
    events: AuditEvent[],
    operation: AuditOperation,
    phase: "intent" | "result",
    outcome: AuditOutcome,
    detailCode: string,
    fields: AuditFields,
    ruleApplied: boolean,
    cloudCode: string | null,
    cloudRequestId: string | null = null,
  ): Promise<boolean> {
    const event = buildAuditEvent({
      phase,
      operation,
      outcome,
      service: AZURE_SQL_FIREWALL_PROFILE.id,
      detailCode,
      resourceId: fields.resourceId,
      ruleName: fields.ruleName,
      ipv4: fields.ipv4,
      ttlSeconds: fields.ttlSeconds,
      replayed: false,
      ruleApplied,
      cloudCode,
      cloudRequestId,
      writersCommitSha: this.commitSha,
      occurredAt: this.now().toISOString(),
    });
    try {
      await this.auditSink.emit(event);
    } catch {
      return false;
    }
    events.push(event);
    return true;
  }
}

export function createAzureSqlRuleProvider(options: AzureSqlRuleProviderOptions): AzureSqlRuleProvider {
  return new AzureSqlFirewallRuleProvider(options);
}

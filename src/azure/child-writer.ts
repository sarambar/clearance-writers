// Copyright 2026 Sarambar
// SPDX-License-Identifier: Apache-2.0

import { buildAuditEvent, type AuditEvent, type AuditOperation, type AuditOutcome, type AuditSink } from "../audit.js";
import { PUBLIC_ACCESS_DISABLED_MESSAGE, writerError, WriterError } from "../errors.js";
import { parseIpv4 } from "../ip.js";
import { normalizeAzureLocation } from "../location.js";
import { isClearanceRuleName } from "../names.js";
import { WRITERS_VERSION } from "../provenance.js";
import { validateAddRequest, validateListRequest, validateRemoveRequest } from "../request.js";
import type {
  AddRuleRequest,
  AddRuleValue,
  FirewallWriter,
  ListRulesRequest,
  RemoveRuleRequest,
  RemoveRuleValue,
  RuleListValue,
  RuleView,
  WriterDescriptor,
  WriterOutcome,
} from "../writer.js";
import { ArmClient, type ArmCall } from "./arm.js";
import type { ArmTokenProvider, HttpTransport } from "./http.js";
import {
  AZURE_POSTGRES_FIREWALL_PROFILE,
  AZURE_SQL_FIREWALL_PROFILE,
  childPath,
  collectionPath,
  parentPath,
  parseAzureParentId,
  type AzureChildFirewallProfile,
  type ParsedParent,
} from "./profiles.js";

export interface AzureWriterOptions {
  transport: HttpTransport;
  tokenProvider: ArmTokenProvider;
  audit: AuditSink;
  endpoint?: string;
  now?: () => Date;
  sleep?: (ms: number) => Promise<void>;
}

/**
 * REST adapter for Azure firewall rules that are named child resources.
 * SQL and PostgreSQL each pass a profile. Collection PUT, which replaces
 * every rule, is never sent from this class.
 * A later whole-list cloud (Key Vault, Storage, an AWS security group) is a
 * new class that implements FirewallWriter and merges inside add and remove.
 * It must not be added by widening this class.
 */
export class AzureChildFirewallWriter implements FirewallWriter {
  readonly descriptor: WriterDescriptor;
  private readonly profile: AzureChildFirewallProfile;
  private readonly arm: ArmClient;
  private readonly auditSink: AuditSink;
  private readonly now: () => Date;

  constructor(profile: AzureChildFirewallProfile, options: AzureWriterOptions) {
    this.profile = profile;
    this.descriptor = { id: profile.id, cloud: "azure", listShape: "child-resource" };
    this.auditSink = options.audit;
    this.now = options.now ?? (() => new Date());
    this.arm = new ArmClient({
      transport: options.transport,
      tokenProvider: options.tokenProvider,
      endpoint: options.endpoint,
      sleep: options.sleep,
      userAgent: `clearance-writers/${WRITERS_VERSION} (${profile.id})`,
    });
  }

  async addRule(request: AddRuleRequest): Promise<WriterOutcome<AddRuleValue>> {
    const validated = validateAddRequest(request);
    if (!validated.ok) {
      return this.denied("add", validated.error, emptyFields());
    }
    const parsed = parseAzureParentId(this.profile, validated.value.resourceId);
    if (!parsed.ok) {
      return this.denied("add", parsed.error, { ...emptyFields(), ruleName: validated.value.ruleName });
    }
    const fields = {
      resourceId: parsed.value.canonicalId,
      ruleName: validated.value.ruleName,
      ipv4: validated.value.address.canonical,
      ttlSeconds: validated.value.ttlSeconds,
    };
    const events: AuditEvent[] = [];
    if (!(await this.record(events, "add", "intent", "succeeded", "ok", fields, false, false, null))) {
      return this.auditFailed("audit_intent_failed", events, false, false);
    }

    const parent = await this.arm.get(parentPath(this.profile, parsed.value), this.profile.apiVersion);
    if (!parent.ok) {
      return this.failed("add", events, parent.error, fields, false);
    }
    const locationRaw = readLocation(parent.body);
    const locationNormalized = locationRaw === null ? null : normalizeAzureLocation(locationRaw);
    const expectedNormalized =
      validated.value.expectedLocation === null ? null : normalizeAzureLocation(validated.value.expectedLocation);
    if (validated.value.expectedLocation !== null && expectedNormalized === null) {
      return this.failed(
        "add",
        events,
        writerError({ code: "invalid_input", message: "Expected location is not an Azure location name." }),
        fields,
        false,
        parent.requestId,
      );
    }
    if (expectedNormalized !== null) {
      if (locationNormalized === null) {
        return this.failed(
          "add",
          events,
          writerError({ code: "location_unavailable", message: "The server response did not include a location." }),
          fields,
          false,
          parent.requestId,
        );
      }
      if (locationNormalized !== expectedNormalized) {
        return this.failed(
          "add",
          events,
          writerError({
            code: "location_mismatch",
            message: "Server location does not match the expected location after normalization.",
          }),
          fields,
          false,
          parent.requestId,
        );
      }
    }
    if (publicAccessClosed(parent.body)) {
      return this.failed(
        "add",
        events,
        writerError({
          code: "public_access_disabled",
          message: PUBLIC_ACCESS_DISABLED_MESSAGE,
        }),
        fields,
        false,
        parent.requestId,
      );
    }

    const listed = await this.readRules(parsed.value);
    if (!listed.ok) {
      return this.failed("add", events, listed.error, fields, false);
    }
    const wantedStart = validated.value.address.startIpv4;
    const wantedEnd = validated.value.address.endIpv4;
    const existing = listed.rules.find((rule) => rule.ruleName.toLowerCase() === validated.value.ruleName.toLowerCase());
    if (existing !== undefined) {
      const sameAddress = existing.startIpv4 === wantedStart && existing.endIpv4 === wantedEnd;
      if (!sameAddress) {
        return this.failed(
          "add",
          events,
          writerError({
            code: "rule_conflict",
            message: "A firewall rule with this name already exists and was not overwritten.",
          }),
          fields,
          true,
        );
      }
      const value: AddRuleValue = {
        resourceId: parsed.value.canonicalId,
        ruleName: validated.value.ruleName,
        startIpv4: wantedStart,
        endIpv4: wantedEnd,
        replayed: true,
        locationRaw,
        locationNormalized,
        ruleCountBefore: listed.rules.length,
      };
      return this.succeeded("add", events, fields, true, true, value, null);
    }
    if (this.profile.ruleCap !== null && listed.rules.length >= this.profile.ruleCap) {
      return this.failed(
        "add",
        events,
        writerError({
          code: "rule_cap_exceeded",
          message: `Refusing to add a rule because the server already has ${this.profile.ruleCap} firewall rules.`,
        }),
        fields,
        false,
      );
    }

    const put = await this.arm.put(childPath(this.profile, parsed.value, validated.value.ruleName), this.profile.apiVersion, {
      properties: { startIpAddress: wantedStart, endIpAddress: wantedEnd },
    });
    if (!put.ok) {
      const presence = await this.rulePresence(parsed.value, validated.value.ruleName, wantedStart, wantedEnd);
      const applied = presence !== "absent";
      return this.failed("add", events, withApplied(put.error, applied), fields, applied, put.requestId);
    }
    const verified = await this.readNamedRule(parsed.value, validated.value.ruleName);
    if (!verified.ok) {
      return this.failed("add", events, withApplied(verified.error, true), fields, true, verified.requestId);
    }
    if (verified.rule.startIpv4 !== wantedStart || verified.rule.endIpv4 !== wantedEnd) {
      return this.failed(
        "add",
        events,
        writerError({
          code: "verify_failed",
          message: "The firewall rule read back after create did not match the requested address.",
          ruleApplied: true,
        }),
        fields,
        true,
        verified.requestId,
      );
    }
    const value: AddRuleValue = {
      resourceId: parsed.value.canonicalId,
      ruleName: validated.value.ruleName,
      startIpv4: wantedStart,
      endIpv4: wantedEnd,
      replayed: false,
      locationRaw,
      locationNormalized,
      ruleCountBefore: listed.rules.length,
    };
    return this.succeeded("add", events, fields, false, true, value, verified.requestId);
  }

  async removeRule(request: RemoveRuleRequest): Promise<WriterOutcome<RemoveRuleValue>> {
    const validated = validateRemoveRequest(request);
    if (!validated.ok) {
      return this.denied("remove", validated.error, emptyFields());
    }
    const parsed = parseAzureParentId(this.profile, validated.value.resourceId);
    if (!parsed.ok) {
      return this.denied("remove", parsed.error, { ...emptyFields(), ruleName: validated.value.ruleName });
    }
    const fields = {
      resourceId: parsed.value.canonicalId,
      ruleName: validated.value.ruleName,
      ipv4: null,
      ttlSeconds: null,
    };
    const events: AuditEvent[] = [];
    const intentOk = await this.record(events, "remove", "intent", "succeeded", "ok", fields, false, false, null);
    const current = await this.readNamedRule(parsed.value, validated.value.ruleName);
    if (!current.ok && current.error.code !== "not_found") {
      return this.failed("remove", events, withApplied(current.error, true), fields, true, current.requestId);
    }
    if (current.ok && current.rule.ruleName.toLowerCase() !== validated.value.ruleName.toLowerCase()) {
      return this.failed(
        "remove",
        events,
        writerError({
          code: "rule_conflict",
          message: "The stored rule name does not match the requested name, so it was not deleted.",
          ruleApplied: true,
        }),
        fields,
        true,
        current.requestId,
      );
    }
    if (current.ok && this.profile.deleteGuard === "refuse-last-rule") {
      const listed = await this.readRules(parsed.value);
      if (!listed.ok) {
        return this.failed("remove", events, listed.error, fields, true);
      }
      if (listed.rules.length === 1) {
        return this.failed(
          "remove",
          events,
          writerError({
            code: "last_rule_refused",
            message: "Refusing to delete the last firewall rule because an empty list can open public access.",
            ruleApplied: true,
          }),
          fields,
          true,
        );
      }
    }

    let alreadyAbsent = !current.ok;
    if (current.ok) {
      const deleted = await this.arm.delete(
        childPath(this.profile, parsed.value, validated.value.ruleName),
        this.profile.apiVersion,
      );
      if (!deleted.ok && deleted.error.code !== "not_found") {
        const presence = await this.rulePresence(parsed.value, validated.value.ruleName);
        if (presence === "absent") {
          alreadyAbsent = true;
        } else {
          return this.failed("remove", events, withApplied(deleted.error, true), fields, true, deleted.requestId);
        }
      } else {
        alreadyAbsent = deleted.ok === false;
      }
    }
    const after = await this.readNamedRule(parsed.value, validated.value.ruleName);
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
      return this.failed("remove", events, withApplied(after.error, true), fields, true, after.requestId);
    }
    const value: RemoveRuleValue = {
      resourceId: parsed.value.canonicalId,
      ruleName: validated.value.ruleName,
      alreadyAbsent,
      removalVerified: true,
    };
    const outcome = await this.succeeded("remove", events, fields, false, false, value, after.requestId);
    if (!intentOk && outcome.ok) {
      return this.markAuditGap(outcome, "audit_intent_failed");
    }
    if (!intentOk && !outcome.ok) {
      return this.markAuditGap(outcome, "audit_intent_failed");
    }
    return outcome;
  }

  async listOwnedRules(request: ListRulesRequest): Promise<WriterOutcome<RuleListValue>> {
    const validated = validateListRequest(request.resourceId);
    if (!validated.ok) {
      return this.denied("list_owned", validated.error, emptyFields());
    }
    const parsed = parseAzureParentId(this.profile, validated.value);
    if (!parsed.ok) {
      return this.denied("list_owned", parsed.error, emptyFields());
    }
    const fields = { resourceId: parsed.value.canonicalId, ruleName: null, ipv4: null, ttlSeconds: null };
    const listed = await this.readRules(parsed.value);
    const events: AuditEvent[] = [];
    if (!listed.ok) {
      return this.failed("list_owned", events, listed.error, fields, false);
    }
    return this.succeeded(
      "list_owned",
      events,
      fields,
      false,
      false,
      { resourceId: parsed.value.canonicalId, rules: listed.rules.filter((rule) => rule.owned) },
      null,
    );
  }

  async readWholeList(request: ListRulesRequest): Promise<WriterOutcome<RuleListValue>> {
    const validated = validateListRequest(request.resourceId);
    if (!validated.ok) {
      return this.denied("read_whole_list", validated.error, emptyFields());
    }
    const parsed = parseAzureParentId(this.profile, validated.value);
    if (!parsed.ok) {
      return this.denied("read_whole_list", parsed.error, emptyFields());
    }
    const fields = { resourceId: parsed.value.canonicalId, ruleName: null, ipv4: null, ttlSeconds: null };
    const listed = await this.readRules(parsed.value);
    const events: AuditEvent[] = [];
    if (!listed.ok) {
      return this.failed("read_whole_list", events, listed.error, fields, false);
    }
    const value = { resourceId: parsed.value.canonicalId, rules: listed.rules };
    return this.succeeded("read_whole_list", events, fields, false, false, value, null);
  }

  private async readRules(
    parent: ParsedParent,
  ): Promise<{ ok: true; rules: RuleView[] } | { ok: false; error: WriterError }> {
    const rules: RuleView[] = [];
    const seen = new Set<string>();
    let call: ArmCall = await this.arm.get(collectionPath(this.profile, parent), this.profile.apiVersion);
    for (let page = 0; page < 512; page += 1) {
      if (!call.ok) {
        return { ok: false, error: call.error };
      }
      const record = asRecord(call.body);
      const value = record?.value;
      if (!Array.isArray(value)) {
        return {
          ok: false,
          error: writerError({ code: "cloud_response_invalid", message: "Firewall rule list did not contain a value array." }),
        };
      }
      for (const item of value) {
        const rule = parseRule(item);
        if (rule === null) {
          return {
            ok: false,
            error: writerError({
              code: "cloud_response_invalid",
              message: "A firewall rule in the list could not be parsed. The list was not trimmed.",
            }),
          };
        }
        rules.push(rule);
      }
      const nextLink = record?.nextLink;
      if (nextLink === undefined || nextLink === null) {
        return { ok: true, rules };
      }
      if (typeof nextLink !== "string" || seen.has(nextLink)) {
        return {
          ok: false,
          error: writerError({ code: "unsafe_poll_url", message: "The firewall rule list returned a nextLink that will not be followed." }),
        };
      }
      seen.add(nextLink);
      call = await this.arm.getAbsolute(nextLink);
    }
    return {
      ok: false,
      error: writerError({ code: "cloud_response_invalid", message: "The firewall rule list exceeded the page limit." }),
    };
  }

  private async readNamedRule(
    parent: ParsedParent,
    ruleName: string,
  ): Promise<{ ok: true; rule: RuleView; requestId: string | null } | { ok: false; error: WriterError; requestId: string | null }> {
    const response = await this.arm.get(childPath(this.profile, parent, ruleName), this.profile.apiVersion);
    if (!response.ok) {
      return { ok: false, error: response.error, requestId: response.requestId };
    }
    const rule = parseRule(response.body);
    if (rule === null) {
      return {
        ok: false,
        requestId: response.requestId,
        error: writerError({ code: "cloud_response_invalid", message: "The firewall rule response could not be parsed." }),
      };
    }
    return { ok: true, rule, requestId: response.requestId };
  }

  private async rulePresence(
    parent: ParsedParent,
    ruleName: string,
    start?: string,
    end?: string,
  ): Promise<"present" | "absent" | "unknown"> {
    const rule = await this.readNamedRule(parent, ruleName);
    if (!rule.ok) {
      return rule.error.code === "not_found" ? "absent" : "unknown";
    }
    if (start !== undefined && end !== undefined && (rule.rule.startIpv4 !== start || rule.rule.endIpv4 !== end)) {
      return "present";
    }
    return "present";
  }

  private async denied(
    operation: AuditOperation,
    error: WriterError,
    fields: AuditFields,
  ): Promise<WriterOutcome<never>> {
    const events: AuditEvent[] = [];
    const recorded = await this.record(events, operation, "result", "denied", error.code, fields, false, false, error.cloudCode);
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
  ): Promise<WriterOutcome<never>> {
    const ok = await this.record(
      events,
      operation,
      "result",
      "failed",
      error.code,
      fields,
      false,
      ruleApplied,
      error.cloudCode,
      requestId,
    );
    if (!ok) {
      return this.auditFailed("audit_completion_failed", events, ruleApplied, false);
    }
    return { ok: false, error: withApplied(error, ruleApplied), audit: events };
  }

  private async succeeded<T>(
    operation: AuditOperation,
    events: AuditEvent[],
    fields: AuditFields,
    replayed: boolean,
    ruleApplied: boolean,
    value: T,
    requestId: string | null,
  ): Promise<WriterOutcome<T>> {
    const ok = await this.record(events, operation, "result", "succeeded", "ok", fields, replayed, ruleApplied, null, requestId);
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
  ): WriterOutcome<never> {
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

  private markAuditGap<T>(outcome: WriterOutcome<T>, code: "audit_intent_failed"): WriterOutcome<T> {
    if (!outcome.ok && outcome.error.code === "audit_completion_failed") {
      return outcome;
    }
    const removalVerified = outcome.ok ? outcome.value !== null && "removalVerified" in (outcome.value as object) : outcome.error.removalVerified;
    return {
      ok: false,
      audit: outcome.audit,
      error: writerError({
        code,
        message: "The audit sink did not accept the intent event. Cleanup was not skipped.",
        ruleApplied: outcome.ok ? false : outcome.error.ruleApplied,
        removalVerified: Boolean(removalVerified),
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
    replayed: boolean,
    ruleApplied: boolean,
    cloudCode: string | null,
    cloudRequestId: string | null = null,
  ): Promise<boolean> {
    const event = buildAuditEvent({
      phase,
      operation,
      outcome,
      service: this.profile.id,
      detailCode,
      resourceId: fields.resourceId,
      ruleName: fields.ruleName,
      ipv4: fields.ipv4,
      ttlSeconds: fields.ttlSeconds,
      replayed,
      ruleApplied,
      cloudCode,
      cloudRequestId,
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

interface AuditFields {
  resourceId: string | null;
  ruleName: string | null;
  ipv4: string | null;
  ttlSeconds: number | null;
}

function emptyFields(): AuditFields {
  return { resourceId: null, ruleName: null, ipv4: null, ttlSeconds: null };
}

function withApplied(error: WriterError, ruleApplied: boolean): WriterError {
  return writerError({
    code: error.code,
    message: error.message,
    retryable: error.retryable,
    ruleApplied,
    removalVerified: error.removalVerified,
    authorizationDenial: error.authorizationDenial,
    cloudCode: error.cloudCode,
    cloudStatus: error.cloudStatus,
  });
}

function asRecord(value: unknown): Record<string, unknown> | null {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    return null;
  }
  return value as Record<string, unknown>;
}

function readLocation(body: unknown): string | null {
  const location = asRecord(body)?.location;
  return typeof location === "string" && location.trim() !== "" ? location : null;
}

function publicAccessClosed(body: unknown): boolean {
  const properties = asRecord(asRecord(body)?.properties);
  const network = asRecord(properties?.network);
  const delegated = network?.delegatedSubnetResourceId;
  if (typeof delegated === "string" && delegated.trim() !== "") {
    return true;
  }
  for (const value of [properties?.publicNetworkAccess, network?.publicNetworkAccess]) {
    if (typeof value === "string" && value.toLowerCase() !== "enabled") {
      return true;
    }
  }
  return false;
}

function parseRule(body: unknown): RuleView | null {
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
  return {
    ruleName: record.name,
    startIpv4: start,
    endIpv4: end,
    owned: isClearanceRuleName(record.name),
    providerId: typeof record.id === "string" ? record.id : null,
  };
}

export function createAzureSqlFirewallWriter(options: AzureWriterOptions): FirewallWriter {
  return new AzureChildFirewallWriter(AZURE_SQL_FIREWALL_PROFILE, options);
}

export function createAzurePostgresFirewallWriter(options: AzureWriterOptions): FirewallWriter {
  return new AzureChildFirewallWriter(AZURE_POSTGRES_FIREWALL_PROFILE, options);
}

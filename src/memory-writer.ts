// Copyright 2026 Sarambar
// SPDX-License-Identifier: Apache-2.0

import { buildAuditEvent, type AuditEvent, type AuditSink } from "./audit.js";
import { WriterError, writerError } from "./errors.js";
import { validateAddRequest, validateListRequest, validateRemoveRequest } from "./request.js";
import type {
  AddRuleRequest,
  AddRuleValue,
  FirewallWriter,
  ListRulesRequest,
  RemoveRuleRequest,
  RemoveRuleValue,
  RuleListValue,
  RuleView,
  WriterOutcome,
} from "./writer.js";

const MEMORY_ID = /^memory:[a-z0-9][a-z0-9/_-]{0,200}$/;

/**
 * Reference FirewallWriter with no cloud. It exists so callers and tests can
 * exercise the four operations without Azure types. It does not open a rule
 * on any network.
 */
export class InMemoryFirewallWriter implements FirewallWriter {
  readonly descriptor = {
    id: "in-memory",
    cloud: "other" as const,
    listShape: "child-resource" as const,
  };

  private readonly rules = new Map<string, Map<string, RuleView>>();
  private readonly auditSink: AuditSink;
  private readonly now: () => Date;

  constructor(options: { audit: AuditSink; now?: () => Date }) {
    this.auditSink = options.audit;
    this.now = options.now ?? (() => new Date());
  }

  async addRule(request: AddRuleRequest): Promise<WriterOutcome<AddRuleValue>> {
    const validated = validateAddRequest(request);
    if (!validated.ok) {
      return this.finish("add", "denied", validated.error.code, null, false, false, validated.error);
    }
    if (!MEMORY_ID.test(validated.value.resourceId)) {
      return this.finish(
        "add",
        "denied",
        "invalid_resource_id",
        null,
        false,
        false,
        writerError({ code: "invalid_resource_id", message: "In-memory resource ids use the memory: prefix." }),
      );
    }
    const intent = await this.emit("add", "intent", "succeeded", "ok", validated.value, false, false);
    if (intent === null) {
      return {
        ok: false,
        audit: [],
        error: writerError({
          code: "audit_intent_failed",
          message: "The audit sink did not accept the intent event.",
          ruleApplied: false,
        }),
      };
    }
    const bucket = this.bucket(validated.value.resourceId);
    const existing = [...bucket.values()].find((rule) => rule.ruleName.toLowerCase() === validated.value.ruleName.toLowerCase());
    if (existing !== undefined) {
      const same =
        existing.ruleName === validated.value.ruleName &&
        existing.startIpv4 === validated.value.address.startIpv4 &&
        existing.endIpv4 === validated.value.address.endIpv4;
      if (!same) {
        return this.finish(
          "add",
          "failed",
          "rule_conflict",
          validated.value,
          false,
          true,
          writerError({ code: "rule_conflict", message: "An in-memory rule with this name already exists.", ruleApplied: true }),
          validated.value.resourceId,
          [intent],
        );
      }
      return this.finish(
        "add",
        "succeeded",
        "ok",
        validated.value,
        true,
        true,
        {
          resourceId: validated.value.resourceId,
          ruleName: validated.value.ruleName,
          startIpv4: validated.value.address.startIpv4,
          endIpv4: validated.value.address.endIpv4,
          replayed: true,
          locationRaw: null,
          locationNormalized: null,
          ruleCountBefore: bucket.size,
        },
        undefined,
        [intent],
      );
    }
    bucket.set(validated.value.ruleName, {
      ruleName: validated.value.ruleName,
      startIpv4: validated.value.address.startIpv4,
      endIpv4: validated.value.address.endIpv4,
      owned: true,
      providerId: null,
    });
    const created = await this.finish<AddRuleValue>(
      "add",
      "succeeded",
      "ok",
      validated.value,
      false,
      true,
      {
        resourceId: validated.value.resourceId,
        ruleName: validated.value.ruleName,
        startIpv4: validated.value.address.startIpv4,
        endIpv4: validated.value.address.endIpv4,
        replayed: false,
        locationRaw: null,
        locationNormalized: null,
        ruleCountBefore: bucket.size - 1,
      },
      undefined,
      [intent],
    );
    if (!created.ok) {
      bucket.delete(validated.value.ruleName);
    }
    return created;
  }

  async removeRule(request: RemoveRuleRequest): Promise<WriterOutcome<RemoveRuleValue>> {
    const validated = validateRemoveRequest(request);
    if (!validated.ok) {
      return this.finish("remove", "denied", validated.error.code, null, false, false, validated.error);
    }
    if (!MEMORY_ID.test(validated.value.resourceId)) {
      return this.finish(
        "remove",
        "denied",
        "invalid_resource_id",
        null,
        false,
        false,
        writerError({ code: "invalid_resource_id", message: "In-memory resource ids use the memory: prefix." }),
      );
    }
    const intent = await this.emit("remove", "intent", "succeeded", "ok", validated.value, false, false);
    const intentOk = intent !== null;
    const prior = intent === null ? [] : [intent];
    const bucket = this.bucket(validated.value.resourceId);
    const existing = bucket.get(validated.value.ruleName);
    const alreadyAbsent = existing === undefined;
    bucket.delete(validated.value.ruleName);
    if (bucket.has(validated.value.ruleName)) {
      return this.finish(
        "remove",
        "failed",
        "delete_not_verified",
        validated.value,
        false,
        true,
        writerError({ code: "delete_not_verified", message: "The in-memory rule is still present.", ruleApplied: true }),
        undefined,
        prior,
      );
    }
    const removed = await this.finish<RemoveRuleValue>(
      "remove",
      "succeeded",
      "ok",
      validated.value,
      false,
      false,
      {
        resourceId: validated.value.resourceId,
        ruleName: validated.value.ruleName,
        alreadyAbsent,
        removalVerified: true,
      },
      undefined,
      prior,
    );
    if (!intentOk && removed.ok) {
      return {
        ok: false,
        audit: removed.audit,
        error: writerError({
          code: "audit_intent_failed",
          message: "The audit sink did not accept the intent event. Cleanup was not skipped.",
          removalVerified: true,
          ruleApplied: false,
        }),
      };
    }
    return removed;
  }

  async listOwnedRules(request: ListRulesRequest): Promise<WriterOutcome<RuleListValue>> {
    const validated = validateListRequest(request.resourceId);
    if (!validated.ok) {
      return this.finish("list_owned", "denied", validated.error.code, null, false, false, validated.error);
    }
    if (!MEMORY_ID.test(validated.value)) {
      return this.finish(
        "list_owned",
        "denied",
        "invalid_resource_id",
        null,
        false,
        false,
        writerError({ code: "invalid_resource_id", message: "In-memory resource ids use the memory: prefix." }),
      );
    }
    const rules = [...this.bucket(validated.value).values()].filter((rule) => rule.owned);
    return this.finish(
      "list_owned",
      "succeeded",
      "ok",
      null,
      false,
      false,
      { resourceId: validated.value, rules },
      validated.value,
    );
  }

  async readWholeList(request: ListRulesRequest): Promise<WriterOutcome<RuleListValue>> {
    const validated = validateListRequest(request.resourceId);
    if (!validated.ok) {
      return this.finish("read_whole_list", "denied", validated.error.code, null, false, false, validated.error);
    }
    if (!MEMORY_ID.test(validated.value)) {
      return this.finish(
        "read_whole_list",
        "denied",
        "invalid_resource_id",
        null,
        false,
        false,
        writerError({ code: "invalid_resource_id", message: "In-memory resource ids use the memory: prefix." }),
      );
    }
    const rules = [...this.bucket(validated.value).values()];
    return this.finish(
      "read_whole_list",
      "succeeded",
      "ok",
      null,
      false,
      false,
      { resourceId: validated.value, rules },
      validated.value,
    );
  }

  private bucket(resourceId: string): Map<string, RuleView> {
    const existing = this.rules.get(resourceId);
    if (existing !== undefined) {
      return existing;
    }
    const created = new Map<string, RuleView>();
    this.rules.set(resourceId, created);
    return created;
  }

  private async emit(
    operation: "add" | "remove" | "list_owned" | "read_whole_list",
    phase: "intent" | "result",
    outcome: "succeeded" | "failed" | "denied",
    detailCode: string,
    validated: { resourceId: string; ruleName: string; address?: { canonical: string }; ttlSeconds?: number } | null,
    replayed: boolean,
    ruleApplied: boolean,
    canonicalId?: string,
  ): Promise<AuditEvent | null> {
    const event = buildAuditEvent({
      phase,
      operation,
      outcome,
      service: this.descriptor.id,
      detailCode,
      resourceId: canonicalId ?? validated?.resourceId ?? null,
      ruleName: validated?.ruleName ?? null,
      ipv4: validated?.address?.canonical ?? null,
      ttlSeconds: validated?.ttlSeconds ?? null,
      replayed,
      ruleApplied,
      occurredAt: this.now().toISOString(),
    });
    try {
      await this.auditSink.emit(event);
    } catch {
      return null;
    }
    return event;
  }

  private async finish<T>(
    operation: "add" | "remove" | "list_owned" | "read_whole_list",
    outcome: "succeeded" | "failed" | "denied",
    detailCode: string,
    validated: { resourceId: string; ruleName: string; address?: { canonical: string }; ttlSeconds?: number } | null,
    replayed: boolean,
    ruleApplied: boolean,
    valueOrError: NoInfer<T | WriterError>,
    canonicalId?: string,
    priorEvents: readonly AuditEvent[] = [],
  ): Promise<WriterOutcome<T>> {
    const event = buildAuditEvent({
      phase: "result",
      operation,
      outcome,
      service: this.descriptor.id,
      detailCode,
      resourceId: canonicalId ?? validated?.resourceId ?? null,
      ruleName: validated?.ruleName ?? null,
      ipv4: validated?.address?.canonical ?? null,
      ttlSeconds: validated?.ttlSeconds ?? null,
      replayed,
      ruleApplied,
      occurredAt: this.now().toISOString(),
    });
    const events: AuditEvent[] = [...priorEvents];
    try {
      await this.auditSink.emit(event);
      events.push(event);
    } catch {
      return {
        ok: false,
        audit: events,
        error: writerError({ code: "audit_completion_failed", message: "The audit sink did not accept the event.", ruleApplied }),
      };
    }
    if (valueOrError instanceof WriterError) {
      return { ok: false, error: valueOrError, audit: events };
    }
    return { ok: true, value: valueOrError, audit: events };
  }
}

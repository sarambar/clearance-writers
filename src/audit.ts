// Copyright 2026 Sarambar
// SPDX-License-Identifier: Apache-2.0

import { randomUUID } from "node:crypto";

import { canonicalJson, sha256Hex } from "./codec.js";
import { writersCommitSha, WRITERS_VERSION } from "./provenance.js";

/**
 * Genesis prev-hash for a backend chain. 64 hex zeros.
 * event_hash = SHA-256(prev_hash concatenated with the canonical event body).
 * The body includes the writers version and commit SHA and does not include
 * contentHash or prev_hash, so those fields cannot be rewritten to hide a change.
 */
export const AUDIT_GENESIS_HASH = "0".repeat(64);

export const AUDIT_SCHEMA_VERSION = 1 as const;

export type AuditPhase = "intent" | "result";
export type AuditOperation = "add" | "remove" | "list_owned" | "read_whole_list";
export type AuditOutcome = "succeeded" | "failed" | "denied";

export interface AuditEventBody {
  schemaVersion: typeof AUDIT_SCHEMA_VERSION;
  eventId: string;
  occurredAt: string;
  phase: AuditPhase;
  operation: AuditOperation;
  outcome: AuditOutcome;
  writersVersion: string;
  writersCommitSha: string;
  service: string;
  detailCode: string;
  resourceId: string | null;
  ruleName: string | null;
  ipv4: string | null;
  ttlSeconds: number | null;
  replayed: boolean;
  ruleApplied: boolean;
  cloudCode: string | null;
  cloudRequestId: string | null;
}

export interface AuditEvent extends AuditEventBody {
  /** SHA-256 of the canonical body. Not itself part of the body. */
  contentHash: string;
}

export interface AuditSink {
  emit(event: AuditEvent): Promise<void>;
}

export function sealAuditEvent(body: AuditEventBody): AuditEvent {
  return {
    ...body,
    contentHash: sha256Hex(canonicalJson(body)),
  };
}

export function auditEventHash(prevHash: string, body: AuditEventBody): string {
  if (!/^[0-9a-f]{64}$/.test(prevHash)) {
    throw new Error("prev hash must be 64 lowercase hex characters");
  }
  return sha256Hex(prevHash + canonicalJson(body));
}

export interface AuditDraft {
  phase: AuditPhase;
  operation: AuditOperation;
  outcome: AuditOutcome;
  service: string;
  detailCode: string;
  resourceId: string | null;
  ruleName: string | null;
  ipv4: string | null;
  ttlSeconds: number | null;
  replayed?: boolean;
  ruleApplied?: boolean;
  cloudCode?: string | null;
  cloudRequestId?: string | null;
  occurredAt: string;
}

export function buildAuditEvent(draft: AuditDraft): AuditEvent {
  const body: AuditEventBody = {
    schemaVersion: AUDIT_SCHEMA_VERSION,
    eventId: randomUUID(),
    occurredAt: draft.occurredAt,
    phase: draft.phase,
    operation: draft.operation,
    outcome: draft.outcome,
    writersVersion: WRITERS_VERSION,
    writersCommitSha: writersCommitSha(),
    service: draft.service,
    detailCode: draft.detailCode,
    resourceId: draft.resourceId,
    ruleName: draft.ruleName,
    ipv4: draft.ipv4,
    ttlSeconds: draft.ttlSeconds,
    replayed: draft.replayed ?? false,
    ruleApplied: draft.ruleApplied ?? false,
    cloudCode: draft.cloudCode ?? null,
    cloudRequestId: draft.cloudRequestId ?? null,
  };
  return sealAuditEvent(body);
}

/** In-process sink for tests. Not a durable audit log. */
export class MemoryAuditSink implements AuditSink {
  readonly events: AuditEvent[] = [];
  failOnEmit: "never" | "intent" | "result" | "always" = "never";

  async emit(event: AuditEvent): Promise<void> {
    if (
      this.failOnEmit === "always" ||
      (this.failOnEmit === "intent" && event.phase === "intent") ||
      (this.failOnEmit === "result" && event.phase === "result")
    ) {
      throw new Error("audit sink refused the event");
    }
    this.events.push(event);
  }
}

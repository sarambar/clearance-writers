// Copyright 2026 Sarambar
// SPDX-License-Identifier: Apache-2.0

import type { AuditEvent } from "./audit.js";
import type { WriterError } from "./errors.js";
import type { IpPolicy } from "./ip.js";

/**
 * Provider-neutral firewall writer.
 *
 * Callers depend on these four operations and not on Azure, ARM, or security
 * groups. An adapter owns the translation:
 *
 * - Child-resource clouds (Azure SQL, PostgreSQL Flexible Server) create or
 *   delete one named child and never replace the collection.
 * - A later whole-list cloud (Key Vault, Storage, an AWS security group that
 *   must be rewritten) still implements the same four methods. Inside add or
 *   remove it reads the whole list, merges one entry, and writes that list
 *   back. Callers do not grow a fifth method or an Azure-shaped argument.
 *
 * `resourceId` is opaque here. Each adapter allowlists its own id shape.
 * `ruleName` is a Clearance name, not a cloud-generated id.
 */
export interface FirewallWriter {
  readonly descriptor: WriterDescriptor;
  addRule(request: AddRuleRequest): Promise<WriterOutcome<AddRuleValue>>;
  removeRule(request: RemoveRuleRequest): Promise<WriterOutcome<RemoveRuleValue>>;
  listOwnedRules(request: ListRulesRequest): Promise<WriterOutcome<RuleListValue>>;
  readWholeList(request: ListRulesRequest): Promise<WriterOutcome<RuleListValue>>;
}

export interface WriterDescriptor {
  /** Stable adapter id, for example `azure-sql-server-firewall`. */
  id: string;
  cloud: "azure" | "aws" | "gcp" | "other";
  /**
   * Informational. Callers must not branch on this to change the four calls.
   * `child-resource` adapters address one rule. `whole-list` adapters rewrite
   * a parent property and still present one rule at this boundary.
   */
  listShape: "child-resource" | "whole-list";
}

export interface AddRuleRequest {
  resourceId: string;
  ruleName: string;
  /** One IPv4 host, or a CIDR the active policy allows. */
  ipv4: string;
  ttlSeconds: number;
  /**
   * The private backend sets this only after the ledger records an add it
   * verified. The prefix on the name is not ownership. A missing or false
   * value is refused before any cloud call.
   */
  ledgerOwned: true;
  ipPolicy?: IpPolicy;
  /**
   * Optional location check. Azure adapters compare this only after folding
   * display names (`Central US` and `centralus`). Other clouds compare their
   * own location form and must not assume that fold.
   */
  expectedLocation?: string;
}

export interface RemoveRuleRequest {
  resourceId: string;
  ruleName: string;
  /** Same ledger assertion as add. Prefix alone does not authorize a delete. */
  ledgerOwned: true;
}

export interface ListRulesRequest {
  resourceId: string;
}

export interface RuleView {
  ruleName: string;
  startIpv4: string;
  endIpv4: string;
  /** True when the name passes the Clearance rule-name allowlist. */
  owned: boolean;
  providerId: string | null;
}

export interface AddRuleValue {
  resourceId: string;
  ruleName: string;
  startIpv4: string;
  endIpv4: string;
  replayed: boolean;
  locationRaw: string | null;
  locationNormalized: string | null;
  ruleCountBefore: number;
}

export interface RemoveRuleValue {
  resourceId: string;
  ruleName: string;
  alreadyAbsent: boolean;
  removalVerified: true;
}

export interface RuleListValue {
  resourceId: string;
  rules: RuleView[];
}

export type WriterOutcome<T> =
  | { ok: true; value: T; audit: AuditEvent[] }
  | { ok: false; error: WriterError; audit: AuditEvent[] };

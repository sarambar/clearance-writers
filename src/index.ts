// Copyright 2026 Sarambar
// SPDX-License-Identifier: Apache-2.0

export {
  AUDIT_GENESIS_HASH,
  AUDIT_SCHEMA_VERSION,
  MemoryAuditSink,
  auditEventHash,
  buildAuditEvent,
  sealAuditEvent,
} from "./audit.js";
export type { AuditEvent, AuditEventBody, AuditOperation, AuditOutcome, AuditPhase, AuditSink } from "./audit.js";

export { canonicalJson, escapeForOutput, sha256Hex } from "./codec.js";

export { PUBLIC_ACCESS_DISABLED_MESSAGE, WRITER_ERROR_CODES, WriterError, writerError } from "./errors.js";
export type { WriterErrorCode } from "./errors.js";

export {
  MAX_TTL_SECONDS,
  MIN_TTL_SECONDS,
  STRICT_IP_POLICY,
  exposureBoundSeconds,
  parseAllowAddress,
  parseIpv4,
  parseTtlSeconds,
} from "./ip.js";
export type { IpPolicy, ParsedAddress } from "./ip.js";

export { normalizeAzureLocation } from "./location.js";

export { InMemoryFirewallWriter } from "./memory-writer.js";

export {
  CLEARANCE_RULE_PREFIX,
  RESERVED_FIREWALL_RULE_NAMES,
  SBC_RULE_PREFIX,
  isClearanceRuleName,
  isSbcRuleName,
  parseRuleName,
  parseSbcRuleName,
} from "./names.js";
export type { ParsedSbcRuleName } from "./names.js";

export {
  POSTGRES_FIREWALL_PROPAGATION_WINDOW_SECONDS,
  SQL_FIREWALL_CACHE_WINDOW_SECONDS,
  classifyReachability,
  observePostgresDriverError,
  observeSqlDriverError,
  postDeleteProbePassed,
} from "./probe.js";
export type { ProbeObservation, ReachabilityClass } from "./probe.js";

export { WRITERS_VERSION, resolveWritersCommitSha, writersCommitSha } from "./provenance.js";

export type {
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
} from "./writer.js";

export { createAzurePostgresFirewallWriter, createAzureSqlFirewallWriter } from "./azure/child-writer.js";
export type { AzureWriterOptions } from "./azure/child-writer.js";

export {
  AZURE_SQL_RULE_PROVIDER_ACTIONS,
  AzureSqlFirewallRuleProvider,
  DELETE_VERIFY_BASE_DELAY_MS,
  DELETE_VERIFY_MAX_ATTEMPTS,
  createAzureSqlRuleProvider,
} from "./azure/sql-provider.js";
export type {
  AzureSqlRuleProvider,
  AzureSqlRuleProviderOptions,
  SbcRuleView,
  SqlCloseRuleRequest,
  SqlCloseRuleValue,
  SqlListSbcRulesRequest,
  SqlListSbcRulesValue,
  SqlOpenRuleRequest,
  SqlOpenRuleValue,
  SqlRuleOutcome,
} from "./azure/sql-provider.js";

export { LRO_INITIAL_DELAY_MS, LRO_MAX_DELAY_MS, LRO_MIN_DELAY_MS, MAX_LRO_BUDGET_MS, MAX_LRO_POLLS } from "./azure/arm.js";

export { DEFAULT_HTTP_TIMEOUT_MS, createFetchTransport } from "./azure/http.js";
export type { ArmTokenProvider, HttpTransport } from "./azure/http.js";

export {
  AZURE_POSTGRES_FIREWALL_ACTIONS,
  AZURE_POSTGRES_FIREWALL_API_VERSION,
  AZURE_SQL_FIREWALL_ACTIONS,
  AZURE_SQL_FIREWALL_API_VERSION,
  SQL_RULE_CAP,
} from "./azure/profiles.js";

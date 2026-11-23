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

export {
  AUTHORIZATION_DENIAL_CODES,
  WRITER_ERROR_CODES,
  WriterError,
  isAuthorizationDenialCode,
  writerError,
} from "./errors.js";
export type { AuthorizationDenialCode, WriterErrorCode } from "./errors.js";

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

export { CLEARANCE_RULE_PREFIX, RESERVED_FIREWALL_RULE_NAMES, isClearanceRuleName, parseRuleName } from "./names.js";

export {
  POSTGRES_FIREWALL_PROPAGATION_WINDOW_SECONDS,
  SQL_FIREWALL_CACHE_WINDOW_SECONDS,
  classifyReachability,
  observePostgresDriverError,
  observeSqlDriverError,
  postDeleteProbePassed,
} from "./probe.js";
export type { ProbeObservation, ReachabilityClass } from "./probe.js";

export { WRITERS_VERSION, writersCommitSha } from "./provenance.js";

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

export { ArmClient, LRO_DEFAULT_DELAY_MS } from "./azure/arm.js";
export type { ArmCall, ArmFailure, ArmSuccess } from "./azure/arm.js";

export {
  AzureChildFirewallWriter,
  createAzurePostgresFirewallWriter,
  createAzureSqlFirewallWriter,
} from "./azure/child-writer.js";
export type { AzureWriterOptions } from "./azure/child-writer.js";

export { FakeArm } from "./azure/fake-arm.js";
export type { FakeRule, FakeServerSeed } from "./azure/fake-arm.js";

export { createFetchTransport } from "./azure/http.js";
export type { ArmTokenProvider, HttpRequest, HttpResponse, HttpTransport } from "./azure/http.js";

export {
  AZURE_POSTGRES_FIREWALL_ACTIONS,
  AZURE_POSTGRES_FIREWALL_API_VERSION,
  AZURE_POSTGRES_FIREWALL_PROFILE,
  AZURE_SQL_FIREWALL_ACTIONS,
  AZURE_SQL_FIREWALL_API_VERSION,
  AZURE_SQL_FIREWALL_PROFILE,
  SQL_RULE_CAP,
  UNIMPLEMENTED_SERVICES,
} from "./azure/profiles.js";
export type { AzureChildFirewallProfile, UnimplementedService } from "./azure/profiles.js";

export { validateRoleDefinitionDeleteArgs } from "./azure/role-definition.js";
export type { RoleDefinitionDeleteArgs } from "./azure/role-definition.js";

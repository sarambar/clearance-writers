// Copyright 2026 Sarambar
// SPDX-License-Identifier: Apache-2.0

/**
 * Stable error codes. Authorization denial is a separate flag, not "any failure".
 * Only codes listed in AUTHORIZATION_DENIAL_CODES count as an authorization denial.
 */
export const WRITER_ERROR_CODES = [
  "invalid_input",
  "broad_range",
  "azure_services_forbidden",
  "default_route_forbidden",
  "not_public_unicast",
  "invalid_rule_name",
  "invalid_resource_id",
  "invalid_ttl",
  "ledger_required",
  "rule_conflict",
  "rule_cap_exceeded",
  "last_rule_refused",
  "public_access_disabled",
  "location_mismatch",
  "location_unavailable",
  "not_found",
  "authorization_denied",
  "authentication_failed",
  "gateway_error",
  "cloud_rejected",
  "cloud_forbidden",
  "throttled",
  "lro_malformed",
  "lro_failed",
  "lro_canceled",
  "lro_timeout",
  "redirect_rejected",
  "unsafe_poll_url",
  "cloud_response_invalid",
  "verify_failed",
  "delete_not_verified",
  "audit_intent_failed",
  "audit_completion_failed",
  "transport",
  "confirmation_required",
] as const;

export type WriterErrorCode = (typeof WRITER_ERROR_CODES)[number];

/**
 * ARM error codes that mean the identity was denied by RBAC.
 * Anything else, including BadGateway and an empty list, is not a denial.
 */
export const AUTHORIZATION_DENIAL_CODES = [
  "AuthorizationFailed",
  "LinkedAuthorizationFailed",
] as const;

export type AuthorizationDenialCode = (typeof AUTHORIZATION_DENIAL_CODES)[number];

const DENIAL_SET = new Set<string>(AUTHORIZATION_DENIAL_CODES);

export function isAuthorizationDenialCode(code: string | null | undefined): boolean {
  return code !== null && code !== undefined && DENIAL_SET.has(code);
}

export interface WriterErrorOptions {
  code: WriterErrorCode;
  message: string;
  retryable?: boolean;
  /** A Clearance rule with the requested address may exist in the cloud. */
  ruleApplied?: boolean;
  /** A remove was followed by a read that showed the rule gone. */
  removalVerified?: boolean;
  authorizationDenial?: boolean;
  cloudCode?: string | null;
  cloudStatus?: number | null;
}

/**
 * Failure on the error channel. Success values never carry this object.
 * `message` is already escaped and single-line.
 */
export class WriterError extends Error {
  readonly code: WriterErrorCode;
  readonly retryable: boolean;
  readonly ruleApplied: boolean;
  readonly removalVerified: boolean;
  readonly authorizationDenial: boolean;
  readonly cloudCode: string | null;
  readonly cloudStatus: number | null;
  /** Operator-facing channel. Do not mix this line into a success payload. */
  readonly stream = "error" as const;

  constructor(options: WriterErrorOptions) {
    super(options.message);
    this.name = "WriterError";
    this.code = options.code;
    this.retryable = options.retryable ?? false;
    this.ruleApplied = options.ruleApplied ?? false;
    this.removalVerified = options.removalVerified ?? false;
    this.authorizationDenial = options.authorizationDenial ?? false;
    this.cloudCode = options.cloudCode ?? null;
    this.cloudStatus = options.cloudStatus ?? null;
  }

  /** One escaped line for an operator's error stream. */
  toOperatorLine(): string {
    const cloud = this.cloudCode === null ? "" : ` cloud=${this.cloudCode}`;
    const status = this.cloudStatus === null ? "" : ` status=${this.cloudStatus}`;
    return `clearance-writers ${this.code}${cloud}${status}: ${this.message}`;
  }
}

export function writerError(options: WriterErrorOptions): WriterError {
  return new WriterError(options);
}

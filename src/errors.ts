// Copyright 2026 Sarambar
// SPDX-License-Identifier: Apache-2.0

/**
 * Customer-facing text for `public_access_disabled`.
 * Writers report this and leave the server unchanged. They do not enable public access.
 */
export const PUBLIC_ACCESS_DISABLED_MESSAGE =
  "Clearance only manages server firewall rules when public network access is enabled.";

/**
 * Stable error codes shared by every cloud.
 * `authorization_denied` is the cloud-neutral denial. Adapters set it.
 * Callers should not match a cloud's raw error strings.
 * `lro_*` means a long-running operation, not a specific vendor type.
 * `azure_services_forbidden` is the default-policy refusal of the 0.0.0.0 sentinel.
 */
export const WRITER_ERROR_CODES = [
  "invalid_input",
  "broad_range",
  "azure_services_forbidden",
  "server_allows_azure_services",
  "default_route_forbidden",
  "not_public_unicast",
  "invalid_rule_name",
  "invalid_resource_id",
  "invalid_ttl",
  "ledger_required",
  "rule_conflict",
  "rule_cap_exceeded",
  "rule_limit_reached",
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
  /** Parsed Retry-After delay in seconds when throttled by ARM. */
  retryAfterSeconds?: number | null;
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
  readonly retryAfterSeconds: number | null;
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
    this.retryAfterSeconds = options.retryAfterSeconds ?? null;
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

// Copyright 2026 Sarambar
// SPDX-License-Identifier: Apache-2.0

import { escapeForOutput } from "../codec.js";
import { PUBLIC_ACCESS_DISABLED_MESSAGE, writerError, type WriterError } from "../errors.js";
import { headerValue, sameOriginArmUrl, type ArmTokenProvider, type HttpTransport } from "./http.js";

/** azure-core's default polling interval when Retry-After is absent. */
export const LRO_DEFAULT_DELAY_MS = 30_000;
export const LRO_MIN_DELAY_MS = 1_000;
export const LRO_MAX_DELAY_MS = 30_000;
export const THROTTLE_DEFAULT_DELAY_MS = 1_000;
export const MAX_HTTP_ATTEMPTS = 3;
export const MAX_LRO_POLLS = 40;
export const MAX_LRO_BUDGET_MS = 5 * 60 * 1000;
export const MAX_RESPONSE_CHARS = 1_000_000;

const REDIRECT = new Set([301, 302, 303, 307, 308]);
const ARM_AUTHORIZATION_DENIAL = new Set(["AuthorizationFailed", "LinkedAuthorizationFailed"]);
const ARM_RULE_LIMIT_CODES = new Set([
  "toomanyfirewallrules",
  "firewallrulelimitexceeded",
  "maxfirewallruleslimitexceeded",
  "serverfirewallrulelimitexceeded",
  "maxnumberoffirewallrulesexceeded",
  "firewallrulequotaexceeded",
]);

interface OperationBudget {
  startedAtMs: number;
  sleptMs: number;
}

export interface ArmSuccess {
  ok: true;
  status: number;
  body: unknown;
  headers: Record<string, string>;
  requestId: string | null;
}

export interface ArmFailure {
  ok: false;
  error: WriterError;
  requestId: string | null;
}

export type ArmCall = ArmSuccess | ArmFailure;

export interface ArmClientOptions {
  transport: HttpTransport;
  tokenProvider: ArmTokenProvider;
  endpoint?: string;
  now?: () => Date;
  sleep?: (ms: number) => Promise<void>;
  /**
   * Controls inline 429/503 retries for GET and DELETE within the operation budget.
   * PUT is never retried inline on 429/503 so a delayed retry cannot recreate a rule after cleanup.
   */
  inlineThrottleRetry?: boolean;
  userAgent: string;
}

export class ArmClient {
  private readonly transport: HttpTransport;
  private readonly tokenProvider: ArmTokenProvider;
  readonly endpoint: string;
  private readonly now: () => Date;
  private readonly sleep: (ms: number) => Promise<void>;
  private readonly inlineThrottleRetry: boolean;
  private readonly userAgent: string;

  constructor(options: ArmClientOptions) {
    this.transport = options.transport;
    this.tokenProvider = options.tokenProvider;
    this.endpoint = (options.endpoint ?? "https://management.azure.com").replace(/\/$/, "");
    this.now = options.now ?? (() => new Date());
    this.sleep = options.sleep ?? defaultSleep;
    this.inlineThrottleRetry = options.inlineThrottleRetry ?? true;
    this.userAgent = options.userAgent;
  }

  async get(path: string, apiVersion: string): Promise<ArmCall> {
    return this.request("GET", this.resourceUrl(path, apiVersion), undefined, [200], this.startBudget(), false);
  }

  async getAbsolute(url: string): Promise<ArmCall> {
    if (sameOriginArmUrl(url, this.endpoint) === null) {
      return {
        ok: false,
        requestId: null,
        error: writerError({
          code: "unsafe_poll_url",
          message: "Refusing to follow a URL that is not an HTTPS URL on the ARM endpoint.",
        }),
      };
    }
    return this.request("GET", url, undefined, [200], this.startBudget(), false);
  }

  async put(path: string, apiVersion: string, body: unknown): Promise<ArmCall> {
    const budget = this.startBudget();
    const initial = await this.request(
      "PUT",
      this.resourceUrl(path, apiVersion),
      JSON.stringify(body),
      [200, 201, 202],
      budget,
      false,
    );
    if (!initial.ok || initial.status !== 202) {
      return initial;
    }
    return this.poll(initial, budget);
  }

  async delete(path: string, apiVersion: string): Promise<ArmCall> {
    const budget = this.startBudget();
    const initial = await this.request(
      "DELETE",
      this.resourceUrl(path, apiVersion),
      undefined,
      [200, 202, 204],
      budget,
      false,
    );
    if (!initial.ok || initial.status !== 202) {
      return initial;
    }
    return this.poll(initial, budget);
  }

  private startBudget(): OperationBudget {
    return { startedAtMs: this.now().getTime(), sleptMs: 0 };
  }

  private effectiveNowMs(budget: OperationBudget): number {
    return Math.max(this.now().getTime(), budget.startedAtMs + budget.sleptMs);
  }

  private remainingBudgetMs(budget: OperationBudget): number {
    const wallElapsed = Math.max(0, this.now().getTime() - budget.startedAtMs);
    const elapsed = Math.max(budget.sleptMs, wallElapsed);
    return Math.max(0, MAX_LRO_BUDGET_MS - elapsed);
  }

  private resourceUrl(path: string, apiVersion: string): string {
    const url = new URL(this.endpoint);
    url.pathname = path;
    url.searchParams.set("api-version", apiVersion);
    return url.toString();
  }

  private async poll(initial: ArmSuccess, budget: OperationBudget): Promise<ArmCall> {
    const pollTarget = operationUrl(initial.headers, this.endpoint);
    if (pollTarget.kind !== "url") {
      return {
        ok: false,
        requestId: initial.requestId,
        error: writerError({
          code: pollTarget.kind === "unsafe" ? "unsafe_poll_url" : "lro_malformed",
          message:
            pollTarget.kind === "unsafe"
              ? "Refusing to poll an operation URL that is not an HTTPS URL on the ARM endpoint."
              : "ARM returned 202 without an HTTPS Azure-AsyncOperation or Location URL on the ARM endpoint.",
          cloudStatus: 202,
          ruleApplied: true,
          removalVerified: false,
        }),
      };
    }
    const pollUrl = pollTarget.url;
    const source = pollTarget.source;
    let delay = pollDelayMs(initial.headers, this.effectiveNowMs(budget));
    const successStatuses = source === "location" ? [200, 201, 202, 204] : [200, 202];
    for (let poll = 0; poll < MAX_LRO_POLLS; poll += 1) {
      const remaining = this.remainingBudgetMs(budget);
      if (remaining <= 0) {
        break;
      }
      const wait = Math.min(delay, LRO_MAX_DELAY_MS, remaining);
      budget.sleptMs += wait;
      await this.sleep(wait);
      const status = await this.request("GET", pollUrl, undefined, successStatuses, budget, true);
      if (!status.ok) {
        return {
          ok: false,
          requestId: status.requestId ?? initial.requestId,
          error: indeterminateAfterAccepted(status.error),
        };
      }
      const state = lroState(status.body);
      delay = pollDelayMs(status.headers, this.effectiveNowMs(budget));
      if (state === "failed") {
        const cloud = readError(status.body);
        const specific =
          publicAccessDisabledError(status.status, cloud) ?? ruleLimitReachedError(status.status, cloud, null);
        return {
          ok: false,
          requestId: status.requestId,
          error:
            specific ??
            writerError({
              code: "lro_failed",
              message: escapeForOutput(cloud?.message ?? "The long-running operation failed."),
              cloudCode: safeCloudCode(cloud?.code ?? null),
              cloudStatus: status.status,
            }),
        };
      }
      if (state === "canceled") {
        return {
          ok: false,
          requestId: status.requestId,
          error: writerError({
            code: "lro_canceled",
            message: "The long-running operation was canceled.",
            cloudStatus: status.status,
          }),
        };
      }
      if (state === "succeeded" && status.status !== 202) {
        return status;
      }
      if (state === "inprogress" || status.status === 202) {
        continue;
      }
      return {
        ok: false,
        requestId: status.requestId ?? initial.requestId,
        error: writerError({
          code: "lro_malformed",
          message: "The long-running operation poll returned a non-202 response without a terminal operation status.",
          cloudStatus: status.status,
          ruleApplied: true,
          removalVerified: false,
        }),
      };
    }
    return {
      ok: false,
      requestId: initial.requestId,
      error: writerError({
        code: "lro_timeout",
        message: "The long-running operation did not finish before the poll budget.",
        retryable: true,
        cloudStatus: 202,
        ruleApplied: true,
        removalVerified: false,
      }),
    };
  }

  private async request(
    method: "GET" | "PUT" | "DELETE",
    url: string,
    body: string | undefined,
    success: number[],
    budget: OperationBudget,
    allowAuthRefresh: boolean,
  ): Promise<ArmCall> {
    let last: ArmCall | null = null;
    let authRefreshed = false;
    let forcedToken: string | null = null;
    for (let attempt = 1; attempt <= MAX_HTTP_ATTEMPTS; attempt += 1) {
      const token: string | ArmFailure = forcedToken ?? (await this.acquireToken(budget, false));
      forcedToken = null;
      if (typeof token !== "string") {
        return token;
      }
      let response;
      try {
        response = await this.transport.send({
          method,
          url,
          body,
          headers: {
            authorization: `Bearer ${token}`,
            accept: "application/json",
            "user-agent": this.userAgent,
            ...(body === undefined ? {} : { "content-type": "application/json" }),
          },
        });
      } catch (error) {
        const message = redact(error instanceof Error ? error.message : "transport failure", token);
        last = {
          ok: false,
          requestId: null,
          error: writerError({
            code: "transport",
            message,
            retryable: method === "GET",
          }),
        };
        if (method === "GET" && attempt < MAX_HTTP_ATTEMPTS) {
          continue;
        }
        return last;
      }
      const requestId = headerValue(response.headers, "x-ms-request-id") ?? null;
      if (REDIRECT.has(response.status)) {
        return {
          ok: false,
          requestId,
          error: writerError({
            code: "redirect_rejected",
            message: "ARM redirects are not followed.",
            cloudStatus: response.status,
          }),
        };
      }
      if (response.body.length > MAX_RESPONSE_CHARS) {
        return {
          ok: false,
          requestId,
          error: writerError({
            code: "cloud_response_invalid",
            message: "ARM response exceeded the size limit.",
            cloudStatus: response.status,
          }),
        };
      }
      if (response.status === 401 && allowAuthRefresh && !authRefreshed) {
        authRefreshed = true;
        const refreshed = await this.acquireToken(budget, true);
        if (typeof refreshed === "string" && refreshed !== token) {
          forcedToken = refreshed;
          attempt -= 1;
          continue;
        }
      }
      if (response.status === 429 || response.status === 503) {
        const parsedMs = retryAfterMs(response.headers, this.effectiveNowMs(budget));
        const delayMs = parsedMs === null || parsedMs <= 0 ? THROTTLE_DEFAULT_DELAY_MS : parsedMs;
        const retryAfterSeconds = Math.max(1, Math.ceil(delayMs / 1000));
        if (method !== "PUT" && this.inlineThrottleRetry && attempt < MAX_HTTP_ATTEMPTS) {
          const retryWait = Math.min(Math.max(delayMs, THROTTLE_DEFAULT_DELAY_MS), LRO_MAX_DELAY_MS);
          if (this.remainingBudgetMs(budget) >= retryWait) {
            budget.sleptMs += retryWait;
            await this.sleep(retryWait);
            continue;
          }
        }
        const parsed = parseBody(response.body);
        const cloud = readError(parsed.value);
        return {
          ok: false,
          requestId,
          error: classifyFailure(response.status, cloud, token, retryAfterSeconds),
        };
      }
      const parsed = parseBody(response.body);
      if (success.includes(response.status)) {
        if (parsed.jsonError && response.body.trim() !== "") {
          return {
            ok: false,
            requestId,
            error: writerError({
              code: "cloud_response_invalid",
              message: "ARM success response was not JSON.",
              cloudStatus: response.status,
            }),
          };
        }
        return {
          ok: true,
          status: response.status,
          body: parsed.value,
          headers: lowerHeaders(response.headers),
          requestId,
        };
      }
      const cloud = readError(parsed.value);
      return {
        ok: false,
        requestId,
        error: classifyFailure(response.status, cloud, token, null),
      };
    }
    return (
      last ?? {
        ok: false,
        requestId: null,
        error: writerError({ code: "transport", message: "ARM request was not sent." }),
      }
    );
  }

  private async acquireToken(budget: OperationBudget, forceRefresh: boolean): Promise<string | ArmFailure> {
    let token = await this.bearer(forceRefresh);
    if (typeof token !== "string") {
      return token;
    }
    const nowMs = this.effectiveNowMs(budget);
    const expMs = jwtExpMs(token);
    if (expMs !== null && expMs <= nowMs) {
      if (forceRefresh) {
        return {
          ok: false,
          requestId: null,
          error: writerError({
            code: "authentication_failed",
            message: "ARM bearer token is expired and could not be refreshed.",
          }),
        };
      }
      token = await this.bearer(true);
      if (typeof token !== "string") {
        return token;
      }
      const refreshedExpMs = jwtExpMs(token);
      if (refreshedExpMs !== null && refreshedExpMs <= this.effectiveNowMs(budget)) {
        return {
          ok: false,
          requestId: null,
          error: writerError({
            code: "authentication_failed",
            message: "ARM bearer token is expired and could not be refreshed.",
          }),
        };
      }
    }
    return token;
  }

  private async bearer(forceRefresh: boolean): Promise<string | ArmFailure> {
    let token: string;
    try {
      token = forceRefresh
        ? await this.tokenProvider.getToken({ forceRefresh: true })
        : await this.tokenProvider.getToken();
    } catch {
      return {
        ok: false,
        requestId: null,
        error: writerError({ code: "authentication_failed", message: "Token provider failed." }),
      };
    }
    if (typeof token !== "string" || token.length < 8 || token.length > 16_384 || !/^[A-Za-z0-9._~+/-]+=*$/.test(token)) {
      return {
        ok: false,
        requestId: null,
        error: writerError({ code: "authentication_failed", message: "Token is missing or has characters that cannot go in a header." }),
      };
    }
    return token;
  }
}

function defaultSleep(ms: number): Promise<void> {
  return new Promise((resolve) => {
    setTimeout(resolve, ms);
  });
}

function lowerHeaders(headers: Record<string, string>): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [key, value] of Object.entries(headers)) {
    out[key.toLowerCase()] = value;
  }
  return out;
}

function operationUrl(
  headers: Record<string, string>,
  endpoint: string,
): { kind: "url"; url: string; source: "async" | "location" } | { kind: "missing" } | { kind: "unsafe" } {
  const asyncOperation = headerValue(headers, "azure-asyncoperation");
  if (asyncOperation !== undefined && asyncOperation.trim() !== "") {
    const asyncUrl = resolvePollUrl(asyncOperation, endpoint);
    return asyncUrl !== null ? { kind: "url", url: asyncUrl, source: "async" } : { kind: "unsafe" };
  }
  const location = headerValue(headers, "location");
  if (location !== undefined && location.trim() !== "") {
    const locationUrl = resolvePollUrl(location, endpoint);
    return locationUrl !== null ? { kind: "url", url: locationUrl, source: "location" } : { kind: "unsafe" };
  }
  return { kind: "missing" };
}

function resolvePollUrl(candidate: string, endpoint: string): string | null {
  const trimmed = candidate.trim();
  if (trimmed === "") {
    return null;
  }
  const validated = sameOriginArmUrl(trimmed, endpoint);
  return validated === null ? null : validated.toString();
}

function retryAfterMs(headers: Record<string, string>, nowMs = Date.now()): number | null {
  const milliseconds = headerValue(headers, "retry-after-ms") ?? headerValue(headers, "x-ms-retry-after-ms");
  if (milliseconds !== undefined) {
    const trimmedMs = milliseconds.trim();
    if (/^[1-9][0-9]{0,8}$/.test(trimmedMs)) {
      return Number(trimmedMs);
    }
    if (trimmedMs === "0") {
      return 0;
    }
  }
  const raw = headerValue(headers, "retry-after");
  if (raw === undefined) {
    return null;
  }
  const trimmed = raw.trim();
  if (/^[1-9][0-9]{0,6}$/.test(trimmed)) {
    return Number(trimmed) * 1000;
  }
  if (trimmed === "0") {
    return 0;
  }
  const parsed = Date.parse(trimmed);
  if (!Number.isNaN(parsed)) {
    const delay = parsed - nowMs;
    return delay > 0 ? delay : 0;
  }
  return null;
}

function pollDelayMs(headers: Record<string, string>, nowMs: number): number {
  const parsed = retryAfterMs(headers, nowMs);
  if (parsed === null) {
    return LRO_DEFAULT_DELAY_MS;
  }
  return Math.min(Math.max(parsed, LRO_MIN_DELAY_MS), LRO_MAX_DELAY_MS);
}

function indeterminateAfterAccepted(error: WriterError): WriterError {
  return writerError({
    code: error.code,
    message: error.message,
    retryable: error.retryable,
    ruleApplied: true,
    removalVerified: false,
    authorizationDenial: error.authorizationDenial,
    cloudCode: error.cloudCode,
    cloudStatus: error.cloudStatus,
    retryAfterSeconds: error.retryAfterSeconds,
  });
}

function jwtExpMs(token: string): number | null {
  const parts = token.split(".");
  if (parts.length !== 3 || parts[1] === undefined || parts[1] === "") {
    return null;
  }
  try {
    const decoded = Buffer.from(parts[1], "base64url").toString("utf8");
    const payload = JSON.parse(decoded) as unknown;
    if (payload === null || typeof payload !== "object") {
      return null;
    }
    const exp = (payload as Record<string, unknown>).exp;
    if (typeof exp === "number" && Number.isFinite(exp)) {
      return exp * 1000;
    }
  } catch {
    return null;
  }
  return null;
}

function parseBody(body: string): { value: unknown; jsonError: boolean } {
  const trimmed = body.trim();
  if (trimmed === "") {
    return { value: null, jsonError: false };
  }
  try {
    return { value: JSON.parse(trimmed) as unknown, jsonError: false };
  } catch {
    return { value: null, jsonError: true };
  }
}

function readError(body: unknown): { code: string; message: string } | null {
  if (body === null || typeof body !== "object") {
    return null;
  }
  const record = body as Record<string, unknown>;
  const nested = record.error;
  if (nested !== null && typeof nested === "object") {
    const error = nested as Record<string, unknown>;
    const code = typeof error.code === "string" ? error.code : "";
    const message = typeof error.message === "string" ? error.message : "";
    if (code !== "" || message !== "") {
      return { code, message: message !== "" ? message : code };
    }
  }
  if (typeof record.code === "string") {
    return {
      code: record.code,
      message: typeof record.message === "string" ? record.message : record.code,
    };
  }
  return null;
}

type LroKind = "inprogress" | "succeeded" | "failed" | "canceled" | "unknown";

function lroState(body: unknown): LroKind {
  if (body === null || typeof body !== "object") {
    return "unknown";
  }
  const record = body as Record<string, unknown>;
  if (typeof record.status === "string") {
    const status = record.status.trim().toLowerCase();
    if (status === "succeeded") {
      return "succeeded";
    }
    if (status === "failed") {
      return "failed";
    }
    if (status === "canceled" || status === "cancelled") {
      return "canceled";
    }
    return "inprogress";
  }
  const properties = record.properties;
  if (properties !== null && typeof properties === "object") {
    const provisioning = (properties as Record<string, unknown>).provisioningState;
    if (typeof provisioning === "string") {
      const value = provisioning.trim().toLowerCase();
      if (value === "succeeded") {
        return "succeeded";
      }
      if (value === "failed") {
        return "failed";
      }
      if (value === "canceled" || value === "cancelled") {
        return "canceled";
      }
      return "inprogress";
    }
  }
  return "unknown";
}

/**
 * ARM rejects firewall writes when the server is not open to the public endpoint.
 * SQL publishes code DenyPublicEndpointEnabled:
 * https://learn.microsoft.com/en-us/rest/api/sql/firewall-rules/create-or-update?view=rest-sql-2021-11-01
 * The same sentence is Error 42101 in the connectivity docs (data plane).
 * PostgreSQL publishes the message and no code:
 * https://learn.microsoft.com/en-us/azure/postgresql/network/how-to-networking-servers-deployed-public-access-add-firewall-rules
 * az postgres flexible-server firewall-rule also raises, before ARM, when
 * network.publicNetworkAccess is Disabled (azure-cli postgresql/utils/validators.py
 * validate_public_access_server). That text is mapped if it arrives in an error body.
 * This function does not enable public access.
 */
function publicAccessDisabledError(
  status: number,
  cloud: { code: string; message: string } | null,
): WriterError | null {
  if (cloud === null || !publicAccessDisabled(cloud.code, cloud.message)) {
    return null;
  }
  const cloudCode = cloud.code === "" ? null : safeCloudCode(cloud.code);
  return writerError({
    code: "public_access_disabled",
    message: PUBLIC_ACCESS_DISABLED_MESSAGE,
    cloudCode,
    cloudStatus: status,
    authorizationDenial: false,
    retryable: false,
  });
}

function publicAccessDisabled(code: string, message: string): boolean {
  if (code === "DenyPublicEndpointEnabled") {
    return true;
  }
  const text = message.toLowerCase();
  return (
    text.includes("unable to create or modify firewall rules when public network interface") ||
    text.includes("firewall rule operations cannot be requested for a private access enabled server") ||
    text.includes("firewall rule operations are not supported for a server without public access enabled")
  );
}

function ruleLimitReachedError(
  status: number,
  cloud: { code: string; message: string } | null,
  token: string | null,
): WriterError | null {
  if (cloud === null || !ruleLimitReached(cloud.code, cloud.message)) {
    return null;
  }
  const cloudCode = cloud.code === "" ? null : safeCloudCode(cloud.code);
  const message =
    token === null
      ? escapeForOutput(cloud.message || "The server has reached its firewall rule limit.")
      : redact(cloud.message || "The server has reached its firewall rule limit.", token);
  return writerError({
    code: "rule_limit_reached",
    message,
    cloudCode,
    cloudStatus: status,
    authorizationDenial: false,
    retryable: false,
  });
}

function ruleLimitReached(code: string, message: string): boolean {
  if (code !== "" && ARM_RULE_LIMIT_CODES.has(code.toLowerCase())) {
    return true;
  }
  const text = message.toLowerCase();
  return (
    text.includes("firewall rules are over the limit") ||
    text.includes("maximum number of firewall rules") ||
    text.includes("too many firewall rules") ||
    text.includes("firewall rule limit") ||
    /\b256\b.*firewall rule|firewall rule.*\b256\b/.test(text)
  );
}

function safeCloudCode(code: string | null): string | null {
  if (code === null) {
    return null;
  }
  return /^[A-Za-z0-9.]{1,64}$/.test(code) ? code : "Unrecognized";
}

function classifyFailure(
  status: number,
  cloud: { code: string; message: string } | null,
  token: string,
  retryAfterSeconds: number | null,
): WriterError {
  const closed = publicAccessDisabledError(status, cloud);
  if (closed !== null) {
    return closed;
  }
  const limit = ruleLimitReachedError(status, cloud, token);
  if (limit !== null) {
    return limit;
  }
  const code = safeCloudCode(cloud?.code ?? null);
  const message = redact(cloud?.message ?? `ARM returned HTTP ${status}.`, token);
  if (code !== null && ARM_AUTHORIZATION_DENIAL.has(code)) {
    return writerError({
      code: "authorization_denied",
      message,
      authorizationDenial: true,
      cloudCode: code,
      cloudStatus: status,
    });
  }
  if (status === 401 || code === "InvalidAuthenticationToken" || code === "ExpiredAuthenticationToken") {
    return writerError({
      code: "authentication_failed",
      message,
      cloudCode: code,
      cloudStatus: status,
      authorizationDenial: false,
    });
  }
  if (status === 404 || code === "ResourceNotFound" || code === "ParentResourceNotFound") {
    return writerError({
      code: "not_found",
      message,
      cloudCode: code,
      cloudStatus: status,
      authorizationDenial: false,
    });
  }
  if (
    status === 502 ||
    code === "BadGateway" ||
    (cloud?.message.toLowerCase().includes("does not contain sufficient information to enforce access control policy") ?? false)
  ) {
    return writerError({
      code: "gateway_error",
      message,
      cloudCode: code,
      cloudStatus: status,
      authorizationDenial: false,
      retryable: false,
    });
  }
  if (status === 429 || status === 503 || code === "TooManyRequests" || code === "SubscriptionTooManyRequests") {
    return writerError({
      code: "throttled",
      message,
      cloudCode: code,
      cloudStatus: status,
      retryable: true,
      authorizationDenial: false,
      retryAfterSeconds: retryAfterSeconds ?? 1,
    });
  }
  if (status === 403) {
    return writerError({
      code: "cloud_forbidden",
      message,
      cloudCode: code,
      cloudStatus: status,
      authorizationDenial: false,
    });
  }
  if (code === "ConfirmationRequired") {
    return writerError({
      code: "confirmation_required",
      message,
      cloudCode: code,
      cloudStatus: status,
    });
  }
  return writerError({
    code: status >= 400 && status < 500 ? "cloud_rejected" : "transport",
    message,
    cloudCode: code,
    cloudStatus: status,
    authorizationDenial: false,
    retryable: status >= 500,
  });
}

function redact(message: string, token: string): string {
  const stripped = message.split(token).join("[redacted]").replace(/Bearer\s+\S+/gi, "Bearer [redacted]");
  return escapeForOutput(stripped);
}

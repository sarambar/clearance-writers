// Copyright 2026 Sarambar
// SPDX-License-Identifier: Apache-2.0

import { escapeForOutput } from "../codec.js";
import { writerError, type WriterError } from "../errors.js";
import { headerValue, sameOriginArmUrl, type ArmTokenProvider, type HttpTransport } from "./http.js";

/** azure-core's default polling interval when Retry-After is absent. */
export const LRO_DEFAULT_DELAY_MS = 30_000;
export const LRO_MAX_DELAY_MS = 30_000;
export const THROTTLE_DEFAULT_DELAY_MS = 1_000;
export const MAX_HTTP_ATTEMPTS = 3;
export const MAX_LRO_POLLS = 40;
export const MAX_LRO_BUDGET_MS = 5 * 60 * 1000;
export const MAX_RESPONSE_CHARS = 1_000_000;

const REDIRECT = new Set([301, 302, 303, 307, 308]);
const ARM_AUTHORIZATION_DENIAL = new Set(["AuthorizationFailed", "LinkedAuthorizationFailed"]);

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
  sleep?: (ms: number) => Promise<void>;
  userAgent: string;
}

export class ArmClient {
  private readonly transport: HttpTransport;
  private readonly tokenProvider: ArmTokenProvider;
  readonly endpoint: string;
  private readonly sleep: (ms: number) => Promise<void>;
  private readonly userAgent: string;

  constructor(options: ArmClientOptions) {
    this.transport = options.transport;
    this.tokenProvider = options.tokenProvider;
    this.endpoint = (options.endpoint ?? "https://management.azure.com").replace(/\/$/, "");
    this.sleep = options.sleep ?? defaultSleep;
    this.userAgent = options.userAgent;
  }

  async get(path: string, apiVersion: string): Promise<ArmCall> {
    return this.request("GET", this.resourceUrl(path, apiVersion), undefined, [200]);
  }

  async getAbsolute(url: string): Promise<ArmCall> {
    if (sameOriginArmUrl(url, this.endpoint) === null) {
      return {
        ok: false,
        requestId: null,
        error: writerError({
          code: "unsafe_poll_url",
          message: "Refusing to follow a URL that is not on the ARM endpoint.",
        }),
      };
    }
    return this.request("GET", url, undefined, [200]);
  }

  /**
   * PUT a named child. 200 and 201 are finished writes. 202 is polled.
   * A 202 without a same-origin operation URL is a failure, not a success.
   */
  async put(path: string, apiVersion: string, body: unknown): Promise<ArmCall> {
    const initial = await this.request("PUT", this.resourceUrl(path, apiVersion), JSON.stringify(body), [200, 201, 202]);
    if (!initial.ok || initial.status !== 202) {
      return initial;
    }
    return this.poll(initial, path, apiVersion);
  }

  /** DELETE a named child. 200 and 204 are finished. 202 is polled. 404 is returned as not_found. */
  async delete(path: string, apiVersion: string): Promise<ArmCall> {
    const initial = await this.request("DELETE", this.resourceUrl(path, apiVersion), undefined, [200, 202, 204]);
    if (!initial.ok || initial.status !== 202) {
      return initial;
    }
    return this.poll(initial, path, apiVersion);
  }

  private resourceUrl(path: string, apiVersion: string): string {
    const url = new URL(this.endpoint);
    url.pathname = path;
    url.searchParams.set("api-version", apiVersion);
    return url.toString();
  }

  private async poll(initial: ArmSuccess, _path: string, _apiVersion: string): Promise<ArmCall> {
    const pollTarget = operationUrl(initial.headers, this.endpoint);
    if (pollTarget.kind !== "url") {
      return {
        ok: false,
        requestId: initial.requestId,
        error: writerError({
          code: pollTarget.kind === "unsafe" ? "unsafe_poll_url" : "lro_malformed",
          message:
            pollTarget.kind === "unsafe"
              ? "Refusing to poll an operation URL that is not on the ARM endpoint."
              : "ARM returned 202 without a same-origin Azure-AsyncOperation or Location URL.",
          cloudStatus: 202,
          ruleApplied: false,
        }),
      };
    }
    const pollUrl = pollTarget.url;
    const source = pollTarget.source;
    let budget = 0;
    let delay = retryAfterMs(initial.headers) ?? LRO_DEFAULT_DELAY_MS;
    const successStatuses = source === "location" ? [200, 201, 202, 204] : [200, 202];
    for (let poll = 0; poll < MAX_LRO_POLLS; poll += 1) {
      const remaining = MAX_LRO_BUDGET_MS - budget;
      if (remaining <= 0) {
        break;
      }
      const wait = Math.min(delay, remaining);
      budget += wait;
      await this.sleep(wait);
      const status = await this.request("GET", pollUrl, undefined, successStatuses);
      if (!status.ok) {
        return status;
      }
      const state = lroState(status.body);
      delay = retryAfterMs(status.headers) ?? LRO_DEFAULT_DELAY_MS;
      if (state === "failed") {
        const cloud = readError(status.body);
        return {
          ok: false,
          requestId: status.requestId,
          error: writerError({
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
      if (state === "inprogress" || status.status === 202) {
        continue;
      }
      if (source === "async" && state === "succeeded") {
        return status;
      }
      if (source === "location" && (status.status === 200 || status.status === 201 || status.status === 204)) {
        return status;
      }
    }
    return {
      ok: false,
      requestId: initial.requestId,
      error: writerError({
        code: "lro_timeout",
        message: "The long-running operation did not finish before the poll budget.",
        retryable: true,
        cloudStatus: 202,
      }),
    };
  }

  private async request(
    method: "GET" | "PUT" | "DELETE",
    url: string,
    body: string | undefined,
    success: number[],
  ): Promise<ArmCall> {
    const token = await this.bearer();
    if (typeof token !== "string") {
      return token;
    }
    let last: ArmCall | null = null;
    for (let attempt = 1; attempt <= MAX_HTTP_ATTEMPTS; attempt += 1) {
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
      if ((response.status === 429 || response.status === 503) && attempt < MAX_HTTP_ATTEMPTS) {
        const delay = Math.min(retryAfterMs(response.headers) ?? THROTTLE_DEFAULT_DELAY_MS, LRO_MAX_DELAY_MS);
        await this.sleep(delay);
        continue;
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
        error: classifyFailure(response.status, cloud, token),
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

  private async bearer(): Promise<string | ArmFailure> {
    let token: string;
    try {
      token = await this.tokenProvider.getToken();
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
  const location = headerValue(headers, "location");
  const asyncUrl = resolvePollUrl(asyncOperation, endpoint);
  if (asyncUrl !== null) {
    return { kind: "url", url: asyncUrl, source: "async" };
  }
  const locationUrl = resolvePollUrl(location, endpoint);
  if (locationUrl !== null) {
    return { kind: "url", url: locationUrl, source: "location" };
  }
  const present = [asyncOperation, location].some((value) => value !== undefined && value.trim() !== "");
  return present ? { kind: "unsafe" } : { kind: "missing" };
}

function resolvePollUrl(candidate: string | undefined, endpoint: string): string | null {
  if (candidate === undefined || candidate.trim() === "") {
    return null;
  }
  let target: URL;
  try {
    target = new URL(candidate, endpoint.endsWith("/") ? endpoint : `${endpoint}/`);
  } catch {
    return null;
  }
  if (sameOriginArmUrl(target.toString(), endpoint) === null) {
    return null;
  }
  return target.toString();
}

function retryAfterMs(headers: Record<string, string>): number | null {
  const milliseconds = headerValue(headers, "retry-after-ms") ?? headerValue(headers, "x-ms-retry-after-ms");
  if (milliseconds !== undefined && /^[1-9][0-9]{0,8}$/.test(milliseconds.trim())) {
    return Number(milliseconds.trim());
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
    return null;
  }
  const parsed = Date.parse(trimmed);
  if (!Number.isNaN(parsed)) {
    const delay = parsed - Date.now();
    return delay > 0 ? delay : null;
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
    if (typeof error.code === "string") {
      return {
        code: error.code,
        message: typeof error.message === "string" ? error.message : error.code,
      };
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

type LroKind = "inprogress" | "succeeded" | "failed" | "canceled" | "resource" | "unknown";

function lroState(body: unknown): LroKind {
  if (body === null || typeof body !== "object") {
    return "unknown";
  }
  const record = body as Record<string, unknown>;
  const status = typeof record.status === "string" ? record.status.toLowerCase() : null;
  if (status === "succeeded") {
    return "succeeded";
  }
  if (status === "failed") {
    return "failed";
  }
  if (status === "canceled" || status === "cancelled") {
    return "canceled";
  }
  if (status === "inprogress" || status === "running" || status === "accepted" || status === "creating" || status === "deleting") {
    return "inprogress";
  }
  const properties = record.properties;
  if (properties !== null && typeof properties === "object") {
    const provisioning = (properties as Record<string, unknown>).provisioningState;
    if (typeof provisioning === "string") {
      const value = provisioning.toLowerCase();
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
    if (typeof (properties as Record<string, unknown>).startIpAddress === "string") {
      return "resource";
    }
  }
  return "unknown";
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
): WriterError {
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

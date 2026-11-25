// Copyright 2026 Sarambar
// SPDX-License-Identifier: Apache-2.0

export interface HttpRequest {
  method: "GET" | "PUT" | "DELETE";
  url: string;
  headers: Record<string, string>;
  body?: string;
  timeoutMs?: number;
}

export interface HttpResponse {
  status: number;
  headers: Record<string, string>;
  body: string;
}

export interface HttpTransport {
  send(request: HttpRequest): Promise<HttpResponse>;
}

export interface ArmTokenProvider {
  /** Returns the bearer token only. Do not include the "Bearer " prefix. */
  getToken(options?: { forceRefresh?: boolean }): Promise<string>;
}

export interface FetchLike {
  (input: string, init: RequestInit): Promise<Response>;
}

export function headerValue(headers: Record<string, string>, name: string): string | undefined {
  const target = name.toLowerCase();
  for (const [key, value] of Object.entries(headers)) {
    if (key.toLowerCase() === target) {
      return value;
    }
  }
  return undefined;
}

export const DEFAULT_HTTP_TIMEOUT_MS = 30_000;

/**
 * Production transport. Redirects are not followed: a 3xx is returned to the
 * caller, which rejects it. A hung socket is aborted.
 */
export function createFetchTransport(fetchImpl: FetchLike = globalThis.fetch, timeoutMs = DEFAULT_HTTP_TIMEOUT_MS): HttpTransport {
  return {
    async send(request: HttpRequest): Promise<HttpResponse> {
      const effectiveTimeoutMs =
        request.timeoutMs !== undefined && Number.isFinite(request.timeoutMs) && request.timeoutMs > 0
          ? Math.min(timeoutMs, request.timeoutMs)
          : timeoutMs;
      const response = await fetchImpl(request.url, {
        method: request.method,
        headers: request.headers,
        body: request.body,
        redirect: "manual",
        signal: AbortSignal.timeout(effectiveTimeoutMs),
      });
      const headers: Record<string, string> = {};
      response.headers.forEach((value, key) => {
        headers[key.toLowerCase()] = value;
      });
      return {
        status: response.status,
        headers,
        body: await response.text(),
      };
    },
  };
}

export function sameOriginArmUrl(candidate: string, endpoint: string): URL | null {
  let base: URL;
  let target: URL;
  try {
    base = new URL(endpoint);
    target = new URL(candidate);
  } catch {
    return null;
  }
  if (target.username !== "" || target.password !== "") {
    return null;
  }
  if (base.protocol !== "https:" || target.protocol !== "https:") {
    return null;
  }
  if (target.host !== base.host) {
    return null;
  }
  if (!target.pathname.startsWith("/subscriptions/")) {
    return null;
  }
  return target;
}

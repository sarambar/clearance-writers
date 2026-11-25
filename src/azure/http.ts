// Copyright 2026 Sarambar
// SPDX-License-Identifier: Apache-2.0

export interface HttpRequest {
  method: "GET" | "PUT" | "DELETE";
  url: string;
  headers: Record<string, string>;
  body?: string;
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
  getToken(): Promise<string>;
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
      const response = await fetchImpl(request.url, {
        method: request.method,
        headers: request.headers,
        body: request.body,
        redirect: "manual",
        signal: AbortSignal.timeout(timeoutMs),
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
  if (target.protocol !== "https:" && target.protocol !== "http:") {
    return null;
  }
  if (target.protocol !== base.protocol || target.host !== base.host) {
    return null;
  }
  if (!target.pathname.startsWith("/subscriptions/")) {
    return null;
  }
  return target;
}

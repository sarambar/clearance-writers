// Copyright 2026 Sarambar
// SPDX-License-Identifier: Apache-2.0

import { displayAzureLocation } from "../location.js";
import { parseIpv4, ipv4ToInt } from "../ip.js";
import type { HttpRequest, HttpResponse, HttpTransport } from "./http.js";
import {
  AZURE_POSTGRES_FIREWALL_PROFILE,
  AZURE_SQL_FIREWALL_PROFILE,
  parseAzureParentId,
  type AzureChildFirewallProfile,
  type ParsedParent,
} from "./profiles.js";

export interface FakeRule {
  name: string;
  startIpv4: string;
  endIpv4: string;
}

export interface FakeServerSeed {
  resourceId: string;
  /** Normalized or display location. Stored and returned in display form. */
  location: string;
  publicNetworkAccess?: "Enabled" | "Disabled";
  delegatedSubnet?: boolean;
  rules?: FakeRule[];
  /** Defaults to sync for SQL and async for PostgreSQL, matching the SDKs. */
  lro?: "sync" | "async";
}

interface StoredServer {
  profile: AzureChildFirewallProfile;
  parent: ParsedParent;
  locationNormalized: string;
  publicNetworkAccess: "Enabled" | "Disabled";
  delegatedSubnet: boolean;
  rules: Map<string, FakeRule>;
  lro: "sync" | "async";
}

interface PendingOperation {
  remainingPolls: number;
  action: "put" | "delete";
  serverKey: string;
  ruleName: string;
  startIpv4: string;
  endIpv4: string;
}

interface FailureRule {
  method?: string;
  pathIncludes?: string;
  status: number;
  code: string | null;
  message: string;
  remaining: number;
}

const NAME_PATTERN = /^[0-9A-Za-z_-]{1,128}$/;

/**
 * In-memory ARM stand-in. It rejects malformed requests instead of guessing,
 * overwrites a named rule on PUT (real ARM behavior), and does not treat a
 * confirmation prompt as success. It is not live Azure.
 */
export class FakeArm implements HttpTransport {
  readonly requests: HttpRequest[] = [];
  readonly pageSize: number;
  private readonly servers = new Map<string, StoredServer>();
  private readonly operations = new Map<string, PendingOperation>();
  private readonly failures: FailureRule[] = [];
  private operationCounter = 1;

  constructor(options?: { pageSize?: number }) {
    this.pageSize = options?.pageSize ?? 2;
  }

  seedServer(seed: FakeServerSeed): void {
    const profile = profileForResourceId(seed.resourceId);
    if (profile === null) {
      throw new Error("FakeArm.seedServer requires a SQL or PostgreSQL parent resource id.");
    }
    const parsed = parseAzureParentId(profile, seed.resourceId);
    if (!parsed.ok) {
      throw new Error(parsed.error.message);
    }
    const locationNormalized = seed.location.trim().toLowerCase().replace(/[\s_-]+/g, "");
    const rules = new Map<string, FakeRule>();
    for (const rule of seed.rules ?? []) {
      const start = parseIpv4(rule.startIpv4);
      const end = parseIpv4(rule.endIpv4);
      if (start === null || end === null) {
        throw new Error("Seeded firewall rule addresses must be dotted IPv4.");
      }
      rules.set(rule.name.toLowerCase(), { name: rule.name, startIpv4: start, endIpv4: end });
    }
    this.servers.set(parsed.value.canonicalId, {
      profile,
      parent: parsed.value,
      locationNormalized,
      publicNetworkAccess: seed.publicNetworkAccess ?? "Enabled",
      delegatedSubnet: seed.delegatedSubnet ?? false,
      rules,
      lro: seed.lro ?? profile.lro,
    });
  }

  /** Subsequent matching calls return this ARM error and do not mutate. */
  failMatching(
    match: { method?: string; pathIncludes?: string },
    error: { status: number; code?: string | null; message: string },
    times = Number.POSITIVE_INFINITY,
  ): void {
    this.failures.push({
      method: match.method,
      pathIncludes: match.pathIncludes,
      status: error.status,
      code: error.code ?? null,
      message: error.message,
      remaining: times,
    });
  }

  rulesFor(resourceId: string): FakeRule[] | null {
    const server = this.servers.get(resourceId);
    if (server === undefined) {
      return null;
    }
    return [...server.rules.values()];
  }

  async send(request: HttpRequest): Promise<HttpResponse> {
    this.requests.push({
      method: request.method,
      url: request.url,
      body: request.body,
      headers: { ...request.headers },
    });
    return this.dispatch(request);
  }

  private dispatch(request: HttpRequest): HttpResponse {
    let url: URL;
    try {
      url = new URL(request.url);
    } catch {
      return armError(400, "InvalidResourceId", "The resource id is malformed.");
    }
    if (!authorizationOk(request.headers)) {
      return armError(401, "InvalidAuthenticationToken", "Authentication failed.");
    }
    if (url.searchParams.get("confirm") === "prompt" || header(request.headers, "x-ms-confirmation") === "prompt") {
      return armError(
        400,
        "ConfirmationRequired",
        "Unable to prompt for confirmation as no tty available. Use --yes.",
      );
    }
    const failure = this.matchFailure(request, url);
    if (failure !== null) {
      return failure;
    }
    const apiVersion = url.searchParams.get("api-version");
    if (apiVersion === null || apiVersion.trim() === "") {
      return armError(400, "MissingApiVersionParameter", "The api-version query parameter (?api-version=) is required for all requests.");
    }
    const segments = decodeSegments(url.pathname);
    if (segments === null) {
      return armError(400, "InvalidResourceId", "The resource id is malformed.");
    }
    if (isOperation(segments)) {
      return this.pollOperation(segments, apiVersion);
    }
    const located = this.locate(segments);
    if (!located.ok) {
      return located.response;
    }
    if (apiVersion !== located.server.profile.apiVersion) {
      return armError(
        400,
        "InvalidApiVersionParameter",
        `The api-version '${apiVersion}' is invalid. The supported version is '${located.server.profile.apiVersion}'.`,
      );
    }
    if (request.method === "DELETE" && url.searchParams.has("id")) {
      return armError(400, "BadArgument", "the following arguments are required: --name/-n");
    }
    if (located.kind === "parent" && request.method === "GET") {
      return json(200, parentResource(located.server));
    }
    if (located.kind === "parent") {
      return armError(405, "MethodNotAllowed", "The method is not allowed on this resource.");
    }
    if (located.kind === "collection" && request.method === "GET") {
      return this.listRules(located.server, url, apiVersion);
    }
    if (located.kind === "collection" && request.method === "PUT") {
      return this.replaceAll(located.server, request);
    }
    if (located.kind === "collection" && request.method === "DELETE") {
      return armError(400, "BadArgument", "the following arguments are required: --name/-n");
    }
    const ruleName = located.ruleName ?? "";
    if (request.method === "GET") {
      return this.getRule(located.server, ruleName);
    }
    if (request.method === "DELETE") {
      return this.deleteRule(located.server, ruleName, url);
    }
    if (request.method === "PUT") {
      return this.putRule(located.server, ruleName, request, url);
    }
    return armError(405, "MethodNotAllowed", "The method is not allowed.");
  }

  private matchFailure(request: HttpRequest, url: URL): HttpResponse | null {
    for (const rule of this.failures) {
      if (rule.remaining <= 0) {
        continue;
      }
      if (rule.method !== undefined && rule.method !== request.method) {
        continue;
      }
      if (rule.pathIncludes !== undefined && !url.pathname.includes(rule.pathIncludes)) {
        continue;
      }
      rule.remaining -= 1;
      return armError(rule.status, rule.code, rule.message);
    }
    return null;
  }

  private locate(
    segments: string[],
  ):
    | { ok: true; server: StoredServer; kind: "parent" | "collection" | "child"; ruleName?: string }
    | { ok: false; response: HttpResponse } {
    if (
      segments.length < 8 ||
      segments[0]?.toLowerCase() !== "subscriptions" ||
      segments[2]?.toLowerCase() !== "resourcegroups" ||
      segments[4]?.toLowerCase() !== "providers"
    ) {
      return { ok: false, response: armError(400, "InvalidResourceId", "The resource id is malformed.") };
    }
    const subscription = segments[1]?.toLowerCase() ?? "";
    const group = segments[3]?.toLowerCase() ?? "";
    const namespace = segments[5] ?? "";
    const parentType = segments[6] ?? "";
    const serverName = segments[7]?.toLowerCase() ?? "";
    const profile = profileFor(namespace, parentType);
    if (profile === null) {
      return { ok: false, response: armError(404, "NoRegisteredProviderFound", "The resource provider was not found.") };
    }
    if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(subscription)) {
      return { ok: false, response: armError(400, "InvalidSubscriptionId", "The subscription id is not a GUID.") };
    }
    const canonicalId = `/subscriptions/${subscription}/resourceGroups/${group}/providers/${profile.providerNamespace}/${profile.parentType}/${serverName}`;
    const server = this.servers.get(canonicalId);
    if (server === undefined) {
      return { ok: false, response: armError(404, "ResourceNotFound", "The server was not found.") };
    }
    if (segments.length === 8) {
      return { ok: true, server, kind: "parent" };
    }
    if (segments[8]?.toLowerCase() !== "firewallrules") {
      return { ok: false, response: armError(404, "ResourceNotFound", "The resource type was not found.") };
    }
    if (segments.length === 9) {
      return { ok: true, server, kind: "collection" };
    }
    if (segments.length === 10) {
      return { ok: true, server, kind: "child", ruleName: segments[9] };
    }
    return { ok: false, response: armError(400, "InvalidResourceId", "The resource id has too many segments.") };
  }

  private listRules(server: StoredServer, url: URL, apiVersion: string): HttpResponse {
    const skipRaw = url.searchParams.get("skip") ?? "0";
    if (!/^(0|[1-9][0-9]*)$/.test(skipRaw)) {
      return armError(400, "InvalidResourceId", "The skip token is malformed.");
    }
    const skip = Number(skipRaw);
    const rules = [...server.rules.values()];
    const page = rules.slice(skip, skip + this.pageSize);
    const body: { value: unknown[]; nextLink?: string } = {
      value: page.map((rule) => ruleResource(server, rule)),
    };
    if (skip + this.pageSize < rules.length) {
      const next = new URL(url);
      next.searchParams.set("api-version", apiVersion);
      next.searchParams.set("skip", String(skip + this.pageSize));
      body.nextLink = next.toString();
    }
    return json(200, body);
  }

  private getRule(server: StoredServer, ruleName: string): HttpResponse {
    const nameError = validateCloudName(server, ruleName);
    if (nameError !== null) {
      return nameError;
    }
    const rule = server.rules.get(ruleName.toLowerCase());
    if (rule === undefined) {
      return armError(404, "ResourceNotFound", "The firewall rule was not found.");
    }
    return json(200, ruleResource(server, rule));
  }

  private putRule(server: StoredServer, ruleName: string, request: HttpRequest, url: URL): HttpResponse {
    const nameError = validateCloudName(server, ruleName);
    if (nameError !== null) {
      return nameError;
    }
    const contentType = header(request.headers, "content-type");
    if (contentType === undefined || !contentType.toLowerCase().startsWith("application/json")) {
      return armError(415, "UnsupportedMediaType", "Content-Type must be application/json.");
    }
    const parsed = parseJson(request.body);
    if (!parsed.ok) {
      return armError(400, "InvalidJson", "The request body is not valid JSON.");
    }
    const addresses = readAddresses(parsed.value);
    if (!addresses.ok) {
      return addresses.response;
    }
    if (server.publicNetworkAccess === "Disabled" || server.delegatedSubnet) {
      return privateAccessError(server);
    }
    const key = ruleName.toLowerCase();
    const exists = server.rules.has(key);
    if (!exists && server.profile.ruleCap !== null && server.rules.size >= server.profile.ruleCap) {
      return armError(400, "TooManyFirewallRules", "The provided firewall rules are over the limit.");
    }
    if (server.lro === "async") {
      const id = String(this.operationCounter);
      this.operationCounter += 1;
      this.operations.set(id, {
        remainingPolls: 2,
        action: "put",
        serverKey: server.parent.canonicalId,
        ruleName,
        startIpv4: addresses.start,
        endIpv4: addresses.end,
      });
      return accepted(server, url, id);
    }
    server.rules.set(key, { name: ruleName, startIpv4: addresses.start, endIpv4: addresses.end });
    const stored = server.rules.get(key);
    return json(exists ? 200 : 201, ruleResource(server, stored ?? { name: ruleName, startIpv4: addresses.start, endIpv4: addresses.end }));
  }

  private deleteRule(server: StoredServer, ruleName: string, url: URL): HttpResponse {
    const nameError = validateCloudName(server, ruleName);
    if (nameError !== null) {
      return nameError;
    }
    const key = ruleName.toLowerCase();
    if (!server.rules.has(key)) {
      return armError(404, "ResourceNotFound", "The firewall rule was not found.");
    }
    if (server.lro === "async") {
      const id = String(this.operationCounter);
      this.operationCounter += 1;
      this.operations.set(id, {
        remainingPolls: 2,
        action: "delete",
        serverKey: server.parent.canonicalId,
        ruleName,
        startIpv4: "",
        endIpv4: "",
      });
      return accepted(server, url, id);
    }
    server.rules.delete(key);
    return json(204, null);
  }

  private replaceAll(server: StoredServer, request: HttpRequest): HttpResponse {
    const parsed = parseJson(request.body);
    if (!parsed.ok) {
      return armError(400, "InvalidJson", "The request body is not valid JSON.");
    }
    const record = asRecord(parsed.value);
    const values = record?.values;
    if (!Array.isArray(values)) {
      return armError(400, "InvalidServerFirewallRuleResourceParameters", "Replacing the collection requires a values array.");
    }
    const next = new Map<string, FakeRule>();
    for (const item of values) {
      const itemRecord = asRecord(item);
      const name = itemRecord?.name;
      const addresses = readAddresses(item);
      if (typeof name !== "string" || !addresses.ok) {
        return armError(400, "InvalidServerFirewallRuleResourceParameters", "A replacement rule is malformed.");
      }
      const nameError = validateCloudName(server, name);
      if (nameError !== null) {
        return nameError;
      }
      next.set(name.toLowerCase(), { name, startIpv4: addresses.start, endIpv4: addresses.end });
    }
    if (server.profile.ruleCap !== null && next.size > server.profile.ruleCap) {
      return armError(400, "TooManyFirewallRules", "The provided firewall rules are over the limit.");
    }
    server.rules.clear();
    for (const [key, rule] of next) {
      server.rules.set(key, rule);
    }
    return json(200, { values: [...server.rules.values()].map((rule) => ruleResource(server, rule)) });
  }

  private pollOperation(segments: string[], apiVersion: string): HttpResponse {
    const id = segments[7];
    if (id === undefined) {
      return armError(404, "ResourceNotFound", "The operation was not found.");
    }
    const operation = this.operations.get(id);
    if (operation === undefined) {
      return armError(404, "ResourceNotFound", "The operation was not found.");
    }
    const server = this.servers.get(operation.serverKey);
    if (server === undefined) {
      return armError(404, "ResourceNotFound", "The server was not found.");
    }
    if (apiVersion !== server.profile.apiVersion) {
      return armError(400, "InvalidApiVersionParameter", "The api-version is invalid for this operation.");
    }
    operation.remainingPolls -= 1;
    if (operation.remainingPolls > 0) {
      return json(200, { status: "InProgress" });
    }
    if (operation.action === "put") {
      server.rules.set(operation.ruleName.toLowerCase(), {
        name: operation.ruleName,
        startIpv4: operation.startIpv4,
        endIpv4: operation.endIpv4,
      });
    } else {
      server.rules.delete(operation.ruleName.toLowerCase());
    }
    this.operations.delete(id);
    return json(200, { status: "Succeeded" });
  }
}

function profileForResourceId(resourceId: string): AzureChildFirewallProfile | null {
  if (resourceId.toLowerCase().includes("/providers/microsoft.sql/servers/")) {
    return AZURE_SQL_FIREWALL_PROFILE;
  }
  if (resourceId.toLowerCase().includes("/providers/microsoft.dbforpostgresql/flexibleservers/")) {
    return AZURE_POSTGRES_FIREWALL_PROFILE;
  }
  return null;
}

function profileFor(namespace: string, parentType: string): AzureChildFirewallProfile | null {
  if (namespace.toLowerCase() === "microsoft.sql" && parentType.toLowerCase() === "servers") {
    return AZURE_SQL_FIREWALL_PROFILE;
  }
  if (namespace.toLowerCase() === "microsoft.dbforpostgresql" && parentType.toLowerCase() === "flexibleservers") {
    return AZURE_POSTGRES_FIREWALL_PROFILE;
  }
  return null;
}

function isOperation(segments: string[]): boolean {
  return (
    segments.length === 8 &&
    segments[0]?.toLowerCase() === "subscriptions" &&
    segments[2]?.toLowerCase() === "providers" &&
    segments[4]?.toLowerCase() === "locations" &&
    segments[6]?.toLowerCase() === "operationresults"
  );
}

function accepted(server: StoredServer, requestUrl: URL, operationId: string): HttpResponse {
  const operation = new URL(requestUrl.origin);
  operation.pathname = `/subscriptions/${server.parent.subscriptionId}/providers/${server.profile.providerNamespace}/locations/${server.locationNormalized}/operationResults/${operationId}`;
  operation.searchParams.set("api-version", server.profile.apiVersion);
  const ruleUrl = requestUrl.toString();
  return {
    status: 202,
    headers: {
      "content-type": "application/json",
      "azure-asyncoperation": operation.toString(),
      location: ruleUrl,
      "retry-after": "0",
      "x-ms-request-id": "00000000-0000-0000-0000-000000000000",
    },
    body: "",
  };
}

function validateCloudName(server: StoredServer, name: string): HttpResponse | null {
  if (name.length === 0) {
    return armError(400, "FirewallRuleNameEmpty", "The provided firewall rule name is empty.");
  }
  if (name.length > 128) {
    return armError(400, "FirewallRuleNameTooLong", "The provided firewall rule name is too long.");
  }
  if (name.length < server.profile.cloudRuleNameMin || !NAME_PATTERN.test(name)) {
    return armError(400, "FirewallRuleNameInvalid", "The provided firewall rule name contains special characters.");
  }
  return null;
}

function readAddresses(
  body: unknown,
): { ok: true; start: string; end: string } | { ok: false; response: HttpResponse } {
  const record = asRecord(body);
  const properties = asRecord(record?.properties);
  const startRaw = properties?.startIpAddress;
  const endRaw = properties?.endIpAddress;
  if (typeof startRaw !== "string" || typeof endRaw !== "string") {
    return {
      ok: false,
      response: armError(400, "InvalidServerFirewallRuleResourceParameters", "startIpAddress and endIpAddress are required."),
    };
  }
  const start = parseIpv4(startRaw);
  const end = parseIpv4(endRaw);
  if (start === null || end === null) {
    return { ok: false, response: armError(400, "FirewallRuleNotIPv4Address", "The provided firewall rule address is not IPv4.") };
  }
  if (ipv4ToInt(start) > ipv4ToInt(end)) {
    return { ok: false, response: armError(400, "FirewallRuleInvalidRange", "The specified firewall rule range is invalid.") };
  }
  return { ok: true, start, end };
}

function privateAccessError(server: StoredServer): HttpResponse {
  // SQL: REST Firewall Rules - Create Or Update, 400 DenyPublicEndpointEnabled.
  // https://learn.microsoft.com/en-us/rest/api/sql/firewall-rules/create-or-update?view=rest-sql-2021-11-01
  if (server.profile.id === AZURE_SQL_FIREWALL_PROFILE.id) {
    return armError(
      400,
      "DenyPublicEndpointEnabled",
      "Unable to create or modify firewall rules when public network interface for the server is disabled. To manage server or database level firewall rules, please enable the public network interface.",
    );
  }
  // PostgreSQL Flexible Server publishes this message and no error code.
  // https://learn.microsoft.com/en-us/azure/postgresql/network/how-to-networking-servers-deployed-public-access-add-firewall-rules
  return armError(400, null, "Firewall rule operations cannot be requested for a private access enabled server.");
}

function ruleResource(server: StoredServer, rule: FakeRule): unknown {
  return {
    id: `${server.parent.canonicalId}/firewallRules/${rule.name}`,
    name: rule.name,
    type: `${server.profile.providerNamespace}/${server.profile.parentType}/firewallRules`,
    properties: {
      startIpAddress: rule.startIpv4,
      endIpAddress: rule.endIpv4,
    },
  };
}

function parentResource(server: StoredServer): unknown {
  const delegated =
    "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-example/providers/Microsoft.Network/virtualNetworks/example/subnets/example";
  const properties: Record<string, unknown> =
    server.profile.id === AZURE_SQL_FIREWALL_PROFILE.id
      ? {
          publicNetworkAccess: server.publicNetworkAccess,
          ...(server.delegatedSubnet ? { network: { delegatedSubnetResourceId: delegated } } : {}),
        }
      : {
          network: {
            publicNetworkAccess: server.publicNetworkAccess,
            ...(server.delegatedSubnet ? { delegatedSubnetResourceId: delegated } : {}),
          },
        };
  return {
    id: server.parent.canonicalId,
    name: server.parent.parentName,
    type: `${server.profile.providerNamespace}/${server.profile.parentType}`,
    location: displayAzureLocation(server.locationNormalized),
    properties,
  };
}

function decodeSegments(pathname: string): string[] | null {
  const raw = pathname.split("/").filter((part) => part.length > 0);
  const decoded: string[] = [];
  for (const part of raw) {
    let value = part;
    if (part.includes("%")) {
      try {
        value = decodeURIComponent(part);
      } catch {
        return null;
      }
    }
    if (value.includes("/") || value.includes("\\") || value.includes("..") || value.includes("%")) {
      return null;
    }
    decoded.push(value);
  }
  return decoded;
}

function authorizationOk(headers: Record<string, string>): boolean {
  const value = header(headers, "authorization");
  if (value === undefined || !value.startsWith("Bearer ")) {
    return false;
  }
  return value.slice("Bearer ".length).trim().length > 0;
}

function header(headers: Record<string, string>, name: string): string | undefined {
  const target = name.toLowerCase();
  for (const [key, value] of Object.entries(headers)) {
    if (key.toLowerCase() === target) {
      return value;
    }
  }
  return undefined;
}

function parseJson(body: string | undefined): { ok: true; value: unknown } | { ok: false } {
  if (body === undefined || body.trim() === "") {
    return { ok: false };
  }
  try {
    return { ok: true, value: JSON.parse(body) as unknown };
  } catch {
    return { ok: false };
  }
}

function asRecord(value: unknown): Record<string, unknown> | null {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    return null;
  }
  return value as Record<string, unknown>;
}

function json(status: number, body: unknown): HttpResponse {
  return {
    status,
    headers: {
      "content-type": "application/json",
      "x-ms-request-id": "00000000-0000-0000-0000-000000000000",
    },
    body: body === null ? "" : JSON.stringify(body),
  };
}

function armError(status: number, code: string | null, message: string): HttpResponse {
  const error: Record<string, string> = { message };
  if (code !== null && code !== "") {
    error.code = code;
  }
  return json(status, { error });
}

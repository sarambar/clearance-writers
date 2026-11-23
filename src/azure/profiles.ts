// Copyright 2026 Sarambar
// SPDX-License-Identifier: Apache-2.0

import { escapeForOutput } from "../codec.js";
import { writerError, type WriterError } from "../errors.js";

/**
 * API versions are the defaults of the management SDKs pinned by Azure CLI 2.93:
 * azure-mgmt-sql 5.0.0b2 and azure-mgmt-postgresqlflexibleservers 3.0.0b3.
 */
export const AZURE_SQL_FIREWALL_API_VERSION = "2026-08-01-preview";
export const AZURE_POSTGRES_FIREWALL_API_VERSION = "2026-07-01-preview";

export const SQL_RULE_CAP = 256;

export interface CliFlagPin {
  /** Full command the REST call is modeled on. This package does not shell out. */
  command: string;
  resourceGroupFlags: readonly string[];
  serverFlags: readonly string[];
  ruleFlags: readonly string[];
  startIpFlag: "--start-ip-address";
  endIpFlag: "--end-ip-address";
  /** Flags that must not be used to name the server. Lesson 8. */
  serverMustNotUse: readonly string[];
}

export interface AzureChildFirewallProfile {
  id: string;
  cloud: "azure";
  listShape: "child-resource";
  providerNamespace: string;
  parentType: string;
  childType: "firewallRules";
  apiVersion: string;
  serverNamePattern: RegExp;
  serverNameMin: number;
  serverNameMax: number;
  ruleCap: number | null;
  deleteGuard: "none" | "refuse-last-rule";
  /** Cloud-side minimum. Clearance names are longer than either minimum. */
  cloudRuleNameMin: number;
  permissions: readonly string[];
  cli: CliFlagPin;
  /** Parent read lists database names on SQL. Null when there is no such note. */
  knownReadExposure: string | null;
  propagationSeconds: number;
}

export const AZURE_SQL_FIREWALL_ACTIONS = [
  "Microsoft.Sql/servers/read",
  "Microsoft.Sql/servers/firewallRules/read",
  "Microsoft.Sql/servers/firewallRules/write",
  "Microsoft.Sql/servers/firewallRules/delete",
] as const;

export const AZURE_POSTGRES_FIREWALL_ACTIONS = [
  "Microsoft.DBforPostgreSQL/flexibleServers/read",
  "Microsoft.DBforPostgreSQL/flexibleServers/firewallRules/read",
  "Microsoft.DBforPostgreSQL/flexibleServers/firewallRules/write",
  "Microsoft.DBforPostgreSQL/flexibleServers/firewallRules/delete",
] as const;

const SQL_SERVER_NAME = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
const POSTGRES_SERVER_NAME = /^[a-z0-9]+(?:-[a-z0-9]+)*$/;

export const AZURE_SQL_FIREWALL_PROFILE: AzureChildFirewallProfile = {
  id: "azure-sql-server-firewall",
  cloud: "azure",
  listShape: "child-resource",
  providerNamespace: "Microsoft.Sql",
  parentType: "servers",
  childType: "firewallRules",
  apiVersion: AZURE_SQL_FIREWALL_API_VERSION,
  serverNamePattern: SQL_SERVER_NAME,
  serverNameMin: 1,
  serverNameMax: 63,
  ruleCap: SQL_RULE_CAP,
  deleteGuard: "none",
  cloudRuleNameMin: 1,
  permissions: AZURE_SQL_FIREWALL_ACTIONS,
  knownReadExposure:
    "Microsoft.Sql/servers/read can list database names on the server. That is metadata, not data-plane access. Do not add databases/read or a database login.",
  propagationSeconds: 5 * 60,
  cli: {
    command: "az sql server firewall-rule",
    resourceGroupFlags: ["--resource-group", "-g"],
    serverFlags: ["--server", "-s"],
    ruleFlags: ["--name", "-n"],
    startIpFlag: "--start-ip-address",
    endIpFlag: "--end-ip-address",
    serverMustNotUse: ["--server-name", "-n"],
  },
};

export const AZURE_POSTGRES_FIREWALL_PROFILE: AzureChildFirewallProfile = {
  id: "azure-postgres-flexible-firewall",
  cloud: "azure",
  listShape: "child-resource",
  providerNamespace: "Microsoft.DBforPostgreSQL",
  parentType: "flexibleServers",
  childType: "firewallRules",
  apiVersion: AZURE_POSTGRES_FIREWALL_API_VERSION,
  serverNamePattern: POSTGRES_SERVER_NAME,
  serverNameMin: 3,
  serverNameMax: 63,
  ruleCap: null,
  deleteGuard: "none",
  cloudRuleNameMin: 3,
  permissions: AZURE_POSTGRES_FIREWALL_ACTIONS,
  knownReadExposure: null,
  propagationSeconds: 5 * 60,
  cli: {
    command: "az postgres flexible-server firewall-rule",
    resourceGroupFlags: ["--resource-group", "-g"],
    serverFlags: ["--server-name", "-s"],
    ruleFlags: ["--name", "-n"],
    startIpFlag: "--start-ip-address",
    endIpFlag: "--end-ip-address",
    serverMustNotUse: ["-n", "--rule-name"],
  },
};

export interface UnimplementedService {
  id: string;
  implemented: false;
  reason: string;
  deleteGuard: "none" | "refuse-last-rule";
  permissions: readonly string[];
  cliNote: string;
}

/**
 * Seams only. No writer is constructed for these. MySQL flag names differ from
 * PostgreSQL (`--name` is the server, `--rule-name` is the rule). Classic Redis
 * must refuse to delete the last rule. Synapse is a later adapter.
 */
export const UNIMPLEMENTED_SERVICES: readonly UnimplementedService[] = [
  {
    id: "azure-mysql-flexible-firewall",
    implemented: false,
    reason: "Same child-resource model as PostgreSQL Flexible Server. Not implemented.",
    deleteGuard: "none",
    permissions: [
      "Microsoft.DBforMySQL/flexibleServers/read",
      "Microsoft.DBforMySQL/flexibleServers/firewallRules/read",
      "Microsoft.DBforMySQL/flexibleServers/firewallRules/write",
      "Microsoft.DBforMySQL/flexibleServers/firewallRules/delete",
    ],
    cliNote:
      "az mysql flexible-server firewall-rule uses --name for the server and --rule-name for the rule. Do not reuse the PostgreSQL --server-name / --name pair.",
  },
  {
    id: "azure-redis-classic-firewall",
    implemented: false,
    reason:
      "Classic Microsoft.Cache/redis only. An empty rule list with public access enabled opens the cache, so delete must refuse the last rule. Managed Redis (Microsoft.Cache/redisEnterprise) is a different API and is out of scope.",
    deleteGuard: "refuse-last-rule",
    permissions: [
      "Microsoft.Cache/redis/read",
      "Microsoft.Cache/redis/firewallRules/read",
      "Microsoft.Cache/redis/firewallRules/write",
      "Microsoft.Cache/redis/firewallRules/delete",
    ],
    cliNote: "az redis firewall-rules uses --name for the cache and --rule-name for the rule, with --start-ip and --end-ip.",
  },
  {
    id: "azure-synapse-workspace-firewall",
    implemented: false,
    reason: "Workspace child-resource firewall. Not implemented. A workspace rule covers every public endpoint on that workspace.",
    deleteGuard: "none",
    permissions: [
      "Microsoft.Synapse/workspaces/read",
      "Microsoft.Synapse/workspaces/firewallRules/read",
      "Microsoft.Synapse/workspaces/firewallRules/write",
      "Microsoft.Synapse/workspaces/firewallRules/delete",
    ],
    cliNote: "az synapse workspace firewall-rule uses --workspace-name for the workspace and --name for the rule.",
  },
];

export interface ParsedParent {
  canonicalId: string;
  subscriptionId: string;
  resourceGroup: string;
  serverName: string;
}

const GUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const RESOURCE_GROUP = /^[a-z0-9_().-]{1,90}$/;

export function parseAzureParentId(
  profile: AzureChildFirewallProfile,
  resourceId: string,
): { ok: true; value: ParsedParent } | { ok: false; error: WriterError } {
  if (resourceId.includes("?") || resourceId.includes("#")) {
    return { ok: false, error: writerError({ code: "invalid_resource_id", message: "Resource id must not contain a query or fragment." }) };
  }
  const parts = resourceId.split("/");
  if (parts.length !== 9 || parts[0] !== "") {
    return { ok: false, error: writerError({ code: "invalid_resource_id", message: `Resource id ${escapeForOutput(resourceId)} is not a parent resource.` }) };
  }
  const [, subscriptions, subscriptionId, resourceGroups, resourceGroup, providers, namespace, parentType, serverName] = parts;
  if (
    subscriptions?.toLowerCase() !== "subscriptions" ||
    resourceGroups?.toLowerCase() !== "resourcegroups" ||
    providers?.toLowerCase() !== "providers" ||
    namespace?.toLowerCase() !== profile.providerNamespace.toLowerCase() ||
    parentType?.toLowerCase() !== profile.parentType.toLowerCase()
  ) {
    return {
      ok: false,
      error: writerError({
        code: "invalid_resource_id",
        message: `Resource id is not a ${profile.providerNamespace}/${profile.parentType} parent.`,
      }),
    };
  }
  const subscription = (subscriptionId ?? "").toLowerCase();
  const group = (resourceGroup ?? "").toLowerCase();
  const server = (serverName ?? "").toLowerCase();
  if (!GUID.test(subscription)) {
    return { ok: false, error: writerError({ code: "invalid_resource_id", message: "Subscription id is not a GUID." }) };
  }
  if (!RESOURCE_GROUP.test(group) || group === "." || group === ".." || group.includes("..") || group.endsWith(".")) {
    return { ok: false, error: writerError({ code: "invalid_resource_id", message: "Resource group name is not allowed." }) };
  }
  if (server.length < profile.serverNameMin || server.length > profile.serverNameMax || !profile.serverNamePattern.test(server)) {
    return { ok: false, error: writerError({ code: "invalid_resource_id", message: "Server name is not allowed for this service." }) };
  }
  const canonicalId = `/subscriptions/${subscription}/resourceGroups/${group}/providers/${profile.providerNamespace}/${profile.parentType}/${server}`;
  return {
    ok: true,
    value: { canonicalId, subscriptionId: subscription, resourceGroup: group, serverName: server },
  };
}

export function parentPath(profile: AzureChildFirewallProfile, parent: ParsedParent): string {
  return `/subscriptions/${parent.subscriptionId}/resourceGroups/${parent.resourceGroup}/providers/${profile.providerNamespace}/${profile.parentType}/${parent.serverName}`;
}

export function collectionPath(profile: AzureChildFirewallProfile, parent: ParsedParent): string {
  return `${parentPath(profile, parent)}/${profile.childType}`;
}

export function childPath(profile: AzureChildFirewallProfile, parent: ParsedParent, ruleName: string): string {
  return `${collectionPath(profile, parent)}/${ruleName}`;
}

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
  command: string;
  resourceGroupFlags: readonly string[];
  serverFlags: readonly string[];
  ruleFlags: readonly string[];
  startIpFlag: string;
  endIpFlag: string;
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
  lro: "sync" | "async";
  cloudRuleNameMin: number;
  permissions: readonly string[];
  cli: CliFlagPin;
  knownReadExposure: string | null;
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
  lro: "sync",
  cloudRuleNameMin: 1,
  permissions: AZURE_SQL_FIREWALL_ACTIONS,
  knownReadExposure:
    "Microsoft.Sql/servers/read returns administratorLogin and can list database names. It does not return the administrator password. Do not add databases/read or a database login.",
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
  lro: "async",
  cloudRuleNameMin: 3,
  permissions: AZURE_POSTGRES_FIREWALL_ACTIONS,
  knownReadExposure:
    "Microsoft.DBforPostgreSQL/flexibleServers/read returns administratorLogin. It does not return the administrator password. Do not grant flexibleServers/write or a database login.",
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
  listShape: "child-resource" | "whole-list";
  reason: string;
  deleteGuard: "none" | "refuse-last-rule";
  permissions: readonly string[];
  cli: CliFlagPin | null;
}

export const UNIMPLEMENTED_SERVICES: readonly UnimplementedService[] = [
  {
    id: "azure-mysql-flexible-firewall",
    implemented: false,
    listShape: "child-resource",
    reason: "Same child-resource model as PostgreSQL Flexible Server. Not implemented. Do not copy the PostgreSQL flag pair.",
    deleteGuard: "none",
    permissions: [
      "Microsoft.DBforMySQL/flexibleServers/read",
      "Microsoft.DBforMySQL/flexibleServers/firewallRules/read",
      "Microsoft.DBforMySQL/flexibleServers/firewallRules/write",
      "Microsoft.DBforMySQL/flexibleServers/firewallRules/delete",
    ],
    cli: {
      command: "az mysql flexible-server firewall-rule",
      resourceGroupFlags: ["--resource-group", "-g"],
      serverFlags: ["--name"],
      ruleFlags: ["--rule-name"],
      startIpFlag: "--start-ip-address",
      endIpFlag: "--end-ip-address",
      serverMustNotUse: ["--server-name", "--rule-name"],
    },
  },
  {
    id: "azure-redis-classic-firewall",
    implemented: false,
    listShape: "child-resource",
    reason:
      "Classic Microsoft.Cache/redis only. An empty rule list with public access enabled opens the cache, so delete must refuse the last rule. Managed Redis (Microsoft.Cache/redisEnterprise) is a different API and is out of scope. Not implemented.",
    deleteGuard: "refuse-last-rule",
    permissions: [
      "Microsoft.Cache/redis/read",
      "Microsoft.Cache/redis/firewallRules/read",
      "Microsoft.Cache/redis/firewallRules/write",
      "Microsoft.Cache/redis/firewallRules/delete",
    ],
    cli: {
      command: "az redis firewall-rules",
      resourceGroupFlags: ["--resource-group", "-g"],
      serverFlags: ["--name"],
      ruleFlags: ["--rule-name"],
      startIpFlag: "--start-ip",
      endIpFlag: "--end-ip",
      serverMustNotUse: ["--server-name", "--start-ip-address"],
    },
  },
  {
    id: "azure-synapse-workspace-firewall",
    implemented: false,
    listShape: "child-resource",
    reason: "Workspace child-resource firewall. Not implemented. A workspace rule covers every public endpoint on that workspace.",
    deleteGuard: "none",
    permissions: [
      "Microsoft.Synapse/workspaces/read",
      "Microsoft.Synapse/workspaces/firewallRules/read",
      "Microsoft.Synapse/workspaces/firewallRules/write",
      "Microsoft.Synapse/workspaces/firewallRules/delete",
    ],
    cli: {
      command: "az synapse workspace firewall-rule",
      resourceGroupFlags: ["--resource-group", "-g"],
      serverFlags: ["--workspace-name"],
      ruleFlags: ["--name", "-n"],
      startIpFlag: "--start-ip-address",
      endIpFlag: "--end-ip-address",
      serverMustNotUse: ["--server-name", "--name"],
    },
  },
  {
    id: "azure-key-vault-network-acl",
    implemented: false,
    listShape: "whole-list",
    reason: "Network ACLs are a property of the vault. A future adapter implements FirewallWriter and merges inside add and remove. Not this child-resource class.",
    deleteGuard: "none",
    permissions: [],
    cli: null,
  },
  {
    id: "azure-storage-network-acl",
    implemented: false,
    listShape: "whole-list",
    reason: "IP rules live on the storage account. A future adapter merges inside add and remove. Not this child-resource class.",
    deleteGuard: "none",
    permissions: [],
    cli: null,
  },
  {
    id: "aws-security-group",
    implemented: false,
    listShape: "whole-list",
    reason: "An AWS adapter implements the same four FirewallWriter operations. It does not speak ARM.",
    deleteGuard: "none",
    permissions: [],
    cli: null,
  },
];

export interface ParsedParent {
  canonicalId: string;
  subscriptionId: string;
  resourceGroup: string;
  parentName: string;
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
    value: { canonicalId, subscriptionId: subscription, resourceGroup: group, parentName: server },
  };
}

export function parentPath(profile: AzureChildFirewallProfile, parent: ParsedParent): string {
  return `/subscriptions/${parent.subscriptionId}/resourceGroups/${parent.resourceGroup}/providers/${profile.providerNamespace}/${profile.parentType}/${parent.parentName}`;
}

export function collectionPath(profile: AzureChildFirewallProfile, parent: ParsedParent): string {
  return `${parentPath(profile, parent)}/${profile.childType}`;
}

export function childPath(profile: AzureChildFirewallProfile, parent: ParsedParent, ruleName: string): string {
  return `${collectionPath(profile, parent)}/${ruleName}`;
}

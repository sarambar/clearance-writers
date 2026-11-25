# clearance-writers

**Status: UNTESTED against live Azure.**

This package has been exercised with a strict in-memory ARM fake and unit tests only. No call in this repository has been run against a live Azure subscription. A green CI run is not a real-cloud test. Do not describe SQL or PostgreSQL firewall behavior from this package as tested until a separate real-Azure run says so.

Apache-2.0. The package is the inspectable writer Sarambar Clearance uses to add and remove temporary firewall rules in a customer Azure subscription. Authentication, tenant checks, the ledger, the TTL sweeper, and audit storage live in the private backend. This repository does not issue credentials, store customer data, or schedule cleanup.

## What it does

Callers use four operations. The shape does not change per cloud:

| Operation | Meaning |
| --- | --- |
| `addRule` | Add one allow entry. A repeat of the same Clearance name and address is a success and does not write again. A different address on that name is refused. |
| `removeRule` | Remove one Clearance-named entry. A missing rule is a success. The delete is not finished until a following read shows the rule gone. |
| `listOwnedRules` | Rules whose names pass the Clearance name allowlist. |
| `readWholeList` | Every rule the cloud returned, owned and not owned. Reads do not write. |

`listOwnedRules` is not permission to delete. `removeRule` also requires `ledgerOwned: true`, which the private backend may set only after the ledger has a verified add for that exact resource and name. A name that merely starts with `clearance-` is not ownership.

Azure SQL and PostgreSQL Flexible Server are child resources. The adapter PUTs or DELETEs one named `firewallRules` child. It never PUTs the collection, which on SQL replaces every rule. A later whole-list cloud (Key Vault, Storage, an AWS security group that must be rewritten) implements the same four methods and does the merge inside the adapter.

Implemented adapters:

- Azure SQL logical server firewall, modeled on `az sql server firewall-rule`.
- Azure Database for PostgreSQL Flexible Server firewall, modeled on `az postgres flexible-server firewall-rule`.

Not implemented, and not safe to call: MySQL Flexible Server, classic Azure Cache for Redis, Azure Synapse workspace firewall, Managed Redis, Key Vault. Classic Redis must refuse to delete the last rule, because an empty list with public access enabled opens the cache. That guard exists on the profile and is covered by a unit test. There is no Redis writer.

## Azure permissions

Assign the custom role at the server, or at that server's resource group. Do not assign it at a management group. Do not grant Owner, Contributor, or the parent `write` action. `DataActions` is empty. The Clearance identity must not get a database login.

`Microsoft.Sql/servers/read` can list database names on that server and returns `administratorLogin`. `Microsoft.DBforPostgreSQL/flexibleServers/read` also returns `administratorLogin`. Neither read returns the administrator password. This is metadata, not data-plane access. Do not add a database login or a parent `write`.

The JSON files in `roles/` are the role definitions. `{subscriptionId}` is a placeholder, not an account id. Narrow `AssignableScopes` to the resource group when the definition is created.

### Azure SQL logical server

`roles/azure-sql-firewall.json`

- `Microsoft.Sql/servers/read`
- `Microsoft.Sql/servers/firewallRules/read`
- `Microsoft.Sql/servers/firewallRules/write`
- `Microsoft.Sql/servers/firewallRules/delete`

ARM API version `2026-08-01-preview`, the default of `azure-mgmt-sql` 5.0.0b2, which Azure CLI 2.93 pins. Create and delete are synchronous in that SDK (`200`/`201` and `200`/`204`). A `202` is polled rather than treated as a finished rule.

CLI flags this REST call corresponds to: `--resource-group`/`-g`, `--server`/`-s`, `--name`/`-n`, `--start-ip-address`, `--end-ip-address`. The server flag is not `--server-name` and not `-n`.

Server-level cap used by the adapter: 256 rules, counted before create (`rule_cap_exceeded`). If ARM rejects a create with HTTP 400 and code `TooManyFirewallRules` (or the documented "firewall rules are over the limit" message), the error is mapped to `rule_limit_reached`. HTTP 429, 503, and other 5xx responses stay `throttled` or transport failures and are treated as maybe-applied. Delete is not refused because of the cap. Official docs describe up to a five-minute firewall cache after a change. Control-plane absence is not "closed at".

### PostgreSQL Flexible Server

`roles/azure-postgres-flexible-firewall.json`

- `Microsoft.DBforPostgreSQL/flexibleServers/read`
- `Microsoft.DBforPostgreSQL/flexibleServers/firewallRules/read`
- `Microsoft.DBforPostgreSQL/flexibleServers/firewallRules/write`
- `Microsoft.DBforPostgreSQL/flexibleServers/firewallRules/delete`

ARM API version `2026-07-01-preview`, the default of `azure-mgmt-postgresqlflexibleservers` 3.0.0b3, which Azure CLI 2.93 pins. Create and delete are long-running. The adapter polls `Azure-AsyncOperation` (or a same-origin `Location`) until the operation succeeds, fails, or the poll budget ends, and then reads the rule back.

The SDK treats a non-202 create response as an error. This package also accepts `200` and `201` when the body is already the firewall rule, because those are completed ARM responses. Failing them would hide a rule that exists. This difference is untested against live Azure.

CLI flags: `--resource-group`/`-g`, `--server-name`/`-s`, `--name`/`-n`, `--start-ip-address`, `--end-ip-address`. `-n` is the rule, not the server. MySQL Flexible Server is different again (`--name` is the server, `--rule-name` is the rule) and is not implemented.

No firewall-rule cap is documented for PostgreSQL Flexible Server here, and none is invented. A server with public network access disabled, or a delegated subnet, is refused with `public_access_disabled`. The same code is used when ARM returns SQL `DenyPublicEndpointEnabled` or the PostgreSQL message that firewall rules cannot be requested for a private-access server. The writers do not enable public access. Official docs describe up to a five-minute propagation window.

Creating a rule whose name already exists updates that rule in place on Azure. This package reads first and refuses when the stored address or the stored name casing differs. There is no `If-Match` on these resources. A rule created by someone else in the gap between the read and the PUT can still be overwritten. Unguessable names are the mitigation. That race is a residual, and it is untested live.

## Address, name, and TTL rules

The default policy accepts one public IPv4 host. RFC 5737 documentation ranges (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`) are refused, the same as other non-public space: private, loopback, link-local, shared address space, multicast, and the reserved block. Tests that need a placeholder address set `allowDocumentationRanges` to `true`. A string or any other non-boolean does not turn the flag on. Production callers leave it false.

`0.0.0.0` (Allow Azure services, including other customers) and `0.0.0.0/0` are refused unless the caller passes an explicit policy that turns on `allowAzureServicesRule` or `allowDefaultRoute`. The Clearance default does not. Hyphen ranges are refused. IPv6 is refused. The adapter writes Azure `startIpAddress` and `endIpAddress`. For one host they are equal.

Rule names match `clearance-` plus 8 to 118 characters from `[0-9A-Za-z_-]`, 128 characters maximum. `AllowAllAzureIPs` and `AllowAllWindowsAzureIps` are refused. Resource ids are allowlisted per adapter. Control characters, zero-width characters, and non-NFC text are refused.

TTL is an integer number of seconds from 1 to 3600. `inf`, fractions, and strings are refused. This package does not schedule expiry. The private backend's sweeper must call `removeRule`. The exposure bound the hand-run requires is TTL plus the sweep interval (`exposureBoundSeconds`). Cleanup is not blocked by the rule cap.

## Provenance

Every audit event includes:

- `writersVersion`, the `version` in `package.json` (currently `0.0.0`)
- `writersCommitSha`, from the environment variable `CLEARANCE_WRITERS_COMMIT_SHA`

The private backend sets that variable to the full commit it actually deployed: 40 or 64 lowercase hex characters. A missing, short, or malformed value is the literal `unknown`. An operation cannot supply a SHA and have it recorded as this package's commit.

An intent event with `outcome: succeeded` means the attempt was recorded. It does not mean Azure finished the change. The result event is the one that records success or failure.

`contentHash` is SHA-256 of the canonical JSON body. The body does not include `contentHash`. A backend chain is:

```text
event_hash = SHA-256(prev_hash concatenated with the canonical body)
```

`auditEventHash` computes that. The genesis prev-hash is 64 zeros (`AUDIT_GENESIS_HASH`). This package does not store the chain. If the audit sink rejects the intent event, an add is not sent. If a remove's intent event is rejected, the delete still runs. If the result event is rejected after a successful add, the result is a failure with `ruleApplied: true` so the sweeper can remove the rule.

## Threat-model summary

The trust boundary that matters here is the writer to the customer subscription. The code is public on purpose. There is no security through obscurity in how a rule is added or deleted.

What this package enforces:

- Least privilege is the role above. It cannot stop a broader role someone assigns anyway.
- It will not delete a rule whose name fails the Clearance allowlist.
- It will not send `0.0.0.0` or a broad range under the default policy.
- It will not follow an ARM `nextLink`, `Location`, or `Azure-AsyncOperation` URL onto another host or over non-HTTPS, and the HTTP transport does not follow redirects.
- `PUT` requests are never retried inline on HTTP `429`/`503` (even when `inlineThrottleRetry` is omitted or `true`) so a delayed retry cannot recreate a rule after cleanup. `GET` and `DELETE` may retry inline within the operation budget when `inlineThrottleRetry` is enabled.
- It classifies `AuthorizationFailed` and `LinkedAuthorizationFailed` as authorization denials. `BadGateway`, including the message about insufficient information to enforce access control policy, is not a denial. An empty list is an empty list, not a denial.
- It does not open a database connection and does not hold a data-plane credential.

What this package does not enforce, because those controls are not in this repository:

- Who the caller is, which tenant the subscription belongs to, or whether the ledger actually owns the name.
- Rate limits, the kill switch, and the sweeper clock.
- The five-minute data-plane cache. SQL error 40615 and a PostgreSQL connection timeout are different block signals. `classifyReachability` keeps them apart. `login-succeeded` on a post-delete probe means the path is still open. During the cache window that can happen after a successful control-plane delete.
- A signature on the published release. Pin a commit. Do not pin a floating tag.

A name collision between the read and the PUT, a rule that outlives its TTL because Azure or the sweeper is down, and a stolen backend identity that already holds the custom role remain residual risks. They are not closed by this library.

## Hand-run lessons encoded here

| # | What the tests lock |
| --- | --- |
| 1 | A destructive call that would prompt fails the fake and does not change rules. The writer never sends a confirmation flag. |
| 2 | `Central US` and `centralus` compare equal only after normalization. The fake returns display form. |
| 3 | SQL 40615 is a firewall block. A SQL timeout is a tool error. A PostgreSQL timeout is a firewall block. PostgreSQL does not reuse 40615. |
| 4 | TTL must be an integer in range. `inf` and non-numbers are refused before any ARM call. |
| 5 | Delete success is a later read that shows the rule gone, not the delete status by itself. |
| 6 | The fake rejects a missing or wrong `api-version` and malformed JSON. Live Azure is still UNTESTED. |
| 7 | Exposure is TTL plus the sweep interval. Remove is idempotent and is not blocked by the SQL cap. |
| 8 | SQL uses `--server`. PostgreSQL uses `--server-name`. Neither uses `-n` as the server flag. |
| 9 | Failures are `WriterError` values with an operator line. They are not mixed into a success value. |
| 10 | Authorization checks require `AuthorizationFailed` or `LinkedAuthorizationFailed`. `BadGateway` and an empty list do not pass. |
| 11 | Role-definition delete is not performed here. The recorded az shape requires `--name` and `--scope`. An id-only firewall delete is rejected by the fake. |

## Live smoke

This is a manual run on a machine that already has `az login`. It is not part of CI. The script exits immediately when `CI` or `GITHUB_ACTIONS` is set. It does not create a service principal, and it does not write a password or an access token to disk.

It creates one resource group, `rg-clearance-smoke-<random>`, tagged `purpose=clearance-smoke` and `created-by=live-smoke`. Inside that group:

- An Azure SQL logical server with Microsoft Entra-only authentication and public network access enabled. The signed-in user is the Entra admin. No SQL password is set, and no database is created, so there is no SQL compute SKU. Create passes `--enable-public-network true`. The script then runs `az sql server update --enable-public-network true`, prints `publicNetworkAccess`, and stops before any firewall rule if the value is not `Enabled`.
- An Azure Database for PostgreSQL Flexible Server, Burstable `Standard_B1ms`, 32 GiB (the minimum), public network access on, and password authentication disabled. The signed-in user is the Entra admin. No password is generated or printed. Create uses `--public-access Enabled`. In current Azure CLI, `None` sets public network access to Disabled and adds no rule, so firewall commands are rejected. `Enabled` turns public access on and does not add a client-IP or allow-all rule. The script updates with the same flag, prints `network.publicNetworkAccess`, and stops before any firewall rule if the value is not `Enabled`.

B1ms is the smallest flexible-server SKU. The cost of a run is that server for as long as it exists, plus the time to provision it. Provisioning is usually 10–20 minutes, most of it the PostgreSQL server. The script deletes the group on exit, including after an error or Ctrl-C. If the group is left behind, the flexible server keeps billing until the group is deleted.

A `trap` runs `az group delete --yes --no-wait` and then checks that the group is gone or deleting. The script prints the same manual command before it creates anything:

```bash
az login
SUBSCRIPTION_ID="<subscription-guid>" scripts/live-smoke.sh
```

`LOCATION` defaults to `centralus`. The script refuses to run when the active `az` subscription is different from `SUBSCRIPTION_ID`. It reads the runner's public IPv4 from `https://api.ipify.org` and asks the writers to allow that one host, then remove it. A foreign rule named `office-vpn` is created with `az` and must still be there at the end. Output is a PASS/FAIL table and the audit events' package version and commit SHA.

Requires Node.js 22, Azure CLI, curl, openssl, and git. From the repo after `npm ci`:

```bash
SUBSCRIPTION_ID="<subscription-guid>" LOCATION=centralus scripts/live-smoke.sh
```

`zsh scripts/live-smoke.sh` runs the same script. If teardown does not finish, use the `az group delete --name rg-clearance-smoke-... --subscription <subscription-guid> --yes --no-wait` line the script printed.

## Development

Node.js 22 or newer. No runtime dependencies. ARM is called with `fetch`.

```bash
npm ci
npm run lint
npm run typecheck
npm test
```

CI runs those three and does not publish. Set `CLEARANCE_WRITERS_COMMIT_SHA` in the deploying environment. Tests and fixtures use `example.com` only as a non-Azure host, documentation addresses, and the all-zero subscription GUID.

## License

Apache License 2.0. See `LICENSE`.

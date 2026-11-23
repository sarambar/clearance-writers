#!/usr/bin/env bash
# Live smoke for clearance-writers. Runs under bash or zsh.
# Uses the current `az login`. Does not store a service principal or a password.
# Refuses to run in CI.

if [ -n "${ZSH_VERSION:-}" ]; then
  setopt pipefail
else
  set -o pipefail
fi
set -eu

if [ -n "${GITHUB_ACTIONS:-}" ] || [ "${CI:-}" = "true" ] || [ -n "${GITLAB_CI:-}" ] || [ "${TF_BUILD:-}" = "True" ] || [ -n "${BUILDKITE:-}" ]; then
  printf '%s\n' "live-smoke refuses to run in CI" >&2
  exit 1
fi

if [ -z "${SUBSCRIPTION_ID:-}" ]; then
  printf '%s\n' "SUBSCRIPTION_ID is required. LOCATION defaults to centralus." >&2
  exit 1
fi

LOCATION="${LOCATION:-centralus}"
case "$SUBSCRIPTION_ID" in
  *[!0-9a-fA-F-]*) printf '%s\n' "SUBSCRIPTION_ID is not a GUID." >&2; exit 1 ;;
esac
case "$LOCATION" in
  *[!a-z0-9]*) printf '%s\n' "LOCATION must be an Azure name such as centralus, with no spaces." >&2; exit 1 ;;
esac

for cmd in az curl openssl npm git; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    printf '%s\n' "Required command not found: $cmd" >&2
    exit 1
  fi
done

active="$(az account show --query id --output tsv)"
if [ "$active" != "$SUBSCRIPTION_ID" ]; then
  printf '%s\n' "The active az subscription does not match SUBSCRIPTION_ID. Refusing to change subscription." >&2
  exit 1
fi

script_path="$0"
if [ -n "${BASH_SOURCE:-}" ]; then
  script_path="${BASH_SOURCE[0]}"
fi
root="$(cd "$(dirname "$script_path")/.." && pwd)"
suffix="$(openssl rand -hex 4)"
RG="rg-clearance-smoke-${suffix}"
SQL_NAME="sqlsmoke${suffix}"
PG_NAME="pgsmoke${suffix}"
RULE_NAME="clearance-smoke${suffix}"
FOREIGN_RULE="office-vpn"
FOREIGN_IP="198.51.100.20"
RG_CREATED=0
CLEANED=0

cleanup() {
  exit_status=$?
  if [ "$CLEANED" = "1" ]; then
    exit "$exit_status"
  fi
  CLEANED=1
  unset ARM_ACCESS_TOKEN || true
  if [ "$RG_CREATED" != "1" ]; then
    exit "$exit_status"
  fi
  printf '%s\n' "Deleting resource group ${RG}."
  az group delete --name "$RG" --subscription "$SUBSCRIPTION_ID" --yes --no-wait --only-show-errors || true
  attempt=0
  while [ "$attempt" -lt 6 ]; do
    attempt=$((attempt + 1))
    if ! az group show --name "$RG" --subscription "$SUBSCRIPTION_ID" --output none >/dev/null 2>&1; then
      printf '%s\n' "Resource group ${RG} is gone."
      exit "$exit_status"
    fi
    state="$(az group show --name "$RG" --subscription "$SUBSCRIPTION_ID" --query properties.provisioningState --output tsv 2>/dev/null || true)"
    if [ "$state" = "Deleting" ]; then
      printf '%s\n' "Resource group ${RG} is deleting."
      exit "$exit_status"
    fi
    sleep 5
  done
  printf '%s\n' "Resource group ${RG} is still present. Manual cleanup: az group delete --name ${RG} --subscription ${SUBSCRIPTION_ID} --yes --no-wait" >&2
  exit "$exit_status"
}

trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

printf '%s\n' "Manual cleanup: az group delete --name ${RG} --subscription ${SUBSCRIPTION_ID} --yes --no-wait"

public_ip="$(curl -4 -fsS --max-time 20 https://api.ipify.org)"
case "$public_ip" in
  *[!0-9.]*) printf '%s\n' "api.ipify.org did not return an IPv4 address." >&2; exit 1 ;;
esac
printf '%s\n' "Runner public IPv4: ${public_ip}"

admin_id="$(az ad signed-in-user show --query id --output tsv)"
admin_name="$(az ad signed-in-user show --query userPrincipalName --output tsv)"
if [ -z "$admin_id" ] || [ -z "$admin_name" ]; then
  printf '%s\n' "az login must be a user account. A service principal cannot be the Entra admin for this smoke." >&2
  exit 1
fi

az group create \
  --name "$RG" \
  --location "$LOCATION" \
  --subscription "$SUBSCRIPTION_ID" \
  --tags purpose=clearance-smoke created-by=live-smoke \
  --only-show-errors \
  --output none
RG_CREATED=1

az sql server create \
  --name "$SQL_NAME" \
  --resource-group "$RG" \
  --location "$LOCATION" \
  --subscription "$SUBSCRIPTION_ID" \
  --enable-ad-only-auth \
  --enable-public-network true \
  --external-admin-principal-type User \
  --external-admin-name "$admin_name" \
  --external-admin-sid "$admin_id" \
  --only-show-errors \
  --output none

az postgres flexible-server create \
  --resource-group "$RG" \
  --name "$PG_NAME" \
  --location "$LOCATION" \
  --subscription "$SUBSCRIPTION_ID" \
  --tier Burstable \
  --sku-name Standard_B1ms \
  --storage-size 32 \
  --version 16 \
  --backup-retention 7 \
  --geo-redundant-backup Disabled \
  --public-access None \
  --microsoft-entra-auth Enabled \
  --password-auth Disabled \
  --admin-object-id "$admin_id" \
  --admin-display-name "$admin_name" \
  --admin-type User \
  --yes \
  --only-show-errors \
  --output none

az sql server firewall-rule create \
  --resource-group "$RG" \
  --server "$SQL_NAME" \
  --name "$FOREIGN_RULE" \
  --start-ip-address "$FOREIGN_IP" \
  --end-ip-address "$FOREIGN_IP" \
  --subscription "$SUBSCRIPTION_ID" \
  --only-show-errors \
  --output none

az postgres flexible-server firewall-rule create \
  --resource-group "$RG" \
  --server-name "$PG_NAME" \
  --name "$FOREIGN_RULE" \
  --start-ip-address "$FOREIGN_IP" \
  --end-ip-address "$FOREIGN_IP" \
  --subscription "$SUBSCRIPTION_ID" \
  --only-show-errors \
  --output none

export ARM_ACCESS_TOKEN
ARM_ACCESS_TOKEN="$(az account get-access-token --resource https://management.azure.com --query accessToken --output tsv --subscription "$SUBSCRIPTION_ID")"
case "$ARM_ACCESS_TOKEN" in
  *$'\n'*|"") printf '%s\n' "Could not read an ARM access token." >&2; exit 1 ;;
esac

export SMOKE_SQL_RESOURCE_ID="/subscriptions/${SUBSCRIPTION_ID}/resourceGroups/${RG}/providers/Microsoft.Sql/servers/${SQL_NAME}"
export SMOKE_PG_RESOURCE_ID="/subscriptions/${SUBSCRIPTION_ID}/resourceGroups/${RG}/providers/Microsoft.DBforPostgreSQL/flexibleServers/${PG_NAME}"
export SMOKE_IPV4="$public_ip"
export SMOKE_RULE_NAME="$RULE_NAME"
export SMOKE_FOREIGN_RULE="$FOREIGN_RULE"
export SMOKE_LOCATION="$LOCATION"
export CLEARANCE_WRITERS_COMMIT_SHA
CLEARANCE_WRITERS_COMMIT_SHA="$(git -C "$root" rev-parse HEAD)"

set +e
( cd "$root" && npm run live-smoke )
smoke_status=$?
set -e
unset ARM_ACCESS_TOKEN || true
exit "$smoke_status"

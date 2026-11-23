// Copyright 2026 Sarambar
// SPDX-License-Identifier: Apache-2.0

import { containsDisallowedCharacters } from "./codec.js";
import { writerError, type WriterError } from "./errors.js";
import { parseAllowAddress, parseTtlSeconds, STRICT_IP_POLICY, type IpPolicy, type ParsedAddress } from "./ip.js";
import { parseOpaqueResourceId, parseRuleName } from "./names.js";
import type { AddRuleRequest, RemoveRuleRequest } from "./writer.js";

export interface ValidatedAdd {
  resourceId: string;
  ruleName: string;
  address: ParsedAddress;
  ttlSeconds: number;
  policy: IpPolicy;
  expectedLocation: string | null;
}

export interface ValidatedRemove {
  resourceId: string;
  ruleName: string;
}

function ledgerError(): WriterError {
  return writerError({
    code: "ledger_required",
    message: "Refusing to change a rule without an explicit ledger ownership assertion.",
  });
}

export function validateAddRequest(
  request: AddRuleRequest,
): { ok: true; value: ValidatedAdd } | { ok: false; error: WriterError } {
  if (request.ledgerOwned !== true) {
    return { ok: false, error: ledgerError() };
  }
  const resourceId = parseOpaqueResourceId(request.resourceId);
  if (!resourceId.ok) {
    return resourceId;
  }
  const ruleName = parseRuleName(request.ruleName);
  if (!ruleName.ok) {
    return ruleName;
  }
  const policy = request.ipPolicy ?? STRICT_IP_POLICY;
  const address = parseAllowAddress(request.ipv4, policy);
  if (!address.ok) {
    return address;
  }
  const ttl = parseTtlSeconds(request.ttlSeconds);
  if (!ttl.ok) {
    return ttl;
  }
  let expectedLocation: string | null = null;
  if (request.expectedLocation !== undefined) {
    if (
      typeof request.expectedLocation !== "string" ||
      request.expectedLocation.trim().length === 0 ||
      request.expectedLocation.trim().length > 64 ||
      containsDisallowedCharacters(request.expectedLocation)
    ) {
      return {
        ok: false,
        error: writerError({ code: "invalid_input", message: "Expected location must be a single-line location name." }),
      };
    }
    expectedLocation = request.expectedLocation.trim();
  }
  return {
    ok: true,
    value: {
      resourceId: resourceId.value,
      ruleName: ruleName.value,
      address: address.value,
      ttlSeconds: ttl.value,
      policy,
      expectedLocation,
    },
  };
}

export function validateRemoveRequest(
  request: RemoveRuleRequest,
): { ok: true; value: ValidatedRemove } | { ok: false; error: WriterError } {
  if (request.ledgerOwned !== true) {
    return { ok: false, error: ledgerError() };
  }
  const resourceId = parseOpaqueResourceId(request.resourceId);
  if (!resourceId.ok) {
    return resourceId;
  }
  const ruleName = parseRuleName(request.ruleName);
  if (!ruleName.ok) {
    return ruleName;
  }
  return { ok: true, value: { resourceId: resourceId.value, ruleName: ruleName.value } };
}

export function validateListRequest(
  resourceId: unknown,
): { ok: true; value: string } | { ok: false; error: WriterError } {
  return parseOpaqueResourceId(resourceId);
}

// Copyright 2026 Sarambar
// SPDX-License-Identifier: Apache-2.0

import { containsDisallowedCharacters, escapeForOutput } from "./codec.js";
import { writerError, type WriterError } from "./errors.js";

/** Clearance rule names start with this exact prefix. Comparison is case-sensitive. */
export const CLEARANCE_RULE_PREFIX = "clearance-";

/**
 * Names Azure uses for "allow all Azure IPs". Never a Clearance rule.
 * The pattern below already rejects them because they lack the prefix.
 */
export const RESERVED_FIREWALL_RULE_NAMES = [
  "AllowAllAzureIPs",
  "AllowAllWindowsAzureIps",
] as const;

const RULE_NAME = /^clearance-[0-9A-Za-z_-]{8,118}$/;

export function parseRuleName(
  input: unknown,
): { ok: true; value: string } | { ok: false; error: WriterError } {
  if (typeof input !== "string") {
    return { ok: false, error: writerError({ code: "invalid_rule_name", message: "Rule name must be a string." }) };
  }
  if (input.length > 128) {
    return {
      ok: false,
      error: writerError({ code: "invalid_rule_name", message: "Rule name is longer than 128 characters." }),
    };
  }
  if (containsDisallowedCharacters(input) || input !== input.normalize("NFC")) {
    return {
      ok: false,
      error: writerError({
        code: "invalid_rule_name",
        message: `Rule name ${escapeForOutput(input)} contains characters that are not allowed.`,
      }),
    };
  }
  const reserved = RESERVED_FIREWALL_RULE_NAMES.some((name) => name.toLowerCase() === input.toLowerCase());
  if (reserved || !RULE_NAME.test(input)) {
    return {
      ok: false,
      error: writerError({
        code: "invalid_rule_name",
        message: `Rule name ${escapeForOutput(input)} must match ${CLEARANCE_RULE_PREFIX} plus 8 to 118 letters, digits, underscores, or hyphens.`,
      }),
    };
  }
  return { ok: true, value: input };
}

export function isClearanceRuleName(name: string): boolean {
  return parseRuleName(name).ok;
}

/** Shared limits for any cloud's resource id before the adapter parses it. */
export function parseOpaqueResourceId(
  input: unknown,
): { ok: true; value: string } | { ok: false; error: WriterError } {
  if (typeof input !== "string") {
    return {
      ok: false,
      error: writerError({ code: "invalid_resource_id", message: "Resource id must be a string." }),
    };
  }
  if (input.length === 0 || input.length > 2048) {
    return {
      ok: false,
      error: writerError({ code: "invalid_resource_id", message: "Resource id length is not allowed." }),
    };
  }
  if (containsDisallowedCharacters(input) || /\s/.test(input) || input.includes("\\") || input.includes("%")) {
    return {
      ok: false,
      error: writerError({
        code: "invalid_resource_id",
        message: `Resource id ${escapeForOutput(input)} contains characters that are not allowed.`,
      }),
    };
  }
  return { ok: true, value: input };
}

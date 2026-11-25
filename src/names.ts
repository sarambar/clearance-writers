// Copyright 2026 Sarambar
// SPDX-License-Identifier: Apache-2.0

import { containsDisallowedCharacters, escapeForOutput } from "./codec.js";
import { writerError, type WriterError } from "./errors.js";

/** Clearance rule names start with this exact prefix. Comparison is case-sensitive. */
export const CLEARANCE_RULE_PREFIX = "clearance-";

/** Single-rule Azure SQL names carry their expiry and a ULID. */
export const SBC_RULE_PREFIX = "sbc-";

/** Names Azure uses for "allow all Azure IPs". Never a Clearance rule. */
export const RESERVED_FIREWALL_RULE_NAMES = [
  "AllowAllAzureIPs",
  "AllowAllWindowsAzureIps",
] as const;

export const RULE_NAME = /^clearance-[0-9A-Za-z_-]{8,118}$/;
export const SBC_RULE_NAME = /^sbc-([1-9][0-9]{0,12})-([0-9A-HJKMNP-TV-Z]{26})$/;

export interface ParsedSbcRuleName {
  ruleName: string;
  expiresAtSeconds: number;
  ulid: string;
}

export function parseSbcRuleName(
  input: unknown,
): { ok: true; value: ParsedSbcRuleName } | { ok: false; error: WriterError } {
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
  const match = SBC_RULE_NAME.exec(input);
  if (match === null) {
    return {
      ok: false,
      error: writerError({
        code: "invalid_rule_name",
        message: "Rule name must match sbc-<expiry>-<ulid>.",
      }),
    };
  }
  const expiresAtSeconds = Number(match[1]);
  if (!Number.isSafeInteger(expiresAtSeconds) || expiresAtSeconds <= 0) {
    return {
      ok: false,
      error: writerError({ code: "invalid_rule_name", message: "Rule name expiry must be a positive Unix timestamp." }),
    };
  }
  return {
    ok: true,
    value: { ruleName: input, expiresAtSeconds, ulid: match[2] ?? "" },
  };
}

export function isSbcRuleName(name: string): boolean {
  return parseSbcRuleName(name).ok;
}

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

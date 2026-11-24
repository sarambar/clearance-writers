// Copyright 2026 Sarambar
// SPDX-License-Identifier: Apache-2.0

import { escapeForOutput } from "./codec.js";
import { writerError, type WriterError } from "./errors.js";

/**
 * Default Clearance address policy: one public IPv4 host.
 * RFC 5737 documentation ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24)
 * are refused. Tests set allowDocumentationRanges to true. Production must not.
 * 0.0.0.0 (Allow Azure services) and 0.0.0.0/0 stay refused unless the
 * matching flag on the policy is set.
 */
export interface IpPolicy {
  /** Narrowest prefix is 32. A smaller number allows a broader CIDR. */
  minimumPrefixLength: number;
  allowNonPublic: boolean;
  /** 0.0.0.0/32, the Azure "allow Azure services" sentinel. */
  allowAzureServicesRule: boolean;
  /** 0.0.0.0/0 only. Does not allow any other reserved range. */
  allowDefaultRoute: boolean;
  /**
   * Test-only. When true, a range that sits entirely inside one RFC 5737
   * documentation block is accepted. The default policy sets this false.
   */
  allowDocumentationRanges: boolean;
}

export const STRICT_IP_POLICY: IpPolicy = {
  minimumPrefixLength: 32,
  allowNonPublic: false,
  allowAzureServicesRule: false,
  allowDefaultRoute: false,
  allowDocumentationRanges: false,
};

export const MIN_TTL_SECONDS = 1;
/** Hard safety ceiling. Sixty minutes. The backend may impose a lower cap. */
export const MAX_TTL_SECONDS = 60 * 60;

export interface ParsedAddress {
  canonical: string;
  /** Inclusive start and end, equal for a single host. */
  startIpv4: string;
  endIpv4: string;
  prefixLength: number;
}

interface Interval {
  start: number;
  end: number;
}

const DOCUMENTATION: Interval[] = [
  block("192.0.2.0", "192.0.2.255"),
  block("198.51.100.0", "198.51.100.255"),
  block("203.0.113.0", "203.0.113.255"),
];

const NON_PUBLIC: Interval[] = [
  block("0.0.0.0", "0.255.255.255"),
  block("10.0.0.0", "10.255.255.255"),
  block("100.64.0.0", "100.127.255.255"),
  block("127.0.0.0", "127.255.255.255"),
  block("169.254.0.0", "169.254.255.255"),
  block("172.16.0.0", "172.31.255.255"),
  block("192.0.0.0", "192.0.0.255"),
  block("192.168.0.0", "192.168.255.255"),
  block("198.18.0.0", "198.19.255.255"),
  block("192.88.99.0", "192.88.99.255"),
];

const MULTICAST_AND_RESERVED: Interval = block("224.0.0.0", "255.255.255.255");

function block(start: string, end: string): Interval {
  return { start: ipv4ToInt(start), end: ipv4ToInt(end) };
}

export function ipv4ToInt(canonical: string): number {
  const parts = canonical.split(".");
  let value = 0;
  for (const part of parts) {
    value = value * 256 + Number(part);
  }
  return value >>> 0;
}

export function intToIpv4(value: number): string {
  return [
    (value >>> 24) & 255,
    (value >>> 16) & 255,
    (value >>> 8) & 255,
    value & 255,
  ].join(".");
}

function parseOctet(octet: string): number | null {
  if (!/^(0|[1-9][0-9]{0,2})$/.test(octet)) {
    return null;
  }
  const value = Number(octet);
  if (!Number.isInteger(value) || value < 0 || value > 255) {
    return null;
  }
  return value;
}

/** Parse a single dotted IPv4 address. Rejects leading zeros and IPv6. */
export function parseIpv4(value: string): string | null {
  const parts = value.split(".");
  if (parts.length !== 4) {
    return null;
  }
  const numbers: number[] = [];
  for (const part of parts) {
    const octet = parseOctet(part);
    if (octet === null) {
      return null;
    }
    numbers.push(octet);
  }
  return numbers.join(".");
}

function overlaps(range: Interval, other: Interval): boolean {
  return range.start <= other.end && other.start <= range.end;
}

function contains(outer: Interval, inner: Interval): boolean {
  return outer.start <= inner.start && inner.end <= outer.end;
}

function invalid(code: WriterError["code"], message: string): WriterError {
  return writerError({ code, message });
}

function readPolicyFlags(policy: IpPolicy):
  | {
      ok: true;
      value: {
        allowNonPublic: boolean;
        allowAzureServicesRule: boolean;
        allowDefaultRoute: boolean;
        allowDocumentationRanges: boolean;
      };
    }
  | { ok: false; error: WriterError } {
  const allowNonPublic = booleanFlag(policy.allowNonPublic, "allowNonPublic");
  const allowAzureServicesRule = booleanFlag(policy.allowAzureServicesRule, "allowAzureServicesRule");
  const allowDefaultRoute = booleanFlag(policy.allowDefaultRoute, "allowDefaultRoute");
  const allowDocumentationRanges = booleanFlag(policy.allowDocumentationRanges, "allowDocumentationRanges");
  if (!allowNonPublic.ok) {
    return allowNonPublic;
  }
  if (!allowAzureServicesRule.ok) {
    return allowAzureServicesRule;
  }
  if (!allowDefaultRoute.ok) {
    return allowDefaultRoute;
  }
  if (!allowDocumentationRanges.ok) {
    return allowDocumentationRanges;
  }
  return {
    ok: true,
    value: {
      allowNonPublic: allowNonPublic.value,
      allowAzureServicesRule: allowAzureServicesRule.value,
      allowDefaultRoute: allowDefaultRoute.value,
      allowDocumentationRanges: allowDocumentationRanges.value,
    },
  };
}

function booleanFlag(
  value: unknown,
  name: string,
): { ok: true; value: boolean } | { ok: false; error: WriterError } {
  if (value === true) {
    return { ok: true, value: true };
  }
  if (value === false) {
    return { ok: true, value: false };
  }
  return {
    ok: false,
    error: invalid("invalid_input", `Address policy ${name} must be a boolean.`),
  };
}

/**
 * Accept a bare IPv4 host or a CIDR. Dash ranges are refused: Azure start/end
 * pairs are produced by this package, never taken from the caller as text.
 */
export function parseAllowAddress(
  input: unknown,
  policy: IpPolicy = STRICT_IP_POLICY,
): { ok: true; value: ParsedAddress } | { ok: false; error: WriterError } {
  if (typeof input !== "string") {
    return { ok: false, error: invalid("invalid_input", "Address must be a string.") };
  }
  if (input.length === 0 || input.length > 64) {
    return { ok: false, error: invalid("invalid_input", "Address length is not allowed.") };
  }
  if (input !== input.trim() || /\s/.test(input) || input.includes("%")) {
    return { ok: false, error: invalid("invalid_input", "Address contains whitespace or encoding.") };
  }
  if (input.includes("-")) {
    return {
      ok: false,
      error: invalid(
        "broad_range",
        "Address ranges written with a hyphen are refused. Pass one IPv4 host.",
      ),
    };
  }
  if (input.includes(":")) {
    return { ok: false, error: invalid("invalid_input", "IPv6 addresses are refused.") };
  }

  const slash = input.indexOf("/");
  const hostText = slash === -1 ? input : input.slice(0, slash);
  const prefixText = slash === -1 ? "32" : input.slice(slash + 1);
  if (slash !== -1 && (prefixText.length === 0 || input.indexOf("/", slash + 1) !== -1)) {
    return { ok: false, error: invalid("invalid_input", "CIDR prefix is malformed.") };
  }
  if (!/^(0|[1-9][0-9]?)$/.test(prefixText)) {
    return { ok: false, error: invalid("invalid_input", "CIDR prefix is malformed.") };
  }
  const prefixLength = Number(prefixText);
  if (prefixLength > 32) {
    return { ok: false, error: invalid("invalid_input", "CIDR prefix is larger than 32.") };
  }
  const flags = readPolicyFlags(policy);
  if (!flags.ok) {
    return flags;
  }
  const hostForSpecial = parseIpv4(hostText);
  const defaultRoute = hostForSpecial === "0.0.0.0" && prefixLength === 0;
  if (defaultRoute && !flags.value.allowDefaultRoute) {
    return {
      ok: false,
      error: invalid("default_route_forbidden", "0.0.0.0/0 is refused."),
    };
  }
  if (
    !Number.isInteger(policy.minimumPrefixLength) ||
    policy.minimumPrefixLength < 0 ||
    policy.minimumPrefixLength > 32
  ) {
    return { ok: false, error: invalid("invalid_input", "Address policy prefix is malformed.") };
  }
  if (!defaultRoute && prefixLength < policy.minimumPrefixLength) {
    return {
      ok: false,
      error: invalid(
        "broad_range",
        `Prefix /${prefixLength} is broader than the policy minimum /${policy.minimumPrefixLength}.`,
      ),
    };
  }

  const host = parseIpv4(hostText);
  if (host === null) {
    return {
      ok: false,
      error: invalid("invalid_input", `Address ${escapeForOutput(input)} is not a single IPv4 host.`),
    };
  }

  const hostInt = ipv4ToInt(host);
  const mask = prefixLength === 0 ? 0 : (0xffffffff << (32 - prefixLength)) >>> 0;
  const start = (hostInt & mask) >>> 0;
  const end = (start | (~mask >>> 0)) >>> 0;
  if (start !== hostInt) {
    return {
      ok: false,
      error: invalid("invalid_input", "CIDR host bits must be zero."),
    };
  }

  const range: Interval = { start, end };
  const startIpv4 = intToIpv4(start);
  const endIpv4 = intToIpv4(end);

  if (start === 0 && end === 0) {
    if (!flags.value.allowAzureServicesRule) {
      return {
        ok: false,
        error: invalid(
          "azure_services_forbidden",
          "0.0.0.0 is the Allow Azure services rule and is refused.",
        ),
      };
    }
  } else if (start === 0 && end === 0xffffffff) {
    if (!flags.value.allowDefaultRoute) {
      return {
        ok: false,
        error: invalid("default_route_forbidden", "0.0.0.0/0 is refused."),
      };
    }
  } else if (DOCUMENTATION.some((item) => overlaps(range, item))) {
    const entirelyInside = DOCUMENTATION.some((item) => contains(item, range));
    if (!flags.value.allowDocumentationRanges || !entirelyInside) {
      return {
        ok: false,
        error: invalid(
          "not_public_unicast",
          "RFC 5737 documentation addresses are refused unless allowDocumentationRanges is true.",
        ),
      };
    }
  } else if (overlaps(range, MULTICAST_AND_RESERVED)) {
    return {
      ok: false,
      error: invalid("not_public_unicast", "Multicast and reserved addresses are refused."),
    };
  } else if (NON_PUBLIC.some((item) => overlaps(range, item))) {
    if (!flags.value.allowNonPublic || !NON_PUBLIC.some((item) => contains(item, range))) {
      return {
        ok: false,
        error: invalid(
          "not_public_unicast",
          "Only a public IPv4 unicast host is accepted by the default policy.",
        ),
      };
    }
  }

  return {
    ok: true,
    value: {
      canonical: prefixLength === 32 ? startIpv4 : `${startIpv4}/${prefixLength}`,
      startIpv4,
      endIpv4,
      prefixLength,
    },
  };
}

export function parseTtlSeconds(
  input: unknown,
): { ok: true; value: number } | { ok: false; error: WriterError } {
  if (typeof input !== "number" || !Number.isFinite(input) || !Number.isInteger(input)) {
    return {
      ok: false,
      error: invalid("invalid_ttl", "TTL must be an integer number of seconds."),
    };
  }
  if (input < MIN_TTL_SECONDS || input > MAX_TTL_SECONDS) {
    return {
      ok: false,
      error: invalid(
        "invalid_ttl",
        `TTL must be from ${MIN_TTL_SECONDS} to ${MAX_TTL_SECONDS} seconds.`,
      ),
    };
  }
  return { ok: true, value: input };
}

/**
 * Target exposure bound: at most TTL plus the sweep interval.
 * This package does not run the sweeper. It checks the arithmetic the backend records.
 */
export function exposureBoundSeconds(ttlSeconds: unknown, sweepIntervalSeconds: unknown): number {
  const ttl = parseTtlSeconds(ttlSeconds);
  if (!ttl.ok) {
    throw ttl.error;
  }
  if (
    typeof sweepIntervalSeconds !== "number" ||
    !Number.isFinite(sweepIntervalSeconds) ||
    !Number.isInteger(sweepIntervalSeconds) ||
    sweepIntervalSeconds < 1 ||
    sweepIntervalSeconds > 24 * 60 * 60
  ) {
    throw invalid("invalid_ttl", "Sweep interval must be an integer number of seconds from 1 to 86400.");
  }
  return ttl.value + sweepIntervalSeconds;
}

// Copyright 2026 Sarambar
// SPDX-License-Identifier: Apache-2.0

import { createHash } from "node:crypto";

/** SHA-256 hex of a UTF-8 string. */
export function sha256Hex(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

function sortValue(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map((item) => sortValue(item));
  }
  if (value !== null && typeof value === "object") {
    const source = value as Record<string, unknown>;
    const sorted: Record<string, unknown> = {};
    for (const key of Object.keys(source).sort()) {
      const item = source[key];
      if (item !== undefined) {
        sorted[key] = sortValue(item);
      }
    }
    return sorted;
  }
  return value;
}

/** Canonical JSON: sorted keys, no insignificant whitespace, undefined dropped. */
export function canonicalJson(value: unknown): string {
  return JSON.stringify(sortValue(value));
}

const DISALLOWED =
  /[\u0000-\u001F\u007F-\u009F\u200B-\u200F\u2028\u2029\u202A-\u202E\u2066-\u2069\uFEFF]/;

/**
 * Escape a value for an error line or log field.
 * Control characters, bidi overrides, and zero-width characters become \uXXXX.
 * The result is truncated and cannot contain a raw newline.
 */
export function escapeForOutput(value: string, maxLength = 160): string {
  const normalized = value.normalize("NFC");
  const escaped = normalized.replace(
    new RegExp(DISALLOWED.source, "g"),
    (char) => {
      const hex = char.codePointAt(0)?.toString(16).padStart(4, "0") ?? "0000";
      return `\\u${hex}`;
    },
  );
  if (escaped.length <= maxLength) {
    return escaped;
  }
  return `${escaped.slice(0, maxLength)}…`;
}

/** True when the string is not NFC or contains characters we refuse as input. */
export function containsDisallowedCharacters(value: string): boolean {
  const normalized = value.normalize("NFC");
  if (normalized !== value) {
    return true;
  }
  return DISALLOWED.test(normalized);
}

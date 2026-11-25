// Copyright 2026 Sarambar
// SPDX-License-Identifier: Apache-2.0

export const WRITERS_VERSION = "0.0.0";

const SHA_PATTERN = /^(?:[0-9a-f]{40}|[0-9a-f]{64})$/;

/**
 * Git commit this process is actually running.
 * The host backend configures the pinned commit once at construction time via
 * `writersCommitSha` (or deploy-time CLEARANCE_WRITERS_COMMIT_SHA env). A missing
 * or malformed value is reported as "unknown". Individual rule operations cannot
 * pass or override the recorded SHA.
 */
export function resolveWritersCommitSha(candidate?: string): string {
  const raw = candidate ?? (typeof process === "undefined" ? undefined : process.env.CLEARANCE_WRITERS_COMMIT_SHA);
  if (raw === undefined) {
    return "unknown";
  }
  const trimmed = raw.trim();
  if (!SHA_PATTERN.test(trimmed)) {
    return "unknown";
  }
  return trimmed;
}

export function writersCommitSha(): string {
  return resolveWritersCommitSha();
}

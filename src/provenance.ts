// Copyright 2026 Sarambar
// SPDX-License-Identifier: Apache-2.0

/**
 * Writers package version. Keep this equal to package.json "version".
 * A test fails if the two drift.
 */
export const WRITERS_VERSION = "0.0.0";

const SHA_PATTERN = /^(?:[0-9a-f]{40}|[0-9a-f]{64})$/;

/**
 * Git commit this process is actually running.
 * The private backend sets CLEARANCE_WRITERS_COMMIT_SHA to the pinned commit
 * at deploy time. A missing or malformed value is reported as "unknown".
 * Callers cannot pass a SHA into an operation and have it recorded as ours.
 */
export function writersCommitSha(): string {
  const raw = process.env.CLEARANCE_WRITERS_COMMIT_SHA;
  if (raw === undefined) {
    return "unknown";
  }
  const trimmed = raw.trim();
  if (!SHA_PATTERN.test(trimmed)) {
    return "unknown";
  }
  return trimmed;
}

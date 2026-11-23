// Copyright 2026 Sarambar
// SPDX-License-Identifier: Apache-2.0

/**
 * Reachability is per service. Azure SQL returns error 40615 when the firewall
 * blocks a login. PostgreSQL Flexible Server drops the connection, which shows
 * up as a timeout, and does not return 40615. A timeout on SQL is a tool error.
 * `login-succeeded` on a post-delete probe means the path is still open.
 *
 * This package does not open a database connection. Callers map a driver result
 * through the observe functions and then classify it.
 */

export type ReachabilityClass =
  | "firewall-block"
  | "reachable-login-rejected"
  | "login-succeeded"
  | "tool-error";

export type ProbeService = "azure-sql" | "azure-postgres";

export interface ProbeObservation {
  service: ProbeService;
  outcome: "connected" | "error" | "timeout" | "tool-error";
  errorNumber?: number;
  sqlState?: string;
}

export interface DriverErrorInput {
  message?: string;
  code?: string;
  number?: number;
  sqlState?: string;
}

/** Documented control-plane cache. A delete is not "closed at" before this window. */
export const SQL_FIREWALL_CACHE_WINDOW_SECONDS = 5 * 60;
export const POSTGRES_FIREWALL_PROPAGATION_WINDOW_SECONDS = 5 * 60;

export function observeSqlDriverError(input: DriverErrorInput): ProbeObservation {
  const message = input.message ?? "";
  if (input.number === 40615 || /\b40615\b/.test(message)) {
    return { service: "azure-sql", outcome: "error", errorNumber: 40615 };
  }
  if (input.number === 18456 || /login failed/i.test(message)) {
    return { service: "azure-sql", outcome: "error", errorNumber: 18456 };
  }
  if (input.code === "ETIMEDOUT" || /timeout expired|timed out/i.test(message)) {
    return { service: "azure-sql", outcome: "timeout" };
  }
  return { service: "azure-sql", outcome: "tool-error" };
}

export function observePostgresDriverError(input: DriverErrorInput): ProbeObservation {
  const message = input.message ?? "";
  if (input.number === 40615 || /\b40615\b/.test(message)) {
    return { service: "azure-postgres", outcome: "tool-error", errorNumber: 40615 };
  }
  if (input.sqlState === "28P01" || /password authentication failed/i.test(message)) {
    return { service: "azure-postgres", outcome: "error", sqlState: "28P01" };
  }
  if (
    input.code === "ETIMEDOUT" ||
    /timeout expired|timed out|connection terminated unexpectedly/i.test(message)
  ) {
    return { service: "azure-postgres", outcome: "timeout" };
  }
  return { service: "azure-postgres", outcome: "tool-error" };
}

export function classifyReachability(observation: ProbeObservation): ReachabilityClass {
  if (observation.outcome === "connected") {
    return "login-succeeded";
  }
  if (observation.outcome === "tool-error") {
    return "tool-error";
  }
  if (observation.service === "azure-sql") {
    if (observation.outcome === "timeout") {
      return "tool-error";
    }
    if (observation.errorNumber === 40615) {
      return "firewall-block";
    }
    if (observation.errorNumber === 18456) {
      return "reachable-login-rejected";
    }
    return "tool-error";
  }
  if (observation.outcome === "timeout") {
    return "firewall-block";
  }
  if (observation.sqlState === "28P01") {
    return "reachable-login-rejected";
  }
  if (observation.errorNumber === 40615) {
    return "tool-error";
  }
  return "tool-error";
}

/**
 * A post-delete data-plane probe passes only when the service's own block
 * signal is observed. Login success is a failed probe. During the cache
 * window, login success is expected and is not proof the control-plane
 * delete failed.
 */
export function postDeleteProbePassed(classification: ReachabilityClass): boolean {
  return classification === "firewall-block";
}

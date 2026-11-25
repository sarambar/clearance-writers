// Copyright 2026 Sarambar
// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { ArmClient, LRO_INITIAL_DELAY_MS, LRO_MAX_DELAY_MS, MAX_LRO_BUDGET_MS, MAX_RESPONSE_CHARS } from "../src/azure/arm.js";
import { FakeArm } from "../src/azure/fake-arm.js";
import { createFetchTransport, type HttpRequest, type HttpResponse, type HttpTransport } from "../src/azure/http.js";
import { AZURE_SQL_FIREWALL_PROFILE } from "../src/azure/profiles.js";
import {
  InMemoryFirewallWriter,
  MemoryAuditSink,
  SQL_RULE_CAP,
  createAzurePostgresFirewallWriter,
  createAzureSqlFirewallWriter,
  createAzureSqlRuleProvider,
  type AuditEvent,
  type AuditSink,
} from "../src/index.js";
import { FOREIGN_IP, IP, NOW, PG_ID, RULE, SQL_ID, TOKEN, addRequest } from "./helpers.js";

const SBC_RULE = "sbc-1700000600-01HF7YAT00S5WARN4TQ5A8XEWP";
const PUBLIC_IP = "8.8.8.8";

function makeJwt(expSeconds: number): string {
  const header = Buffer.from(JSON.stringify({ alg: "RS256", typ: "JWT" })).toString("base64url");
  const payload = Buffer.from(JSON.stringify({ exp: expSeconds, aud: "https://management.azure.com/" })).toString("base64url");
  return `${header}.${payload}.signature`;
}

function wrapFakeArm(
  fake: FakeArm,
  intercept: (request: HttpRequest, next: () => Promise<HttpResponse>) => Promise<HttpResponse>,
): HttpTransport {
  return {
    send(request: HttpRequest): Promise<HttpResponse> {
      return intercept(request, () => fake.send(request));
    },
  };
}

describe("TLA+ audit Slice A regressions", () => {
  it("#9 does not treat Updating or NotStarted LRO statuses as done and returns indeterminate on budget exhaustion", async () => {
    // Subcase A: Location-only LRO returns NotStarted -> Updating -> Succeeded.
    const fakeProgress = new FakeArm();
    fakeProgress.seedServer({ resourceId: PG_ID, location: "centralus", lro: "async" });
    const locationPollUrl = `https://management.azure.com/subscriptions/00000000-0000-0000-0000-000000000000/providers/Microsoft.DBforPostgreSQL/locations/centralus/operationResults/9001?api-version=2026-07-01-preview`;
    const statuses = ["NotStarted", "Updating", "Succeeded"];
    let pollCount = 0;
    const progressTransport = wrapFakeArm(fakeProgress, async (req, next) => {
      if (req.method === "PUT") {
        const res = await next();
        return {
          status: 202,
          headers: {
            "content-type": "application/json",
            location: locationPollUrl,
            "retry-after": "1",
            "x-ms-request-id": res.headers["x-ms-request-id"] ?? "00000000-0000-0000-0000-000000000000",
          },
          body: "",
        };
      }
      if (req.url === locationPollUrl) {
        const nextStatus = statuses[pollCount] ?? "Succeeded";
        pollCount += 1;
        if (nextStatus === "Succeeded") {
          // Materialize the rule in FakeArm only when the operation actually succeeds.
          fakeProgress.seedServer({
            resourceId: PG_ID,
            location: "centralus",
            lro: "async",
            rules: [{ name: RULE, startIpv4: IP, endIpv4: IP }],
          });
        }
        return {
          status: 200,
          headers: { "content-type": "application/json", "retry-after": "1" },
          body: JSON.stringify({ status: nextStatus }),
        };
      }
      return next();
    });

    const writerProgress = createAzurePostgresFirewallWriter({
      transport: progressTransport,
      tokenProvider: { async getToken() { return TOKEN; } },
      audit: new MemoryAuditSink(),
      now: () => NOW,
      sleep: async () => undefined,
    });
    const progressResult = await writerProgress.addRule(addRequest(PG_ID));
    assert.equal(progressResult.ok, true);
    assert.equal(pollCount, 3, "must keep polling through NotStarted and Updating until Succeeded");

    // Subcase B: Location LRO stuck in Updating forever -> never early success, returns lro_timeout with ruleApplied=true.
    const fakeStuck = new FakeArm();
    fakeStuck.seedServer({ resourceId: PG_ID, location: "centralus", lro: "async" });
    let stuckPolls = 0;
    const stuckTransport = wrapFakeArm(fakeStuck, async (req, next) => {
      if (req.method === "PUT") {
        await next();
        return {
          status: 202,
          headers: {
            "content-type": "application/json",
            location: locationPollUrl,
            "retry-after": "30",
          },
          body: "",
        };
      }
      if (req.url === locationPollUrl) {
        stuckPolls += 1;
        return {
          status: 200,
          headers: { "content-type": "application/json", "retry-after": "30" },
          body: JSON.stringify({ status: "Updating" }),
        };
      }
      return next();
    });

    const stuckAudit = new MemoryAuditSink();
    const writerStuck = createAzurePostgresFirewallWriter({
      transport: stuckTransport,
      tokenProvider: { async getToken() { return TOKEN; } },
      audit: stuckAudit,
      now: () => NOW,
      sleep: async () => undefined,
    });
    const stuckResult = await writerStuck.addRule(addRequest(PG_ID));
    assert.equal(stuckResult.ok, false);
    assert.ok(stuckPolls > 1, "must keep polling while Updating instead of exiting early");
    if (!stuckResult.ok) {
      assert.equal(stuckResult.error.code, "lro_timeout");
      assert.equal(stuckResult.error.ruleApplied, true);
      assert.equal(stuckResult.error.removalVerified, false);
    }
    const stuckResultEvent = stuckAudit.events.find((e) => e.phase === "result");
    assert.equal(stuckResultEvent?.ruleApplied, true);

    // Subcase C: Failed and Canceled terminal statuses return lro_failed / lro_canceled.
    for (const [terminalStatus, expectedCode] of [
      ["Failed", "lro_failed"],
      ["Canceled", "lro_canceled"],
    ] as const) {
      const fakeTerm = new FakeArm();
      fakeTerm.seedServer({ resourceId: PG_ID, location: "centralus", lro: "async" });
      const termTransport = wrapFakeArm(fakeTerm, async (req, next) => {
        if (req.url.includes("/operationResults/")) {
          return {
            status: 200,
            headers: { "content-type": "application/json" },
            body: JSON.stringify({
              status: terminalStatus,
              ...(terminalStatus === "Failed" ? { error: { code: "OperationFailed", message: "operation failed" } } : {}),
            }),
          };
        }
        return next();
      });
      const writerTerm = createAzurePostgresFirewallWriter({
        transport: termTransport,
        tokenProvider: { async getToken() { return TOKEN; } },
        audit: new MemoryAuditSink(),
        now: () => NOW,
        sleep: async () => undefined,
      });
      const termRes = await writerTerm.addRule(addRequest(PG_ID));
      assert.equal(termRes.ok, false);
      if (!termRes.ok) {
        assert.equal(termRes.error.code, expectedCode);
      }
    }
  });

  it("#1 reports ruleApplied=true and removalVerified=false when polling fails after 202 in sql-provider and child-writer", async () => {
    // Interleaving: PUT gets 202 (async op still in flight, rule NOT materialized yet so GET returns 404),
    // then the operation poll fails (500 or 429). Neither writer may report ruleApplied=false.
    for (const pollStatus of [500, 429] as const) {
      // 1) AzureSqlFirewallRuleProvider (sql-provider.ts)
      const sqlFake = new FakeArm();
      sqlFake.seedServer({ resourceId: SQL_ID, location: "centralus", lro: "async" });
      const sqlTransport = wrapFakeArm(sqlFake, async (req, next) => {
        if (req.url.includes("/operationResults/")) {
          return {
            status: pollStatus,
            headers: pollStatus === 429 ? { "retry-after": "10" } : {},
            body: JSON.stringify({
              error: {
                code: pollStatus === 429 ? "TooManyRequests" : "InternalServerError",
                message: "poll failed",
              },
            }),
          };
        }
        return next();
      });
      const sqlAudit = new MemoryAuditSink();
      const sqlProvider = createAzureSqlRuleProvider({
        transport: sqlTransport,
        tokenProvider: { async getToken() { return TOKEN; } },
        audit: sqlAudit,
        now: () => NOW,
        sleep: async () => undefined,
      });
      const sqlRes = await sqlProvider.openRule({
        ledgerOwned: true,
        resourceId: SQL_ID,
        ruleName: SBC_RULE,
        ipv4: PUBLIC_IP,
        ttlSeconds: 300,
      });
      assert.equal(sqlRes.ok, false, `sql-provider poll ${pollStatus}`);
      if (!sqlRes.ok) {
        assert.equal(sqlRes.error.ruleApplied, true, `sql-provider poll ${pollStatus}: ruleApplied must be true`);
        assert.equal(sqlRes.error.removalVerified, false, `sql-provider poll ${pollStatus}: removalVerified must be false`);
      }
      assert.equal(
        sqlAudit.events.find((e) => e.phase === "result")?.ruleApplied,
        true,
        `sql-provider poll ${pollStatus}: audit must record ruleApplied=true`,
      );

      // 2) AzureChildFirewallWriter (child-writer.ts)
      const pgFake = new FakeArm();
      pgFake.seedServer({ resourceId: PG_ID, location: "centralus", lro: "async" });
      const pgTransport = wrapFakeArm(pgFake, async (req, next) => {
        if (req.url.includes("/operationResults/")) {
          return {
            status: pollStatus,
            headers: pollStatus === 429 ? { "retry-after": "10" } : {},
            body: JSON.stringify({
              error: {
                code: pollStatus === 429 ? "TooManyRequests" : "InternalServerError",
                message: "poll failed",
              },
            }),
          };
        }
        return next();
      });
      const pgAudit = new MemoryAuditSink();
      const pgWriter = createAzurePostgresFirewallWriter({
        transport: pgTransport,
        tokenProvider: { async getToken() { return TOKEN; } },
        audit: pgAudit,
        now: () => NOW,
        sleep: async () => undefined,
        inlineThrottleRetry: false,
      });
      const pgRes = await pgWriter.addRule(addRequest(PG_ID));
      assert.equal(pgRes.ok, false, `child-writer poll ${pollStatus}`);
      if (!pgRes.ok) {
        assert.equal(pgRes.error.ruleApplied, true, `child-writer poll ${pollStatus}: ruleApplied must be true`);
        assert.equal(pgRes.error.removalVerified, false, `child-writer poll ${pollStatus}: removalVerified must be false`);
      }
      assert.equal(
        pgAudit.events.find((e) => e.phase === "result")?.ruleApplied,
        true,
        `child-writer poll ${pollStatus}: audit must record ruleApplied=true`,
      );
    }
  });

  it("#11 rejects unsafe or non-HTTPS poll URLs without Location fallback and stops non-LRO resource body spin immediately", async () => {
    // Subcase A: Unsafe Azure-AsyncOperation with a same-origin Location must NOT fall back to Location.
    const fakeFallback = new FakeArm();
    fakeFallback.seedServer({ resourceId: PG_ID, location: "centralus", lro: "async" });
    const seenUrls: string[] = [];
    const fallbackDelays: number[] = [];
    const fallbackTransport = wrapFakeArm(fakeFallback, async (req, next) => {
      seenUrls.push(`${req.method} ${req.url}`);
      if (req.method === "PUT") {
        const res = await next();
        return {
          status: 202,
          headers: {
            ...res.headers,
            "azure-asyncoperation": "https://evil.example/subscriptions/00000000-0000-0000-0000-000000000000/operationResults/1",
            location: req.url,
          },
          body: "",
        };
      }
      return next();
    });
    const writerFallback = createAzurePostgresFirewallWriter({
      transport: fallbackTransport,
      tokenProvider: { async getToken() { return TOKEN; } },
      audit: new MemoryAuditSink(),
      now: () => NOW,
      sleep: async (ms) => {
        fallbackDelays.push(ms);
      },
    });
    const fallbackRes = await writerFallback.addRule(addRequest(PG_ID));
    assert.equal(fallbackRes.ok, false);
    if (!fallbackRes.ok) {
      assert.equal(fallbackRes.error.code, "unsafe_poll_url");
      assert.equal(fallbackRes.error.ruleApplied, true);
      assert.equal(fallbackRes.error.removalVerified, false);
    }
    assert.deepEqual(fallbackDelays, [], "must stop immediately without sleeping/spinning");
    assert.equal(seenUrls.some((u) => u.includes("evil.example")), false);
    assert.equal(seenUrls.filter((u) => u.includes(`/firewallRules/${RULE}`)).length, 1, "must not poll Location fallback");

    // Subcase B: Non-HTTPS poll URL over http:// even on the same host is rejected immediately.
    const httpClient = new ArmClient({
      endpoint: "http://management.azure.com",
      transport: {
        async send(): Promise<HttpResponse> {
          return {
            status: 202,
            headers: {
              "azure-asyncoperation":
                "http://management.azure.com/subscriptions/00000000-0000-0000-0000-000000000000/providers/Microsoft.Sql/locations/centralus/operationResults/1",
            },
            body: "",
          };
        },
      },
      tokenProvider: { async getToken() { return TOKEN; } },
      userAgent: "clearance-writers-test",
      sleep: async () => {
        throw new Error("should not sleep on non-HTTPS poll URL");
      },
    });
    const httpRes = await httpClient.put(`${SQL_ID}/firewallRules/${RULE}`, AZURE_SQL_FIREWALL_PROFILE.apiVersion, {});
    assert.equal(httpRes.ok, false);
    if (!httpRes.ok) {
      assert.equal(httpRes.error.code, "unsafe_poll_url");
      assert.equal(httpRes.error.ruleApplied, true);
      assert.equal(httpRes.error.removalVerified, false);
    }

    // Subcase C: Allowlisted Azure-AsyncOperation returns HTTP 200 with a raw resource body (no status / provisioningState).
    // Previously lroState returned "resource" and spun for 5 minutes (MAX_LRO_BUDGET_MS).
    const fakeSpin = new FakeArm();
    fakeSpin.seedServer({ resourceId: PG_ID, location: "centralus", lro: "async" });
    let spinPolls = 0;
    const spinDelays: number[] = [];
    const spinTransport = wrapFakeArm(fakeSpin, async (req, next) => {
      if (req.url.includes("/operationResults/")) {
        spinPolls += 1;
        return {
          status: 200,
          headers: { "content-type": "application/json" },
          body: JSON.stringify({
            name: RULE,
            properties: { startIpAddress: IP, endIpAddress: IP },
          }),
        };
      }
      return next();
    });
    const writerSpin = createAzurePostgresFirewallWriter({
      transport: spinTransport,
      tokenProvider: { async getToken() { return TOKEN; } },
      audit: new MemoryAuditSink(),
      now: () => NOW,
      sleep: async (ms) => {
        spinDelays.push(ms);
      },
    });
    const spinRes = await writerSpin.addRule(addRequest(PG_ID));
    assert.equal(spinRes.ok, false);
    assert.equal(spinPolls, 1, "must stop after 1 malformed non-LRO poll instead of spinning for 5 minutes");
    if (!spinRes.ok) {
      assert.equal(spinRes.error.code, "lro_malformed");
      assert.equal(spinRes.error.ruleApplied, true);
      assert.equal(spinRes.error.removalVerified, false);
    }
  });

  it("#10 caps huge Retry-After poll delays, enforces total budget, and avoids tight loops on Retry-After 0 or garbage", async () => {
    // Subcase A: Huge Retry-After (3600s) is capped per poll at LRO_MAX_DELAY_MS (30s) within MAX_LRO_BUDGET_MS.
    const fakeHuge = new FakeArm();
    fakeHuge.seedServer({ resourceId: PG_ID, location: "centralus", lro: "async" });
    const hugeDelays: number[] = [];
    const hugeTransport = wrapFakeArm(fakeHuge, async (req, next) => {
      if (req.method === "PUT") {
        const res = await next();
        return { ...res, headers: { ...res.headers, "retry-after": "3600" } };
      }
      if (req.url.includes("/operationResults/")) {
        return {
          status: 200,
          headers: { "content-type": "application/json", "retry-after": "3600" },
          body: JSON.stringify({ status: "InProgress" }),
        };
      }
      return next();
    });
    const writerHuge = createAzurePostgresFirewallWriter({
      transport: hugeTransport,
      tokenProvider: { async getToken() { return TOKEN; } },
      audit: new MemoryAuditSink(),
      now: () => NOW,
      sleep: async (ms) => {
        hugeDelays.push(ms);
      },
    });
    const hugeRes = await writerHuge.addRule(addRequest(PG_ID));
    assert.equal(hugeRes.ok, false);
    assert.ok(hugeDelays.length >= 2, "must not consume entire budget in a single uncapped sleep");
    assert.equal(
      hugeDelays.every((ms) => ms > 0 && ms <= LRO_MAX_DELAY_MS),
      true,
      `all delays must be <= ${LRO_MAX_DELAY_MS}, got ${JSON.stringify(hugeDelays)}`,
    );
    const totalHuge = hugeDelays.reduce((sum, ms) => sum + ms, 0);
    assert.ok(totalHuge <= MAX_LRO_BUDGET_MS, `total sleep ${totalHuge} exceeded budget ${MAX_LRO_BUDGET_MS}`);

    // Subcase B: Retry-After: 0, retry-after-ms: 1, and Retry-After: garbage never cause a 0ms/1ms tight loop.
    for (const badHeader of [
      { "retry-after": "0" },
      { "retry-after-ms": "1" },
      { "retry-after": "not-a-valid-header" },
    ] as Array<Record<string, string>>) {
      const fakeBad = new FakeArm();
      fakeBad.seedServer({ resourceId: PG_ID, location: "centralus", lro: "async" });
      const badDelays: number[] = [];
      const badTransport = wrapFakeArm(fakeBad, async (req, next) => {
        if (req.method === "PUT") {
          const res = await next();
          return { ...res, headers: { ...res.headers, ...badHeader } };
        }
        if (req.url.includes("/operationResults/")) {
          const res = await next();
          return { ...res, headers: { ...res.headers, ...badHeader } };
        }
        return next();
      });
      const writerBad = createAzurePostgresFirewallWriter({
        transport: badTransport,
        tokenProvider: { async getToken() { return TOKEN; } },
        audit: new MemoryAuditSink(),
        now: () => NOW,
        sleep: async (ms) => {
          badDelays.push(ms);
        },
      });
      const badRes = await writerBad.addRule(addRequest(PG_ID));
      assert.equal(badRes.ok, true);
      assert.ok(badDelays.length >= 1);
      assert.equal(
        badDelays.every((ms) => ms >= 1_000 && ms <= LRO_MAX_DELAY_MS),
        true,
        `header ${JSON.stringify(badHeader)} produced tight or uncapped loop delays: ${JSON.stringify(badDelays)}`,
      );
    }
  });

  it("#10 refreshes an expiring JWT mid-poll or aborts as indeterminate when refresh fails", async () => {
    // Subcase A: JWT expires after 1s, poll sleeps 2s -> provider refreshes on forceRefresh and poll succeeds.
    const fakeRefresh = new FakeArm();
    fakeRefresh.seedServer({ resourceId: PG_ID, location: "centralus", lro: "async" });
    let clockMs = NOW.getTime();
    const expiredJwt = makeJwt(Math.floor(clockMs / 1000) + 1);
    const freshJwt = makeJwt(Math.floor(clockMs / 1000) + 3600);
    let currentJwt = expiredJwt;
    let refreshCalls = 0;
    const authHeadersSeen: string[] = [];
    const refreshTransport = wrapFakeArm(fakeRefresh, async (req, next) => {
      authHeadersSeen.push(req.headers.authorization ?? "");
      return next();
    });
    const writerRefresh = createAzurePostgresFirewallWriter({
      transport: refreshTransport,
      tokenProvider: {
        async getToken(opts?: { forceRefresh?: boolean }) {
          if (opts?.forceRefresh) {
            refreshCalls += 1;
            currentJwt = freshJwt;
          }
          return currentJwt;
        },
      },
      audit: new MemoryAuditSink(),
      now: () => new Date(clockMs),
      sleep: async (ms) => {
        clockMs += ms;
      },
    });
    const refreshRes = await writerRefresh.addRule(addRequest(PG_ID));
    assert.equal(refreshRes.ok, true);
    assert.ok(refreshCalls >= 1, "must request token refresh when JWT expires mid-poll");
    assert.equal(authHeadersSeen.some((h) => h === `Bearer ${freshJwt}`), true);

    // Subcase B: JWT expires mid-poll and provider keeps returning expired JWT -> abort as indeterminate without sending expired token.
    const fakeStale = new FakeArm();
    fakeStale.seedServer({ resourceId: PG_ID, location: "centralus", lro: "async" });
    let staleClockMs = NOW.getTime();
    const staleExpSec = Math.floor(staleClockMs / 1000) + 1;
    const alwaysExpiredSoonJwt = makeJwt(staleExpSec);
    let pollSentAfterExpiry = false;
    const staleTransport = wrapFakeArm(fakeStale, async (req, next) => {
      if (req.url.includes("/operationResults/") && staleClockMs >= staleExpSec * 1000) {
        pollSentAfterExpiry = true;
      }
      return next();
    });
    const writerStale = createAzurePostgresFirewallWriter({
      transport: staleTransport,
      tokenProvider: { async getToken() { return alwaysExpiredSoonJwt; } },
      audit: new MemoryAuditSink(),
      now: () => new Date(staleClockMs),
      sleep: async (ms) => {
        staleClockMs += ms;
      },
    });
    const staleRes = await writerStale.addRule(addRequest(PG_ID));
    assert.equal(staleRes.ok, false);
    assert.equal(pollSentAfterExpiry, false, "must not send poll request after JWT expires");
    if (!staleRes.ok) {
      assert.equal(staleRes.error.code, "authentication_failed");
      assert.equal(staleRes.error.ruleApplied, true);
      assert.equal(staleRes.error.removalVerified, false);
    }

    // Subcase C: Opaque token expires server-side mid-poll (HTTP 401) -> refreshes once and completes poll.
    const fakeOpaque = new FakeArm();
    fakeOpaque.seedServer({ resourceId: PG_ID, location: "centralus", lro: "async" });
    let opaqueToken = "opaque-token-v1";
    let opaque401Injected = false;
    const opaqueTransport = wrapFakeArm(fakeOpaque, async (req, next) => {
      if (req.url.includes("/operationResults/") && !opaque401Injected && req.headers.authorization === "Bearer opaque-token-v1") {
        opaque401Injected = true;
        return {
          status: 401,
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ error: { code: "ExpiredAuthenticationToken", message: "The access token has expired." } }),
        };
      }
      return next();
    });
    const writerOpaque = createAzurePostgresFirewallWriter({
      transport: opaqueTransport,
      tokenProvider: {
        async getToken(opts?: { forceRefresh?: boolean }) {
          if (opts?.forceRefresh) {
            opaqueToken = "opaque-token-v2";
          }
          return opaqueToken;
        },
      },
      audit: new MemoryAuditSink(),
      now: () => NOW,
      sleep: async () => undefined,
    });
    const opaqueRes = await writerOpaque.addRule(addRequest(PG_ID));
    assert.equal(opaqueRes.ok, true);
    assert.equal(opaque401Injected, true);
  });

  it("#8 re-checks absence a bounded number of times with short backoff after delete before failing", async () => {
    // Subcase A: Rule lingers for 2 GETs after DELETE (eventual consistency), absent on 3rd GET -> succeeds.
    const fakeEventual = new FakeArm();
    fakeEventual.seedServer({
      resourceId: SQL_ID,
      location: "centralus",
      rules: [{ name: SBC_RULE, startIpv4: PUBLIC_IP, endIpv4: PUBLIC_IP }],
    });
    let staleGetsRemaining = 2;
    let postDeleteGets = 0;
    let deleted = false;
    const delays: number[] = [];
    const eventualTransport = wrapFakeArm(fakeEventual, async (req, next) => {
      if (req.method === "DELETE") {
        deleted = true;
        return next();
      }
      if (deleted && req.method === "GET") {
        postDeleteGets += 1;
        if (staleGetsRemaining > 0) {
          staleGetsRemaining -= 1;
          return {
            status: 200,
            headers: { "content-type": "application/json" },
            body: JSON.stringify({
              name: SBC_RULE,
              properties: { startIpAddress: PUBLIC_IP, endIpAddress: PUBLIC_IP },
            }),
          };
        }
      }
      return next();
    });
    const providerEventual = createAzureSqlRuleProvider({
      transport: eventualTransport,
      tokenProvider: { async getToken() { return TOKEN; } },
      audit: new MemoryAuditSink(),
      now: () => NOW,
      sleep: async (ms) => {
        delays.push(ms);
      },
    });
    const eventualRes = await providerEventual.closeRule({
      ledgerOwned: true,
      resourceId: SQL_ID,
      ruleName: SBC_RULE,
    });
    assert.equal(eventualRes.ok, true);
    if (eventualRes.ok) {
      assert.equal(eventualRes.value.removalVerified, true);
    }
    assert.equal(postDeleteGets, 3);
    assert.equal(delays.length, 2);
    assert.equal(delays.every((ms) => ms > 0 && ms <= 2_000), true);

    // Subcase B: Rule genuinely stays present -> bounded retries then delete_not_verified with removalVerified=false.
    const fakeStuck = new FakeArm();
    fakeStuck.seedServer({
      resourceId: SQL_ID,
      location: "centralus",
      rules: [{ name: SBC_RULE, startIpv4: PUBLIC_IP, endIpv4: PUBLIC_IP }],
    });
    let stuckPostDeleteGets = 0;
    const stuckTransport = wrapFakeArm(fakeStuck, async (req, next) => {
      if (req.method === "DELETE") {
        return { status: 204, headers: {}, body: "" };
      }
      if (req.method === "GET") {
        stuckPostDeleteGets += 1;
      }
      return next();
    });
    const providerStuck = createAzureSqlRuleProvider({
      transport: stuckTransport,
      tokenProvider: { async getToken() { return TOKEN; } },
      audit: new MemoryAuditSink(),
      now: () => NOW,
      sleep: async () => undefined,
    });
    const stuckRes = await providerStuck.closeRule({
      ledgerOwned: true,
      resourceId: SQL_ID,
      ruleName: SBC_RULE,
    });
    assert.equal(stuckRes.ok, false);
    assert.ok(stuckPostDeleteGets > 1 && stuckPostDeleteGets <= 5, `expected bounded re-checks, got ${stuckPostDeleteGets}`);
    if (!stuckRes.ok) {
      assert.equal(stuckRes.error.code, "delete_not_verified");
      assert.equal(stuckRes.error.ruleApplied, true);
      assert.equal(stuckRes.error.removalVerified, false);
    }
  });

  it("#3 never retries PUT inline on 429/503 (preventing rule recreation after cleanup) while GET/DELETE may retry within budget", async () => {
    // Bad interleaving: PUT gets 429 or 503; if ArmClient slept and retried PUT inline, a concurrent cleanup could run
    // during the sleep and the retried PUT would recreate the rule after cleanup.
    for (const status of [429, 503] as const) {
      for (const inlineThrottleRetry of [undefined, true] as const) {
        const fake = new FakeArm();
        fake.seedServer({ resourceId: SQL_ID, location: "centralus" });
        fake.failMatching(
          { method: "PUT", pathIncludes: `/firewallRules/${RULE}` },
          { status, code: status === 429 ? "TooManyRequests" : "ServiceUnavailable", message: "throttled" },
          1,
        );
        const delays: number[] = [];
        const writer = createAzureSqlFirewallWriter({
          transport: fake,
          tokenProvider: { async getToken() { return TOKEN; } },
          audit: new MemoryAuditSink(),
          now: () => NOW,
          ...(inlineThrottleRetry === undefined ? {} : { inlineThrottleRetry }),
          sleep: async (ms) => {
            delays.push(ms);
          },
        });
        const res = await writer.addRule(addRequest(SQL_ID));
        assert.equal(res.ok, false, `status=${status} inlineThrottleRetry=${String(inlineThrottleRetry)}: PUT must not retry inline`);
        if (!res.ok) {
          assert.equal(res.error.code, "throttled");
          if (status === 503) {
            assert.equal(res.error.ruleApplied, true);
            assert.equal(res.error.removalVerified, false);
          }
        }
        assert.equal(fake.requests.filter((r) => r.method === "PUT").length, 1, "must send at most 1 PUT");
        assert.equal(fake.rulesFor(SQL_ID)?.length, 0, "rule must not be recreated by an inline PUT retry");
        assert.deepEqual(delays, [], "must not sleep inline on PUT 429/503");
      }
    }

    // GET and DELETE may still retry 429 inline within budget by default.
    const fakeRetry = new FakeArm();
    fakeRetry.seedServer({
      resourceId: SQL_ID,
      location: "centralus",
      rules: [{ name: RULE, startIpv4: IP, endIpv4: IP }],
    });
    fakeRetry.failMatching(
      { method: "GET", pathIncludes: `/firewallRules/${RULE}` },
      { status: 429, code: "TooManyRequests", message: "throttled" },
      1,
    );
    fakeRetry.failMatching(
      { method: "DELETE", pathIncludes: `/firewallRules/${RULE}` },
      { status: 429, code: "TooManyRequests", message: "throttled" },
      1,
    );
    const deleteDelays: number[] = [];
    const writerRetry = createAzureSqlFirewallWriter({
      transport: fakeRetry,
      tokenProvider: { async getToken() { return TOKEN; } },
      audit: new MemoryAuditSink(),
      now: () => NOW,
      sleep: async (ms) => {
        deleteDelays.push(ms);
      },
    });
    const removed = await writerRetry.removeRule({ resourceId: SQL_ID, ruleName: RULE, ledgerOwned: true });
    assert.equal(removed.ok, true);
    assert.equal(fakeRetry.requests.filter((r) => r.method === "DELETE").length, 2);
    assert.equal(deleteDelays.length, 2);
  });

  it("#7 maps ARM 256-firewall-rule limit errors to distinct rule_limit_reached error code", async () => {
    const fullRules = Array.from({ length: SQL_RULE_CAP }, (_, index) => ({
      name: `customer-${index}`,
      startIpv4: FOREIGN_IP,
      endIpv4: FOREIGN_IP,
    }));

    // Subcase A: sql-provider hits FakeArm's 256-rule cap (400 TooManyFirewallRules).
    const fake = new FakeArm();
    fake.seedServer({ resourceId: SQL_ID, location: "centralus", rules: fullRules });
    const audit = new MemoryAuditSink();
    const provider = createAzureSqlRuleProvider({
      transport: fake,
      tokenProvider: { async getToken() { return TOKEN; } },
      audit,
      now: () => NOW,
      sleep: async () => undefined,
    });
    const res = await provider.openRule({
      ledgerOwned: true,
      resourceId: SQL_ID,
      ruleName: SBC_RULE,
      ipv4: PUBLIC_IP,
      ttlSeconds: 300,
    });
    assert.equal(res.ok, false);
    if (!res.ok) {
      assert.equal(res.error.code, "rule_limit_reached");
      assert.equal(res.error.cloudCode, "TooManyFirewallRules");
      assert.equal(res.error.cloudStatus, 400);
      assert.equal(res.error.ruleApplied, false);
    }
    assert.equal(audit.events.some((e) => e.phase === "result" && e.detailCode === "rule_limit_reached"), true);

    // Subcase B: child-writer hits ARM 256-rule limit on PUT when the 256th rule arrives concurrently after pre-list.
    const fakeRace = new FakeArm();
    fakeRace.seedServer({ resourceId: SQL_ID, location: "centralus", rules: fullRules.slice(0, SQL_RULE_CAP - 1) });
    fakeRace.failMatching(
      { method: "PUT", pathIncludes: `/firewallRules/${RULE}` },
      { status: 400, code: "TooManyFirewallRules", message: "The provided firewall rules are over the limit." },
      1,
    );
    const writer = createAzureSqlFirewallWriter({
      transport: fakeRace,
      tokenProvider: { async getToken() { return TOKEN; } },
      audit: new MemoryAuditSink(),
      now: () => NOW,
      sleep: async () => undefined,
    });
    const raceRes = await writer.addRule(addRequest(SQL_ID));
    assert.equal(raceRes.ok, false);
    if (!raceRes.ok) {
      assert.equal(raceRes.error.code, "rule_limit_reached");
      assert.equal(raceRes.error.cloudCode, "TooManyFirewallRules");
      assert.equal(raceRes.error.cloudStatus, 400);
      assert.equal(raceRes.error.ruleApplied, false);
    }

    // Subcase C: 503 with 'firewall rule limit' text must stay throttled with ruleApplied=true (never rule_limit_reached).
    const fake503 = new FakeArm();
    fake503.seedServer({ resourceId: SQL_ID, location: "centralus", rules: [] });
    fake503.failMatching(
      { method: "PUT", pathIncludes: `/firewallRules/${SBC_RULE}` },
      {
        status: 503,
        code: "ServiceUnavailable",
        message: "Temporary service error checking firewall rule limit; firewall rules are over the limit.",
      },
      1,
    );
    const provider503 = createAzureSqlRuleProvider({
      transport: fake503,
      tokenProvider: { async getToken() { return TOKEN; } },
      audit: new MemoryAuditSink(),
      now: () => NOW,
      sleep: async () => undefined,
    });
    const res503 = await provider503.openRule({
      ledgerOwned: true,
      resourceId: SQL_ID,
      ruleName: SBC_RULE,
      ipv4: PUBLIC_IP,
      ttlSeconds: 300,
    });
    assert.equal(res503.ok, false);
    if (!res503.ok) {
      assert.equal(res503.error.code, "throttled", "503 must stay throttled, never rule_limit_reached");
      assert.equal(res503.error.cloudStatus, 503);
      assert.equal(res503.error.ruleApplied, true, "503 PUT must stay ruleApplied=true");
      assert.equal(res503.error.removalVerified, false);
    }

    // Subcase D: 429 with TooManyFirewallRules code must stay throttled, never rule_limit_reached.
    const fake429 = new FakeArm();
    fake429.seedServer({ resourceId: SQL_ID, location: "centralus", rules: [] });
    fake429.failMatching(
      { method: "PUT", pathIncludes: `/firewallRules/${SBC_RULE}` },
      { status: 429, code: "TooManyFirewallRules", message: "The provided firewall rules are over the limit." },
      1,
    );
    const provider429 = createAzureSqlRuleProvider({
      transport: fake429,
      tokenProvider: { async getToken() { return TOKEN; } },
      audit: new MemoryAuditSink(),
      now: () => NOW,
      sleep: async () => undefined,
    });
    const res429 = await provider429.openRule({
      ledgerOwned: true,
      resourceId: SQL_ID,
      ruleName: SBC_RULE,
      ipv4: PUBLIC_IP,
      ttlSeconds: 300,
    });
    assert.equal(res429.ok, false);
    if (!res429.ok) {
      assert.equal(res429.error.code, "throttled", "429 must stay throttled, never rule_limit_reached");
      assert.equal(res429.error.cloudStatus, 429);
    }
  });

  it("#8 emits a remove intent audit event strictly before DELETE in closeRule, removeRule, rollbackOwnRule, and InMemoryFirewallWriter", async () => {
    // Subcase A: AzureSqlFirewallRuleProvider.closeRule emits remove/intent before DELETE reaches ARM.
    const timelineClose: string[] = [];
    const fakeClose = new FakeArm();
    fakeClose.seedServer({
      resourceId: SQL_ID,
      location: "centralus",
      rules: [{ name: SBC_RULE, startIpv4: PUBLIC_IP, endIpv4: PUBLIC_IP }],
    });
    const closeAudit: AuditSink = {
      async emit(event: AuditEvent) {
        timelineClose.push(`audit:${event.operation}:${event.phase}:${event.outcome}`);
      },
    };
    const closeTransport = wrapFakeArm(fakeClose, async (req, next) => {
      timelineClose.push(`http:${req.method}`);
      return next();
    });
    const sqlProvider = createAzureSqlRuleProvider({
      transport: closeTransport,
      tokenProvider: { async getToken() { return TOKEN; } },
      audit: closeAudit,
      now: () => NOW,
      sleep: async () => undefined,
    });
    const closed = await sqlProvider.closeRule({ ledgerOwned: true, resourceId: SQL_ID, ruleName: SBC_RULE });
    assert.equal(closed.ok, true);
    const closeIntentIdx = timelineClose.indexOf("audit:remove:intent:succeeded");
    const closeDeleteIdx = timelineClose.indexOf("http:DELETE");
    assert.ok(closeIntentIdx >= 0, `missing remove intent event in ${JSON.stringify(timelineClose)}`);
    assert.ok(closeDeleteIdx > closeIntentIdx, `remove intent must precede DELETE in ${JSON.stringify(timelineClose)}`);

    // Subcase B: AzureSqlFirewallRuleProvider rollbackOwnRule (triggered on read-back violation) emits remove/intent before DELETE.
    const timelineRollback: string[] = [];
    const fakeRollback = new FakeArm();
    fakeRollback.seedServer({
      resourceId: SQL_ID,
      location: "centralus",
      rules: [{ name: "customer-wide-open", startIpv4: "0.0.0.0", endIpv4: "255.255.255.255" }],
    });
    const rollbackAudit: AuditSink = {
      async emit(event: AuditEvent) {
        timelineRollback.push(`audit:${event.operation}:${event.phase}:${event.outcome}`);
      },
    };
    const rollbackTransport = wrapFakeArm(fakeRollback, async (req, next) => {
      timelineRollback.push(`http:${req.method}`);
      return next();
    });
    const rollbackProvider = createAzureSqlRuleProvider({
      transport: rollbackTransport,
      tokenProvider: { async getToken() { return TOKEN; } },
      audit: rollbackAudit,
      now: () => NOW,
      sleep: async () => undefined,
    });
    const rolledBack = await rollbackProvider.openRule({
      ledgerOwned: true,
      resourceId: SQL_ID,
      ruleName: SBC_RULE,
      ipv4: PUBLIC_IP,
      ttlSeconds: 300,
    });
    assert.equal(rolledBack.ok, false);
    const rbIntentIdx = timelineRollback.indexOf("audit:remove:intent:succeeded");
    const rbDeleteIdx = timelineRollback.indexOf("http:DELETE");
    assert.ok(rbIntentIdx >= 0, `rollbackOwnRule must emit remove intent before DELETE: ${JSON.stringify(timelineRollback)}`);
    assert.ok(rbDeleteIdx > rbIntentIdx, `rollback remove intent must precede DELETE: ${JSON.stringify(timelineRollback)}`);

    // Subcase C: AzureChildFirewallWriter.removeRule emits remove/intent before DELETE reaches ARM.
    const timelineWriter: string[] = [];
    const fakeWriter = new FakeArm();
    fakeWriter.seedServer({
      resourceId: SQL_ID,
      location: "centralus",
      rules: [{ name: RULE, startIpv4: IP, endIpv4: IP }],
    });
    const writerAudit: AuditSink = {
      async emit(event: AuditEvent) {
        timelineWriter.push(`audit:${event.operation}:${event.phase}:${event.outcome}`);
      },
    };
    const writerTransport = wrapFakeArm(fakeWriter, async (req, next) => {
      timelineWriter.push(`http:${req.method}`);
      return next();
    });
    const writer = createAzureSqlFirewallWriter({
      transport: writerTransport,
      tokenProvider: { async getToken() { return TOKEN; } },
      audit: writerAudit,
      now: () => NOW,
      sleep: async () => undefined,
    });
    const removed = await writer.removeRule({ resourceId: SQL_ID, ruleName: RULE, ledgerOwned: true });
    assert.equal(removed.ok, true);
    const wIntentIdx = timelineWriter.indexOf("audit:remove:intent:succeeded");
    const wDeleteIdx = timelineWriter.indexOf("http:DELETE");
    assert.ok(wIntentIdx >= 0, `missing remove intent event in ${JSON.stringify(timelineWriter)}`);
    assert.ok(wDeleteIdx > wIntentIdx, `remove intent must precede DELETE in ${JSON.stringify(timelineWriter)}`);

    // Subcase D: InMemoryFirewallWriter.removeRule includes remove/intent before remove/result in outcome.audit.
    const memAudit = new MemoryAuditSink();
    const mem = new InMemoryFirewallWriter({ audit: memAudit, now: () => NOW });
    const memAdded = await mem.addRule(addRequest("memory:sql-example"));
    assert.equal(memAdded.ok, true);
    const memRemoved = await mem.removeRule({ resourceId: "memory:sql-example", ruleName: RULE, ledgerOwned: true });
    assert.equal(memRemoved.ok, true);
    assert.deepEqual(
      memRemoved.audit.map((e) => `${e.operation}:${e.phase}`),
      ["remove:intent", "remove:result"],
    );
  });

  it("#1 preserves ruleApplied=true and removalVerified=false when initial 202 PUT body is invalid JSON or oversized", async () => {
    const cases: Array<{ label: string; body: string }> = [
      { label: "invalid JSON", body: "<html>Accepted</html>" },
      { label: "oversized body", body: "x".repeat(MAX_RESPONSE_CHARS + 1) },
    ];

    for (const testCase of cases) {
      // AzureSqlRuleProvider: 202 with bad body, rule not yet visible on read-back (404).
      const fakeSql = new FakeArm();
      fakeSql.seedServer({ resourceId: SQL_ID, location: "centralus", rules: [] });
      const sqlTransport = wrapFakeArm(fakeSql, async (req, next) => {
        if (req.method === "PUT") {
          return {
            status: 202,
            headers: {
              "azure-asyncoperation": `https://management.azure.com/subscriptions/00000000-0000-0000-0000-000000000000/providers/Microsoft.Sql/locations/centralus/operationResults/op-bad-202`,
              "x-ms-request-id": "req-bad-202-sql",
            },
            body: testCase.body,
          };
        }
        return next();
      });
      const sqlAudit = new MemoryAuditSink();
      const sqlProvider = createAzureSqlRuleProvider({
        transport: sqlTransport,
        tokenProvider: { async getToken() { return TOKEN; } },
        audit: sqlAudit,
        now: () => NOW,
        sleep: async () => undefined,
      });
      const sqlOutcome = await sqlProvider.openRule({
        ledgerOwned: true,
        resourceId: SQL_ID,
        ruleName: SBC_RULE,
        ipv4: PUBLIC_IP,
        ttlSeconds: 600,
      });
      assert.equal(sqlOutcome.ok, false, `sql-provider ${testCase.label}`);
      if (!sqlOutcome.ok) {
        assert.equal(sqlOutcome.error.code, "cloud_response_invalid", `sql-provider ${testCase.label}`);
        assert.equal(sqlOutcome.error.cloudStatus, 202, `sql-provider ${testCase.label}`);
        assert.equal(sqlOutcome.error.ruleApplied, true, `sql-provider ${testCase.label} must preserve ruleApplied=true`);
        assert.equal(sqlOutcome.error.removalVerified, false, `sql-provider ${testCase.label} must keep removalVerified=false`);
      }

      // AzureChildFirewallWriter: 202 with bad body, rule not yet visible on read-back (404).
      const fakePg = new FakeArm();
      fakePg.seedServer({ resourceId: PG_ID, location: "centralus", rules: [] });
      const pgTransport = wrapFakeArm(fakePg, async (req, next) => {
        if (req.method === "PUT") {
          return {
            status: 202,
            headers: {
              "azure-asyncoperation": `https://management.azure.com/subscriptions/00000000-0000-0000-0000-000000000000/providers/Microsoft.DBforPostgreSQL/locations/centralus/operationResults/op-bad-202`,
              "x-ms-request-id": "req-bad-202-pg",
            },
            body: testCase.body,
          };
        }
        return next();
      });
      const pgAudit = new MemoryAuditSink();
      const pgWriter = createAzurePostgresFirewallWriter({
        transport: pgTransport,
        tokenProvider: { async getToken() { return TOKEN; } },
        audit: pgAudit,
        now: () => NOW,
        sleep: async () => undefined,
      });
      const pgOutcome = await pgWriter.addRule(addRequest(PG_ID));
      assert.equal(pgOutcome.ok, false, `child-writer ${testCase.label}`);
      if (!pgOutcome.ok) {
        assert.equal(pgOutcome.error.code, "cloud_response_invalid", `child-writer ${testCase.label}`);
        assert.equal(pgOutcome.error.cloudStatus, 202, `child-writer ${testCase.label}`);
        assert.equal(pgOutcome.error.ruleApplied, true, `child-writer ${testCase.label} must preserve ruleApplied=true`);
        assert.equal(pgOutcome.error.removalVerified, false, `child-writer ${testCase.label} must keep removalVerified=false`);
      }
    }
  });

  it("#10 enforces strict poll deadline without overdue GETs, passes remaining budget timeoutMs, and stops retries past deadline", async () => {
    // Subcase A: Sleep reaches deadline -> no GET is sent once budget hits 0, and each poll receives bounded timeoutMs.
    const opUrl = `https://management.azure.com/subscriptions/00000000-0000-0000-0000-000000000000/providers/Microsoft.Sql/locations/centralus/operationResults/op-deadline`;
    let clockMs = NOW.getTime();
    const pollTimeouts: Array<number | undefined> = [];
    const pollElapsedAtSend: number[] = [];
    const transport: HttpTransport = {
      async send(req: HttpRequest): Promise<HttpResponse> {
        if (req.method === "PUT") {
          return {
            status: 202,
            headers: { "azure-asyncoperation": opUrl, "retry-after": "30" },
            body: JSON.stringify({ status: "InProgress" }),
          };
        }
        pollTimeouts.push(req.timeoutMs);
        pollElapsedAtSend.push(clockMs - NOW.getTime());
        clockMs += Math.min(5_000, req.timeoutMs ?? 5_000);
        return {
          status: 200,
          headers: { "retry-after": "30" },
          body: JSON.stringify({ status: "InProgress" }),
        };
      },
    };
    const arm = new ArmClient({
      transport,
      tokenProvider: { async getToken() { return TOKEN; } },
      userAgent: "test-agent",
      now: () => new Date(clockMs),
      sleep: async (ms) => {
        clockMs += ms;
      },
    });
    const res = await arm.put(`${SQL_ID}/firewallRules/${SBC_RULE}`, AZURE_SQL_FIREWALL_PROFILE.apiVersion, {
      properties: { startIpAddress: PUBLIC_IP, endIpAddress: PUBLIC_IP },
    });
    assert.equal(res.ok, false);
    if (!res.ok) {
      assert.equal(res.error.code, "lro_timeout");
      assert.equal(res.error.ruleApplied, true);
      assert.equal(res.error.removalVerified, false);
    }
    assert.ok(clockMs - NOW.getTime() <= MAX_LRO_BUDGET_MS, `total elapsed ${clockMs - NOW.getTime()}ms exceeded budget ${MAX_LRO_BUDGET_MS}ms`);
    assert.ok(pollElapsedAtSend.length > 0);
    for (let i = 0; i < pollElapsedAtSend.length; i += 1) {
      const elapsed = pollElapsedAtSend[i] ?? MAX_LRO_BUDGET_MS;
      const timeout = pollTimeouts[i];
      assert.ok(elapsed < MAX_LRO_BUDGET_MS, `poll ${i} sent at ${elapsed}ms (must be < ${MAX_LRO_BUDGET_MS}ms)`);
      assert.ok(
        timeout !== undefined && timeout > 0 && elapsed + timeout <= MAX_LRO_BUDGET_MS,
        `poll ${i} timeoutMs=${timeout} at elapsed=${elapsed} exceeds deadline ${MAX_LRO_BUDGET_MS}`,
      );
    }

    // Subcase B: Transport failure that consumes remaining budget does not trigger additional GET retries past the deadline.
    let retryClockMs = NOW.getTime();
    let getAttempts = 0;
    const retryTransport: HttpTransport = {
      async send(req: HttpRequest): Promise<HttpResponse> {
        if (req.method === "PUT") {
          return {
            status: 202,
            headers: { "azure-asyncoperation": opUrl, "retry-after": "10" },
            body: JSON.stringify({ status: "InProgress" }),
          };
        }
        getAttempts += 1;
        // Simulate transport hanging until past MAX_LRO_BUDGET_MS.
        retryClockMs = NOW.getTime() + MAX_LRO_BUDGET_MS + 1;
        throw new Error("socket timed out");
      },
    };
    const armRetry = new ArmClient({
      transport: retryTransport,
      tokenProvider: { async getToken() { return TOKEN; } },
      userAgent: "test-agent",
      now: () => new Date(retryClockMs),
      sleep: async (ms) => {
        retryClockMs += ms;
      },
    });
    const retryRes = await armRetry.put(`${SQL_ID}/firewallRules/${SBC_RULE}`, AZURE_SQL_FIREWALL_PROFILE.apiVersion, {
      properties: { startIpAddress: PUBLIC_IP, endIpAddress: PUBLIC_IP },
    });
    assert.equal(retryRes.ok, false);
    assert.equal(getAttempts, 1, "must not retry poll GET after budget is exhausted");
    if (!retryRes.ok) {
      assert.equal(retryRes.error.ruleApplied, true);
      assert.equal(retryRes.error.removalVerified, false);
    }

    // Subcase C: createFetchTransport honors request.timeoutMs when smaller than default timeout.
    let seenSignal: AbortSignal | undefined;
    const fetchTransport = createFetchTransport(
      async (_input, init) => {
        seenSignal = init.signal ?? undefined;
        return new Response("{}", { status: 200 });
      },
      30_000,
    );
    const fetchResp = await fetchTransport.send({
      method: "GET",
      url: opUrl,
      headers: {},
      timeoutMs: 2_500,
    });
    assert.equal(fetchResp.status, 200);
    assert.ok(seenSignal !== undefined, "createFetchTransport must pass AbortSignal");
  });

  it("#8 surfaces rollback audit failures (audit_intent_failed and audit_completion_failed) without skipping cleanup", async () => {
    for (const failPhase of ["intent", "result"] as const) {
      const fake = new FakeArm();
      fake.seedServer({
        resourceId: SQL_ID,
        location: "centralus",
        rules: [{ name: "AllowAllWindowsAzureIps", startIpv4: "0.0.0.0", endIpv4: "0.0.0.0" }],
      });
      let deleteSent = false;
      const transport = wrapFakeArm(fake, async (req, next) => {
        if (req.method === "DELETE") {
          deleteSent = true;
        }
        return next();
      });
      const audit: AuditSink = {
        async emit(event: AuditEvent) {
          if (event.operation === "remove" && event.phase === failPhase) {
            throw new Error("audit sink unavailable");
          }
        },
      };
      const provider = createAzureSqlRuleProvider({
        transport,
        tokenProvider: { async getToken() { return TOKEN; } },
        audit,
        now: () => NOW,
        sleep: async () => undefined,
      });
      const outcome = await provider.openRule({
        ledgerOwned: true,
        resourceId: SQL_ID,
        ruleName: SBC_RULE,
        ipv4: PUBLIC_IP,
        ttlSeconds: 600,
      });
      assert.equal(deleteSent, true, `cleanup DELETE must not be skipped when rollback ${failPhase} audit fails`);
      assert.equal(outcome.ok, false);
      if (!outcome.ok) {
        assert.equal(
          outcome.error.code,
          failPhase === "intent" ? "audit_intent_failed" : "audit_completion_failed",
          `rollback ${failPhase} audit failure must be surfaced`,
        );
        assert.equal(outcome.error.ruleApplied, false, "verified rollback removal must preserve ruleApplied=false");
        assert.equal(outcome.error.removalVerified, true, "verified rollback removal must preserve removalVerified=true");
      }
    }
  });

  it("#2 treats PUT 5xx, 504, and transport timeout as maybe-applied (ruleApplied=true) even when read-back returns 404", async () => {
    const uncertainCases: Array<{
      label: string;
      handlePut: () => Promise<HttpResponse>;
      expectedCode: string;
    }> = [
      {
        label: "HTTP 500",
        handlePut: async () => ({
          status: 500,
          headers: {},
          body: JSON.stringify({ error: { code: "InternalServerError", message: "transient failure" } }),
        }),
        expectedCode: "transport",
      },
      {
        label: "HTTP 502",
        handlePut: async () => ({
          status: 502,
          headers: {},
          body: JSON.stringify({ error: { code: "BadGateway", message: "bad gateway" } }),
        }),
        expectedCode: "gateway_error",
      },
      {
        label: "HTTP 504",
        handlePut: async () => ({
          status: 504,
          headers: {},
          body: JSON.stringify({ error: { code: "GatewayTimeout", message: "gateway timeout" } }),
        }),
        expectedCode: "transport",
      },
      {
        label: "transport timeout",
        handlePut: async () => {
          throw new Error("The operation was aborted due to timeout");
        },
        expectedCode: "transport",
      },
    ];

    for (const tc of uncertainCases) {
      // AzureSqlRuleProvider: PUT hits uncertain 5xx/transport; rule is still absent on read-back (404).
      const fakeSql = new FakeArm();
      fakeSql.seedServer({ resourceId: SQL_ID, location: "centralus", rules: [] });
      const sqlTransport = wrapFakeArm(fakeSql, async (req, next) => {
        if (req.method === "PUT") {
          return tc.handlePut();
        }
        return next();
      });
      const sqlAudit = new MemoryAuditSink();
      const sqlProvider = createAzureSqlRuleProvider({
        transport: sqlTransport,
        tokenProvider: { async getToken() { return TOKEN; } },
        audit: sqlAudit,
        now: () => NOW,
        sleep: async () => undefined,
      });
      const sqlRes = await sqlProvider.openRule({
        ledgerOwned: true,
        resourceId: SQL_ID,
        ruleName: SBC_RULE,
        ipv4: PUBLIC_IP,
        ttlSeconds: 600,
      });
      assert.equal(sqlRes.ok, false, `sql-provider ${tc.label}`);
      if (!sqlRes.ok) {
        assert.equal(sqlRes.error.code, tc.expectedCode, `sql-provider ${tc.label}`);
        assert.equal(sqlRes.error.ruleApplied, true, `sql-provider ${tc.label} must remain ruleApplied=true despite 404`);
        assert.equal(sqlRes.error.removalVerified, false, `sql-provider ${tc.label} must remain removalVerified=false`);
      }

      // AzureChildFirewallWriter: same uncertain 5xx/transport; rule is absent on read-back (404).
      const fakeWriter = new FakeArm();
      fakeWriter.seedServer({ resourceId: SQL_ID, location: "centralus", rules: [] });
      const writerTransport = wrapFakeArm(fakeWriter, async (req, next) => {
        if (req.method === "PUT") {
          return tc.handlePut();
        }
        return next();
      });
      const writerAudit = new MemoryAuditSink();
      const writer = createAzureSqlFirewallWriter({
        transport: writerTransport,
        tokenProvider: { async getToken() { return TOKEN; } },
        audit: writerAudit,
        now: () => NOW,
        sleep: async () => undefined,
      });
      const writerRes = await writer.addRule(addRequest(SQL_ID));
      assert.equal(writerRes.ok, false, `child-writer ${tc.label}`);
      if (!writerRes.ok) {
        assert.equal(writerRes.error.code, tc.expectedCode, `child-writer ${tc.label}`);
        assert.equal(writerRes.error.ruleApplied, true, `child-writer ${tc.label} must remain ruleApplied=true despite 404`);
        assert.equal(writerRes.error.removalVerified, false, `child-writer ${tc.label} must remain removalVerified=false`);
      }
    }

    // Contrast: definite 400 rejection + 404 read-back still reports ruleApplied=false.
    const fake400 = new FakeArm();
    fake400.seedServer({ resourceId: SQL_ID, location: "centralus", rules: [] });
    fake400.failMatching(
      { method: "PUT", pathIncludes: `/firewallRules/${SBC_RULE}` },
      { status: 400, code: "InvalidRequest", message: "invalid ip" },
      1,
    );
    const provider400 = createAzureSqlRuleProvider({
      transport: fake400,
      tokenProvider: { async getToken() { return TOKEN; } },
      audit: new MemoryAuditSink(),
      now: () => NOW,
      sleep: async () => undefined,
    });
    const res400 = await provider400.openRule({
      ledgerOwned: true,
      resourceId: SQL_ID,
      ruleName: SBC_RULE,
      ipv4: PUBLIC_IP,
      ttlSeconds: 600,
    });
    assert.equal(res400.ok, false);
    if (!res400.ok) {
      assert.equal(res400.error.code, "cloud_rejected");
      assert.equal(res400.error.ruleApplied, false);
    }
  });

  it("#3 Location-header polling treats non-202 2xx (200 resource body and 204 empty body) as success", async () => {
    // Subcase A: PUT with Location header -> poll 1 returns 202, poll 2 returns 200 with resource body (no status/provisioningState).
    const putOpUrl = `https://management.azure.com/subscriptions/00000000-0000-0000-0000-000000000000/providers/Microsoft.Sql/locations/centralus/operationResults/op-loc-put`;
    let putPolls = 0;
    const putArm = new ArmClient({
      transport: {
        async send(req: HttpRequest): Promise<HttpResponse> {
          if (req.method === "PUT") {
            return {
              status: 202,
              headers: { location: putOpUrl, "retry-after": "1" },
              body: "",
            };
          }
          putPolls += 1;
          if (putPolls === 1) {
            return { status: 202, headers: { "retry-after": "1" }, body: "" };
          }
          return {
            status: 200,
            headers: { "content-type": "application/json" },
            body: JSON.stringify({
              id: `${SQL_ID}/firewallRules/${SBC_RULE}`,
              name: SBC_RULE,
              properties: { startIpAddress: PUBLIC_IP, endIpAddress: PUBLIC_IP },
            }),
          };
        },
      },
      tokenProvider: { async getToken() { return TOKEN; } },
      userAgent: "test-agent",
      now: () => NOW,
      sleep: async () => undefined,
    });
    const putResult = await putArm.put(`${SQL_ID}/firewallRules/${SBC_RULE}`, AZURE_SQL_FIREWALL_PROFILE.apiVersion, {
      properties: { startIpAddress: PUBLIC_IP, endIpAddress: PUBLIC_IP },
    });
    assert.equal(putResult.ok, true, "Location poll ending with 200+resource body must succeed");
    assert.equal(putPolls, 2);

    // Subcase B: DELETE with Location header -> poll 1 returns 202, poll 2 returns 204 No Content.
    const delOpUrl = `https://management.azure.com/subscriptions/00000000-0000-0000-0000-000000000000/providers/Microsoft.Sql/locations/centralus/operationResults/op-loc-del`;
    let delPolls = 0;
    const delArm = new ArmClient({
      transport: {
        async send(req: HttpRequest): Promise<HttpResponse> {
          if (req.method === "DELETE") {
            return {
              status: 202,
              headers: { location: delOpUrl, "retry-after": "1" },
              body: "",
            };
          }
          delPolls += 1;
          if (delPolls === 1) {
            return { status: 202, headers: { "retry-after": "1" }, body: "" };
          }
          return { status: 204, headers: {}, body: "" };
        },
      },
      tokenProvider: { async getToken() { return TOKEN; } },
      userAgent: "test-agent",
      now: () => NOW,
      sleep: async () => undefined,
    });
    const delResult = await delArm.delete(`${SQL_ID}/firewallRules/${SBC_RULE}`, AZURE_SQL_FIREWALL_PROFILE.apiVersion);
    assert.equal(delResult.ok, true, "Location poll ending with 204 must succeed");
    assert.equal(delPolls, 2);
  });

  it("#7 closeRule and removeRule report alreadyAbsent=false (removed) when DELETE 202 poll fails and read-back shows absent", async () => {
    // Subcase A: sql-provider.closeRule — DELETE accepted (202), rule actually deleted, poll returns 500 -> read-back 404 -> removed (alreadyAbsent=false).
    const fakeSql = new FakeArm();
    fakeSql.seedServer({
      resourceId: SQL_ID,
      location: "centralus",
      lro: "async",
      rules: [{ name: SBC_RULE, startIpv4: PUBLIC_IP, endIpv4: PUBLIC_IP }],
    });
    const sqlTransport = wrapFakeArm(fakeSql, async (req, next) => {
      if (req.method === "GET" && req.url.includes("/operationResults/")) {
        // Drain FakeArm's background delete, then report the poll as a 500.
        await next();
        await next();
        return {
          status: 500,
          headers: {},
          body: JSON.stringify({ error: { code: "InternalServerError", message: "poll failed" } }),
        };
      }
      return next();
    });
    const sqlProvider = createAzureSqlRuleProvider({
      transport: sqlTransport,
      tokenProvider: { async getToken() { return TOKEN; } },
      audit: new MemoryAuditSink(),
      now: () => NOW,
      sleep: async () => undefined,
    });
    const closed = await sqlProvider.closeRule({
      ledgerOwned: true,
      resourceId: SQL_ID,
      ruleName: SBC_RULE,
    });
    assert.equal(closed.ok, true);
    if (closed.ok) {
      assert.equal(closed.value.removalVerified, true);
      assert.equal(closed.value.alreadyAbsent, false, "accepted DELETE whose poll failed must report removed (alreadyAbsent=false)");
    }

    // Subcase B: child-writer.removeRule — DELETE accepted (202), poll returns 500 -> read-back 404 -> removed (alreadyAbsent=false).
    const fakeWriter = new FakeArm();
    fakeWriter.seedServer({
      resourceId: PG_ID,
      location: "centralus",
      lro: "async",
      rules: [{ name: RULE, startIpv4: IP, endIpv4: IP }],
    });
    const writerTransport = wrapFakeArm(fakeWriter, async (req, next) => {
      if (req.method === "GET" && req.url.includes("/operationResults/")) {
        // Drain FakeArm's background delete, then report the poll as a 500.
        await next();
        await next();
        return {
          status: 500,
          headers: {},
          body: JSON.stringify({ error: { code: "InternalServerError", message: "poll failed" } }),
        };
      }
      return next();
    });
    const writer = createAzurePostgresFirewallWriter({
      transport: writerTransport,
      tokenProvider: { async getToken() { return TOKEN; } },
      audit: new MemoryAuditSink(),
      now: () => NOW,
      sleep: async () => undefined,
    });
    const removed = await writer.removeRule({
      ledgerOwned: true,
      resourceId: PG_ID,
      ruleName: RULE,
    });
    assert.equal(removed.ok, true);
    if (removed.ok) {
      assert.equal(removed.value.removalVerified, true);
      assert.equal(removed.value.alreadyAbsent, false, "accepted DELETE whose poll failed must report removed (alreadyAbsent=false)");
    }
  });

  it("#8 default no-Retry-After poll delay starts at 2s with exponential backoff capped at 30s and honors Retry-After with 1s floor", async () => {
    const opUrl = `https://management.azure.com/subscriptions/00000000-0000-0000-0000-000000000000/providers/Microsoft.Sql/locations/centralus/operationResults/op-backoff`;
    // Subcase A: No Retry-After -> 2s, 4s, 8s, 16s, 30s, 30s then Succeeded.
    let backoffPoll = 0;
    const backoffDelays: number[] = [];
    const armBackoff = new ArmClient({
      transport: {
        async send(req: HttpRequest): Promise<HttpResponse> {
          if (req.method === "PUT") {
            return { status: 202, headers: { "azure-asyncoperation": opUrl }, body: JSON.stringify({ status: "InProgress" }) };
          }
          backoffPoll += 1;
          return {
            status: 200,
            headers: {},
            body: JSON.stringify({ status: backoffPoll >= 6 ? "Succeeded" : "InProgress" }),
          };
        },
      },
      tokenProvider: { async getToken() { return TOKEN; } },
      userAgent: "test-agent",
      now: () => NOW,
      sleep: async (ms) => {
        backoffDelays.push(ms);
      },
    });
    const backoffRes = await armBackoff.put(`${SQL_ID}/firewallRules/${SBC_RULE}`, AZURE_SQL_FIREWALL_PROFILE.apiVersion, {
      properties: { startIpAddress: PUBLIC_IP, endIpAddress: PUBLIC_IP },
    });
    assert.equal(backoffRes.ok, true);
    assert.deepEqual(backoffDelays, [LRO_INITIAL_DELAY_MS, 4_000, 8_000, 16_000, 30_000, 30_000]);

    // Subcase B: Honors Retry-After with 1s floor and 30s ceiling.
    const retryAfterHeaders = ["0", "5", "60"];
    let headerPoll = 0;
    const headerDelays: number[] = [];
    const armHeaders = new ArmClient({
      transport: {
        async send(req: HttpRequest): Promise<HttpResponse> {
          if (req.method === "PUT") {
            return {
              status: 202,
              headers: { "azure-asyncoperation": opUrl, "retry-after": retryAfterHeaders[0] ?? "0" },
              body: JSON.stringify({ status: "InProgress" }),
            };
          }
          headerPoll += 1;
          if (headerPoll >= retryAfterHeaders.length) {
            return { status: 200, headers: {}, body: JSON.stringify({ status: "Succeeded" }) };
          }
          return {
            status: 200,
            headers: { "retry-after": retryAfterHeaders[headerPoll] ?? "5" },
            body: JSON.stringify({ status: "InProgress" }),
          };
        },
      },
      tokenProvider: { async getToken() { return TOKEN; } },
      userAgent: "test-agent",
      now: () => NOW,
      sleep: async (ms) => {
        headerDelays.push(ms);
      },
    });
    const headersRes = await armHeaders.put(`${SQL_ID}/firewallRules/${SBC_RULE}`, AZURE_SQL_FIREWALL_PROFILE.apiVersion, {
      properties: { startIpAddress: PUBLIC_IP, endIpAddress: PUBLIC_IP },
    });
    assert.equal(headersRes.ok, true);
    assert.deepEqual(headerDelays, [1_000, 5_000, 30_000]);
  });
});

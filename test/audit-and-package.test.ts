// Copyright 2026 Sarambar
// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import { readFileSync, readdirSync, statSync } from "node:fs";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";

import {
  AUDIT_GENESIS_HASH,
  AZURE_POSTGRES_FIREWALL_ACTIONS,
  AZURE_SQL_FIREWALL_ACTIONS,
  WRITERS_VERSION,
  auditEventHash,
  canonicalJson,
  createFetchTransport,
  sha256Hex,
  writersCommitSha,
} from "../src/index.js";
import { RULE, TOKEN, addRequest, harness } from "./helpers.js";

const root = join(dirname(fileURLToPath(import.meta.url)), "../..");

describe("audit provenance", () => {
  it("records the package version and commit SHA and a content hash", async () => {
    const previous = process.env.CLEARANCE_WRITERS_COMMIT_SHA;
    process.env.CLEARANCE_WRITERS_COMMIT_SHA = "0123456789abcdef";
    try {
      const { writer, audit, resourceId } = harness("sql");
      const added = await writer.addRule(addRequest(resourceId));
      assert.equal(added.ok, true);
      assert.ok(audit.events.length >= 2);
      for (const event of audit.events) {
        assert.equal(event.writersVersion, WRITERS_VERSION);
        assert.equal(event.writersCommitSha, "0123456789abcdef");
        const { contentHash, ...body } = event;
        assert.equal(contentHash, sha256Hex(canonicalJson(body)));
        assert.equal(JSON.stringify(event).includes(TOKEN), false);
      }
      const first = audit.events[0];
      assert.ok(first);
      const { contentHash: _ignored, ...body } = first;
      const linked = auditEventHash(AUDIT_GENESIS_HASH, body);
      const tampered = { ...body, detailCode: "tampered" };
      assert.notEqual(auditEventHash(AUDIT_GENESIS_HASH, tampered), linked);
      process.env.CLEARANCE_WRITERS_COMMIT_SHA = "not a sha";
      assert.equal(writersCommitSha(), "unknown");
    } finally {
      if (previous === undefined) {
        delete process.env.CLEARANCE_WRITERS_COMMIT_SHA;
      } else {
        process.env.CLEARANCE_WRITERS_COMMIT_SHA = previous;
      }
    }
  });

  it("does not call ARM when the intent event is refused", async () => {
    const { fake, audit, writer, resourceId } = harness("sql");
    audit.failOnEmit = "intent";
    const result = await writer.addRule(addRequest(resourceId));
    assert.equal(result.ok, false);
    if (!result.ok) {
      assert.equal(result.error.code, "audit_intent_failed");
      assert.equal(result.error.ruleApplied, false);
    }
    assert.equal(fake.requests.length, 0);
  });

  it("reports an audit gap when the rule was created and the result event is refused", async () => {
    const { fake, audit, writer, resourceId } = harness("sql");
    audit.failOnEmit = "result";
    const result = await writer.addRule(addRequest(resourceId));
    assert.equal(result.ok, false);
    if (!result.ok) {
      assert.equal(result.error.code, "audit_completion_failed");
      assert.equal(result.error.ruleApplied, true);
    }
    assert.equal(fake.rulesFor(resourceId)?.some((rule) => rule.name === RULE), true);
  });

  it("does not follow an HTTP redirect", async () => {
    const seen: string[] = [];
    const transport = createFetchTransport(async (url) => {
      seen.push(url);
      return new Response(null, { status: 302, headers: { location: "https://evil.example/collect" } });
    });
    const response = await transport.send({
      method: "GET",
      url: "https://management.azure.com/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-example/providers/Microsoft.Sql/servers/sql-example",
      headers: { authorization: `Bearer ${TOKEN}` },
    });
    assert.equal(response.status, 302);
    assert.equal(seen.length, 1);
  });
});

describe("package boundaries", () => {
  it("has no runtime dependencies and the role files match the profiles", () => {
    const pkg = JSON.parse(readFileSync(join(root, "package.json"), "utf8")) as {
      license: string;
      version: string;
      dependencies?: Record<string, string>;
    };
    assert.equal(pkg.license, "Apache-2.0");
    assert.equal(pkg.version, WRITERS_VERSION);
    assert.equal(pkg.dependencies, undefined);
    const sql = JSON.parse(readFileSync(join(root, "roles/azure-sql-firewall.json"), "utf8")) as {
      Actions: string[];
      DataActions: string[];
      NotActions: string[];
    };
    const postgres = JSON.parse(readFileSync(join(root, "roles/azure-postgres-flexible-firewall.json"), "utf8")) as {
      Actions: string[];
      DataActions: string[];
    };
    assert.deepEqual(sql.Actions, [...AZURE_SQL_FIREWALL_ACTIONS]);
    assert.deepEqual(postgres.Actions, [...AZURE_POSTGRES_FIREWALL_ACTIONS]);
    assert.deepEqual(sql.DataActions, []);
    assert.deepEqual(postgres.DataActions, []);
    assert.equal(sql.Actions.some((action) => action.endsWith("/servers/write")), false);
    assert.equal(postgres.Actions.some((action) => action.endsWith("/flexibleServers/write")), false);
  });

  it("keeps placeholders out of source, tests, and roles", () => {
    const files = [join(root, "README.md"), ...walk(join(root, "src")), ...walk(join(root, "test")), ...walk(join(root, "roles")), ...walk(join(root, ".github"))];
    const guid = /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/gi;
    const email = /[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g;
    for (const path of files) {
      const text = readFileSync(path, "utf8");
      for (const match of text.match(email) ?? []) {
        assert.equal(match.endsWith("@example.com") || match.includes("@typescript-eslint") || match.startsWith("@types"), true, path);
      }
      for (const match of text.match(guid) ?? []) {
        assert.equal(match.toLowerCase(), "00000000-0000-0000-0000-000000000000", `${path} has ${match}`);
      }
    }
  });
});

function walk(directory: string): string[] {
  const found: string[] = [];
  for (const name of readdirSync(directory)) {
    if (name === "node_modules" || name === "dist" || name === ".git") {
      continue;
    }
    const path = join(directory, name);
    if (statSync(path).isDirectory()) {
      found.push(...walk(path));
    } else {
      found.push(path);
    }
  }
  return found;
}

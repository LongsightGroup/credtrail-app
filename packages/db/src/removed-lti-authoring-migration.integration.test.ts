import { readFile } from "node:fs/promises";

import pg from "pg";
import { expect, it } from "vitest";

import { describeDbIntegration, requireTestDatabaseUrl } from "./postgres-test-support.js";

const REMOVED_TEMPLATE_KEY = ["lti", "Instructor", "Placement"].join("");
const REMOVED_DELEGATION_ACTION = ["configure", "course", "rule"].join("_");

describeDbIntegration("removed LTI authoring policy migration with Postgres", () => {
  it("removes only superseded policy data, preserves unrelated metadata, and is idempotent", async () => {
    const schemaName = `removed_lti_authoring_${crypto.randomUUID().replaceAll("-", "")}`;
    const pool = new pg.Pool({ connectionString: requireTestDatabaseUrl() });
    const client = await pool.connect();

    try {
      await client.query(`CREATE SCHEMA ${schemaName}`);
      await client.query(`SET search_path TO ${schemaName}`);
      await client.query(`
        CREATE TABLE badge_templates (
          id TEXT PRIMARY KEY,
          governance_metadata_json TEXT,
          updated_at TEXT NOT NULL
        );
        CREATE TABLE delegated_issuing_authority_grants (
          id TEXT PRIMARY KEY,
          allowed_actions_json TEXT NOT NULL,
          updated_at TEXT NOT NULL
        );
      `);
      const oldTimestamp = "2026-01-01T00:00:00.000Z";
      await client.query(
        `
          INSERT INTO badge_templates (id, governance_metadata_json, updated_at)
          VALUES
            ('template_changed', $1, $3),
            ('template_unchanged', $2, $3),
            ('template_null', NULL, $3)
        `,
        [
          JSON.stringify({
            stability: "institution_registry",
            approval: "registrar",
            [REMOVED_TEMPLATE_KEY]: { enabled: true },
          }),
          JSON.stringify({ stability: "institution_registry" }),
          oldTimestamp,
        ],
      );
      await client.query(
        `
          INSERT INTO delegated_issuing_authority_grants (id, allowed_actions_json, updated_at)
          VALUES
            ('grant_mixed', $1, $4),
            ('grant_removed_only', $2, $4),
            ('grant_unchanged', $3, $4)
        `,
        [
          JSON.stringify(["issue", REMOVED_DELEGATION_ACTION]),
          JSON.stringify([REMOVED_DELEGATION_ACTION]),
          JSON.stringify(["issue"]),
          oldTimestamp,
        ],
      );
      const migrationSql = await readFile(
        new URL("../migrations/0083_remove_template_lti_placement_policy.sql", import.meta.url),
        "utf8",
      );

      await client.query(migrationSql);
      await client.query(migrationSql);

      const templates = await client.query<{
        id: string;
        governance_metadata_json: string | null;
        updated_at: string;
      }>("SELECT id, governance_metadata_json, updated_at FROM badge_templates ORDER BY id");
      const grants = await client.query<{
        id: string;
        allowed_actions_json: string;
        updated_at: string;
      }>(
        "SELECT id, allowed_actions_json, updated_at FROM delegated_issuing_authority_grants ORDER BY id",
      );

      expect(
        templates.rows.map((row) => ({
          id: row.id,
          metadata:
            row.governance_metadata_json === null
              ? null
              : (JSON.parse(row.governance_metadata_json) as unknown),
          changed: row.updated_at !== oldTimestamp,
        })),
      ).toEqual([
        {
          id: "template_changed",
          metadata: { approval: "registrar", stability: "institution_registry" },
          changed: true,
        },
        {
          id: "template_null",
          metadata: null,
          changed: false,
        },
        {
          id: "template_unchanged",
          metadata: { stability: "institution_registry" },
          changed: false,
        },
      ]);
      expect(
        grants.rows.map((row) => ({
          id: row.id,
          actions: JSON.parse(row.allowed_actions_json) as unknown,
          changed: row.updated_at !== oldTimestamp,
        })),
      ).toEqual([
        { id: "grant_mixed", actions: ["issue"], changed: true },
        { id: "grant_removed_only", actions: [], changed: true },
        { id: "grant_unchanged", actions: ["issue"], changed: false },
      ]);
    } finally {
      await client.query("RESET search_path");
      await client.query(`DROP SCHEMA IF EXISTS ${schemaName} CASCADE`);
      client.release();
      await pool.end();
    }
  });
});

import { readFile } from "node:fs/promises";

import pg from "pg";
import { expect, it } from "vitest";

import {
  ACHIEVEMENT_SNAPSHOT_MIGRATION,
  ACHIEVEMENT_SNAPSHOT_REPAIR,
  applyAchievementSnapshotMigrationRepair,
} from "../scripts/achievement-snapshot-migration-repair.mjs";
import { calculateMigrationChecksum } from "../scripts/migration-integrity.mjs";
import { describeDbIntegration, requireTestDatabaseUrl } from "./postgres-test-support";

describeDbIntegration("populated achievement snapshot migration repair", () => {
  it("preserves existing rows without fabricating an issuance snapshot", async () => {
    const schemaName = `repair_${crypto.randomUUID().replaceAll("-", "")}`;
    const pool = new pg.Pool({ connectionString: requireTestDatabaseUrl() });
    const client = await pool.connect();

    try {
      await client.query(`CREATE SCHEMA ${schemaName}`);
      await client.query(`SET search_path TO ${schemaName}`);
      await client.query(`
        CREATE TABLE badge_issuance_rules (
          tenant_id TEXT NOT NULL,
          id TEXT NOT NULL,
          PRIMARY KEY (tenant_id, id)
        );
        CREATE TABLE badge_issuance_rule_versions (
          id TEXT NOT NULL,
          tenant_id TEXT NOT NULL,
          rule_id TEXT NOT NULL,
          UNIQUE (tenant_id, rule_id, id)
        );
        CREATE TABLE assertions (
          id TEXT PRIMARY KEY,
          tenant_id TEXT NOT NULL,
          badge_template_id TEXT NOT NULL,
          vc_r2_key TEXT NOT NULL
        );
        CREATE TABLE assertion_issuance_provenance (
          tenant_id TEXT NOT NULL,
          rule_id TEXT,
          version_id TEXT,
          source TEXT NOT NULL,
          provenance_json TEXT
        );
        CREATE TABLE schema_migration_repairs (
          repair_version TEXT PRIMARY KEY,
          blocked_version TEXT NOT NULL,
          repair_checksum TEXT NOT NULL,
          applied_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
      `);
      await client.query(`
        INSERT INTO badge_issuance_rules (tenant_id, id)
        VALUES ('tenant_123', 'rule_123');
        INSERT INTO badge_issuance_rule_versions (tenant_id, rule_id, id)
        VALUES ('tenant_123', 'rule_123', 'version_123');
        INSERT INTO assertions (id, tenant_id, badge_template_id, vc_r2_key)
        VALUES ('assertion_123', 'tenant_123', 'template_123', 'credentials/assertion_123.json');
        INSERT INTO assertion_issuance_provenance (
          tenant_id,
          rule_id,
          version_id,
          source,
          provenance_json
        )
        VALUES ('tenant_123', NULL, NULL, 'manual', NULL);
      `);

      const migrationSql = await readFile(
        new URL("../migrations/0063_badge_rule_achievement_snapshots.sql", import.meta.url),
        "utf8",
      );
      const repairSql = await readFile(
        new URL(
          "../migration-repairs/0063_preserve_populated_achievement_history.sql",
          import.meta.url,
        ),
        "utf8",
      );

      await client.query("BEGIN");
      const repaired = await applyAchievementSnapshotMigrationRepair(
        client,
        {
          fileName: ACHIEVEMENT_SNAPSHOT_MIGRATION,
          sql: migrationSql,
          checksum: calculateMigrationChecksum(migrationSql),
        },
        {
          fileName: ACHIEVEMENT_SNAPSHOT_REPAIR,
          sql: repairSql,
          checksum: calculateMigrationChecksum(repairSql),
        },
      );
      await client.query("COMMIT");

      expect(repaired).toBe(true);

      const statusMigrationSql = await readFile(
        new URL(
          "../migrations/0072_preserve_unavailable_achievement_snapshots.sql",
          import.meta.url,
        ),
        "utf8",
      );
      await client.query(statusMigrationSql);

      const preserved = await client.query<{
        achievement_snapshot_json: string | null;
        achievement_snapshot_status: string;
        vc_r2_key: string;
      }>(`
        SELECT achievement_snapshot_json, achievement_snapshot_status, vc_r2_key
        FROM assertions
        WHERE id = 'assertion_123'
      `);

      expect(preserved.rows).toEqual([
        {
          achievement_snapshot_json: null,
          achievement_snapshot_status: "unavailable",
          vc_r2_key: "credentials/assertion_123.json",
        },
      ]);
      await expect(
        client.query(`
          INSERT INTO assertions (id, tenant_id, badge_template_id, vc_r2_key)
          VALUES ('assertion_missing_snapshot', 'tenant_123', 'template_123', 'missing.json')
        `),
      ).rejects.toThrow("assertions_achievement_snapshot_state_check");
    } finally {
      await client.query("RESET search_path");
      await client.query(`DROP SCHEMA IF EXISTS ${schemaName} CASCADE`);
      client.release();
      await pool.end();
    }
  });
});

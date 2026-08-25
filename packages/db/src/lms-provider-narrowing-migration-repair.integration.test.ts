import { readFile } from "node:fs/promises";

import pg from "pg";
import { expect, it } from "vitest";

import {
  LMS_PROVIDER_NARROWING_MIGRATION,
  LMS_PROVIDER_NARROWING_REPAIR,
  applyMigrationReplacement,
} from "../scripts/migration-replacements.mjs";
import { calculateMigrationChecksum } from "../scripts/migration-integrity.mjs";
import { describeDbIntegration, requireTestDatabaseUrl } from "./postgres-test-support";

describeDbIntegration("LMS provider narrowing migration repair", () => {
  it("detaches restrictive dependents before narrowing and validates in the next migration", async () => {
    const schemaName = `repair_${crypto.randomUUID().replaceAll("-", "")}`;
    const pool = new pg.Pool({ connectionString: requireTestDatabaseUrl() });
    const client = await pool.connect();

    try {
      await client.query(`CREATE SCHEMA ${schemaName}`);
      await client.query(`SET search_path TO ${schemaName}`);
      await client.query(`
        CREATE TABLE badge_issuance_rules (
          id TEXT PRIMARY KEY,
          tenant_id TEXT NOT NULL,
          lms_provider_kind TEXT NOT NULL,
          UNIQUE (tenant_id, id)
        );
        CREATE TABLE badge_issuance_rule_versions (
          id TEXT PRIMARY KEY,
          tenant_id TEXT NOT NULL,
          rule_id TEXT NOT NULL,
          snapshot_lms_provider_kind TEXT NOT NULL,
          UNIQUE (tenant_id, rule_id, id),
          FOREIGN KEY (rule_id) REFERENCES badge_issuance_rules (id) ON DELETE CASCADE
        );
        CREATE TABLE badge_issuance_rule_registry_projection (
          tenant_id TEXT NOT NULL,
          rule_id TEXT NOT NULL,
          lms_provider_kind TEXT NOT NULL,
          PRIMARY KEY (tenant_id, rule_id),
          FOREIGN KEY (tenant_id, rule_id)
            REFERENCES badge_issuance_rules (tenant_id, id) ON DELETE CASCADE
        );
        CREATE TABLE lti_resource_link_placements (
          id TEXT PRIMARY KEY,
          rule_id TEXT REFERENCES badge_issuance_rules (id) ON DELETE SET NULL
        );
        CREATE TABLE assertion_issuance_provenance (
          assertion_id TEXT PRIMARY KEY,
          tenant_id TEXT NOT NULL,
          rule_id TEXT NOT NULL,
          version_id TEXT NOT NULL,
          FOREIGN KEY (tenant_id, rule_id)
            REFERENCES badge_issuance_rules (tenant_id, id) ON DELETE RESTRICT,
          FOREIGN KEY (tenant_id, rule_id, version_id)
            REFERENCES badge_issuance_rule_versions (tenant_id, rule_id, id) ON DELETE RESTRICT
        );
        CREATE TABLE schema_migration_repairs (
          repair_version TEXT PRIMARY KEY,
          blocked_version TEXT NOT NULL,
          repair_checksum TEXT NOT NULL,
          applied_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
      `);
      await client.query(`
        INSERT INTO badge_issuance_rules (id, tenant_id, lms_provider_kind)
        VALUES
          ('rule_supported', 'tenant_123', 'sakai'),
          ('rule_unsupported', 'tenant_123', 'moodle');
        INSERT INTO badge_issuance_rule_versions (
          id,
          tenant_id,
          rule_id,
          snapshot_lms_provider_kind
        )
        VALUES
          ('version_supported', 'tenant_123', 'rule_supported', 'sakai'),
          ('version_unsupported', 'tenant_123', 'rule_unsupported', 'moodle');
        INSERT INTO badge_issuance_rule_registry_projection (
          tenant_id,
          rule_id,
          lms_provider_kind
        )
        VALUES
          ('tenant_123', 'rule_supported', 'sakai'),
          ('tenant_123', 'rule_unsupported', 'moodle');
        INSERT INTO lti_resource_link_placements (id, rule_id)
        VALUES
          ('placement_supported', 'rule_supported'),
          ('placement_unsupported', 'rule_unsupported');
        INSERT INTO assertion_issuance_provenance (
          assertion_id,
          tenant_id,
          rule_id,
          version_id
        )
        VALUES
          ('assertion_supported', 'tenant_123', 'rule_supported', 'version_supported'),
          ('assertion_unsupported', 'tenant_123', 'rule_unsupported', 'version_unsupported');
      `);

      const migrationSql = await readFile(
        new URL("../migrations/0078_narrow_badge_rule_lms_providers.sql", import.meta.url),
        "utf8",
      );
      const repairSql = await readFile(
        new URL(
          "../migration-repairs/0078_detach_dependents_and_narrow_lms_providers.sql",
          import.meta.url,
        ),
        "utf8",
      );

      await client.query("BEGIN");
      const repaired = await applyMigrationReplacement(
        client,
        {
          fileName: LMS_PROVIDER_NARROWING_MIGRATION,
          sql: migrationSql,
          checksum: calculateMigrationChecksum(migrationSql),
        },
        {
          blockedVersion: LMS_PROVIDER_NARROWING_MIGRATION,
          repairFileName: LMS_PROVIDER_NARROWING_REPAIR,
        },
        {
          fileName: LMS_PROVIDER_NARROWING_REPAIR,
          sql: repairSql,
          checksum: calculateMigrationChecksum(repairSql),
        },
      );

      const unvalidated = await client.query<{ conname: string; convalidated: boolean }>(`
        SELECT conname, convalidated
        FROM pg_constraint
        WHERE conname IN (
          'badge_issuance_rules_lms_provider_kind_check',
          'badge_rule_version_snapshot_lms_provider_kind_check',
          'badge_rule_registry_projection_lms_provider_kind_check'
        )
          AND connamespace = current_schema()::regnamespace
        ORDER BY conname
      `);
      await client.query("COMMIT");

      expect(repaired).toBe(true);
      expect(unvalidated.rows).toEqual([
        {
          conname: "badge_issuance_rules_lms_provider_kind_check",
          convalidated: false,
        },
        {
          conname: "badge_rule_registry_projection_lms_provider_kind_check",
          convalidated: false,
        },
        {
          conname: "badge_rule_version_snapshot_lms_provider_kind_check",
          convalidated: false,
        },
      ]);

      const validationSql = await readFile(
        new URL(
          "../migrations/0079_validate_badge_rule_lms_provider_constraints.sql",
          import.meta.url,
        ),
        "utf8",
      );
      await client.query(validationSql);

      const rules = await client.query<{ id: string }>(
        "SELECT id FROM badge_issuance_rules ORDER BY id",
      );
      const placements = await client.query<{ id: string; rule_id: string | null }>(
        "SELECT id, rule_id FROM lti_resource_link_placements ORDER BY id",
      );
      const provenance = await client.query<{ assertion_id: string }>(
        "SELECT assertion_id FROM assertion_issuance_provenance ORDER BY assertion_id",
      );
      const validated = await client.query<{ convalidated: boolean }>(`
        SELECT convalidated
        FROM pg_constraint
        WHERE conname IN (
          'badge_issuance_rules_lms_provider_kind_check',
          'badge_rule_version_snapshot_lms_provider_kind_check',
          'badge_rule_registry_projection_lms_provider_kind_check'
        )
          AND connamespace = current_schema()::regnamespace
        ORDER BY conname
      `);

      expect(rules.rows).toEqual([{ id: "rule_supported" }]);
      expect(placements.rows).toEqual([
        { id: "placement_supported", rule_id: "rule_supported" },
        { id: "placement_unsupported", rule_id: null },
      ]);
      expect(provenance.rows).toEqual([{ assertion_id: "assertion_supported" }]);
      expect(validated.rows).toEqual([
        { convalidated: true },
        { convalidated: true },
        { convalidated: true },
      ]);
      await expect(
        client.query(`
          INSERT INTO badge_issuance_rules (id, tenant_id, lms_provider_kind)
          VALUES ('rule_invalid', 'tenant_123', 'moodle')
        `),
      ).rejects.toThrow("badge_issuance_rules_lms_provider_kind_check");
    } finally {
      await client.query("ROLLBACK");
      await client.query("RESET search_path");
      await client.query(`DROP SCHEMA IF EXISTS ${schemaName} CASCADE`);
      client.release();
      await pool.end();
    }
  });
});

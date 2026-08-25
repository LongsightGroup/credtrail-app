import { readFile } from "node:fs/promises";

import pg from "pg";
import { expect, it } from "vitest";

import { describeDbIntegration, requireTestDatabaseUrl } from "./postgres-test-support";

describeDbIntegration("reporting attribution backfill migration repair", () => {
  it("backfills assertion ID ranges idempotently", async () => {
    const schemaName = `repair_${crypto.randomUUID().replaceAll("-", "")}`;
    const pool = new pg.Pool({ connectionString: requireTestDatabaseUrl() });
    const client = await pool.connect();

    try {
      await client.query(`CREATE SCHEMA ${schemaName}`);
      await client.query(`SET search_path TO ${schemaName}`);
      await client.query(`
        CREATE TABLE badge_templates (
          tenant_id TEXT NOT NULL,
          id TEXT NOT NULL,
          owner_org_unit_id TEXT NOT NULL,
          PRIMARY KEY (tenant_id, id)
        );
        CREATE TABLE assertions (
          id TEXT PRIMARY KEY,
          tenant_id TEXT NOT NULL,
          badge_template_id TEXT NOT NULL,
          issued_at TEXT NOT NULL
        );
        CREATE TABLE badge_template_ownership_events (
          id TEXT PRIMARY KEY,
          tenant_id TEXT NOT NULL,
          badge_template_id TEXT NOT NULL,
          to_org_unit_id TEXT NOT NULL,
          transferred_at TEXT NOT NULL,
          created_at TEXT NOT NULL
        );
        CREATE TABLE assertion_reporting_attributions (
          assertion_id TEXT PRIMARY KEY,
          tenant_id TEXT NOT NULL,
          badge_template_id TEXT NOT NULL,
          org_unit_id TEXT NOT NULL,
          attribution_source TEXT NOT NULL,
          attributed_at TEXT NOT NULL,
          created_at TEXT NOT NULL,
          updated_at TEXT NOT NULL
        );
      `);
      await client.query(`
        INSERT INTO badge_templates (tenant_id, id, owner_org_unit_id)
        VALUES ('tenant_123', 'template_123', 'org_current');
        INSERT INTO badge_template_ownership_events (
          id,
          tenant_id,
          badge_template_id,
          to_org_unit_id,
          transferred_at,
          created_at
        )
        VALUES (
          'ownership_123',
          'tenant_123',
          'template_123',
          'org_historical',
          '2026-01-02T00:00:00.000Z',
          '2026-01-02T00:00:00.000Z'
        );
        INSERT INTO assertions (id, tenant_id, badge_template_id, issued_at)
        VALUES
          ('assertion_a', 'tenant_123', 'template_123', '2026-01-01T00:00:00.000Z'),
          ('assertion_z', 'tenant_123', 'template_123', '2026-01-03T00:00:00.000Z');
        INSERT INTO assertions (id, tenant_id, badge_template_id, issued_at)
        SELECT
          'bulk_' || LPAD(assertion_number::text, 5, '0'),
          'tenant_123',
          'template_123',
          '2026-01-03T00:00:00.000Z'
        FROM generate_series(1, 10001) assertion_number;
      `);

      const repairSql = await readFile(
        new URL(
          "../migration-repairs/0077_batch_assertion_reporting_attributions.sql",
          import.meta.url,
        ),
        "utf8",
      );
      await client.query(repairSql);
      await client.query(repairSql);

      const attributions = await client.query<{
        assertion_id: string;
        attribution_source: string;
        org_unit_id: string;
      }>(`
        SELECT assertion_id, attribution_source, org_unit_id
        FROM assertion_reporting_attributions
        WHERE assertion_id IN ('assertion_a', 'assertion_z')
        ORDER BY assertion_id
      `);
      const attributionCount = await client.query<{ total: number }>(`
        SELECT COUNT(*)::integer AS total
        FROM assertion_reporting_attributions
      `);

      expect(attributionCount.rows).toEqual([{ total: 10003 }]);
      expect(attributions.rows).toEqual([
        {
          assertion_id: "assertion_a",
          attribution_source: "current_owner_fallback",
          org_unit_id: "org_current",
        },
        {
          assertion_id: "assertion_z",
          attribution_source: "historical_backfill",
          org_unit_id: "org_historical",
        },
      ]);
    } finally {
      await client.query("ROLLBACK");
      await client.query("RESET search_path");
      await client.query(`DROP SCHEMA IF EXISTS ${schemaName} CASCADE`);
      client.release();
      await pool.end();
    }
  });
});

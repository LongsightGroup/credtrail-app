import { readdir, readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

import pg from "pg";

import {
  calculateMigrationChecksum,
  createMigrationPlan,
  parseAppliedMigrationRows,
  parseMigrationChecksumManifest,
  verifyMigrationChecksumManifest,
} from "./migration-integrity.mjs";

const { Pool } = pg;

const databaseUrl = process.env.DATABASE_URL?.trim();

if (databaseUrl === undefined || databaseUrl.length === 0) {
  throw new Error("DATABASE_URL is required");
}

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const migrationsDir = path.resolve(scriptDir, "../migrations");
const pool = new Pool({ connectionString: databaseUrl });

const migrationFileNames = (await readdir(migrationsDir))
  .filter((fileName) => fileName.endsWith(".sql"))
  .sort((left, right) => left.localeCompare(right));
const migrationFiles = await Promise.all(
  migrationFileNames.map(async (fileName) => {
    const sql = await readFile(path.join(migrationsDir, fileName), "utf8");
    return { fileName, sql, checksum: calculateMigrationChecksum(sql) };
  }),
);
const checksumManifestValue = JSON.parse(
  await readFile(path.join(migrationsDir, "checksums.json"), "utf8"),
);
const checksumManifest = parseMigrationChecksumManifest(checksumManifestValue);
verifyMigrationChecksumManifest(migrationFiles, checksumManifest);

const client = await pool.connect();
let migrationLockAcquired = false;

try {
  await client.query("SELECT pg_advisory_lock(hashtext('credtrail_schema_migrations'))");
  migrationLockAcquired = true;

  await client.query(`
    CREATE TABLE IF NOT EXISTS schema_migrations (
      version TEXT PRIMARY KEY,
      checksum TEXT,
      applied_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
    )
  `);

  await client.query("ALTER TABLE schema_migrations ADD COLUMN IF NOT EXISTS checksum TEXT");

  const appliedMigrationResult = await client.query(
    "SELECT version, checksum FROM schema_migrations ORDER BY version",
  );
  const migrationPlan = createMigrationPlan(
    migrationFiles,
    parseAppliedMigrationRows(appliedMigrationResult.rows),
  );

  for (const action of migrationPlan) {
    if (action.kind === "skip") {
      console.log(`Verified ${action.migration.fileName}`);
      continue;
    }

    await client.query("BEGIN");

    try {
      let successMessage;

      if (action.kind === "apply") {
        await client.query(action.migration.sql);
        await client.query("INSERT INTO schema_migrations (version, checksum) VALUES ($1, $2)", [
          action.migration.fileName,
          action.migration.checksum,
        ]);
        successMessage = `Applied ${action.migration.fileName}`;
      } else {
        const baselineResult = await client.query(
          "UPDATE schema_migrations SET checksum = $2 WHERE version = $1 AND checksum IS NULL",
          [action.migration.fileName, action.migration.checksum],
        );

        if (baselineResult.rowCount !== 1) {
          throw new Error(
            `Migration history changed while recording the checksum baseline for ${action.migration.fileName}`,
          );
        }

        successMessage = `Recorded checksum baseline for ${action.migration.fileName}`;
      }

      await client.query("COMMIT");
      console.log(successMessage);
    } catch (error) {
      await client.query("ROLLBACK");
      throw error;
    }
  }

  await client.query("BEGIN");

  try {
    await client.query("ALTER TABLE schema_migrations ALTER COLUMN checksum SET NOT NULL");
    await client.query(`
      DO $$
      BEGIN
        IF NOT EXISTS (
          SELECT 1
          FROM pg_constraint
          WHERE conname = 'schema_migrations_checksum_format_check'
            AND conrelid = 'schema_migrations'::regclass
        ) THEN
          ALTER TABLE schema_migrations
            ADD CONSTRAINT schema_migrations_checksum_format_check
            CHECK (checksum ~ '^[0-9a-f]{64}$');
        END IF;
      END $$
    `);
    await client.query("COMMIT");
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  }
} finally {
  try {
    if (migrationLockAcquired) {
      await client.query("SELECT pg_advisory_unlock(hashtext('credtrail_schema_migrations'))");
    }
  } finally {
    client.release();
    await pool.end();
  }
}

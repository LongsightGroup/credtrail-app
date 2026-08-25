import { readdir, readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

import pg from "pg";

import {
  ACHIEVEMENT_SNAPSHOT_MIGRATION,
  ACHIEVEMENT_SNAPSHOT_REPAIR,
  applyAchievementSnapshotMigrationRepair,
} from "./achievement-snapshot-migration-repair.mjs";
import {
  calculateMigrationChecksum,
  createMigrationPlan,
  parseAppliedMigrationRows,
  parseMigrationChecksumManifest,
  verifyMigrationChecksumManifest,
} from "./migration-integrity.mjs";
import {
  LMS_PROVIDER_NARROWING_MIGRATION,
  LMS_PROVIDER_NARROWING_REPAIR,
  REPORTING_ATTRIBUTION_BACKFILL_MIGRATION,
  REPORTING_ATTRIBUTION_BACKFILL_REPAIR,
  applyMigrationReplacement,
  verifyMigrationRepairHistory,
} from "./migration-replacements.mjs";

const { Pool } = pg;

const databaseUrl = process.env.DATABASE_URL?.trim();

if (databaseUrl === undefined || databaseUrl.length === 0) {
  throw new Error("DATABASE_URL is required");
}

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const migrationsDir = path.resolve(scriptDir, "../migrations");
const migrationRepairsDir = path.resolve(scriptDir, "../migration-repairs");
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
const achievementSnapshotRepairSql = await readFile(
  path.join(migrationRepairsDir, ACHIEVEMENT_SNAPSHOT_REPAIR),
  "utf8",
);
const achievementSnapshotRepair = {
  fileName: ACHIEVEMENT_SNAPSHOT_REPAIR,
  sql: achievementSnapshotRepairSql,
  checksum: calculateMigrationChecksum(achievementSnapshotRepairSql),
};
const reportingAttributionBackfillRepairSql = await readFile(
  path.join(migrationRepairsDir, REPORTING_ATTRIBUTION_BACKFILL_REPAIR),
  "utf8",
);
const reportingAttributionBackfillRepair = {
  fileName: REPORTING_ATTRIBUTION_BACKFILL_REPAIR,
  sql: reportingAttributionBackfillRepairSql,
  checksum: calculateMigrationChecksum(reportingAttributionBackfillRepairSql),
};
const lmsProviderNarrowingRepairSql = await readFile(
  path.join(migrationRepairsDir, LMS_PROVIDER_NARROWING_REPAIR),
  "utf8",
);
const lmsProviderNarrowingRepair = {
  fileName: LMS_PROVIDER_NARROWING_REPAIR,
  sql: lmsProviderNarrowingRepairSql,
  checksum: calculateMigrationChecksum(lmsProviderNarrowingRepairSql),
};
const migrationRepairManifestValue = JSON.parse(
  await readFile(path.join(migrationRepairsDir, "checksums.json"), "utf8"),
);
const migrationRepairManifest = parseMigrationChecksumManifest(migrationRepairManifestValue);
verifyMigrationChecksumManifest(
  [achievementSnapshotRepair, reportingAttributionBackfillRepair, lmsProviderNarrowingRepair],
  migrationRepairManifest,
);

const knownMigrationRepairs = [
  {
    blockedVersion: ACHIEVEMENT_SNAPSHOT_MIGRATION,
    repair: achievementSnapshotRepair,
  },
  {
    blockedVersion: REPORTING_ATTRIBUTION_BACKFILL_MIGRATION,
    repair: reportingAttributionBackfillRepair,
  },
  {
    blockedVersion: LMS_PROVIDER_NARROWING_MIGRATION,
    repair: lmsProviderNarrowingRepair,
  },
];

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
  await client.query(`
    CREATE TABLE IF NOT EXISTS schema_migration_repairs (
      repair_version TEXT PRIMARY KEY,
      blocked_version TEXT NOT NULL,
      repair_checksum TEXT NOT NULL CHECK (repair_checksum ~ '^[0-9a-f]{64}$'),
      applied_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
    )
  `);

  const migrationRepairHistory = await client.query(
    "SELECT repair_version, blocked_version, repair_checksum FROM schema_migration_repairs",
  );
  verifyMigrationRepairHistory(migrationRepairHistory.rows, knownMigrationRepairs);

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
        let appliedRepair;
        const achievementSnapshotRepaired = await applyAchievementSnapshotMigrationRepair(
          client,
          action.migration,
          achievementSnapshotRepair,
        );

        if (achievementSnapshotRepaired) {
          appliedRepair = achievementSnapshotRepair;
        }

        if (appliedRepair === undefined) {
          const reportingAttributionBackfillRepaired = await applyMigrationReplacement(
            client,
            action.migration,
            {
              blockedVersion: REPORTING_ATTRIBUTION_BACKFILL_MIGRATION,
              repairFileName: REPORTING_ATTRIBUTION_BACKFILL_REPAIR,
            },
            reportingAttributionBackfillRepair,
          );

          if (reportingAttributionBackfillRepaired) {
            appliedRepair = reportingAttributionBackfillRepair;
          }
        }

        if (appliedRepair === undefined) {
          const lmsProviderNarrowingRepaired = await applyMigrationReplacement(
            client,
            action.migration,
            {
              blockedVersion: LMS_PROVIDER_NARROWING_MIGRATION,
              repairFileName: LMS_PROVIDER_NARROWING_REPAIR,
            },
            lmsProviderNarrowingRepair,
          );

          if (lmsProviderNarrowingRepaired) {
            appliedRepair = lmsProviderNarrowingRepair;
          }
        }

        if (appliedRepair === undefined) {
          await client.query(action.migration.sql);
        }

        await client.query("INSERT INTO schema_migrations (version, checksum) VALUES ($1, $2)", [
          action.migration.fileName,
          action.migration.checksum,
        ]);
        successMessage = appliedRepair
          ? `Applied ${appliedRepair.fileName} in place of blocked ${action.migration.fileName}`
          : `Applied ${action.migration.fileName}`;
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

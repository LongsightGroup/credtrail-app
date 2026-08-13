/** The committed migration that requires a data-preserving populated-database repair. */
export const ACHIEVEMENT_SNAPSHOT_MIGRATION =
  "0063_badge_rule_achievement_snapshots.sql";

/** Stable audit identifier for the populated-database repair. */
export const ACHIEVEMENT_SNAPSHOT_REPAIR =
  "0063_preserve_populated_achievement_history.sql";

/**
 * Verify the persisted repair audit row against the committed repair artifact.
 *
 * @param {unknown} rows
 * @param {{ fileName: string, checksum: string }} repair
 * @returns {void}
 */
export const verifyAchievementSnapshotMigrationRepairHistory = (rows, repair) => {
  if (!Array.isArray(rows)) {
    throw new Error("Migration repair history query did not return rows");
  }

  for (const row of rows) {
    if (typeof row !== "object" || row === null) {
      throw new Error("Migration repair history contains an invalid row");
    }

    const repairVersion = Reflect.get(row, "repair_version");
    const blockedVersion = Reflect.get(row, "blocked_version");
    const repairChecksum = Reflect.get(row, "repair_checksum");

    if (
      repairVersion !== repair.fileName ||
      blockedVersion !== ACHIEVEMENT_SNAPSHOT_MIGRATION ||
      repairChecksum !== repair.checksum
    ) {
      throw new Error("Applied achievement snapshot migration repair does not match source");
    }
  }
};

/**
 * Apply the audited alternative schema transition when migration 0063 would
 * otherwise require deleting existing assertion or rule-version records.
 *
 * @param {import("pg").PoolClient} client
 * @param {{ fileName: string, sql: string, checksum: string }} migration
 * @param {{ fileName: string, sql: string, checksum: string }} repair
 * @returns {Promise<boolean>}
 */
export const applyAchievementSnapshotMigrationRepair = async (
  client,
  migration,
  repair,
) => {
  if (
    migration.fileName !== ACHIEVEMENT_SNAPSHOT_MIGRATION ||
    repair.fileName !== ACHIEVEMENT_SNAPSHOT_REPAIR
  ) {
    return false;
  }

  const populatedResult = await client.query(`
    SELECT
      EXISTS (SELECT 1 FROM badge_issuance_rule_versions LIMIT 1)
      OR EXISTS (SELECT 1 FROM assertions LIMIT 1) AS populated
  `);
  const populated = populatedResult.rows[0]?.populated;

  if (populated !== true) {
    return false;
  }

  await client.query(repair.sql);
  await client.query(
    `
      INSERT INTO schema_migration_repairs (
        repair_version,
        blocked_version,
        repair_checksum
      )
      VALUES ($1, $2, $3)
    `,
    [repair.fileName, migration.fileName, repair.checksum],
  );

  return true;
};

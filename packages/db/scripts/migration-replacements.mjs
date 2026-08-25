/** The committed reporting attribution migration replaced with bounded batches. */
export const REPORTING_ATTRIBUTION_BACKFILL_MIGRATION =
  "0077_backfill_assertion_reporting_attributions.sql";

/** Stable audit identifier for the bounded reporting attribution replacement. */
export const REPORTING_ATTRIBUTION_BACKFILL_REPAIR =
  "0077_batch_assertion_reporting_attributions.sql";

/** The committed provider-narrowing migration replaced with dependency cleanup. */
export const LMS_PROVIDER_NARROWING_MIGRATION = "0078_narrow_badge_rule_lms_providers.sql";

/** Stable audit identifier for the provider-narrowing replacement. */
export const LMS_PROVIDER_NARROWING_REPAIR = "0078_detach_dependents_and_narrow_lms_providers.sql";

/**
 * Verify all persisted repair audit rows against the known committed artifacts.
 *
 * @param {unknown} rows
 * @param {ReadonlyArray<{
 *   blockedVersion: string,
 *   repair: { fileName: string, checksum: string }
 * }>} knownRepairs
 * @returns {void}
 */
export const verifyMigrationRepairHistory = (rows, knownRepairs) => {
  if (!Array.isArray(rows)) {
    throw new Error("Migration repair history query did not return rows");
  }

  const repairsByVersion = new Map();

  for (const knownRepair of knownRepairs) {
    if (repairsByVersion.has(knownRepair.repair.fileName)) {
      throw new Error(`Duplicate known migration repair ${knownRepair.repair.fileName}`);
    }

    repairsByVersion.set(knownRepair.repair.fileName, knownRepair);
  }

  for (const row of rows) {
    if (typeof row !== "object" || row === null) {
      throw new Error("Migration repair history contains an invalid row");
    }

    const repairVersion = Reflect.get(row, "repair_version");
    const blockedVersion = Reflect.get(row, "blocked_version");
    const repairChecksum = Reflect.get(row, "repair_checksum");

    if (typeof repairVersion !== "string") {
      throw new Error("Migration repair history contains an invalid repair version");
    }

    const knownRepair = repairsByVersion.get(repairVersion);

    if (knownRepair === undefined) {
      throw new Error(`Applied migration repair ${repairVersion} is not a known artifact`);
    }

    if (
      blockedVersion !== knownRepair.blockedVersion ||
      repairChecksum !== knownRepair.repair.checksum
    ) {
      throw new Error(`Applied migration repair ${repairVersion} does not match source`);
    }
  }
};

/**
 * Apply an audited SQL replacement for one unapplied committed migration.
 *
 * @param {import("pg").PoolClient} client
 * @param {{ fileName: string, sql: string, checksum: string }} migration
 * @param {{ blockedVersion: string, repairFileName: string }} replacement
 * @param {{ fileName: string, sql: string, checksum: string }} repair
 * @returns {Promise<boolean>}
 */
export const applyMigrationReplacement = async (client, migration, replacement, repair) => {
  if (
    migration.fileName !== replacement.blockedVersion ||
    repair.fileName !== replacement.repairFileName
  ) {
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

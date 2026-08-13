import { createHash } from "node:crypto";

const SHA_256_HEX_PATTERN = /^[0-9a-f]{64}$/;

/**
 * @typedef {object} MigrationFile
 * @property {string} fileName
 * @property {string} sql
 * @property {string} checksum
 */

/**
 * @typedef {object} AppliedMigration
 * @property {string} version
 * @property {string | null} checksum
 */

/**
 * @typedef {
 *   | { kind: "apply", migration: MigrationFile }
 *   | { kind: "baseline", migration: MigrationFile }
 *   | { kind: "skip", migration: MigrationFile }
 * } MigrationAction
 */

/**
 * Calculate the canonical SHA-256 checksum for a migration's exact SQL bytes.
 *
 * @param {string} sql
 * @returns {string}
 */
export const calculateMigrationChecksum = (sql) =>
  createHash("sha256").update(sql, "utf8").digest("hex");

/**
 * Parse migration history rows returned by Postgres.
 *
 * @param {unknown} rows
 * @returns {Array<AppliedMigration>}
 */
export const parseAppliedMigrationRows = (rows) => {
  if (!Array.isArray(rows)) {
    throw new Error("Migration history query did not return rows");
  }

  return rows.map((row) => {
    if (typeof row !== "object" || row === null) {
      throw new Error("Migration history contains an invalid row");
    }

    const version = Reflect.get(row, "version");
    const checksum = Reflect.get(row, "checksum");

    if (typeof version !== "string" || version.length === 0) {
      throw new Error("Migration history contains an invalid version");
    }

    if (checksum !== null && typeof checksum !== "string") {
      throw new Error(`Migration history for ${version} contains an invalid checksum`);
    }

    return { version, checksum };
  });
};

/**
 * Parse the committed migration checksum manifest.
 *
 * @param {unknown} value
 * @returns {Map<string, string>}
 */
export const parseMigrationChecksumManifest = (value) => {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error("Migration checksum manifest must be an object");
  }

  const checksums = new Map();

  for (const [fileName, checksum] of Object.entries(value)) {
    if (
      !fileName.endsWith(".sql") ||
      typeof checksum !== "string" ||
      !SHA_256_HEX_PATTERN.test(checksum)
    ) {
      throw new Error(`Migration checksum manifest contains an invalid entry for ${fileName}`);
    }

    checksums.set(fileName, checksum);
  }

  return checksums;
};

/**
 * Verify every migration file against the committed checksum manifest.
 *
 * @param {ReadonlyArray<MigrationFile>} migrationFiles
 * @param {ReadonlyMap<string, string>} manifest
 * @returns {void}
 */
export const verifyMigrationChecksumManifest = (migrationFiles, manifest) => {
  const fileNames = new Set(migrationFiles.map((migration) => migration.fileName));

  for (const migration of migrationFiles) {
    const expectedChecksum = manifest.get(migration.fileName);

    if (expectedChecksum === undefined) {
      throw new Error(`Migration ${migration.fileName} is missing from the checksum manifest`);
    }

    if (expectedChecksum !== migration.checksum) {
      throw new Error(
        `Migration ${migration.fileName} does not match the committed checksum manifest`,
      );
    }
  }

  for (const fileName of manifest.keys()) {
    if (!fileNames.has(fileName)) {
      throw new Error(`Checksum manifest references missing migration ${fileName}`);
    }
  }
};

/**
 * Plan append-only migration actions and reject altered or missing history.
 * Null checksums are legacy rows that receive a one-time baseline without
 * reapplying their SQL.
 *
 * @param {ReadonlyArray<MigrationFile>} migrationFiles
 * @param {ReadonlyArray<AppliedMigration>} appliedMigrations
 * @returns {Array<MigrationAction>}
 */
export const createMigrationPlan = (migrationFiles, appliedMigrations) => {
  const sortedMigrations = [...migrationFiles].sort((left, right) =>
    left.fileName.localeCompare(right.fileName),
  );
  const migrationsByVersion = new Map();

  for (const migration of sortedMigrations) {
    if (migrationsByVersion.has(migration.fileName)) {
      throw new Error(`Duplicate migration file ${migration.fileName}`);
    }

    if (!SHA_256_HEX_PATTERN.test(migration.checksum)) {
      throw new Error(`Migration ${migration.fileName} has an invalid SHA-256 checksum`);
    }

    migrationsByVersion.set(migration.fileName, migration);
  }

  const appliedByVersion = new Map();

  for (const appliedMigration of appliedMigrations) {
    if (appliedByVersion.has(appliedMigration.version)) {
      throw new Error(`Migration history contains duplicate version ${appliedMigration.version}`);
    }

    if (!migrationsByVersion.has(appliedMigration.version)) {
      throw new Error(
        `Applied migration ${appliedMigration.version} is missing from the migration directory`,
      );
    }

    appliedByVersion.set(appliedMigration.version, appliedMigration);
  }

  const latestAppliedVersion = [...appliedByVersion.keys()]
    .sort((left, right) => left.localeCompare(right))
    .at(-1);

  return sortedMigrations.map((migration) => {
    const appliedMigration = appliedByVersion.get(migration.fileName);

    if (appliedMigration === undefined) {
      if (
        latestAppliedVersion !== undefined &&
        migration.fileName.localeCompare(latestAppliedVersion) < 0
      ) {
        throw new Error(
          `Migration ${migration.fileName} was inserted before already-applied ${latestAppliedVersion}; add a new migration after existing history`,
        );
      }

      return { kind: "apply", migration };
    }

    if (appliedMigration.checksum === null) {
      return { kind: "baseline", migration };
    }

    if (!SHA_256_HEX_PATTERN.test(appliedMigration.checksum)) {
      throw new Error(
        `Applied migration ${migration.fileName} has an invalid stored SHA-256 checksum`,
      );
    }

    if (appliedMigration.checksum !== migration.checksum) {
      throw new Error(
        `Applied migration ${migration.fileName} checksum mismatch: expected ${appliedMigration.checksum}, found ${migration.checksum}`,
      );
    }

    return { kind: "skip", migration };
  });
};

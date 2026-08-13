import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import test from "node:test";

import {
  calculateMigrationChecksum,
  createMigrationPlan,
  parseAppliedMigrationRows,
  parseMigrationChecksumManifest,
  verifyMigrationChecksumManifest,
} from "../packages/db/scripts/migration-integrity.mjs";

const migration = (fileName, sql) => ({
  fileName,
  sql,
  checksum: calculateMigrationChecksum(sql),
});

test("migration checksums are deterministic for exact SQL bytes", () => {
  const sql = "CREATE TABLE example (id TEXT PRIMARY KEY);\n";

  assert.equal(calculateMigrationChecksum(sql), calculateMigrationChecksum(sql));
  assert.notEqual(calculateMigrationChecksum(sql), calculateMigrationChecksum(`${sql}\n`));
});

test("existing installations receive a checksum baseline and then verify it", () => {
  const first = migration("0001_example.sql", "SELECT 1;\n");
  const baselinePlan = createMigrationPlan([first], [{ version: first.fileName, checksum: null }]);

  assert.deepEqual(
    baselinePlan.map((action) => action.kind),
    ["baseline"],
  );

  const verifiedPlan = createMigrationPlan(
    [first],
    [{ version: first.fileName, checksum: first.checksum }],
  );
  assert.deepEqual(
    verifiedPlan.map((action) => action.kind),
    ["skip"],
  );
});

test("changed applied migrations fail before new migrations are planned", () => {
  const first = migration("0001_example.sql", "SELECT 1;\n");
  const changed = migration(first.fileName, "SELECT 2;\n");

  assert.throws(
    () => createMigrationPlan([changed], [{ version: first.fileName, checksum: first.checksum }]),
    /checksum mismatch/,
  );
});

test("deleted and retroactively inserted migrations are rejected", () => {
  const first = migration("0001_example.sql", "SELECT 1;\n");
  const third = migration("0003_example.sql", "SELECT 3;\n");

  assert.throws(
    () => createMigrationPlan([third], [{ version: first.fileName, checksum: first.checksum }]),
    /missing from the migration directory/,
  );

  assert.throws(
    () =>
      createMigrationPlan(
        [first, migration("0002_example.sql", "SELECT 2;\n"), third],
        [
          { version: first.fileName, checksum: first.checksum },
          { version: third.fileName, checksum: third.checksum },
        ],
      ),
    /inserted before already-applied/,
  );
});

test("migration history rows are parsed at the database boundary", () => {
  assert.deepEqual(parseAppliedMigrationRows([{ version: "0001_example.sql", checksum: null }]), [
    { version: "0001_example.sql", checksum: null },
  ]);
  assert.throws(
    () => parseAppliedMigrationRows([{ version: "", checksum: null }]),
    /invalid version/,
  );
  assert.throws(
    () => parseAppliedMigrationRows([{ version: "0001_example.sql", checksum: 42 }]),
    /invalid checksum/,
  );
});

test("every committed migration matches the checksum manifest", () => {
  const migrationsDirectory = new URL("../packages/db/migrations/", import.meta.url);
  const migrationFiles = readdirSync(migrationsDirectory)
    .filter((fileName) => fileName.endsWith(".sql"))
    .map((fileName) => {
      const sql = readFileSync(new URL(fileName, migrationsDirectory), "utf8");
      return migration(fileName, sql);
    });
  const manifestValue = JSON.parse(
    readFileSync(new URL("checksums.json", migrationsDirectory), "utf8"),
  );
  const manifest = parseMigrationChecksumManifest(manifestValue);

  assert.doesNotThrow(() => verifyMigrationChecksumManifest(migrationFiles, manifest));
  assert.throws(
    () =>
      verifyMigrationChecksumManifest(
        [...migrationFiles, migration("0065_missing.sql", "")],
        manifest,
      ),
    /missing from the checksum manifest/,
  );
});

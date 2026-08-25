import type { PoolClient } from "pg";

/** Committed migration replaced with bounded reporting attribution batches. */
export const REPORTING_ATTRIBUTION_BACKFILL_MIGRATION: string;

/** Audit identifier for the bounded reporting attribution replacement. */
export const REPORTING_ATTRIBUTION_BACKFILL_REPAIR: string;

/** Committed migration replaced with dependency-safe provider narrowing. */
export const LMS_PROVIDER_NARROWING_MIGRATION: string;

/** Audit identifier for the dependency-safe provider narrowing replacement. */
export const LMS_PROVIDER_NARROWING_REPAIR: string;

/** Exact SQL artifact and its committed checksum. */
export interface MigrationSqlFile {
  readonly fileName: string;
  readonly sql: string;
  readonly checksum: string;
}

/** Expected audit identity for one known migration repair. */
export interface KnownMigrationRepair {
  readonly blockedVersion: string;
  readonly repair: Pick<MigrationSqlFile, "fileName" | "checksum">;
}

/** Mapping from an immutable migration to its audited replacement. */
export interface MigrationReplacement {
  readonly blockedVersion: string;
  readonly repairFileName: string;
}

/** Verifies persisted repair audit rows against the known committed artifacts. */
export function verifyMigrationRepairHistory(
  rows: unknown,
  knownRepairs: readonly KnownMigrationRepair[],
): void;

/** Applies and audits a replacement when it owns the supplied migration. */
export function applyMigrationReplacement(
  client: PoolClient,
  migration: MigrationSqlFile,
  replacement: MigrationReplacement,
  repair: MigrationSqlFile,
): Promise<boolean>;

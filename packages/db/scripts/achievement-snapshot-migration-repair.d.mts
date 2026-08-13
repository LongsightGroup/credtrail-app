import type { PoolClient } from "pg";

export const ACHIEVEMENT_SNAPSHOT_MIGRATION: string;
export const ACHIEVEMENT_SNAPSHOT_REPAIR: string;

export interface MigrationSqlFile {
  readonly fileName: string;
  readonly sql: string;
  readonly checksum: string;
}

export function applyAchievementSnapshotMigrationRepair(
  client: PoolClient,
  migration: MigrationSqlFile,
  repair: MigrationSqlFile,
): Promise<boolean>;

export function verifyAchievementSnapshotMigrationRepairHistory(
  rows: unknown,
  repair: Pick<MigrationSqlFile, "fileName" | "checksum">,
): void;

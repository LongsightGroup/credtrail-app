import { createPrefixedId } from "./shared-helpers";
import type { SqlDatabase, SqlQueryResult, SqlRunResult } from "./tenant-scope";

export interface AuditLogRecord {
  id: string;
  tenantId: string;
  actorUserId: string | null;
  action: string;
  targetType: string;
  targetId: string;
  metadataJson: string | null;
  occurredAt: string;
  createdAt: string;
}

export interface CreateAuditLogInput {
  tenantId: string;
  actorUserId?: string | undefined;
  action: string;
  targetType: string;
  targetId: string;
  metadata?: unknown;
  occurredAt?: string | undefined;
}

export interface ListAuditLogsInput {
  tenantId: string;
  action?: string | undefined;
  targetType?: string | undefined;
  targetId?: string | undefined;
  limit?: number | undefined;
}
interface AuditLogRow {
  id: string;
  tenantId: string;
  actorUserId: string | null;
  action: string;
  targetType: string;
  targetId: string;
  metadataJson: string | null;
  occurredAt: string;
  createdAt: string;
}
const isMissingAuditLogsTableError = (error: unknown): boolean => {
  if (!(error instanceof Error)) {
    return false;
  }

  return (
    (error.message.includes("no such table") ||
      error.message.includes("relation") ||
      error.message.includes("does not exist")) &&
    error.message.includes("audit_logs")
  );
};
const ensureAuditLogsTable = async (db: SqlDatabase): Promise<void> => {
  await db
    .prepare(
      `
      CREATE TABLE IF NOT EXISTS audit_logs (
        id TEXT PRIMARY KEY,
        tenant_id TEXT NOT NULL,
        actor_user_id TEXT,
        action TEXT NOT NULL,
        target_type TEXT NOT NULL,
        target_id TEXT NOT NULL,
        metadata_json TEXT,
        occurred_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (tenant_id) REFERENCES tenants (id) ON DELETE CASCADE,
        FOREIGN KEY (actor_user_id) REFERENCES users (id) ON DELETE SET NULL
      )
    `,
    )
    .run();

  await db
    .prepare(
      `
      CREATE INDEX IF NOT EXISTS idx_audit_logs_tenant_occurred_at
        ON audit_logs (tenant_id, occurred_at DESC)
    `,
    )
    .run();

  await db
    .prepare(
      `
      CREATE INDEX IF NOT EXISTS idx_audit_logs_action
        ON audit_logs (action)
    `,
    )
    .run();

  await db
    .prepare(
      `
      CREATE INDEX IF NOT EXISTS idx_audit_logs_tenant_target_occurred_at
        ON audit_logs (tenant_id, target_type, target_id, occurred_at DESC)
    `,
    )
    .run();
};
const mapAuditLogRow = (row: AuditLogRow): AuditLogRecord => {
  return {
    id: row.id,
    tenantId: row.tenantId,
    actorUserId: row.actorUserId,
    action: row.action,
    targetType: row.targetType,
    targetId: row.targetId,
    metadataJson: row.metadataJson,
    occurredAt: row.occurredAt,
    createdAt: row.createdAt,
  };
};
export const createAuditLog = async (
  db: SqlDatabase,
  input: CreateAuditLogInput,
): Promise<AuditLogRecord> => {
  const id = createPrefixedId("aud");
  const occurredAt = input.occurredAt ?? new Date().toISOString();
  const metadataJson = input.metadata === undefined ? null : JSON.stringify(input.metadata);

  const insertStatement = (): Promise<SqlRunResult> =>
    db
      .prepare(
        `
        INSERT INTO audit_logs (
          id,
          tenant_id,
          actor_user_id,
          action,
          target_type,
          target_id,
          metadata_json,
          occurred_at,
          created_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
      `,
      )
      .bind(
        id,
        input.tenantId,
        input.actorUserId ?? null,
        input.action,
        input.targetType,
        input.targetId,
        metadataJson,
        occurredAt,
        occurredAt,
      )
      .run();

  try {
    await insertStatement();
  } catch (error: unknown) {
    if (!isMissingAuditLogsTableError(error)) {
      throw error;
    }

    await ensureAuditLogsTable(db);
    await insertStatement();
  }

  const row = await db
    .prepare(
      `
      SELECT
        id,
        tenant_id AS tenantId,
        actor_user_id AS actorUserId,
        action,
        target_type AS targetType,
        target_id AS targetId,
        metadata_json AS metadataJson,
        occurred_at AS occurredAt,
        created_at AS createdAt
      FROM audit_logs
      WHERE id = ?
      LIMIT 1
    `,
    )
    .bind(id)
    .first<AuditLogRow>();

  if (row === null) {
    throw new Error(`Unable to create audit log "${id}"`);
  }

  return mapAuditLogRow(row);
};

export const listAuditLogs = async (
  db: SqlDatabase,
  input: ListAuditLogsInput,
): Promise<AuditLogRecord[]> => {
  const queryLimit = Math.max(1, Math.min(input.limit ?? 100, 200));
  const whereClauses = ["tenant_id = ?"];
  const queryParams: unknown[] = [input.tenantId];

  if (input.action !== undefined) {
    whereClauses.push("action = ?");
    queryParams.push(input.action);
  }

  if (input.targetType !== undefined) {
    whereClauses.push("target_type = ?");
    queryParams.push(input.targetType);
  }

  if (input.targetId !== undefined) {
    whereClauses.push("target_id = ?");
    queryParams.push(input.targetId);
  }

  const listStatement = (): Promise<SqlQueryResult<AuditLogRow>> =>
    db
      .prepare(
        `
        SELECT
          id,
          tenant_id AS tenantId,
          actor_user_id AS actorUserId,
          action,
          target_type AS targetType,
          target_id AS targetId,
          metadata_json AS metadataJson,
          occurred_at AS occurredAt,
          created_at AS createdAt
        FROM audit_logs
        WHERE ${whereClauses.join("\n          AND ")}
        ORDER BY occurred_at DESC, created_at DESC, id DESC
        LIMIT ?
      `,
      )
      .bind(...queryParams, queryLimit)
      .all<AuditLogRow>();

  let result: SqlQueryResult<AuditLogRow>;

  try {
    result = await listStatement();
  } catch (error: unknown) {
    if (!isMissingAuditLogsTableError(error)) {
      throw error;
    }

    await ensureAuditLogsTable(db);
    result = await listStatement();
  }

  return result.results.map((row) => mapAuditLogRow(row));
};

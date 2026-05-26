import { createPrefixedId } from "./shared-helpers";
import type { SqlDatabase, SqlQueryResult, SqlRunResult } from "./tenant-scope";

export interface DedicatedDbProvisioningRequestStatusInput {
  status: "pending" | "provisioned" | "failed" | "canceled";
}

export type DedicatedDbProvisioningRequestStatus =
  DedicatedDbProvisioningRequestStatusInput["status"];

export interface DedicatedDbProvisioningRequestRecord {
  id: string;
  tenantId: string;
  requestedByUserId: string | null;
  targetRegion: string;
  status: DedicatedDbProvisioningRequestStatus;
  dedicatedDatabaseUrl: string | null;
  notes: string | null;
  requestedAt: string;
  resolvedAt: string | null;
  createdAt: string;
  updatedAt: string;
}

export interface CreateDedicatedDbProvisioningRequestInput {
  tenantId: string;
  requestedByUserId?: string | undefined;
  targetRegion: string;
  notes?: string | undefined;
  requestedAt?: string | undefined;
}

export interface ListDedicatedDbProvisioningRequestsInput {
  tenantId: string;
  status?: DedicatedDbProvisioningRequestStatus | undefined;
}

export interface ResolveDedicatedDbProvisioningRequestInput {
  tenantId: string;
  requestId: string;
  status: Exclude<DedicatedDbProvisioningRequestStatus, "pending">;
  dedicatedDatabaseUrl?: string | undefined;
  notes?: string | undefined;
  resolvedAt?: string | undefined;
}

interface DedicatedDbProvisioningRequestRow {
  id: string;
  tenantId: string;
  requestedByUserId: string | null;
  targetRegion: string;
  status: DedicatedDbProvisioningRequestStatus;
  dedicatedDatabaseUrl: string | null;
  notes: string | null;
  requestedAt: string;
  resolvedAt: string | null;
  createdAt: string;
  updatedAt: string;
}

const isMissingDedicatedDbProvisioningRequestsTableError = (error: unknown): boolean => {
  if (!(error instanceof Error)) {
    return false;
  }

  return (
    (error.message.includes("no such table") ||
      error.message.includes("relation") ||
      error.message.includes("does not exist")) &&
    error.message.includes("tenant_dedicated_db_provisioning_requests")
  );
};

const ensureDedicatedDbProvisioningRequestsTable = async (db: SqlDatabase): Promise<void> => {
  await db
    .prepare(
      `
      CREATE TABLE IF NOT EXISTS tenant_dedicated_db_provisioning_requests (
        id TEXT PRIMARY KEY,
        tenant_id TEXT NOT NULL,
        requested_by_user_id TEXT,
        target_region TEXT NOT NULL,
        status TEXT NOT NULL CHECK (status IN ('pending', 'provisioned', 'failed', 'canceled')),
        dedicated_database_url TEXT,
        notes TEXT,
        requested_at TEXT NOT NULL,
        resolved_at TEXT,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (tenant_id) REFERENCES tenants (id) ON DELETE CASCADE,
        FOREIGN KEY (requested_by_user_id) REFERENCES users (id) ON DELETE SET NULL
      )
    `,
    )
    .run();

  await db
    .prepare(
      `
      CREATE INDEX IF NOT EXISTS idx_dedicated_db_provisioning_tenant_status
        ON tenant_dedicated_db_provisioning_requests (tenant_id, status, requested_at DESC)
    `,
    )
    .run();
};

const mapDedicatedDbProvisioningRequestRow = (
  row: DedicatedDbProvisioningRequestRow,
): DedicatedDbProvisioningRequestRecord => {
  return {
    id: row.id,
    tenantId: row.tenantId,
    requestedByUserId: row.requestedByUserId,
    targetRegion: row.targetRegion,
    status: row.status,
    dedicatedDatabaseUrl: row.dedicatedDatabaseUrl,
    notes: row.notes,
    requestedAt: row.requestedAt,
    resolvedAt: row.resolvedAt,
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
  };
};

export const createDedicatedDbProvisioningRequest = async (
  db: SqlDatabase,
  input: CreateDedicatedDbProvisioningRequestInput,
): Promise<DedicatedDbProvisioningRequestRecord> => {
  const id = createPrefixedId("dpr");
  const requestedAt = input.requestedAt ?? new Date().toISOString();
  const insertStatement = (): Promise<SqlRunResult> =>
    db
      .prepare(
        `
        INSERT INTO tenant_dedicated_db_provisioning_requests (
          id,
          tenant_id,
          requested_by_user_id,
          target_region,
          status,
          dedicated_database_url,
          notes,
          requested_at,
          resolved_at,
          created_at,
          updated_at
        )
        VALUES (?, ?, ?, ?, 'pending', NULL, ?, ?, NULL, ?, ?)
      `,
      )
      .bind(
        id,
        input.tenantId,
        input.requestedByUserId ?? null,
        input.targetRegion,
        input.notes ?? null,
        requestedAt,
        requestedAt,
        requestedAt,
      )
      .run();

  try {
    await insertStatement();
  } catch (error: unknown) {
    if (!isMissingDedicatedDbProvisioningRequestsTableError(error)) {
      throw error;
    }

    await ensureDedicatedDbProvisioningRequestsTable(db);
    await insertStatement();
  }

  const row = await db
    .prepare(
      `
      SELECT
        id,
        tenant_id AS tenantId,
        requested_by_user_id AS requestedByUserId,
        target_region AS targetRegion,
        status,
        dedicated_database_url AS dedicatedDatabaseUrl,
        notes,
        requested_at AS requestedAt,
        resolved_at AS resolvedAt,
        created_at AS createdAt,
        updated_at AS updatedAt
      FROM tenant_dedicated_db_provisioning_requests
      WHERE id = ?
      LIMIT 1
    `,
    )
    .bind(id)
    .first<DedicatedDbProvisioningRequestRow>();

  if (row === null) {
    throw new Error(`Unable to create dedicated DB provisioning request "${id}"`);
  }

  return mapDedicatedDbProvisioningRequestRow(row);
};

export const listDedicatedDbProvisioningRequests = async (
  db: SqlDatabase,
  input: ListDedicatedDbProvisioningRequestsInput,
): Promise<DedicatedDbProvisioningRequestRecord[]> => {
  const whereClauses = ["tenant_id = ?"];
  const queryParams: unknown[] = [input.tenantId];

  if (input.status !== undefined) {
    whereClauses.push("status = ?");
    queryParams.push(input.status);
  }

  const listStatement = (): Promise<SqlQueryResult<DedicatedDbProvisioningRequestRow>> =>
    db
      .prepare(
        `
        SELECT
          id,
          tenant_id AS tenantId,
          requested_by_user_id AS requestedByUserId,
          target_region AS targetRegion,
          status,
          dedicated_database_url AS dedicatedDatabaseUrl,
          notes,
          requested_at AS requestedAt,
          resolved_at AS resolvedAt,
          created_at AS createdAt,
          updated_at AS updatedAt
        FROM tenant_dedicated_db_provisioning_requests
        WHERE ${whereClauses.join("\n          AND ")}
        ORDER BY requested_at DESC, created_at DESC
      `,
      )
      .bind(...queryParams)
      .all<DedicatedDbProvisioningRequestRow>();

  let result: SqlQueryResult<DedicatedDbProvisioningRequestRow>;

  try {
    result = await listStatement();
  } catch (error: unknown) {
    if (!isMissingDedicatedDbProvisioningRequestsTableError(error)) {
      throw error;
    }

    await ensureDedicatedDbProvisioningRequestsTable(db);
    result = await listStatement();
  }

  return result.results.map((row) => mapDedicatedDbProvisioningRequestRow(row));
};

export const resolveDedicatedDbProvisioningRequest = async (
  db: SqlDatabase,
  input: ResolveDedicatedDbProvisioningRequestInput,
): Promise<DedicatedDbProvisioningRequestRecord | null> => {
  const resolvedAt = input.resolvedAt ?? new Date().toISOString();
  let result: SqlRunResult;
  const updateStatement = (): Promise<SqlRunResult> =>
    db
      .prepare(
        `
        UPDATE tenant_dedicated_db_provisioning_requests
        SET
          status = ?,
          dedicated_database_url = ?,
          notes = ?,
          resolved_at = ?,
          updated_at = ?
        WHERE tenant_id = ?
          AND id = ?
          AND status = 'pending'
      `,
      )
      .bind(
        input.status,
        input.dedicatedDatabaseUrl ?? null,
        input.notes ?? null,
        resolvedAt,
        resolvedAt,
        input.tenantId,
        input.requestId,
      )
      .run();

  try {
    result = await updateStatement();
  } catch (error: unknown) {
    if (!isMissingDedicatedDbProvisioningRequestsTableError(error)) {
      throw error;
    }

    await ensureDedicatedDbProvisioningRequestsTable(db);
    result = await updateStatement();
  }

  if ((result.meta.rowsWritten ?? 0) === 0) {
    return null;
  }

  const row = await db
    .prepare(
      `
      SELECT
        id,
        tenant_id AS tenantId,
        requested_by_user_id AS requestedByUserId,
        target_region AS targetRegion,
        status,
        dedicated_database_url AS dedicatedDatabaseUrl,
        notes,
        requested_at AS requestedAt,
        resolved_at AS resolvedAt,
        created_at AS createdAt,
        updated_at AS updatedAt
      FROM tenant_dedicated_db_provisioning_requests
      WHERE tenant_id = ?
        AND id = ?
      LIMIT 1
    `,
    )
    .bind(input.tenantId, input.requestId)
    .first<DedicatedDbProvisioningRequestRow>();

  return row === null ? null : mapDedicatedDbProvisioningRequestRow(row);
};

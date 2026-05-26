import { createPrefixedId } from "./shared-helpers";
import type { SqlDatabase, SqlQueryResult, SqlRunResult } from "./tenant-scope";

export interface TenantApiKeyRecord {
  id: string;
  tenantId: string;
  label: string;
  keyPrefix: string;
  keyHash: string;
  scopesJson: string;
  createdByUserId: string | null;
  expiresAt: string | null;
  lastUsedAt: string | null;
  revokedAt: string | null;
  createdAt: string;
  updatedAt: string;
}

export interface CreateTenantApiKeyInput {
  tenantId: string;
  label: string;
  keyPrefix: string;
  keyHash: string;
  scopesJson: string;
  createdByUserId?: string | undefined;
  expiresAt?: string | undefined;
}

export interface ListTenantApiKeysInput {
  tenantId: string;
  includeRevoked?: boolean | undefined;
}

export interface RevokeTenantApiKeyInput {
  tenantId: string;
  apiKeyId: string;
  revokedAt: string;
}

export interface FindActiveTenantApiKeyByHashInput {
  keyHash: string;
  nowIso: string;
}
interface TenantApiKeyRow {
  id: string;
  tenantId: string;
  label: string;
  keyPrefix: string;
  keyHash: string;
  scopesJson: string;
  createdByUserId: string | null;
  expiresAt: string | null;
  lastUsedAt: string | null;
  revokedAt: string | null;
  createdAt: string;
  updatedAt: string;
}
const isMissingTenantApiKeysTableError = (error: unknown): boolean => {
  if (!(error instanceof Error)) {
    return false;
  }

  return (
    (error.message.includes("no such table") ||
      error.message.includes("relation") ||
      error.message.includes("does not exist")) &&
    error.message.includes("tenant_api_keys")
  );
};
const ensureTenantApiKeysTable = async (db: SqlDatabase): Promise<void> => {
  await db
    .prepare(
      `
      CREATE TABLE IF NOT EXISTS tenant_api_keys (
        id TEXT PRIMARY KEY,
        tenant_id TEXT NOT NULL,
        label TEXT NOT NULL,
        key_prefix TEXT NOT NULL,
        key_hash TEXT NOT NULL UNIQUE,
        scopes_json TEXT NOT NULL,
        created_by_user_id TEXT,
        expires_at TEXT,
        last_used_at TEXT,
        revoked_at TEXT,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (tenant_id) REFERENCES tenants (id) ON DELETE CASCADE,
        FOREIGN KEY (created_by_user_id) REFERENCES users (id) ON DELETE SET NULL
      )
    `,
    )
    .run();

  await db
    .prepare(
      `
      CREATE INDEX IF NOT EXISTS idx_tenant_api_keys_tenant_active
        ON tenant_api_keys (tenant_id, revoked_at, expires_at, created_at DESC)
    `,
    )
    .run();
};
const mapTenantApiKeyRow = (row: TenantApiKeyRow): TenantApiKeyRecord => {
  return {
    id: row.id,
    tenantId: row.tenantId,
    label: row.label,
    keyPrefix: row.keyPrefix,
    keyHash: row.keyHash,
    scopesJson: row.scopesJson,
    createdByUserId: row.createdByUserId,
    expiresAt: row.expiresAt,
    lastUsedAt: row.lastUsedAt,
    revokedAt: row.revokedAt,
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
  };
};
export const createTenantApiKey = async (
  db: SqlDatabase,
  input: CreateTenantApiKeyInput,
): Promise<TenantApiKeyRecord> => {
  const id = createPrefixedId("tak");
  const nowIso = new Date().toISOString();
  const insertStatement = (): Promise<SqlRunResult> =>
    db
      .prepare(
        `
        INSERT INTO tenant_api_keys (
          id,
          tenant_id,
          label,
          key_prefix,
          key_hash,
          scopes_json,
          created_by_user_id,
          expires_at,
          last_used_at,
          revoked_at,
          created_at,
          updated_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, ?, ?)
      `,
      )
      .bind(
        id,
        input.tenantId,
        input.label,
        input.keyPrefix,
        input.keyHash,
        input.scopesJson,
        input.createdByUserId ?? null,
        input.expiresAt ?? null,
        nowIso,
        nowIso,
      )
      .run();

  try {
    await insertStatement();
  } catch (error: unknown) {
    if (!isMissingTenantApiKeysTableError(error)) {
      throw error;
    }

    await ensureTenantApiKeysTable(db);
    await insertStatement();
  }

  const row = await db
    .prepare(
      `
      SELECT
        id,
        tenant_id AS tenantId,
        label,
        key_prefix AS keyPrefix,
        key_hash AS keyHash,
        scopes_json AS scopesJson,
        created_by_user_id AS createdByUserId,
        expires_at AS expiresAt,
        last_used_at AS lastUsedAt,
        revoked_at AS revokedAt,
        created_at AS createdAt,
        updated_at AS updatedAt
      FROM tenant_api_keys
      WHERE id = ?
      LIMIT 1
    `,
    )
    .bind(id)
    .first<TenantApiKeyRow>();

  if (row === null) {
    throw new Error(`Unable to create tenant API key "${id}"`);
  }

  return mapTenantApiKeyRow(row);
};

export const listTenantApiKeys = async (
  db: SqlDatabase,
  input: ListTenantApiKeysInput,
): Promise<TenantApiKeyRecord[]> => {
  const query = input.includeRevoked
    ? `
      SELECT
        id,
        tenant_id AS tenantId,
        label,
        key_prefix AS keyPrefix,
        key_hash AS keyHash,
        scopes_json AS scopesJson,
        created_by_user_id AS createdByUserId,
        expires_at AS expiresAt,
        last_used_at AS lastUsedAt,
        revoked_at AS revokedAt,
        created_at AS createdAt,
        updated_at AS updatedAt
      FROM tenant_api_keys
      WHERE tenant_id = ?
      ORDER BY created_at DESC
    `
    : `
      SELECT
        id,
        tenant_id AS tenantId,
        label,
        key_prefix AS keyPrefix,
        key_hash AS keyHash,
        scopes_json AS scopesJson,
        created_by_user_id AS createdByUserId,
        expires_at AS expiresAt,
        last_used_at AS lastUsedAt,
        revoked_at AS revokedAt,
        created_at AS createdAt,
        updated_at AS updatedAt
      FROM tenant_api_keys
      WHERE tenant_id = ?
        AND revoked_at IS NULL
      ORDER BY created_at DESC
    `;

  let result: SqlQueryResult<TenantApiKeyRow>;

  try {
    result = await db.prepare(query).bind(input.tenantId).all<TenantApiKeyRow>();
  } catch (error: unknown) {
    if (!isMissingTenantApiKeysTableError(error)) {
      throw error;
    }

    await ensureTenantApiKeysTable(db);
    result = await db.prepare(query).bind(input.tenantId).all<TenantApiKeyRow>();
  }

  return result.results.map((row) => mapTenantApiKeyRow(row));
};

export const findActiveTenantApiKeyByHash = async (
  db: SqlDatabase,
  input: FindActiveTenantApiKeyByHashInput,
): Promise<TenantApiKeyRecord | null> => {
  const lookupStatement = (): Promise<TenantApiKeyRow | null> =>
    db
      .prepare(
        `
        SELECT
          id,
          tenant_id AS tenantId,
          label,
          key_prefix AS keyPrefix,
          key_hash AS keyHash,
          scopes_json AS scopesJson,
          created_by_user_id AS createdByUserId,
          expires_at AS expiresAt,
          last_used_at AS lastUsedAt,
          revoked_at AS revokedAt,
          created_at AS createdAt,
          updated_at AS updatedAt
        FROM tenant_api_keys
        WHERE key_hash = ?
          AND revoked_at IS NULL
          AND (expires_at IS NULL OR expires_at > ?)
        LIMIT 1
      `,
      )
      .bind(input.keyHash, input.nowIso)
      .first<TenantApiKeyRow>();

  let row: TenantApiKeyRow | null;

  try {
    row = await lookupStatement();
  } catch (error: unknown) {
    if (!isMissingTenantApiKeysTableError(error)) {
      throw error;
    }

    await ensureTenantApiKeysTable(db);
    row = await lookupStatement();
  }

  return row === null ? null : mapTenantApiKeyRow(row);
};

export const touchTenantApiKeyLastUsedAt = async (
  db: SqlDatabase,
  id: string,
  lastUsedAt: string,
): Promise<void> => {
  const touchStatement = (): Promise<SqlRunResult> =>
    db
      .prepare(
        `
        UPDATE tenant_api_keys
        SET
          last_used_at = ?,
          updated_at = ?
        WHERE id = ?
      `,
      )
      .bind(lastUsedAt, lastUsedAt, id)
      .run();

  try {
    await touchStatement();
  } catch (error: unknown) {
    if (!isMissingTenantApiKeysTableError(error)) {
      throw error;
    }

    await ensureTenantApiKeysTable(db);
    await touchStatement();
  }
};

export const revokeTenantApiKey = async (
  db: SqlDatabase,
  input: RevokeTenantApiKeyInput,
): Promise<boolean> => {
  const updateStatement = (): Promise<SqlRunResult> =>
    db
      .prepare(
        `
        UPDATE tenant_api_keys
        SET
          revoked_at = ?,
          updated_at = ?
        WHERE tenant_id = ?
          AND id = ?
          AND revoked_at IS NULL
      `,
      )
      .bind(input.revokedAt, input.revokedAt, input.tenantId, input.apiKeyId)
      .run();

  let result: SqlRunResult;

  try {
    result = await updateStatement();
  } catch (error: unknown) {
    if (!isMissingTenantApiKeysTableError(error)) {
      throw error;
    }

    await ensureTenantApiKeysTable(db);
    result = await updateStatement();
  }

  return (result.meta.rowsWritten ?? 0) > 0;
};

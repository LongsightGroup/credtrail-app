import { createPrefixedId } from "./shared-helpers";
import type { SqlDatabase, SqlQueryResult, SqlRunResult } from "./tenant-scope";

export interface Ob3SubjectCredentialRecord {
  id: string;
  tenantId: string;
  userId: string;
  credentialId: string;
  payloadJson: string | null;
  compactJws: string | null;
  issuedAt: string;
  createdAt: string;
  updatedAt: string;
}

export interface UpsertOb3SubjectCredentialInput {
  tenantId: string;
  userId: string;
  credentialId: string;
  payloadJson?: string | null | undefined;
  compactJws?: string | null | undefined;
  issuedAt?: string | undefined;
}

export interface UpsertOb3SubjectCredentialResult {
  status: "created" | "updated";
  credential: Ob3SubjectCredentialRecord;
}

export interface ListOb3SubjectCredentialsInput {
  tenantId: string;
  userId: string;
  limit: number;
  offset: number;
  since?: string | undefined;
}

export interface ListOb3SubjectCredentialsResult {
  totalCount: number;
  credentials: Ob3SubjectCredentialRecord[];
}

export interface Ob3SubjectProfileRecord {
  tenantId: string;
  userId: string;
  profileJson: string;
  createdAt: string;
  updatedAt: string;
}

export interface UpsertOb3SubjectProfileInput {
  tenantId: string;
  userId: string;
  profileJson: string;
}

interface Ob3SubjectCredentialRow {
  id: string;
  tenantId: string;
  userId: string;
  credentialId: string;
  payloadJson: string | null;
  compactJws: string | null;
  issuedAt: string;
  createdAt: string;
  updatedAt: string;
}

interface Ob3SubjectCredentialCountRow {
  totalCount: number | string;
}

interface Ob3SubjectProfileRow {
  tenantId: string;
  userId: string;
  profileJson: string;
  createdAt: string;
  updatedAt: string;
}

const mapOb3SubjectCredentialRow = (row: Ob3SubjectCredentialRow): Ob3SubjectCredentialRecord => {
  return {
    id: row.id,
    tenantId: row.tenantId,
    userId: row.userId,
    credentialId: row.credentialId,
    payloadJson: row.payloadJson,
    compactJws: row.compactJws,
    issuedAt: row.issuedAt,
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
  };
};

const mapOb3SubjectProfileRow = (row: Ob3SubjectProfileRow): Ob3SubjectProfileRecord => {
  return {
    tenantId: row.tenantId,
    userId: row.userId,
    profileJson: row.profileJson,
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
  };
};

export const listOb3SubjectCredentials = async (
  db: SqlDatabase,
  input: ListOb3SubjectCredentialsInput,
): Promise<ListOb3SubjectCredentialsResult> => {
  const normalizedLimit = Math.max(1, Math.trunc(input.limit));
  const normalizedOffset = Math.max(0, Math.trunc(input.offset));
  const sinceFilter = input.since === undefined ? "" : " AND issued_at > ?";
  const sharedParams: unknown[] =
    input.since === undefined
      ? [input.tenantId, input.userId]
      : [input.tenantId, input.userId, input.since];
  const countStatement = (): Promise<Ob3SubjectCredentialCountRow | null> =>
    db
      .prepare(
        `
        SELECT COUNT(*) AS totalCount
        FROM ob3_subject_credentials
        WHERE tenant_id = ?
          AND user_id = ?${sinceFilter}
      `,
      )
      .bind(...sharedParams)
      .first<Ob3SubjectCredentialCountRow>();
  const listStatement = (): Promise<SqlQueryResult<Ob3SubjectCredentialRow>> =>
    db
      .prepare(
        `
        SELECT
          id,
          tenant_id AS tenantId,
          user_id AS userId,
          credential_id AS credentialId,
          payload_json AS payloadJson,
          compact_jws AS compactJws,
          issued_at AS issuedAt,
          created_at AS createdAt,
          updated_at AS updatedAt
        FROM ob3_subject_credentials
        WHERE tenant_id = ?
          AND user_id = ?${sinceFilter}
        ORDER BY issued_at DESC, id DESC
        LIMIT ?
        OFFSET ?
      `,
      )
      .bind(...sharedParams, normalizedLimit, normalizedOffset)
      .all<Ob3SubjectCredentialRow>();

  const totalCountRow = await countStatement();
  const rowsResult = await listStatement();

  const rawTotalCount = totalCountRow?.totalCount ?? 0;
  const totalCount = Number.isFinite(Number(rawTotalCount)) ? Number(rawTotalCount) : 0;

  return {
    totalCount,
    credentials: rowsResult.results.map((row) => mapOb3SubjectCredentialRow(row)),
  };
};

export const upsertOb3SubjectCredential = async (
  db: SqlDatabase,
  input: UpsertOb3SubjectCredentialInput,
): Promise<UpsertOb3SubjectCredentialResult> => {
  const nowIso = new Date().toISOString();
  const issuedAt = input.issuedAt ?? nowIso;
  const safePayloadJson = input.payloadJson ?? null;
  const safeCompactJws = input.compactJws ?? null;
  const selectStatement = (): Promise<Ob3SubjectCredentialRow | null> =>
    db
      .prepare(
        `
        SELECT
          id,
          tenant_id AS tenantId,
          user_id AS userId,
          credential_id AS credentialId,
          payload_json AS payloadJson,
          compact_jws AS compactJws,
          issued_at AS issuedAt,
          created_at AS createdAt,
          updated_at AS updatedAt
        FROM ob3_subject_credentials
        WHERE tenant_id = ?
          AND user_id = ?
          AND credential_id = ?
        LIMIT 1
      `,
      )
      .bind(input.tenantId, input.userId, input.credentialId)
      .first<Ob3SubjectCredentialRow>();
  const upsertStatement = (id: string): Promise<SqlRunResult> =>
    db
      .prepare(
        `
        INSERT INTO ob3_subject_credentials (
          id,
          tenant_id,
          user_id,
          credential_id,
          payload_json,
          compact_jws,
          issued_at,
          created_at,
          updated_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT (tenant_id, user_id, credential_id)
        DO UPDATE SET
          payload_json = excluded.payload_json,
          compact_jws = excluded.compact_jws,
          issued_at = excluded.issued_at,
          updated_at = excluded.updated_at
      `,
      )
      .bind(
        id,
        input.tenantId,
        input.userId,
        input.credentialId,
        safePayloadJson,
        safeCompactJws,
        issuedAt,
        nowIso,
        nowIso,
      )
      .run();

  const existingCredential = await selectStatement();

  const credentialId = existingCredential?.id ?? createPrefixedId("ob3c");
  await upsertStatement(credentialId);
  const persistedCredential = await selectStatement();

  if (persistedCredential === null) {
    throw new Error(
      `Failed to upsert OB3 subject credential "${input.tenantId}:${input.userId}:${input.credentialId}"`,
    );
  }

  return {
    status: existingCredential === null ? "created" : "updated",
    credential: mapOb3SubjectCredentialRow(persistedCredential),
  };
};

export const findOb3SubjectProfile = async (
  db: SqlDatabase,
  input: {
    tenantId: string;
    userId: string;
  },
): Promise<Ob3SubjectProfileRecord | null> => {
  const findStatement = (): Promise<Ob3SubjectProfileRow | null> =>
    db
      .prepare(
        `
        SELECT
          tenant_id AS tenantId,
          user_id AS userId,
          profile_json AS profileJson,
          created_at AS createdAt,
          updated_at AS updatedAt
        FROM ob3_subject_profiles
        WHERE tenant_id = ?
          AND user_id = ?
        LIMIT 1
      `,
      )
      .bind(input.tenantId, input.userId)
      .first<Ob3SubjectProfileRow>();

  const row = await findStatement();

  return row === null ? null : mapOb3SubjectProfileRow(row);
};

export const upsertOb3SubjectProfile = async (
  db: SqlDatabase,
  input: UpsertOb3SubjectProfileInput,
): Promise<Ob3SubjectProfileRecord> => {
  const nowIso = new Date().toISOString();
  const upsertStatement = (): Promise<SqlRunResult> =>
    db
      .prepare(
        `
        INSERT INTO ob3_subject_profiles (
          tenant_id,
          user_id,
          profile_json,
          created_at,
          updated_at
        )
        VALUES (?, ?, ?, ?, ?)
        ON CONFLICT (tenant_id, user_id)
        DO UPDATE SET
          profile_json = excluded.profile_json,
          updated_at = excluded.updated_at
      `,
      )
      .bind(input.tenantId, input.userId, input.profileJson, nowIso, nowIso)
      .run();
  const findStatement = (): Promise<Ob3SubjectProfileRow | null> =>
    db
      .prepare(
        `
        SELECT
          tenant_id AS tenantId,
          user_id AS userId,
          profile_json AS profileJson,
          created_at AS createdAt,
          updated_at AS updatedAt
        FROM ob3_subject_profiles
        WHERE tenant_id = ?
          AND user_id = ?
        LIMIT 1
      `,
      )
      .bind(input.tenantId, input.userId)
      .first<Ob3SubjectProfileRow>();

  await upsertStatement();

  const row = await findStatement();

  if (row === null) {
    throw new Error(`Failed to upsert OB3 subject profile "${input.tenantId}:${input.userId}"`);
  }

  return mapOb3SubjectProfileRow(row);
};

import { createPrefixedId } from "./shared-helpers";
import type { SqlDatabase, SqlRunResult } from "./tenant-scope";

export interface Oid4vciPreAuthorizedCodeRecord {
  id: string;
  codeHash: string;
  tenantId: string;
  assertionId: string;
  publicBadgeId: string;
  expiresAt: string;
  usedAt: string | null;
  createdAt: string;
}

export interface CreateOid4vciPreAuthorizedCodeInput {
  codeHash: string;
  tenantId: string;
  assertionId: string;
  publicBadgeId: string;
  expiresAt: string;
}

export interface ConsumeOid4vciPreAuthorizedCodeInput {
  codeHash: string;
  nowIso: string;
}

export interface Oid4vciAccessTokenRecord {
  id: string;
  accessTokenHash: string;
  tenantId: string;
  assertionId: string;
  expiresAt: string;
  revokedAt: string | null;
  createdAt: string;
}

export interface CreateOid4vciAccessTokenInput {
  accessTokenHash: string;
  tenantId: string;
  assertionId: string;
  expiresAt: string;
}

export interface FindActiveOid4vciAccessTokenByHashInput {
  accessTokenHash: string;
  nowIso: string;
}

interface Oid4vciPreAuthorizedCodeRow {
  id: string;
  codeHash: string;
  tenantId: string;
  assertionId: string;
  publicBadgeId: string;
  expiresAt: string;
  usedAt: string | null;
  createdAt: string;
}

interface Oid4vciAccessTokenRow {
  id: string;
  accessTokenHash: string;
  tenantId: string;
  assertionId: string;
  expiresAt: string;
  revokedAt: string | null;
  createdAt: string;
}

const mapOid4vciPreAuthorizedCodeRow = (
  row: Oid4vciPreAuthorizedCodeRow,
): Oid4vciPreAuthorizedCodeRecord => {
  return {
    id: row.id,
    codeHash: row.codeHash,
    tenantId: row.tenantId,
    assertionId: row.assertionId,
    publicBadgeId: row.publicBadgeId,
    expiresAt: row.expiresAt,
    usedAt: row.usedAt,
    createdAt: row.createdAt,
  };
};

const mapOid4vciAccessTokenRow = (row: Oid4vciAccessTokenRow): Oid4vciAccessTokenRecord => {
  return {
    id: row.id,
    accessTokenHash: row.accessTokenHash,
    tenantId: row.tenantId,
    assertionId: row.assertionId,
    expiresAt: row.expiresAt,
    revokedAt: row.revokedAt,
    createdAt: row.createdAt,
  };
};

export const createOid4vciPreAuthorizedCode = async (
  db: SqlDatabase,
  input: CreateOid4vciPreAuthorizedCodeInput,
): Promise<Oid4vciPreAuthorizedCodeRecord> => {
  const id = createPrefixedId("ovp");
  const createdAt = new Date().toISOString();

  const insertStatement = (): Promise<SqlRunResult> =>
    db
      .prepare(
        `
        INSERT INTO oid4vci_pre_authorized_codes (
          id,
          code_hash,
          tenant_id,
          assertion_id,
          public_badge_id,
          expires_at,
          created_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?)
      `,
      )
      .bind(
        id,
        input.codeHash,
        input.tenantId,
        input.assertionId,
        input.publicBadgeId,
        input.expiresAt,
        createdAt,
      )
      .run();

  await insertStatement();

  return {
    id,
    codeHash: input.codeHash,
    tenantId: input.tenantId,
    assertionId: input.assertionId,
    publicBadgeId: input.publicBadgeId,
    expiresAt: input.expiresAt,
    usedAt: null,
    createdAt,
  };
};

export const consumeOid4vciPreAuthorizedCode = async (
  db: SqlDatabase,
  input: ConsumeOid4vciPreAuthorizedCodeInput,
): Promise<Oid4vciPreAuthorizedCodeRecord | null> => {
  const consumeStatement = (): Promise<Oid4vciPreAuthorizedCodeRow | null> =>
    db
      .prepare(
        `
        UPDATE oid4vci_pre_authorized_codes
        SET used_at = ?
        WHERE code_hash = ?
          AND used_at IS NULL
          AND expires_at > ?
        RETURNING
          id,
          code_hash AS codeHash,
          tenant_id AS tenantId,
          assertion_id AS assertionId,
          public_badge_id AS publicBadgeId,
          expires_at AS expiresAt,
          used_at AS usedAt,
          created_at AS createdAt
      `,
      )
      .bind(input.nowIso, input.codeHash, input.nowIso)
      .first<Oid4vciPreAuthorizedCodeRow>();

  const row = await consumeStatement();

  return row === null ? null : mapOid4vciPreAuthorizedCodeRow(row);
};

export const createOid4vciAccessToken = async (
  db: SqlDatabase,
  input: CreateOid4vciAccessTokenInput,
): Promise<Oid4vciAccessTokenRecord> => {
  const id = createPrefixedId("ova");
  const createdAt = new Date().toISOString();

  const insertStatement = (): Promise<SqlRunResult> =>
    db
      .prepare(
        `
        INSERT INTO oid4vci_access_tokens (
          id,
          access_token_hash,
          tenant_id,
          assertion_id,
          expires_at,
          created_at
        )
        VALUES (?, ?, ?, ?, ?, ?)
      `,
      )
      .bind(
        id,
        input.accessTokenHash,
        input.tenantId,
        input.assertionId,
        input.expiresAt,
        createdAt,
      )
      .run();

  await insertStatement();

  return {
    id,
    accessTokenHash: input.accessTokenHash,
    tenantId: input.tenantId,
    assertionId: input.assertionId,
    expiresAt: input.expiresAt,
    revokedAt: null,
    createdAt,
  };
};

export const findActiveOid4vciAccessTokenByHash = async (
  db: SqlDatabase,
  input: FindActiveOid4vciAccessTokenByHashInput,
): Promise<Oid4vciAccessTokenRecord | null> => {
  const findStatement = (): Promise<Oid4vciAccessTokenRow | null> =>
    db
      .prepare(
        `
        SELECT
          id,
          access_token_hash AS accessTokenHash,
          tenant_id AS tenantId,
          assertion_id AS assertionId,
          expires_at AS expiresAt,
          revoked_at AS revokedAt,
          created_at AS createdAt
        FROM oid4vci_access_tokens
        WHERE access_token_hash = ?
          AND revoked_at IS NULL
          AND expires_at > ?
        LIMIT 1
      `,
      )
      .bind(input.accessTokenHash, input.nowIso)
      .first<Oid4vciAccessTokenRow>();

  const row = await findStatement();

  return row === null ? null : mapOid4vciAccessTokenRow(row);
};

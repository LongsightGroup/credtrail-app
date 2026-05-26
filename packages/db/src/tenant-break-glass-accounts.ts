import type { SqlDatabase, SqlQueryResult, SqlRunResult } from "./tenant-scope";
import { normalizeEmail } from "./users";

const tenantBreakGlassSelectSql = `
  SELECT
    account.tenant_id AS tenantId,
    account.user_id AS userId,
    users.email AS email,
    account.created_by_user_id AS createdByUserId,
    account.last_used_at AS lastUsedAt,
    account.last_enrollment_email_sent_at AS lastEnrollmentEmailSentAt,
    account.revoked_at AS revokedAt,
    account.created_at AS createdAt,
    account.updated_at AS updatedAt,
    auth_user.id AS betterAuthUserId,
    CASE
      WHEN auth_account.id IS NULL OR auth_account.password IS NULL THEN 0
      ELSE 1
    END AS localCredentialEnabled,
    COALESCE(auth_user.two_factor_enabled, 0) AS twoFactorEnabled
  FROM tenant_break_glass_accounts AS account
  INNER JOIN users
    ON users.id = account.user_id
  LEFT JOIN auth.user AS auth_user
    ON auth_user.email = users.email
  LEFT JOIN auth.account AS auth_account
    ON auth_account.user_id = auth_user.id
   AND auth_account.provider_id = 'credential'
`;

export interface TenantBreakGlassAccountRecord {
  tenantId: string;
  userId: string;
  email: string;
  createdByUserId: string | null;
  lastUsedAt: string | null;
  lastEnrollmentEmailSentAt: string | null;
  revokedAt: string | null;
  createdAt: string;
  updatedAt: string;
  betterAuthUserId: string | null;
  localCredentialEnabled: boolean;
  twoFactorEnabled: boolean;
}

export interface UpsertTenantBreakGlassAccountInput {
  tenantId: string;
  userId: string;
  createdByUserId?: string | null | undefined;
  lastEnrollmentEmailSentAt?: string | null | undefined;
}

export interface RevokeTenantBreakGlassAccountInput {
  tenantId: string;
  userId: string;
  revokedAt: string;
}

export interface MarkTenantBreakGlassAccountUsedInput {
  tenantId: string;
  userId: string;
  usedAt: string;
}

export interface MarkTenantBreakGlassEnrollmentEmailSentInput {
  tenantId: string;
  userId: string;
  sentAt: string;
}

interface TenantBreakGlassAccountRow {
  tenantId: string;
  userId: string;
  email: string;
  createdByUserId: string | null;
  lastUsedAt: string | null;
  lastEnrollmentEmailSentAt: string | null;
  revokedAt: string | null;
  createdAt: string;
  updatedAt: string;
  betterAuthUserId: string | null;
  localCredentialEnabled: number | boolean;
  twoFactorEnabled: number | boolean;
}

const mapTenantBreakGlassAccountRow = (
  row: TenantBreakGlassAccountRow,
): TenantBreakGlassAccountRecord => {
  return {
    tenantId: row.tenantId,
    userId: row.userId,
    email: row.email,
    createdByUserId: row.createdByUserId,
    lastUsedAt: row.lastUsedAt,
    lastEnrollmentEmailSentAt: row.lastEnrollmentEmailSentAt,
    revokedAt: row.revokedAt,
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
    betterAuthUserId: row.betterAuthUserId,
    localCredentialEnabled: row.localCredentialEnabled === 1 || row.localCredentialEnabled === true,
    twoFactorEnabled: row.twoFactorEnabled === 1 || row.twoFactorEnabled === true,
  };
};

export const listTenantBreakGlassAccounts = async (
  db: SqlDatabase,
  tenantId: string,
): Promise<TenantBreakGlassAccountRecord[]> => {
  const listStatement = (): Promise<SqlQueryResult<TenantBreakGlassAccountRow>> =>
    db
      .prepare(
        `
        ${tenantBreakGlassSelectSql}
        WHERE account.tenant_id = ?
        ORDER BY
          account.revoked_at IS NULL DESC,
          account.last_used_at DESC,
          account.created_at ASC,
          users.email ASC
      `,
      )
      .bind(tenantId)
      .all<TenantBreakGlassAccountRow>();

  const result = await listStatement();

  return result.results.map(mapTenantBreakGlassAccountRow);
};

export const findActiveTenantBreakGlassAccountByUserId = async (
  db: SqlDatabase,
  tenantId: string,
  userId: string,
): Promise<TenantBreakGlassAccountRecord | null> => {
  const lookupStatement = (): Promise<TenantBreakGlassAccountRow | null> =>
    db
      .prepare(
        `
        ${tenantBreakGlassSelectSql}
        WHERE account.tenant_id = ?
          AND account.user_id = ?
          AND account.revoked_at IS NULL
        LIMIT 1
      `,
      )
      .bind(tenantId, userId)
      .first<TenantBreakGlassAccountRow>();

  const row = await lookupStatement();

  return row === null ? null : mapTenantBreakGlassAccountRow(row);
};

export const findActiveTenantBreakGlassAccountByEmail = async (
  db: SqlDatabase,
  tenantId: string,
  email: string,
): Promise<TenantBreakGlassAccountRecord | null> => {
  const normalizedEmail = normalizeEmail(email);
  const lookupStatement = (): Promise<TenantBreakGlassAccountRow | null> =>
    db
      .prepare(
        `
        ${tenantBreakGlassSelectSql}
        WHERE account.tenant_id = ?
          AND users.email = ?
          AND account.revoked_at IS NULL
        LIMIT 1
      `,
      )
      .bind(tenantId, normalizedEmail)
      .first<TenantBreakGlassAccountRow>();

  const row = await lookupStatement();

  return row === null ? null : mapTenantBreakGlassAccountRow(row);
};

export const upsertTenantBreakGlassAccount = async (
  db: SqlDatabase,
  input: UpsertTenantBreakGlassAccountInput,
): Promise<TenantBreakGlassAccountRecord> => {
  const nowIso = new Date().toISOString();
  const upsertStatement = (): Promise<SqlRunResult> =>
    db
      .prepare(
        `
        INSERT INTO tenant_break_glass_accounts (
          tenant_id,
          user_id,
          created_by_user_id,
          last_used_at,
          last_enrollment_email_sent_at,
          revoked_at,
          created_at,
          updated_at
        )
        VALUES (?, ?, ?, NULL, ?, NULL, ?, ?)
        ON CONFLICT (tenant_id, user_id)
        DO UPDATE SET
          created_by_user_id = excluded.created_by_user_id,
          last_enrollment_email_sent_at = COALESCE(
            excluded.last_enrollment_email_sent_at,
            tenant_break_glass_accounts.last_enrollment_email_sent_at
          ),
          revoked_at = NULL,
          updated_at = excluded.updated_at
      `,
      )
      .bind(
        input.tenantId,
        input.userId,
        input.createdByUserId ?? null,
        input.lastEnrollmentEmailSentAt ?? null,
        nowIso,
        nowIso,
      )
      .run();

  await upsertStatement();

  const account = await findActiveTenantBreakGlassAccountByUserId(db, input.tenantId, input.userId);

  if (account === null) {
    throw new Error(
      `Unable to upsert break-glass account for tenant "${input.tenantId}" and user "${input.userId}"`,
    );
  }

  return account;
};

export const revokeTenantBreakGlassAccount = async (
  db: SqlDatabase,
  input: RevokeTenantBreakGlassAccountInput,
): Promise<boolean> => {
  const revokeStatement = (): Promise<SqlRunResult> =>
    db
      .prepare(
        `
        UPDATE tenant_break_glass_accounts
        SET
          revoked_at = ?,
          updated_at = ?
        WHERE tenant_id = ?
          AND user_id = ?
          AND revoked_at IS NULL
      `,
      )
      .bind(input.revokedAt, input.revokedAt, input.tenantId, input.userId)
      .run();

  const result = await revokeStatement();

  return (result.meta.rowsWritten ?? 0) > 0;
};

export const markTenantBreakGlassAccountUsed = async (
  db: SqlDatabase,
  input: MarkTenantBreakGlassAccountUsedInput,
): Promise<void> => {
  const updateStatement = (): Promise<SqlRunResult> =>
    db
      .prepare(
        `
        UPDATE tenant_break_glass_accounts
        SET
          last_used_at = ?,
          updated_at = ?
        WHERE tenant_id = ?
          AND user_id = ?
      `,
      )
      .bind(input.usedAt, input.usedAt, input.tenantId, input.userId)
      .run();

  await updateStatement();
};

export const markTenantBreakGlassEnrollmentEmailSent = async (
  db: SqlDatabase,
  input: MarkTenantBreakGlassEnrollmentEmailSentInput,
): Promise<void> => {
  const updateStatement = (): Promise<SqlRunResult> =>
    db
      .prepare(
        `
        UPDATE tenant_break_glass_accounts
        SET
          last_enrollment_email_sent_at = ?,
          updated_at = ?
        WHERE tenant_id = ?
          AND user_id = ?
      `,
      )
      .bind(input.sentAt, input.sentAt, input.tenantId, input.userId)
      .run();

  await updateStatement();
};

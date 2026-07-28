import type { SqlDatabase } from "./tenant-scope";

export interface TenantLmsUserIdentityRecord {
  readonly tenantId: string;
  readonly connectionId: string;
  readonly userId: string;
  readonly providerUserId: string;
  readonly createdAt: string;
  readonly updatedAt: string;
}

/** Finds the provider identity linked to one CredTrail user and LMS connection. */
export const findTenantLmsUserIdentity = async (
  db: SqlDatabase,
  input: {
    readonly tenantId: string;
    readonly connectionId: string;
    readonly userId: string;
  },
): Promise<TenantLmsUserIdentityRecord | null> => {
  return db
    .prepare(
      `
        SELECT
          tenant_id AS tenantId,
          connection_id AS connectionId,
          user_id AS userId,
          provider_user_id AS providerUserId,
          created_at AS createdAt,
          updated_at AS updatedAt
        FROM tenant_lms_user_identities
        WHERE tenant_id = ?
          AND connection_id = ?
          AND user_id = ?
        LIMIT 1
      `,
    )
    .bind(input.tenantId, input.connectionId, input.userId)
    .first<TenantLmsUserIdentityRecord>();
};

/** Records the stable LMS subject established by a verified LTI launch. */
export const upsertTenantLmsUserIdentity = async (
  db: SqlDatabase,
  input: {
    readonly tenantId: string;
    readonly connectionId: string;
    readonly userId: string;
    readonly providerUserId: string;
  },
): Promise<TenantLmsUserIdentityRecord> => {
  return db
    .prepare(
      `
        INSERT INTO tenant_lms_user_identities (
          tenant_id,
          connection_id,
          user_id,
          provider_user_id
        )
        VALUES (?, ?, ?, ?)
        ON CONFLICT (tenant_id, connection_id, user_id)
        DO UPDATE SET
          provider_user_id = excluded.provider_user_id,
          updated_at = CURRENT_TIMESTAMP
        RETURNING
          tenant_id AS tenantId,
          connection_id AS connectionId,
          user_id AS userId,
          provider_user_id AS providerUserId,
          created_at AS createdAt,
          updated_at AS updatedAt
      `,
    )
    .bind(input.tenantId, input.connectionId, input.userId, input.providerUserId)
    .first<TenantLmsUserIdentityRecord>()
    .then((record) => {
      if (record === null) {
        throw new Error("LMS user identity upsert returned no record");
      }

      return record;
    });
};

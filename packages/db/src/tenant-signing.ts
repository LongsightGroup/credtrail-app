import type { SqlDatabase, SqlRunResult } from "./tenant-scope";

export interface TenantSigningRegistrationRecord {
  tenantId: string;
  did: string;
  keyId: string;
  publicJwkJson: string;
  privateJwkJson: string | null;
  createdAt: string;
  updatedAt: string;
}

export interface UpsertTenantSigningRegistrationInput {
  tenantId: string;
  did: string;
  keyId: string;
  publicJwkJson: string;
  privateJwkJson?: string | undefined;
}

interface TenantSigningRegistrationRow {
  tenantId: string;
  did: string;
  keyId: string;
  publicJwkJson: string;
  privateJwkJson: string | null;
  createdAt: string;
  updatedAt: string;
}

const mapTenantSigningRegistrationRow = (
  row: TenantSigningRegistrationRow,
): TenantSigningRegistrationRecord => {
  return {
    tenantId: row.tenantId,
    did: row.did,
    keyId: row.keyId,
    publicJwkJson: row.publicJwkJson,
    privateJwkJson: row.privateJwkJson,
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
  };
};

export const upsertTenantSigningRegistration = async (
  db: SqlDatabase,
  input: UpsertTenantSigningRegistrationInput,
): Promise<TenantSigningRegistrationRecord> => {
  const nowIso = new Date().toISOString();

  const upsertStatement = (): Promise<SqlRunResult> =>
    db
      .prepare(
        `
        INSERT INTO tenant_signing_registrations (
          tenant_id,
          did,
          key_id,
          public_jwk_json,
          private_jwk_json,
          created_at,
          updated_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT (tenant_id)
        DO UPDATE SET
          did = excluded.did,
          key_id = excluded.key_id,
          public_jwk_json = excluded.public_jwk_json,
          private_jwk_json = excluded.private_jwk_json,
          updated_at = excluded.updated_at
      `,
      )
      .bind(
        input.tenantId,
        input.did,
        input.keyId,
        input.publicJwkJson,
        input.privateJwkJson ?? null,
        nowIso,
        nowIso,
      )
      .run();

  await upsertStatement();

  const row = await db
    .prepare(
      `
      SELECT
        tenant_id AS tenantId,
        did,
        key_id AS keyId,
        public_jwk_json AS publicJwkJson,
        private_jwk_json AS privateJwkJson,
        created_at AS createdAt,
        updated_at AS updatedAt
      FROM tenant_signing_registrations
      WHERE tenant_id = ?
      LIMIT 1
    `,
    )
    .bind(input.tenantId)
    .first<TenantSigningRegistrationRow>();

  if (row === null) {
    throw new Error(`Unable to upsert signing registration for tenant "${input.tenantId}"`);
  }

  return mapTenantSigningRegistrationRow(row);
};

export const findTenantSigningRegistrationByDid = async (
  db: SqlDatabase,
  did: string,
): Promise<TenantSigningRegistrationRecord | null> => {
  const findStatement = (): Promise<TenantSigningRegistrationRow | null> =>
    db
      .prepare(
        `
        SELECT
          tenant_id AS tenantId,
          did,
          key_id AS keyId,
          public_jwk_json AS publicJwkJson,
          private_jwk_json AS privateJwkJson,
          created_at AS createdAt,
          updated_at AS updatedAt
        FROM tenant_signing_registrations
        WHERE did = ?
        LIMIT 1
      `,
      )
      .bind(did)
      .first<TenantSigningRegistrationRow>();

  const row = await findStatement();

  if (row === null) {
    return null;
  }

  return mapTenantSigningRegistrationRow(row);
};

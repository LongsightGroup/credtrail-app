import type { SqlDatabase, SqlRunResult } from "./tenant-scope";

export interface Ed25519PublicJwkRecord {
  kty: "OKP";
  crv: "Ed25519";
  x: string;
  kid?: string | undefined;
}

export interface Ed25519PrivateJwkRecord extends Ed25519PublicJwkRecord {
  d: string;
}

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

const isMissingTenantSigningRegistrationsTableError = (error: unknown): boolean => {
  if (!(error instanceof Error)) {
    return false;
  }

  return (
    (error.message.includes("no such table") ||
      error.message.includes("relation") ||
      error.message.includes("does not exist")) &&
    error.message.includes("tenant_signing_registrations")
  );
};

const ensureTenantSigningRegistrationsTable = async (db: SqlDatabase): Promise<void> => {
  await db
    .prepare(
      `
      CREATE TABLE IF NOT EXISTS tenant_signing_registrations (
        tenant_id TEXT PRIMARY KEY,
        did TEXT NOT NULL UNIQUE,
        key_id TEXT NOT NULL,
        public_jwk_json TEXT NOT NULL,
        private_jwk_json TEXT,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (tenant_id) REFERENCES tenants (id) ON DELETE CASCADE
      )
    `,
    )
    .run();

  await db
    .prepare(
      `
      CREATE INDEX IF NOT EXISTS idx_tenant_signing_registrations_did
        ON tenant_signing_registrations (did)
    `,
    )
    .run();
};

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

  try {
    await upsertStatement();
  } catch (error: unknown) {
    if (!isMissingTenantSigningRegistrationsTableError(error)) {
      throw error;
    }

    await ensureTenantSigningRegistrationsTable(db);
    await upsertStatement();
  }

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

  let row: TenantSigningRegistrationRow | null;

  try {
    row = await findStatement();
  } catch (error: unknown) {
    if (!isMissingTenantSigningRegistrationsTableError(error)) {
      throw error;
    }

    await ensureTenantSigningRegistrationsTable(db);
    row = await findStatement();
  }

  if (row === null) {
    return null;
  }

  return mapTenantSigningRegistrationRow(row);
};

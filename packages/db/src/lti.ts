import type { SqlDatabase, SqlQueryResult, SqlRunResult } from "./tenant-scope";

export interface LtiIssuerRegistrationRecord {
  issuer: string;
  tenantId: string;
  authorizationEndpoint: string;
  clientId: string;
  platformJwksEndpoint: string | null;
  tokenEndpoint: string | null;
  clientSecret: string | null;
  createdAt: string;
  updatedAt: string;
}

export interface UpsertLtiIssuerRegistrationInput {
  issuer: string;
  tenantId: string;
  authorizationEndpoint: string;
  clientId: string;
  platformJwksEndpoint?: string | undefined;
  tokenEndpoint?: string | undefined;
  clientSecret?: string | undefined;
}

export class LtiIssuerTenantConflictError extends Error {
  constructor(
    readonly issuer: string,
    readonly existingTenantId: string,
    readonly requestedTenantId: string,
  ) {
    super("LTI issuer is already registered to a different tenant");
    this.name = "LtiIssuerTenantConflictError";
  }
}

export const isLtiIssuerTenantConflictError = (
  error: unknown,
): error is LtiIssuerTenantConflictError => {
  return error instanceof LtiIssuerTenantConflictError;
};

export interface LtiDeploymentRecord {
  id: string;
  tenantId: string;
  issuer: string;
  clientId: string;
  deploymentId: string;
  name: string | null;
  description: string | null;
  createdAt: string;
  updatedAt: string;
}

export interface UpsertLtiDeploymentInput {
  id?: string | undefined;
  tenantId: string;
  issuer: string;
  clientId: string;
  deploymentId: string;
  name?: string | undefined;
  description?: string | undefined;
}

export interface LtiToolKeyRecord {
  id: string;
  keyId: string;
  publicJwkJson: string;
  privateJwkJson: string;
  isActive: boolean;
  createdAt: string;
  updatedAt: string;
}

export interface CreateLtiToolKeyInput {
  id?: string | undefined;
  keyId: string;
  publicJwkJson: string;
  privateJwkJson: string;
  isActive?: boolean | undefined;
}

export interface LtiLaunchSessionRecord {
  id: string;
  issuer: string;
  clientId: string;
  deploymentId: string;
  tenantId: string;
  userId: string | null;
  dataJson: string;
  expiresAt: string;
  createdAt: string;
  updatedAt: string;
}

export interface UpsertLtiLaunchSessionInput {
  id: string;
  issuer: string;
  clientId: string;
  deploymentId: string;
  tenantId: string;
  userId?: string | null | undefined;
  dataJson: string;
  expiresAt: string;
}

export interface AttachLtiLaunchSessionPrincipalInput {
  id: string;
  tenantId: string;
  userId: string;
}

export interface LtiDynamicRegistrationSessionRecord {
  tenantId: string;
  id: string;
  dataJson: string;
  expiresAt: string;
  createdAt: string;
}

interface LtiIssuerRegistrationRow {
  issuer: string;
  tenantId: string;
  authorizationEndpoint: string;
  clientId: string;
  platformJwksEndpoint: string | null;
  tokenEndpoint: string | null;
  clientSecret: string | null;
  createdAt: string;
  updatedAt: string;
}

interface LtiDeploymentRow {
  id: string;
  tenantId: string;
  issuer: string;
  clientId: string;
  deploymentId: string;
  name: string | null;
  description: string | null;
  createdAt: string;
  updatedAt: string;
}

interface LtiToolKeyRow {
  id: string;
  keyId: string;
  publicJwkJson: string;
  privateJwkJson: string;
  isActive: number | boolean;
  createdAt: string;
  updatedAt: string;
}

interface LtiLaunchSessionRow {
  id: string;
  issuer: string;
  clientId: string;
  deploymentId: string;
  tenantId: string;
  userId: string | null;
  dataJson: string;
  expiresAt: string;
  createdAt: string;
  updatedAt: string;
}

interface LtiDynamicRegistrationSessionRow {
  tenantId: string;
  id: string;
  dataJson: string;
  expiresAt: string;
  createdAt: string;
}

const mapLtiIssuerRegistrationRow = (
  row: LtiIssuerRegistrationRow,
): LtiIssuerRegistrationRecord => {
  return {
    issuer: row.issuer,
    tenantId: row.tenantId,
    authorizationEndpoint: row.authorizationEndpoint,
    clientId: row.clientId,
    platformJwksEndpoint: row.platformJwksEndpoint,
    tokenEndpoint: row.tokenEndpoint,
    clientSecret: row.clientSecret,
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
  };
};

const mapLtiDeploymentRow = (row: LtiDeploymentRow): LtiDeploymentRecord => {
  return {
    id: row.id,
    tenantId: row.tenantId,
    issuer: row.issuer,
    clientId: row.clientId,
    deploymentId: row.deploymentId,
    name: row.name,
    description: row.description,
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
  };
};

const mapLtiToolKeyRow = (row: LtiToolKeyRow): LtiToolKeyRecord => {
  return {
    id: row.id,
    keyId: row.keyId,
    publicJwkJson: row.publicJwkJson,
    privateJwkJson: row.privateJwkJson,
    isActive: row.isActive === 1 || row.isActive === true,
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
  };
};

const mapLtiLaunchSessionRow = (row: LtiLaunchSessionRow): LtiLaunchSessionRecord => {
  return {
    id: row.id,
    issuer: row.issuer,
    clientId: row.clientId,
    deploymentId: row.deploymentId,
    tenantId: row.tenantId,
    userId: row.userId,
    dataJson: row.dataJson,
    expiresAt: row.expiresAt,
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
  };
};

const mapLtiDynamicRegistrationSessionRow = (
  row: LtiDynamicRegistrationSessionRow,
): LtiDynamicRegistrationSessionRecord => {
  return {
    tenantId: row.tenantId,
    id: row.id,
    dataJson: row.dataJson,
    expiresAt: row.expiresAt,
    createdAt: row.createdAt,
  };
};

export const normalizeLtiIssuer = (issuer: string): string => {
  return issuer.trim().replace(/\/+$/g, "");
};

export const upsertLtiIssuerRegistration = async (
  db: SqlDatabase,
  input: UpsertLtiIssuerRegistrationInput,
): Promise<LtiIssuerRegistrationRecord> => {
  const nowIso = new Date().toISOString();
  const normalizedIssuer = normalizeLtiIssuer(input.issuer);

  const upsertStatement = (): Promise<SqlRunResult> =>
    db
      .prepare(
        `
        INSERT INTO lti_issuer_registrations (
          issuer,
          tenant_id,
          authorization_endpoint,
          client_id,
          platform_jwks_endpoint,
          token_endpoint,
          client_secret,
          created_at,
          updated_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT (issuer)
        DO UPDATE SET
          tenant_id = excluded.tenant_id,
          authorization_endpoint = excluded.authorization_endpoint,
          client_id = excluded.client_id,
          platform_jwks_endpoint = COALESCE(excluded.platform_jwks_endpoint, lti_issuer_registrations.platform_jwks_endpoint),
          token_endpoint = COALESCE(excluded.token_endpoint, lti_issuer_registrations.token_endpoint),
          client_secret = COALESCE(excluded.client_secret, lti_issuer_registrations.client_secret),
          updated_at = excluded.updated_at
        WHERE lti_issuer_registrations.tenant_id = excluded.tenant_id
      `,
      )
      .bind(
        normalizedIssuer,
        input.tenantId,
        input.authorizationEndpoint,
        input.clientId,
        input.platformJwksEndpoint ?? null,
        input.tokenEndpoint ?? null,
        input.clientSecret ?? null,
        nowIso,
        nowIso,
      )
      .run();

  const findStatement = (): Promise<LtiIssuerRegistrationRow | null> =>
    db
      .prepare(
        `
        SELECT
          issuer,
          tenant_id AS tenantId,
          authorization_endpoint AS authorizationEndpoint,
          client_id AS clientId,
          platform_jwks_endpoint AS platformJwksEndpoint,
          token_endpoint AS tokenEndpoint,
          client_secret AS clientSecret,
          created_at AS createdAt,
          updated_at AS updatedAt
        FROM lti_issuer_registrations
        WHERE issuer = ?
        LIMIT 1
      `,
      )
      .bind(normalizedIssuer)
      .first<LtiIssuerRegistrationRow>();

  await upsertStatement();

  const row = await findStatement();

  if (row === null) {
    throw new Error(`Unable to upsert LTI issuer registration "${normalizedIssuer}"`);
  }

  if (row.tenantId !== input.tenantId) {
    throw new LtiIssuerTenantConflictError(normalizedIssuer, row.tenantId, input.tenantId);
  }

  return mapLtiIssuerRegistrationRow(row);
};

export const listAllLtiIssuerRegistrations = async (
  db: SqlDatabase,
): Promise<LtiIssuerRegistrationRecord[]> => {
  const listStatement = (): Promise<SqlQueryResult<LtiIssuerRegistrationRow>> =>
    db
      .prepare(
        `
        SELECT
          issuer,
          tenant_id AS tenantId,
          authorization_endpoint AS authorizationEndpoint,
          client_id AS clientId,
          platform_jwks_endpoint AS platformJwksEndpoint,
          token_endpoint AS tokenEndpoint,
          client_secret AS clientSecret,
          created_at AS createdAt,
          updated_at AS updatedAt
        FROM lti_issuer_registrations
        ORDER BY issuer ASC
      `,
      )
      .all<LtiIssuerRegistrationRow>();

  const result = await listStatement();

  return result.results.map((row) => mapLtiIssuerRegistrationRow(row));
};

export const listLtiIssuerRegistrationsForTenant = async (
  db: SqlDatabase,
  tenantId: string,
): Promise<LtiIssuerRegistrationRecord[]> => {
  const result = await db
    .prepare(
      `
        SELECT issuer, tenant_id AS tenantId, authorization_endpoint AS authorizationEndpoint,
          client_id AS clientId, platform_jwks_endpoint AS platformJwksEndpoint,
          token_endpoint AS tokenEndpoint, client_secret AS clientSecret,
          created_at AS createdAt, updated_at AS updatedAt
        FROM lti_issuer_registrations
        WHERE tenant_id = ?
        ORDER BY issuer ASC
      `,
    )
    .bind(tenantId)
    .all<LtiIssuerRegistrationRow>();

  return result.results.map(mapLtiIssuerRegistrationRow);
};

export const upsertLtiDeployment = async (
  db: SqlDatabase,
  input: UpsertLtiDeploymentInput,
): Promise<LtiDeploymentRecord> => {
  const nowIso = new Date().toISOString();
  const id = input.id ?? `lti_dep_${crypto.randomUUID().replace(/-/g, "")}`;
  const normalizedIssuer = normalizeLtiIssuer(input.issuer);

  const upsertStatement = (): Promise<SqlRunResult> =>
    db
      .prepare(
        `
        INSERT INTO lti_deployments (
          id,
          tenant_id,
          issuer,
          client_id,
          deployment_id,
          name,
          description,
          created_at,
          updated_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT (tenant_id, issuer, client_id, deployment_id)
        DO UPDATE SET
          name = COALESCE(excluded.name, lti_deployments.name),
          description = COALESCE(excluded.description, lti_deployments.description),
          updated_at = excluded.updated_at
      `,
      )
      .bind(
        id,
        input.tenantId,
        normalizedIssuer,
        input.clientId,
        input.deploymentId,
        input.name ?? null,
        input.description ?? null,
        nowIso,
        nowIso,
      )
      .run();

  await upsertStatement();

  const deployment = await findLtiDeploymentByIssuerClientDeployment(db, {
    tenantId: input.tenantId,
    issuer: normalizedIssuer,
    clientId: input.clientId,
    deploymentId: input.deploymentId,
  });

  if (deployment === null) {
    throw new Error(`Unable to upsert LTI deployment "${input.deploymentId}"`);
  }

  return deployment;
};

export const findLtiDeploymentByIssuerClientDeployment = async (
  db: SqlDatabase,
  input: {
    tenantId: string;
    issuer: string;
    clientId: string;
    deploymentId: string;
  },
): Promise<LtiDeploymentRecord | null> => {
  const normalizedIssuer = normalizeLtiIssuer(input.issuer);
  const lookupStatement = (): Promise<LtiDeploymentRow | null> =>
    db
      .prepare(
        `
        SELECT
          id,
          tenant_id AS tenantId,
          issuer,
          client_id AS clientId,
          deployment_id AS deploymentId,
          name,
          description,
          created_at AS createdAt,
          updated_at AS updatedAt
        FROM lti_deployments
        WHERE tenant_id = ?
          AND issuer = ?
          AND client_id = ?
          AND deployment_id = ?
        LIMIT 1
      `,
      )
      .bind(input.tenantId, normalizedIssuer, input.clientId, input.deploymentId)
      .first<LtiDeploymentRow>();

  const row = await lookupStatement();

  return row === null ? null : mapLtiDeploymentRow(row);
};

export const listLtiDeploymentsForIssuer = async (
  db: SqlDatabase,
  input: { tenantId: string; issuer: string },
): Promise<LtiDeploymentRecord[]> => {
  const normalizedIssuer = normalizeLtiIssuer(input.issuer);
  const listStatement = (): Promise<SqlQueryResult<LtiDeploymentRow>> =>
    db
      .prepare(
        `
        SELECT
          id,
          tenant_id AS tenantId,
          issuer,
          client_id AS clientId,
          deployment_id AS deploymentId,
          name,
          description,
          created_at AS createdAt,
          updated_at AS updatedAt
        FROM lti_deployments
        WHERE tenant_id = ?
          AND issuer = ?
        ORDER BY created_at ASC
      `,
      )
      .bind(input.tenantId, normalizedIssuer)
      .all<LtiDeploymentRow>();

  const result = await listStatement();

  return result.results.map((row) => mapLtiDeploymentRow(row));
};

export const createLtiToolKey = async (
  db: SqlDatabase,
  input: CreateLtiToolKeyInput,
): Promise<LtiToolKeyRecord> => {
  const nowIso = new Date().toISOString();
  const id = input.id ?? `lti_key_${crypto.randomUUID().replace(/-/g, "")}`;
  const isActive = input.isActive ?? true;

  const insertStatement = (): Promise<SqlRunResult> =>
    db
      .prepare(
        `
        INSERT INTO lti_tool_keys (
          id,
          key_id,
          public_jwk_json,
          private_jwk_json,
          is_active,
          created_at,
          updated_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT (key_id)
        DO UPDATE SET
          public_jwk_json = excluded.public_jwk_json,
          private_jwk_json = excluded.private_jwk_json,
          is_active = excluded.is_active,
          updated_at = excluded.updated_at
      `,
      )
      .bind(
        id,
        input.keyId,
        input.publicJwkJson,
        input.privateJwkJson,
        isActive ? 1 : 0,
        nowIso,
        nowIso,
      )
      .run();

  await insertStatement();

  const key = await findActiveLtiToolKey(db);

  if (key === null) {
    throw new Error(`Unable to create LTI tool key "${input.keyId}"`);
  }

  return key;
};

export const findActiveLtiToolKey = async (db: SqlDatabase): Promise<LtiToolKeyRecord | null> => {
  const findStatement = (): Promise<LtiToolKeyRow | null> =>
    db
      .prepare(
        `
        SELECT
          id,
          key_id AS keyId,
          public_jwk_json AS publicJwkJson,
          private_jwk_json AS privateJwkJson,
          is_active AS isActive,
          created_at AS createdAt,
          updated_at AS updatedAt
        FROM lti_tool_keys
        WHERE is_active = 1
        ORDER BY created_at DESC
        LIMIT 1
      `,
      )
      .first<LtiToolKeyRow>();

  const row = await findStatement();

  return row === null ? null : mapLtiToolKeyRow(row);
};

export const recordLtiLaunchNonceUse = async (
  db: SqlDatabase,
  input: {
    tenantId: string;
    nonce: string;
    expiresAt: string;
    consumedAt: string;
  },
): Promise<boolean> => {
  const insertStatement = (): Promise<SqlQueryResult<{ nonce: string }>> =>
    db
      .prepare(
        `
        INSERT INTO lti_launch_nonces (
          tenant_id,
          nonce,
          expires_at,
          consumed_at
        )
        VALUES (?, ?, ?, ?)
        ON CONFLICT (tenant_id, nonce)
        DO NOTHING
        RETURNING nonce
      `,
      )
      .bind(input.tenantId, input.nonce, input.expiresAt, input.consumedAt)
      .all<{ nonce: string }>();

  const result = await insertStatement();

  return result.results.length > 0;
};

export const upsertLtiLaunchSession = async (
  db: SqlDatabase,
  input: UpsertLtiLaunchSessionInput,
): Promise<LtiLaunchSessionRecord> => {
  const nowIso = new Date().toISOString();
  const upsertStatement = (): Promise<SqlRunResult> =>
    db
      .prepare(
        `
        INSERT INTO lti_launch_sessions (
          id,
          issuer,
          client_id,
          deployment_id,
          tenant_id,
          user_id,
          data_json,
          expires_at,
          created_at,
          updated_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT (tenant_id, id)
        DO UPDATE SET
          tenant_id = excluded.tenant_id,
          user_id = excluded.user_id,
          data_json = excluded.data_json,
          expires_at = excluded.expires_at,
          updated_at = excluded.updated_at
      `,
      )
      .bind(
        input.id,
        normalizeLtiIssuer(input.issuer),
        input.clientId,
        input.deploymentId,
        input.tenantId,
        input.userId ?? null,
        input.dataJson,
        input.expiresAt,
        nowIso,
        nowIso,
      )
      .run();

  await upsertStatement();

  const session = await findLtiLaunchSessionById(db, {
    tenantId: input.tenantId,
    sessionId: input.id,
  });

  if (session === null) {
    throw new Error(`Unable to upsert LTI launch session "${input.id}"`);
  }

  return session;
};

export const attachLtiLaunchSessionPrincipal = async (
  db: SqlDatabase,
  input: AttachLtiLaunchSessionPrincipalInput,
): Promise<LtiLaunchSessionRecord> => {
  const nowIso = new Date().toISOString();
  const updateStatement = (): Promise<SqlRunResult> =>
    db
      .prepare(
        `
        UPDATE lti_launch_sessions
        SET user_id = ?,
            updated_at = ?
        WHERE tenant_id = ?
          AND id = ?
      `,
      )
      .bind(input.userId, nowIso, input.tenantId, input.id)
      .run();

  await updateStatement();

  const session = await findLtiLaunchSessionById(db, {
    tenantId: input.tenantId,
    sessionId: input.id,
  });

  if (session === null) {
    throw new Error(`Unable to attach principal to LTI launch session "${input.id}"`);
  }

  return session;
};

export const findLtiLaunchSessionById = async (
  db: SqlDatabase,
  input: { tenantId: string; sessionId: string },
): Promise<LtiLaunchSessionRecord | null> => {
  const nowIso = new Date().toISOString();
  const findStatement = (): Promise<LtiLaunchSessionRow | null> =>
    db
      .prepare(
        `
        SELECT
          id,
          issuer,
          client_id AS clientId,
          deployment_id AS deploymentId,
          tenant_id AS tenantId,
          user_id AS userId,
          data_json AS dataJson,
          expires_at AS expiresAt,
          created_at AS createdAt,
          updated_at AS updatedAt
        FROM lti_launch_sessions
        WHERE tenant_id = ?
          AND id = ?
          AND expires_at > ?
        LIMIT 1
      `,
      )
      .bind(input.tenantId, input.sessionId, nowIso)
      .first<LtiLaunchSessionRow>();

  const row = await findStatement();

  return row === null ? null : mapLtiLaunchSessionRow(row);
};

/** Reads one active session by its globally unique opaque ID. */
export const findActiveLtiLaunchSessionByOpaqueId = async (
  db: SqlDatabase,
  sessionId: string,
): Promise<LtiLaunchSessionRecord | null> => {
  const row = await db
    .prepare(
      `
        SELECT id, issuer, client_id AS clientId, deployment_id AS deploymentId,
          tenant_id AS tenantId, user_id AS userId, data_json AS dataJson,
          expires_at AS expiresAt, created_at AS createdAt, updated_at AS updatedAt
        FROM lti_launch_sessions
        WHERE id = ?
          AND expires_at > ?
        LIMIT 1
      `,
    )
    .bind(sessionId, new Date().toISOString())
    .first<LtiLaunchSessionRow>();

  return row === null ? null : mapLtiLaunchSessionRow(row);
};

export const listActiveLtiLaunchSessionsForPlatform = async (
  db: SqlDatabase,
  input: {
    tenantId: string;
    issuer: string;
    clientId: string;
    deploymentId: string;
    limit?: number | undefined;
  },
): Promise<LtiLaunchSessionRecord[]> => {
  const nowIso = new Date().toISOString();
  const limit = input.limit ?? 10;
  const listStatement = (): Promise<SqlQueryResult<LtiLaunchSessionRow>> =>
    db
      .prepare(
        `
        SELECT
          id,
          issuer,
          client_id AS clientId,
          deployment_id AS deploymentId,
          tenant_id AS tenantId,
          user_id AS userId,
          data_json AS dataJson,
          expires_at AS expiresAt,
          created_at AS createdAt,
          updated_at AS updatedAt
        FROM lti_launch_sessions
        WHERE tenant_id = ?
          AND issuer = ?
          AND client_id = ?
          AND deployment_id = ?
          AND expires_at > ?
        ORDER BY updated_at DESC, created_at DESC
        LIMIT ?
      `,
      )
      .bind(
        input.tenantId,
        normalizeLtiIssuer(input.issuer),
        input.clientId,
        input.deploymentId,
        nowIso,
        limit,
      )
      .all<LtiLaunchSessionRow>();

  const result = await listStatement();

  return result.results.map((row) => mapLtiLaunchSessionRow(row));
};

export const upsertLtiDynamicRegistrationSession = async (
  db: SqlDatabase,
  input: {
    tenantId: string;
    id: string;
    dataJson: string;
    expiresAt: string;
  },
): Promise<void> => {
  const insertStatement = (): Promise<SqlRunResult> =>
    db
      .prepare(
        `
        INSERT INTO lti_dynamic_registration_sessions (
          tenant_id,
          id,
          data_json,
          expires_at
        )
        VALUES (?, ?, ?, ?)
        ON CONFLICT (tenant_id, id)
        DO UPDATE SET
          data_json = excluded.data_json,
          expires_at = excluded.expires_at
      `,
      )
      .bind(input.tenantId, input.id, input.dataJson, input.expiresAt)
      .run();

  await insertStatement();
};

export const findLtiDynamicRegistrationSessionById = async (
  db: SqlDatabase,
  input: { tenantId: string; sessionId: string },
): Promise<LtiDynamicRegistrationSessionRecord | null> => {
  const nowIso = new Date().toISOString();
  const findStatement = (): Promise<LtiDynamicRegistrationSessionRow | null> =>
    db
      .prepare(
        `
        SELECT
          tenant_id AS tenantId,
          id,
          data_json AS dataJson,
          expires_at AS expiresAt,
          created_at AS createdAt
        FROM lti_dynamic_registration_sessions
        WHERE tenant_id = ?
          AND id = ?
          AND expires_at > ?
        LIMIT 1
      `,
      )
      .bind(input.tenantId, input.sessionId, nowIso)
      .first<LtiDynamicRegistrationSessionRow>();

  const row = await findStatement();

  return row === null ? null : mapLtiDynamicRegistrationSessionRow(row);
};

export const deleteLtiDynamicRegistrationSessionById = async (
  db: SqlDatabase,
  input: { tenantId: string; sessionId: string },
): Promise<void> => {
  const deleteStatement = (): Promise<SqlRunResult> =>
    db
      .prepare(
        `
        DELETE FROM lti_dynamic_registration_sessions
        WHERE tenant_id = ?
          AND id = ?
      `,
      )
      .bind(input.tenantId, input.sessionId)
      .run();

  await deleteStatement();
};

import { ensureOAuthTables, isMissingOAuthTablesError } from "./oauth-tables";
import { createPrefixedId } from "./shared-helpers";
import type { SqlDatabase, SqlRunResult } from "./tenant-scope";

export interface OAuthClientRecord {
  clientId: string;
  clientSecretHash: string;
  clientName: string | null;
  redirectUrisJson: string;
  grantTypesJson: string;
  responseTypesJson: string;
  scope: string;
  tokenEndpointAuthMethod: string;
  createdAt: string;
  updatedAt: string;
}

export interface CreateOAuthClientInput {
  clientId: string;
  clientSecretHash: string;
  clientName?: string | undefined;
  redirectUrisJson: string;
  grantTypesJson: string;
  responseTypesJson: string;
  scope: string;
  tokenEndpointAuthMethod: string;
}

export interface OAuthAuthorizationCodeRecord {
  id: string;
  clientId: string;
  userId: string;
  tenantId: string;
  codeHash: string;
  redirectUri: string;
  scope: string;
  codeChallenge: string | null;
  codeChallengeMethod: string | null;
  expiresAt: string;
  usedAt: string | null;
  createdAt: string;
}

export interface CreateOAuthAuthorizationCodeInput {
  clientId: string;
  userId: string;
  tenantId: string;
  codeHash: string;
  redirectUri: string;
  scope: string;
  expiresAt: string;
  codeChallenge?: string | undefined;
  codeChallengeMethod?: string | undefined;
}

export interface ConsumeOAuthAuthorizationCodeInput {
  clientId: string;
  codeHash: string;
  redirectUri: string;
  nowIso: string;
}

export interface OAuthAccessTokenRecord {
  id: string;
  clientId: string;
  userId: string;
  tenantId: string;
  accessTokenHash: string;
  scope: string;
  expiresAt: string;
  revokedAt: string | null;
  createdAt: string;
}

export interface CreateOAuthAccessTokenInput {
  clientId: string;
  userId: string;
  tenantId: string;
  accessTokenHash: string;
  scope: string;
  expiresAt: string;
}

export interface OAuthRefreshTokenRecord {
  id: string;
  clientId: string;
  userId: string;
  tenantId: string;
  refreshTokenHash: string;
  scope: string;
  expiresAt: string;
  revokedAt: string | null;
  createdAt: string;
}

export interface CreateOAuthRefreshTokenInput {
  clientId: string;
  userId: string;
  tenantId: string;
  refreshTokenHash: string;
  scope: string;
  expiresAt: string;
}

export interface ConsumeOAuthRefreshTokenInput {
  clientId: string;
  refreshTokenHash: string;
  nowIso: string;
}

export interface RevokeOAuthAccessTokenByHashInput {
  clientId: string;
  accessTokenHash: string;
  revokedAt: string;
}

export interface RevokeOAuthRefreshTokenByHashInput {
  clientId: string;
  refreshTokenHash: string;
  revokedAt: string;
}

export interface FindActiveOAuthAccessTokenByHashInput {
  accessTokenHash: string;
  nowIso: string;
}
interface OAuthClientRow {
  clientId: string;
  clientSecretHash: string;
  clientName: string | null;
  redirectUrisJson: string;
  grantTypesJson: string;
  responseTypesJson: string;
  scope: string;
  tokenEndpointAuthMethod: string;
  createdAt: string;
  updatedAt: string;
}

interface OAuthAuthorizationCodeRow {
  id: string;
  clientId: string;
  userId: string;
  tenantId: string;
  codeHash: string;
  redirectUri: string;
  scope: string;
  codeChallenge: string | null;
  codeChallengeMethod: string | null;
  expiresAt: string;
  usedAt: string | null;
  createdAt: string;
}

interface OAuthAccessTokenRow {
  id: string;
  clientId: string;
  userId: string;
  tenantId: string;
  accessTokenHash: string;
  scope: string;
  expiresAt: string;
  revokedAt: string | null;
  createdAt: string;
}

interface OAuthRefreshTokenRow {
  id: string;
  clientId: string;
  userId: string;
  tenantId: string;
  refreshTokenHash: string;
  scope: string;
  expiresAt: string;
  revokedAt: string | null;
  createdAt: string;
}
const mapOAuthClientRow = (row: OAuthClientRow): OAuthClientRecord => {
  return {
    clientId: row.clientId,
    clientSecretHash: row.clientSecretHash,
    clientName: row.clientName,
    redirectUrisJson: row.redirectUrisJson,
    grantTypesJson: row.grantTypesJson,
    responseTypesJson: row.responseTypesJson,
    scope: row.scope,
    tokenEndpointAuthMethod: row.tokenEndpointAuthMethod,
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
  };
};

const mapOAuthAuthorizationCodeRow = (
  row: OAuthAuthorizationCodeRow,
): OAuthAuthorizationCodeRecord => {
  return {
    id: row.id,
    clientId: row.clientId,
    userId: row.userId,
    tenantId: row.tenantId,
    codeHash: row.codeHash,
    redirectUri: row.redirectUri,
    scope: row.scope,
    codeChallenge: row.codeChallenge,
    codeChallengeMethod: row.codeChallengeMethod,
    expiresAt: row.expiresAt,
    usedAt: row.usedAt,
    createdAt: row.createdAt,
  };
};

const mapOAuthAccessTokenRow = (row: OAuthAccessTokenRow): OAuthAccessTokenRecord => {
  return {
    id: row.id,
    clientId: row.clientId,
    userId: row.userId,
    tenantId: row.tenantId,
    accessTokenHash: row.accessTokenHash,
    scope: row.scope,
    expiresAt: row.expiresAt,
    revokedAt: row.revokedAt,
    createdAt: row.createdAt,
  };
};

const mapOAuthRefreshTokenRow = (row: OAuthRefreshTokenRow): OAuthRefreshTokenRecord => {
  return {
    id: row.id,
    clientId: row.clientId,
    userId: row.userId,
    tenantId: row.tenantId,
    refreshTokenHash: row.refreshTokenHash,
    scope: row.scope,
    expiresAt: row.expiresAt,
    revokedAt: row.revokedAt,
    createdAt: row.createdAt,
  };
};
export const createOAuthClient = async (
  db: SqlDatabase,
  input: CreateOAuthClientInput,
): Promise<OAuthClientRecord> => {
  const nowIso = new Date().toISOString();

  const insertStatement = (): Promise<SqlRunResult> =>
    db
      .prepare(
        `
        INSERT INTO oauth_clients (
          client_id,
          client_secret_hash,
          client_name,
          redirect_uris_json,
          grant_types_json,
          response_types_json,
          scope,
          token_endpoint_auth_method,
          created_at,
          updated_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `,
      )
      .bind(
        input.clientId,
        input.clientSecretHash,
        input.clientName ?? null,
        input.redirectUrisJson,
        input.grantTypesJson,
        input.responseTypesJson,
        input.scope,
        input.tokenEndpointAuthMethod,
        nowIso,
        nowIso,
      )
      .run();

  try {
    await insertStatement();
  } catch (error: unknown) {
    if (!isMissingOAuthTablesError(error)) {
      throw error;
    }

    await ensureOAuthTables(db);
    await insertStatement();
  }

  const row = await db
    .prepare(
      `
      SELECT
        client_id AS clientId,
        client_secret_hash AS clientSecretHash,
        client_name AS clientName,
        redirect_uris_json AS redirectUrisJson,
        grant_types_json AS grantTypesJson,
        response_types_json AS responseTypesJson,
        scope,
        token_endpoint_auth_method AS tokenEndpointAuthMethod,
        created_at AS createdAt,
        updated_at AS updatedAt
      FROM oauth_clients
      WHERE client_id = ?
      LIMIT 1
    `,
    )
    .bind(input.clientId)
    .first<OAuthClientRow>();

  if (row === null) {
    throw new Error(`Unable to create OAuth client "${input.clientId}"`);
  }

  return mapOAuthClientRow(row);
};

export const findOAuthClientById = async (
  db: SqlDatabase,
  clientId: string,
): Promise<OAuthClientRecord | null> => {
  const findStatement = (): Promise<OAuthClientRow | null> =>
    db
      .prepare(
        `
        SELECT
          client_id AS clientId,
          client_secret_hash AS clientSecretHash,
          client_name AS clientName,
          redirect_uris_json AS redirectUrisJson,
          grant_types_json AS grantTypesJson,
          response_types_json AS responseTypesJson,
          scope,
          token_endpoint_auth_method AS tokenEndpointAuthMethod,
          created_at AS createdAt,
          updated_at AS updatedAt
        FROM oauth_clients
        WHERE client_id = ?
        LIMIT 1
      `,
      )
      .bind(clientId)
      .first<OAuthClientRow>();

  let row: OAuthClientRow | null;

  try {
    row = await findStatement();
  } catch (error: unknown) {
    if (!isMissingOAuthTablesError(error)) {
      throw error;
    }

    await ensureOAuthTables(db);
    row = await findStatement();
  }

  if (row === null) {
    return null;
  }

  return mapOAuthClientRow(row);
};

export const createOAuthAuthorizationCode = async (
  db: SqlDatabase,
  input: CreateOAuthAuthorizationCodeInput,
): Promise<OAuthAuthorizationCodeRecord> => {
  const id = createPrefixedId("oac");
  const createdAt = new Date().toISOString();

  const insertStatement = (): Promise<SqlRunResult> =>
    db
      .prepare(
        `
        INSERT INTO oauth_authorization_codes (
          id,
          client_id,
          user_id,
          tenant_id,
          code_hash,
          redirect_uri,
          scope,
          code_challenge,
          code_challenge_method,
          expires_at,
          created_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `,
      )
      .bind(
        id,
        input.clientId,
        input.userId,
        input.tenantId,
        input.codeHash,
        input.redirectUri,
        input.scope,
        input.codeChallenge ?? null,
        input.codeChallengeMethod ?? null,
        input.expiresAt,
        createdAt,
      )
      .run();

  try {
    await insertStatement();
  } catch (error: unknown) {
    if (!isMissingOAuthTablesError(error)) {
      throw error;
    }

    await ensureOAuthTables(db);
    await insertStatement();
  }

  return {
    id,
    clientId: input.clientId,
    userId: input.userId,
    tenantId: input.tenantId,
    codeHash: input.codeHash,
    redirectUri: input.redirectUri,
    scope: input.scope,
    codeChallenge: input.codeChallenge ?? null,
    codeChallengeMethod: input.codeChallengeMethod ?? null,
    expiresAt: input.expiresAt,
    usedAt: null,
    createdAt,
  };
};

export const consumeOAuthAuthorizationCode = async (
  db: SqlDatabase,
  input: ConsumeOAuthAuthorizationCodeInput,
): Promise<OAuthAuthorizationCodeRecord | null> => {
  const consumeStatement = (): Promise<OAuthAuthorizationCodeRow | null> =>
    db
      .prepare(
        `
        UPDATE oauth_authorization_codes
        SET used_at = ?
        WHERE client_id = ?
          AND code_hash = ?
          AND redirect_uri = ?
          AND used_at IS NULL
          AND expires_at > ?
        RETURNING
          id,
          client_id AS clientId,
          user_id AS userId,
          tenant_id AS tenantId,
          code_hash AS codeHash,
          redirect_uri AS redirectUri,
          scope,
          code_challenge AS codeChallenge,
          code_challenge_method AS codeChallengeMethod,
          expires_at AS expiresAt,
          used_at AS usedAt,
          created_at AS createdAt
      `,
      )
      .bind(input.nowIso, input.clientId, input.codeHash, input.redirectUri, input.nowIso)
      .first<OAuthAuthorizationCodeRow>();

  let row: OAuthAuthorizationCodeRow | null;

  try {
    row = await consumeStatement();
  } catch (error: unknown) {
    if (!isMissingOAuthTablesError(error)) {
      throw error;
    }

    await ensureOAuthTables(db);
    row = await consumeStatement();
  }

  if (row === null) {
    return null;
  }

  return mapOAuthAuthorizationCodeRow(row);
};

export const createOAuthAccessToken = async (
  db: SqlDatabase,
  input: CreateOAuthAccessTokenInput,
): Promise<OAuthAccessTokenRecord> => {
  const id = createPrefixedId("oat");
  const createdAt = new Date().toISOString();

  const insertStatement = (): Promise<SqlRunResult> =>
    db
      .prepare(
        `
        INSERT INTO oauth_access_tokens (
          id,
          client_id,
          user_id,
          tenant_id,
          access_token_hash,
          scope,
          expires_at,
          created_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      `,
      )
      .bind(
        id,
        input.clientId,
        input.userId,
        input.tenantId,
        input.accessTokenHash,
        input.scope,
        input.expiresAt,
        createdAt,
      )
      .run();

  try {
    await insertStatement();
  } catch (error: unknown) {
    if (!isMissingOAuthTablesError(error)) {
      throw error;
    }

    await ensureOAuthTables(db);
    await insertStatement();
  }

  const row = await db
    .prepare(
      `
      SELECT
        id,
        client_id AS clientId,
        user_id AS userId,
        tenant_id AS tenantId,
        access_token_hash AS accessTokenHash,
        scope,
        expires_at AS expiresAt,
        revoked_at AS revokedAt,
        created_at AS createdAt
      FROM oauth_access_tokens
      WHERE id = ?
      LIMIT 1
    `,
    )
    .bind(id)
    .first<OAuthAccessTokenRow>();

  if (row === null) {
    throw new Error(`Unable to create OAuth access token "${id}"`);
  }

  return mapOAuthAccessTokenRow(row);
};

export const createOAuthRefreshToken = async (
  db: SqlDatabase,
  input: CreateOAuthRefreshTokenInput,
): Promise<OAuthRefreshTokenRecord> => {
  const id = createPrefixedId("ort");
  const createdAt = new Date().toISOString();

  const insertStatement = (): Promise<SqlRunResult> =>
    db
      .prepare(
        `
        INSERT INTO oauth_refresh_tokens (
          id,
          client_id,
          user_id,
          tenant_id,
          refresh_token_hash,
          scope,
          expires_at,
          created_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      `,
      )
      .bind(
        id,
        input.clientId,
        input.userId,
        input.tenantId,
        input.refreshTokenHash,
        input.scope,
        input.expiresAt,
        createdAt,
      )
      .run();

  try {
    await insertStatement();
  } catch (error: unknown) {
    if (!isMissingOAuthTablesError(error)) {
      throw error;
    }

    await ensureOAuthTables(db);
    await insertStatement();
  }

  const row = await db
    .prepare(
      `
      SELECT
        id,
        client_id AS clientId,
        user_id AS userId,
        tenant_id AS tenantId,
        refresh_token_hash AS refreshTokenHash,
        scope,
        expires_at AS expiresAt,
        revoked_at AS revokedAt,
        created_at AS createdAt
      FROM oauth_refresh_tokens
      WHERE id = ?
      LIMIT 1
    `,
    )
    .bind(id)
    .first<OAuthRefreshTokenRow>();

  if (row === null) {
    throw new Error(`Unable to create OAuth refresh token "${id}"`);
  }

  return mapOAuthRefreshTokenRow(row);
};

export const consumeOAuthRefreshToken = async (
  db: SqlDatabase,
  input: ConsumeOAuthRefreshTokenInput,
): Promise<OAuthRefreshTokenRecord | null> => {
  const consumeStatement = (): Promise<OAuthRefreshTokenRow | null> =>
    db
      .prepare(
        `
        UPDATE oauth_refresh_tokens
        SET revoked_at = ?
        WHERE client_id = ?
          AND refresh_token_hash = ?
          AND revoked_at IS NULL
          AND expires_at > ?
        RETURNING
          id,
          client_id AS clientId,
          user_id AS userId,
          tenant_id AS tenantId,
          refresh_token_hash AS refreshTokenHash,
          scope,
          expires_at AS expiresAt,
          revoked_at AS revokedAt,
          created_at AS createdAt
      `,
      )
      .bind(input.nowIso, input.clientId, input.refreshTokenHash, input.nowIso)
      .first<OAuthRefreshTokenRow>();

  let row: OAuthRefreshTokenRow | null;

  try {
    row = await consumeStatement();
  } catch (error: unknown) {
    if (!isMissingOAuthTablesError(error)) {
      throw error;
    }

    await ensureOAuthTables(db);
    row = await consumeStatement();
  }

  if (row === null) {
    return null;
  }

  return mapOAuthRefreshTokenRow(row);
};

export const revokeOAuthAccessTokenByHash = async (
  db: SqlDatabase,
  input: RevokeOAuthAccessTokenByHashInput,
): Promise<void> => {
  const revokeStatement = (): Promise<SqlRunResult> =>
    db
      .prepare(
        `
        UPDATE oauth_access_tokens
        SET revoked_at = COALESCE(revoked_at, ?)
        WHERE client_id = ?
          AND access_token_hash = ?
      `,
      )
      .bind(input.revokedAt, input.clientId, input.accessTokenHash)
      .run();

  try {
    await revokeStatement();
  } catch (error: unknown) {
    if (!isMissingOAuthTablesError(error)) {
      throw error;
    }

    await ensureOAuthTables(db);
    await revokeStatement();
  }
};

export const revokeOAuthRefreshTokenByHash = async (
  db: SqlDatabase,
  input: RevokeOAuthRefreshTokenByHashInput,
): Promise<void> => {
  const revokeStatement = (): Promise<SqlRunResult> =>
    db
      .prepare(
        `
        UPDATE oauth_refresh_tokens
        SET revoked_at = COALESCE(revoked_at, ?)
        WHERE client_id = ?
          AND refresh_token_hash = ?
      `,
      )
      .bind(input.revokedAt, input.clientId, input.refreshTokenHash)
      .run();

  try {
    await revokeStatement();
  } catch (error: unknown) {
    if (!isMissingOAuthTablesError(error)) {
      throw error;
    }

    await ensureOAuthTables(db);
    await revokeStatement();
  }
};

export const findActiveOAuthAccessTokenByHash = async (
  db: SqlDatabase,
  input: FindActiveOAuthAccessTokenByHashInput,
): Promise<OAuthAccessTokenRecord | null> => {
  const findStatement = (): Promise<OAuthAccessTokenRow | null> =>
    db
      .prepare(
        `
        SELECT
          id,
          client_id AS clientId,
          user_id AS userId,
          tenant_id AS tenantId,
          access_token_hash AS accessTokenHash,
          scope,
          expires_at AS expiresAt,
          revoked_at AS revokedAt,
          created_at AS createdAt
        FROM oauth_access_tokens
        WHERE access_token_hash = ?
          AND revoked_at IS NULL
          AND expires_at > ?
        LIMIT 1
      `,
      )
      .bind(input.accessTokenHash, input.nowIso)
      .first<OAuthAccessTokenRow>();

  let row: OAuthAccessTokenRow | null;

  try {
    row = await findStatement();
  } catch (error: unknown) {
    if (!isMissingOAuthTablesError(error)) {
      throw error;
    }

    await ensureOAuthTables(db);
    row = await findStatement();
  }

  return row === null ? null : mapOAuthAccessTokenRow(row);
};

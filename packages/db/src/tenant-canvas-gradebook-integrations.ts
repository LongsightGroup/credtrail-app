import type { SqlDatabase, SqlRunResult } from "./tenant-scope";

export interface TenantCanvasGradebookIntegrationRecord {
  tenantId: string;
  apiBaseUrl: string;
  authorizationEndpoint: string;
  tokenEndpoint: string;
  clientId: string;
  clientSecret: string;
  scope: string;
  accessToken: string | null;
  refreshToken: string | null;
  accessTokenExpiresAt: string | null;
  refreshTokenExpiresAt: string | null;
  connectedAt: string | null;
  createdAt: string;
  updatedAt: string;
}

export interface UpsertTenantCanvasGradebookIntegrationInput {
  tenantId: string;
  apiBaseUrl: string;
  authorizationEndpoint: string;
  tokenEndpoint: string;
  clientId: string;
  clientSecret: string;
  scope: string;
}

export interface UpdateTenantCanvasGradebookIntegrationTokensInput {
  tenantId: string;
  accessToken: string;
  refreshToken?: string | undefined;
  accessTokenExpiresAt?: string | undefined;
  refreshTokenExpiresAt?: string | undefined;
  connectedAt?: string | undefined;
}

interface TenantCanvasGradebookIntegrationRow {
  tenantId: string;
  apiBaseUrl: string;
  authorizationEndpoint: string;
  tokenEndpoint: string;
  clientId: string;
  clientSecret: string;
  scope: string;
  accessToken: string | null;
  refreshToken: string | null;
  accessTokenExpiresAt: string | null;
  refreshTokenExpiresAt: string | null;
  connectedAt: string | null;
  createdAt: string;
  updatedAt: string;
}

const mapTenantCanvasGradebookIntegrationRow = (
  row: TenantCanvasGradebookIntegrationRow,
): TenantCanvasGradebookIntegrationRecord => {
  return {
    tenantId: row.tenantId,
    apiBaseUrl: row.apiBaseUrl,
    authorizationEndpoint: row.authorizationEndpoint,
    tokenEndpoint: row.tokenEndpoint,
    clientId: row.clientId,
    clientSecret: row.clientSecret,
    scope: row.scope,
    accessToken: row.accessToken,
    refreshToken: row.refreshToken,
    accessTokenExpiresAt: row.accessTokenExpiresAt,
    refreshTokenExpiresAt: row.refreshTokenExpiresAt,
    connectedAt: row.connectedAt,
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
  };
};

export const findTenantCanvasGradebookIntegration = async (
  db: SqlDatabase,
  tenantId: string,
): Promise<TenantCanvasGradebookIntegrationRecord | null> => {
  const lookupStatement = (): Promise<TenantCanvasGradebookIntegrationRow | null> =>
    db
      .prepare(
        `
        SELECT
          tenant_id AS tenantId,
          api_base_url AS apiBaseUrl,
          authorization_endpoint AS authorizationEndpoint,
          token_endpoint AS tokenEndpoint,
          client_id AS clientId,
          client_secret AS clientSecret,
          scope,
          access_token AS accessToken,
          refresh_token AS refreshToken,
          access_token_expires_at AS accessTokenExpiresAt,
          refresh_token_expires_at AS refreshTokenExpiresAt,
          connected_at AS connectedAt,
          created_at AS createdAt,
          updated_at AS updatedAt
        FROM tenant_canvas_gradebook_integrations
        WHERE tenant_id = ?
        LIMIT 1
      `,
      )
      .bind(tenantId)
      .first<TenantCanvasGradebookIntegrationRow>();

  const row = await lookupStatement();

  return row === null ? null : mapTenantCanvasGradebookIntegrationRow(row);
};

export const upsertTenantCanvasGradebookIntegration = async (
  db: SqlDatabase,
  input: UpsertTenantCanvasGradebookIntegrationInput,
): Promise<TenantCanvasGradebookIntegrationRecord> => {
  const nowIso = new Date().toISOString();
  const upsertStatement = (): Promise<SqlRunResult> =>
    db
      .prepare(
        `
        INSERT INTO tenant_canvas_gradebook_integrations (
          tenant_id,
          api_base_url,
          authorization_endpoint,
          token_endpoint,
          client_id,
          client_secret,
          scope,
          access_token,
          refresh_token,
          access_token_expires_at,
          refresh_token_expires_at,
          connected_at,
          created_at,
          updated_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, NULL, NULL, NULL, NULL, NULL, ?, ?)
        ON CONFLICT (tenant_id)
        DO UPDATE SET
          api_base_url = excluded.api_base_url,
          authorization_endpoint = excluded.authorization_endpoint,
          token_endpoint = excluded.token_endpoint,
          client_id = excluded.client_id,
          client_secret = excluded.client_secret,
          scope = excluded.scope,
          updated_at = excluded.updated_at
      `,
      )
      .bind(
        input.tenantId,
        input.apiBaseUrl,
        input.authorizationEndpoint,
        input.tokenEndpoint,
        input.clientId,
        input.clientSecret,
        input.scope,
        nowIso,
        nowIso,
      )
      .run();

  await upsertStatement();

  const integration = await findTenantCanvasGradebookIntegration(db, input.tenantId);

  if (integration === null) {
    throw new Error(`Unable to upsert Canvas integration for tenant "${input.tenantId}"`);
  }

  return integration;
};

export const updateTenantCanvasGradebookIntegrationTokens = async (
  db: SqlDatabase,
  input: UpdateTenantCanvasGradebookIntegrationTokensInput,
): Promise<TenantCanvasGradebookIntegrationRecord | null> => {
  const nowIso = new Date().toISOString();
  const connectedAt = input.connectedAt ?? nowIso;
  const updateStatement = (): Promise<SqlRunResult> =>
    db
      .prepare(
        `
        UPDATE tenant_canvas_gradebook_integrations
        SET
          access_token = ?,
          refresh_token = COALESCE(?, refresh_token),
          access_token_expires_at = ?,
          refresh_token_expires_at = ?,
          connected_at = ?,
          updated_at = ?
        WHERE tenant_id = ?
      `,
      )
      .bind(
        input.accessToken,
        input.refreshToken ?? null,
        input.accessTokenExpiresAt ?? null,
        input.refreshTokenExpiresAt ?? null,
        connectedAt,
        nowIso,
        input.tenantId,
      )
      .run();

  const updated = await updateStatement();

  if ((updated.meta.rowsWritten ?? 0) === 0) {
    return null;
  }

  return findTenantCanvasGradebookIntegration(db, input.tenantId);
};

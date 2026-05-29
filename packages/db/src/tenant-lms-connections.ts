import { createPrefixedId } from "./shared-helpers";
import type { SqlDatabase, SqlQueryResult, SqlRunResult } from "./tenant-scope";

export type TenantLmsConnectionProviderKind = "canvas" | "sakai";

export interface TenantLmsConnectionRecord {
  id: string;
  tenantId: string;
  displayName: string;
  providerKind: TenantLmsConnectionProviderKind;
  apiBaseUrl: string;
  authorizationEndpoint: string | null;
  tokenEndpoint: string | null;
  clientId: string | null;
  clientSecret: string | null;
  scope: string | null;
  accessToken: string | null;
  refreshToken: string | null;
  accessTokenExpiresAt: string | null;
  refreshTokenExpiresAt: string | null;
  connectedAt: string | null;
  ltiIssuer: string | null;
  ltiClientId: string | null;
  ltiDeploymentId: string | null;
  createdAt: string;
  updatedAt: string;
}

export interface UpsertTenantLmsConnectionInput {
  id?: string | undefined;
  tenantId: string;
  displayName: string;
  providerKind: TenantLmsConnectionProviderKind;
  apiBaseUrl: string;
  authorizationEndpoint?: string | null | undefined;
  tokenEndpoint?: string | null | undefined;
  clientId?: string | null | undefined;
  clientSecret?: string | null | undefined;
  scope?: string | null | undefined;
  accessToken?: string | null | undefined;
  refreshToken?: string | null | undefined;
  accessTokenExpiresAt?: string | null | undefined;
  refreshTokenExpiresAt?: string | null | undefined;
  ltiIssuer?: string | null | undefined;
  ltiClientId?: string | null | undefined;
  ltiDeploymentId?: string | null | undefined;
}

export interface UpdateTenantLmsConnectionTokensInput {
  tenantId: string;
  connectionId: string;
  accessToken: string;
  refreshToken?: string | null | undefined;
  accessTokenExpiresAt?: string | null | undefined;
  refreshTokenExpiresAt?: string | null | undefined;
  connectedAt?: string | undefined;
}

interface TenantLmsConnectionRow {
  id: string;
  tenantId: string;
  displayName: string;
  providerKind: TenantLmsConnectionProviderKind;
  apiBaseUrl: string;
  authorizationEndpoint: string | null;
  tokenEndpoint: string | null;
  clientId: string | null;
  clientSecret: string | null;
  scope: string | null;
  accessToken: string | null;
  refreshToken: string | null;
  accessTokenExpiresAt: string | null;
  refreshTokenExpiresAt: string | null;
  connectedAt: string | null;
  ltiIssuer: string | null;
  ltiClientId: string | null;
  ltiDeploymentId: string | null;
  createdAt: string;
  updatedAt: string;
}

const mapTenantLmsConnectionRow = (row: TenantLmsConnectionRow): TenantLmsConnectionRecord => {
  return {
    id: row.id,
    tenantId: row.tenantId,
    displayName: row.displayName,
    providerKind: row.providerKind,
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
    ltiIssuer: row.ltiIssuer,
    ltiClientId: row.ltiClientId,
    ltiDeploymentId: row.ltiDeploymentId,
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
  };
};

const tenantLmsConnectionSelectSql = `
  SELECT
    id,
    tenant_id AS tenantId,
    display_name AS displayName,
    provider_kind AS providerKind,
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
    lti_issuer AS ltiIssuer,
    lti_client_id AS ltiClientId,
    lti_deployment_id AS ltiDeploymentId,
    created_at AS createdAt,
    updated_at AS updatedAt
  FROM tenant_lms_connections
`;

export const listTenantLmsConnections = async (
  db: SqlDatabase,
  tenantId: string,
): Promise<TenantLmsConnectionRecord[]> => {
  const listStatement = (): Promise<SqlQueryResult<TenantLmsConnectionRow>> =>
    db
      .prepare(
        `
        ${tenantLmsConnectionSelectSql}
        WHERE tenant_id = ?
        ORDER BY display_name ASC, created_at ASC
      `,
      )
      .bind(tenantId)
      .all<TenantLmsConnectionRow>();

  const result = await listStatement();
  return result.results.map((row) => mapTenantLmsConnectionRow(row));
};

export const findTenantLmsConnectionById = async (
  db: SqlDatabase,
  input: {
    tenantId: string;
    connectionId: string;
  },
): Promise<TenantLmsConnectionRecord | null> => {
  const lookupStatement = (): Promise<TenantLmsConnectionRow | null> =>
    db
      .prepare(
        `
        ${tenantLmsConnectionSelectSql}
        WHERE tenant_id = ?
          AND id = ?
        LIMIT 1
      `,
      )
      .bind(input.tenantId, input.connectionId)
      .first<TenantLmsConnectionRow>();

  const row = await lookupStatement();
  return row === null ? null : mapTenantLmsConnectionRow(row);
};

export const upsertTenantLmsConnection = async (
  db: SqlDatabase,
  input: UpsertTenantLmsConnectionInput,
): Promise<TenantLmsConnectionRecord> => {
  const connectionId = input.id ?? createPrefixedId("lms");
  const nowIso = new Date().toISOString();
  const connectedAt = input.accessToken === undefined || input.accessToken === null ? null : nowIso;
  const upsertStatement = (): Promise<SqlRunResult> =>
    db
      .prepare(
        `
        INSERT INTO tenant_lms_connections (
          id,
          tenant_id,
          display_name,
          provider_kind,
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
          lti_issuer,
          lti_client_id,
          lti_deployment_id,
          created_at,
          updated_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT (id)
        DO UPDATE SET
          display_name = excluded.display_name,
          provider_kind = excluded.provider_kind,
          api_base_url = excluded.api_base_url,
          authorization_endpoint = excluded.authorization_endpoint,
          token_endpoint = excluded.token_endpoint,
          client_id = excluded.client_id,
          client_secret = COALESCE(excluded.client_secret, tenant_lms_connections.client_secret),
          scope = excluded.scope,
          access_token = COALESCE(excluded.access_token, tenant_lms_connections.access_token),
          refresh_token = COALESCE(excluded.refresh_token, tenant_lms_connections.refresh_token),
          access_token_expires_at = COALESCE(excluded.access_token_expires_at, tenant_lms_connections.access_token_expires_at),
          refresh_token_expires_at = COALESCE(excluded.refresh_token_expires_at, tenant_lms_connections.refresh_token_expires_at),
          connected_at = COALESCE(excluded.connected_at, tenant_lms_connections.connected_at),
          lti_issuer = excluded.lti_issuer,
          lti_client_id = excluded.lti_client_id,
          lti_deployment_id = excluded.lti_deployment_id,
          updated_at = excluded.updated_at
      `,
      )
      .bind(
        connectionId,
        input.tenantId,
        input.displayName,
        input.providerKind,
        input.apiBaseUrl,
        input.authorizationEndpoint ?? null,
        input.tokenEndpoint ?? null,
        input.clientId ?? null,
        input.clientSecret ?? null,
        input.scope ?? null,
        input.accessToken ?? null,
        input.refreshToken ?? null,
        input.accessTokenExpiresAt ?? null,
        input.refreshTokenExpiresAt ?? null,
        connectedAt,
        input.ltiIssuer ?? null,
        input.ltiClientId ?? null,
        input.ltiDeploymentId ?? null,
        nowIso,
        nowIso,
      )
      .run();

  await upsertStatement();

  const connection = await findTenantLmsConnectionById(db, {
    tenantId: input.tenantId,
    connectionId,
  });

  if (connection === null) {
    throw new Error(`Unable to upsert LMS connection "${connectionId}"`);
  }

  return connection;
};

export const updateTenantLmsConnectionTokens = async (
  db: SqlDatabase,
  input: UpdateTenantLmsConnectionTokensInput,
): Promise<TenantLmsConnectionRecord | null> => {
  const nowIso = new Date().toISOString();
  const connectedAt = input.connectedAt ?? nowIso;
  const updateStatement = (): Promise<SqlRunResult> =>
    db
      .prepare(
        `
        UPDATE tenant_lms_connections
        SET
          access_token = ?,
          refresh_token = COALESCE(?, refresh_token),
          access_token_expires_at = ?,
          refresh_token_expires_at = ?,
          connected_at = ?,
          updated_at = ?
        WHERE tenant_id = ?
          AND id = ?
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
        input.connectionId,
      )
      .run();

  const updated = await updateStatement();

  if ((updated.meta.rowsWritten ?? 0) === 0) {
    return null;
  }

  return findTenantLmsConnectionById(db, input);
};

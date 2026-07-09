import {
  findTenantLmsConnectionById,
  updateTenantLmsConnectionTokens,
  type SqlDatabase,
  type TenantLmsConnectionRecord,
} from "@credtrail/db";
import { refreshCanvasAccessToken } from "./canvas-oauth";
import { createGradebookProvider } from "./gradebook-provider";
import type { GradebookProvider } from "./gradebook-types";
import { createSakaiSession, type SakaiSessionLoginResult } from "./sakai-gradebook-provider";

const SAKAI_SESSION_CACHE_TTL_SECONDS = 20 * 60;

const isAccessTokenExpired = (accessTokenExpiresAt: string | null, nowIso: string): boolean => {
  if (accessTokenExpiresAt === null) {
    return false;
  }

  const expiryMs = Date.parse(accessTokenExpiresAt);
  const nowMs = Date.parse(nowIso);

  return Number.isFinite(expiryMs) && Number.isFinite(nowMs) && nowMs >= expiryMs;
};

const addSecondsToIso = (timestampIso: string, seconds: number): string => {
  return new Date(Date.parse(timestampIso) + seconds * 1000).toISOString();
};

const hasStoredAccessToken = (connection: TenantLmsConnectionRecord): boolean => {
  return connection.accessToken !== null && connection.accessToken.length > 0;
};

const hasSakaiPasswordCredentials = (
  connection: TenantLmsConnectionRecord,
): connection is TenantLmsConnectionRecord & {
  providerKind: "sakai";
  clientId: string;
  clientSecret: string;
} => {
  return (
    connection.providerKind === "sakai" &&
    connection.clientId !== null &&
    connection.clientId.length > 0 &&
    connection.clientSecret !== null &&
    connection.clientSecret.length > 0
  );
};

const refreshSakaiSessionForConnection = async (input: {
  db: SqlDatabase;
  connection: TenantLmsConnectionRecord & {
    providerKind: "sakai";
    clientId: string;
    clientSecret: string;
  };
  nowIso: string;
  fetchImpl?: typeof fetch;
}): Promise<SakaiSessionLoginResult> => {
  const session = await createSakaiSession({
    apiBaseUrl: input.connection.apiBaseUrl,
    username: input.connection.clientId,
    password: input.connection.clientSecret,
    ...(input.fetchImpl === undefined ? {} : { fetchImpl: input.fetchImpl }),
  });
  const refreshed = await updateTenantLmsConnectionTokens(input.db, {
    tenantId: input.connection.tenantId,
    connectionId: input.connection.id,
    accessToken: session.cookieHeader,
    accessTokenExpiresAt: addSecondsToIso(input.nowIso, SAKAI_SESSION_CACHE_TTL_SECONDS),
  });

  return {
    sessionId: session.sessionId,
    cookieHeader: refreshed?.accessToken ?? session.cookieHeader,
  };
};

export const isTenantLmsConnectionUsable = (connection: TenantLmsConnectionRecord): boolean => {
  if (connection.providerKind === "sakai") {
    return hasStoredAccessToken(connection) || hasSakaiPasswordCredentials(connection);
  }

  return hasStoredAccessToken(connection);
};

export interface PublicTenantLmsConnection {
  id: string;
  tenantId: string;
  displayName: string;
  providerKind: "canvas" | "sakai";
  apiBaseUrl: string;
  status: "connected" | "needs_token";
  hasAccessToken: boolean;
  hasStoredCredential: boolean;
  hasRefreshToken: boolean;
  connectedAt: string | null;
  accessTokenExpiresAt: string | null;
  refreshTokenExpiresAt: string | null;
  ltiIssuer: string | null;
  ltiClientId: string | null;
  ltiDeploymentId: string | null;
  createdAt: string;
  updatedAt: string;
}

export class GradebookProviderResolutionError extends Error {
  public readonly reason: "missing_connection" | "not_found" | "unusable";

  public constructor(reason: "missing_connection" | "not_found" | "unusable", message: string) {
    super(message);
    this.name = "GradebookProviderResolutionError";
    this.reason = reason;
  }
}

export const isClientGradebookProviderResolutionError = (
  error: unknown,
): error is GradebookProviderResolutionError => {
  return (
    error instanceof GradebookProviderResolutionError &&
    (error.reason === "missing_connection" || error.reason === "not_found")
  );
};

export const publicTenantLmsConnection = (
  connection: TenantLmsConnectionRecord,
): PublicTenantLmsConnection => {
  const hasAccessToken = hasStoredAccessToken(connection);
  const hasStoredCredential = isTenantLmsConnectionUsable(connection);
  const hasRefreshToken = connection.refreshToken !== null && connection.refreshToken.length > 0;

  return {
    id: connection.id,
    tenantId: connection.tenantId,
    displayName: connection.displayName,
    providerKind: connection.providerKind,
    apiBaseUrl: connection.apiBaseUrl,
    status: hasStoredCredential ? "connected" : "needs_token",
    hasAccessToken,
    hasStoredCredential,
    hasRefreshToken,
    connectedAt: connection.connectedAt,
    accessTokenExpiresAt: connection.accessTokenExpiresAt,
    refreshTokenExpiresAt: connection.refreshTokenExpiresAt,
    ltiIssuer: connection.ltiIssuer,
    ltiClientId: connection.ltiClientId,
    ltiDeploymentId: connection.ltiDeploymentId,
    createdAt: connection.createdAt,
    updatedAt: connection.updatedAt,
  };
};

export interface ResolvedGradebookProvider {
  connection: TenantLmsConnectionRecord;
  provider: GradebookProvider;
}

export const createGradebookProviderForConnection = async (input: {
  db: SqlDatabase;
  connection: TenantLmsConnectionRecord;
  nowIso: string;
  fetchImpl?: typeof fetch;
}): Promise<GradebookProvider> => {
  let accessToken = input.connection.accessToken;

  if (input.connection.providerKind === "sakai") {
    const hasUsableCachedSession =
      accessToken !== null &&
      accessToken.length > 0 &&
      !isAccessTokenExpired(input.connection.accessTokenExpiresAt, input.nowIso);

    if (!hasUsableCachedSession) {
      if (!hasSakaiPasswordCredentials(input.connection)) {
        throw new Error(
          "Sakai LMS connection needs a Sakai username and password before CredTrail can read the gradebook.",
        );
      }

      const session = await refreshSakaiSessionForConnection({
        db: input.db,
        connection: input.connection,
        nowIso: input.nowIso,
        ...(input.fetchImpl === undefined ? {} : { fetchImpl: input.fetchImpl }),
      });

      accessToken = session.cookieHeader;
    }

    if (accessToken === null || accessToken.length === 0) {
      throw new Error("LMS connection has no access token. Connect the gradebook source first.");
    }

    const sakaiCredentialConnection = hasSakaiPasswordCredentials(input.connection)
      ? input.connection
      : null;

    return createGradebookProvider({
      config: {
        kind: input.connection.providerKind,
        apiBaseUrl: input.connection.apiBaseUrl,
        accessToken,
      },
      ...(input.fetchImpl === undefined ? {} : { fetchImpl: input.fetchImpl }),
      ...(sakaiCredentialConnection === null
        ? {}
        : {
            sakaiRefreshSession: () =>
              refreshSakaiSessionForConnection({
                db: input.db,
                connection: sakaiCredentialConnection,
                nowIso: input.nowIso,
                ...(input.fetchImpl === undefined ? {} : { fetchImpl: input.fetchImpl }),
              }),
          }),
    });
  }

  if (accessToken === null || accessToken.length === 0) {
    throw new Error("LMS connection has no access token. Connect the gradebook source first.");
  }

  if (
    input.connection.providerKind === "canvas" &&
    isAccessTokenExpired(input.connection.accessTokenExpiresAt, input.nowIso)
  ) {
    if (
      input.connection.refreshToken === null ||
      input.connection.tokenEndpoint === null ||
      input.connection.clientId === null ||
      input.connection.clientSecret === null
    ) {
      throw new Error("Canvas LMS connection token has expired. Reconnect the gradebook source.");
    }

    const refresh = await refreshCanvasAccessToken({
      tokenEndpoint: input.connection.tokenEndpoint,
      clientId: input.connection.clientId,
      clientSecret: input.connection.clientSecret,
      refreshToken: input.connection.refreshToken,
    });
    const refreshed = await updateTenantLmsConnectionTokens(input.db, {
      tenantId: input.connection.tenantId,
      connectionId: input.connection.id,
      accessToken: refresh.accessToken,
      refreshToken: refresh.refreshToken,
      accessTokenExpiresAt:
        refresh.expiresInSeconds === undefined
          ? undefined
          : new Date(Date.parse(input.nowIso) + refresh.expiresInSeconds * 1000).toISOString(),
      refreshTokenExpiresAt:
        refresh.refreshTokenExpiresInSeconds === undefined
          ? undefined
          : new Date(
              Date.parse(input.nowIso) + refresh.refreshTokenExpiresInSeconds * 1000,
            ).toISOString(),
    });

    if (refreshed !== null && refreshed.accessToken !== null) {
      accessToken = refreshed.accessToken;
    }
  }

  return createGradebookProvider({
    config: {
      kind: input.connection.providerKind,
      apiBaseUrl: input.connection.apiBaseUrl,
      accessToken,
    },
    ...(input.fetchImpl === undefined ? {} : { fetchImpl: input.fetchImpl }),
  });
};

export const resolveGradebookProviderWithConnection = async (input: {
  db: SqlDatabase;
  tenantId: string;
  lmsConnectionId?: string | null | undefined;
  nowIso: string;
}): Promise<ResolvedGradebookProvider> => {
  if (
    input.lmsConnectionId === undefined ||
    input.lmsConnectionId === null ||
    input.lmsConnectionId.trim().length === 0
  ) {
    throw new GradebookProviderResolutionError(
      "missing_connection",
      "Select an LMS connection before running automated gradebook evaluation.",
    );
  }

  const connection = await findTenantLmsConnectionById(input.db, {
    tenantId: input.tenantId,
    connectionId: input.lmsConnectionId,
  });

  if (connection === null) {
    throw new GradebookProviderResolutionError(
      "not_found",
      "Selected LMS connection was not found",
    );
  }

  try {
    return {
      connection,
      provider: await createGradebookProviderForConnection({
        db: input.db,
        connection,
        nowIso: input.nowIso,
      }),
    };
  } catch (error) {
    throw new GradebookProviderResolutionError(
      "unusable",
      error instanceof Error ? error.message : "Unable to use LMS connection",
    );
  }
};

export const resolveGradebookProvider = async (input: {
  db: SqlDatabase;
  tenantId: string;
  lmsConnectionId?: string | null | undefined;
  nowIso: string;
}): Promise<GradebookProvider> => {
  const resolved = await resolveGradebookProviderWithConnection(input);
  return resolved.provider;
};

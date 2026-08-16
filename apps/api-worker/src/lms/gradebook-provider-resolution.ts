import {
  findTenantLmsConnectionById,
  updateTenantLmsConnectionTokens,
  type SqlDatabase,
  type TenantLmsConnectionRecord,
} from "@credtrail/db";
import { refreshCanvasAccessToken } from "./canvas-oauth";
import { createGradebookProvider } from "./gradebook-provider";
import { isGradebookProviderRequestCancelled } from "./gradebook-provider-error";
import type {
  CanvasGradebookProvider,
  CourseAuthoringGradebookProvider,
  GradebookProvider,
  GradebookRequestOptions,
  SakaiGradebookProvider,
} from "./gradebook-types";
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

const refreshSakaiSessionForConnection = async (
  input: {
    db: SqlDatabase;
    connection: TenantLmsConnectionRecord & {
      providerKind: "sakai";
      clientId: string;
      clientSecret: string;
    };
    nowIso: string;
    fetchImpl?: typeof fetch;
  },
  options: GradebookRequestOptions = {},
): Promise<SakaiSessionLoginResult> => {
  const session = await createSakaiSession(
    {
      apiBaseUrl: input.connection.apiBaseUrl,
      username: input.connection.clientId,
      password: input.connection.clientSecret,
      ...(input.fetchImpl === undefined ? {} : { fetchImpl: input.fetchImpl }),
    },
    options,
  );
  options.signal?.throwIfAborted();
  const refreshed = await updateTenantLmsConnectionTokens(input.db, {
    tenantId: input.connection.tenantId,
    connectionId: input.connection.id,
    accessToken: session.cookieHeader,
    accessTokenExpiresAt: addSecondsToIso(input.nowIso, SAKAI_SESSION_CACHE_TTL_SECONDS),
  });
  options.signal?.throwIfAborted();

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
  public readonly reason: "cancelled" | "missing_connection" | "not_found" | "unusable";

  public constructor(
    reason: "cancelled" | "missing_connection" | "not_found" | "unusable",
    message: string,
  ) {
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

type CanvasTenantLmsConnection = TenantLmsConnectionRecord & {
  readonly providerKind: "canvas";
};

type SakaiTenantLmsConnection = TenantLmsConnectionRecord & {
  readonly providerKind: "sakai";
};

/** Saved LMS connection paired with the matching concrete provider. */
export type ResolvedGradebookProvider =
  | {
      readonly providerKind: "canvas";
      readonly connection: CanvasTenantLmsConnection;
      readonly provider: CanvasGradebookProvider;
    }
  | {
      readonly providerKind: "sakai";
      readonly connection: SakaiTenantLmsConnection;
      readonly provider: SakaiGradebookProvider;
    };

const isCanvasTenantLmsConnection = (
  connection: TenantLmsConnectionRecord,
): connection is CanvasTenantLmsConnection => {
  return connection.providerKind === "canvas";
};

const isSakaiTenantLmsConnection = (
  connection: TenantLmsConnectionRecord,
): connection is SakaiTenantLmsConnection => {
  return connection.providerKind === "sakai";
};

export const createGradebookProviderForConnection = async (
  input: {
    db: SqlDatabase;
    connection: TenantLmsConnectionRecord;
    nowIso: string;
    fetchImpl?: typeof fetch;
  },
  options: GradebookRequestOptions = {},
): Promise<CourseAuthoringGradebookProvider> => {
  options.signal?.throwIfAborted();
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

      const session = await refreshSakaiSessionForConnection(
        {
          db: input.db,
          connection: input.connection,
          nowIso: input.nowIso,
          ...(input.fetchImpl === undefined ? {} : { fetchImpl: input.fetchImpl }),
        },
        options,
      );

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
            sakaiRefreshSession: (refreshOptions) =>
              refreshSakaiSessionForConnection(
                {
                  db: input.db,
                  connection: sakaiCredentialConnection,
                  nowIso: input.nowIso,
                  ...(input.fetchImpl === undefined ? {} : { fetchImpl: input.fetchImpl }),
                },
                refreshOptions,
              ),
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

    const refresh = await refreshCanvasAccessToken(
      {
        tokenEndpoint: input.connection.tokenEndpoint,
        clientId: input.connection.clientId,
        clientSecret: input.connection.clientSecret,
        refreshToken: input.connection.refreshToken,
        ...(input.fetchImpl === undefined ? {} : { fetchImpl: input.fetchImpl }),
      },
      options,
    );
    options.signal?.throwIfAborted();
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
    options.signal?.throwIfAborted();

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

export const resolveGradebookProviderWithConnection = async (
  input: {
    db: SqlDatabase;
    tenantId: string;
    lmsConnectionId?: string | null | undefined;
    nowIso: string;
    fetchImpl?: typeof fetch;
  },
  options: GradebookRequestOptions = {},
): Promise<ResolvedGradebookProvider> => {
  options.signal?.throwIfAborted();
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
  options.signal?.throwIfAborted();

  if (connection === null) {
    throw new GradebookProviderResolutionError(
      "not_found",
      "Selected LMS connection was not found",
    );
  }

  try {
    const provider = await createGradebookProviderForConnection(
      {
        db: input.db,
        connection,
        nowIso: input.nowIso,
        ...(input.fetchImpl === undefined ? {} : { fetchImpl: input.fetchImpl }),
      },
      options,
    );

    if (isCanvasTenantLmsConnection(connection) && provider.kind === "canvas") {
      return {
        providerKind: "canvas",
        connection,
        provider,
      };
    }

    if (isSakaiTenantLmsConnection(connection) && provider.kind === "sakai") {
      return {
        providerKind: "sakai",
        connection,
        provider,
      };
    }

    throw new Error("Resolved LMS provider did not match its saved connection");
  } catch (error) {
    if (isGradebookProviderRequestCancelled(error, options)) {
      throw new GradebookProviderResolutionError("cancelled", "LMS request was cancelled");
    }

    throw new GradebookProviderResolutionError(
      "unusable",
      error instanceof Error ? error.message : "Unable to use LMS connection",
    );
  }
};

export const resolveGradebookProvider = async (
  input: {
    db: SqlDatabase;
    tenantId: string;
    lmsConnectionId?: string | null | undefined;
    nowIso: string;
  },
  options: GradebookRequestOptions = {},
): Promise<GradebookProvider> => {
  const resolved = await resolveGradebookProviderWithConnection(input, options);
  return resolved.provider;
};

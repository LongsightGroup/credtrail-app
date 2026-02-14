import {
  createOAuthAccessToken,
  createOAuthRefreshToken,
  findOAuthClientById,
  type SqlDatabase,
} from '@credtrail/db';
import {
  OAUTH_ACCESS_TOKEN_TTL_SECONDS,
  OAUTH_REFRESH_TOKEN_TTL_SECONDS,
} from './constants';
import {
  parseBasicAuthorizationHeader,
  parseOAuthClientMetadata,
  type OAuthClientMetadata,
} from './oauth-utils';

interface BasicHeaderContext {
  req: {
    header(name: string): string | undefined;
  };
}

interface CreateOAuthTokenHelpersInput<ContextType extends BasicHeaderContext> {
  oauthTokenErrorJson: (
    context: ContextType,
    status: 400 | 401 | 403 | 500,
    error: string,
    errorDescription?: string,
    includeWwwAuthenticate?: boolean,
  ) => Response;
  sha256Hex: (value: string) => Promise<string>;
  generateOpaqueToken: () => string;
  addSecondsToIso: (isoTimestamp: string, seconds: number) => string;
}

interface OAuthTokenHelpers<ContextType extends BasicHeaderContext> {
  authenticateOAuthClient: (
    context: ContextType,
    db: SqlDatabase,
  ) => Promise<
    | Response
    | {
        clientMetadata: OAuthClientMetadata;
      }
  >;
  issueOAuthAccessAndRefreshTokens: (input: {
    db: SqlDatabase;
    clientMetadata: OAuthClientMetadata;
    userId: string;
    tenantId: string;
    scopeTokens: string[];
    nowIso: string;
  }) => Promise<{
    accessToken: string;
    refreshToken: string;
  }>;
}

export const createOAuthTokenHelpers = <ContextType extends BasicHeaderContext>(
  input: CreateOAuthTokenHelpersInput<ContextType>,
): OAuthTokenHelpers<ContextType> => {
  const authenticateOAuthClient = async (
    context: ContextType,
    db: SqlDatabase,
  ): Promise<
    | Response
    | {
        clientMetadata: OAuthClientMetadata;
      }
  > => {
    const basicAuth = parseBasicAuthorizationHeader(context.req.header('authorization'));

    if (basicAuth === null) {
      return input.oauthTokenErrorJson(
        context,
        401,
        'invalid_client',
        'Client authentication with client_secret_basic is required',
        true,
      );
    }

    const registeredClient = await findOAuthClientById(db, basicAuth.clientId);

    if (registeredClient === null) {
      return input.oauthTokenErrorJson(context, 401, 'invalid_client', 'Unknown client_id', true);
    }

    const providedSecretHash = await input.sha256Hex(basicAuth.clientSecret);

    if (providedSecretHash !== registeredClient.clientSecretHash) {
      return input.oauthTokenErrorJson(
        context,
        401,
        'invalid_client',
        'Client authentication failed',
        true,
      );
    }

    const clientMetadata = parseOAuthClientMetadata(registeredClient);

    if (clientMetadata === null) {
      return input.oauthTokenErrorJson(
        context,
        401,
        'invalid_client',
        'Invalid client registration',
        true,
      );
    }

    return {
      clientMetadata,
    };
  };

  const issueOAuthAccessAndRefreshTokens = async (request: {
    db: SqlDatabase;
    clientMetadata: OAuthClientMetadata;
    userId: string;
    tenantId: string;
    scopeTokens: string[];
    nowIso: string;
  }): Promise<{
    accessToken: string;
    refreshToken: string;
  }> => {
    const accessToken = input.generateOpaqueToken();
    const refreshToken = input.generateOpaqueToken();
    const accessTokenHash = await input.sha256Hex(accessToken);
    const refreshTokenHash = await input.sha256Hex(refreshToken);

    await createOAuthAccessToken(request.db, {
      clientId: request.clientMetadata.clientId,
      userId: request.userId,
      tenantId: request.tenantId,
      accessTokenHash,
      scope: request.scopeTokens.join(' '),
      expiresAt: input.addSecondsToIso(request.nowIso, OAUTH_ACCESS_TOKEN_TTL_SECONDS),
    });

    await createOAuthRefreshToken(request.db, {
      clientId: request.clientMetadata.clientId,
      userId: request.userId,
      tenantId: request.tenantId,
      refreshTokenHash,
      scope: request.scopeTokens.join(' '),
      expiresAt: input.addSecondsToIso(request.nowIso, OAUTH_REFRESH_TOKEN_TTL_SECONDS),
    });

    return {
      accessToken,
      refreshToken,
    };
  };

  return {
    authenticateOAuthClient,
    issueOAuthAccessAndRefreshTokens,
  };
};

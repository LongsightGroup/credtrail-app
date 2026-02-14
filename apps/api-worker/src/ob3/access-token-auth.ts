import { findActiveOAuthAccessTokenByHash, type SqlDatabase } from '@credtrail/db';
import { parseBearerAuthorizationHeader, splitSpaceDelimited } from './oauth-utils';

export interface Ob3AccessTokenContext {
  userId: string;
  tenantId: string;
}

interface AccessTokenRequestContext<BindingsType> {
  env: BindingsType;
  req: {
    header(name: string): string | undefined;
  };
}

interface CreateOb3AccessTokenAuthenticatorInput<
  ContextType extends AccessTokenRequestContext<BindingsType>,
  BindingsType,
> {
  resolveDatabase: (bindings: BindingsType) => SqlDatabase;
  sha256Hex: (value: string) => Promise<string>;
  ob3ErrorJson: (
    context: ContextType,
    status: 400 | 401 | 403 | 404 | 500,
    description: string,
    options?: {
      includeWwwAuthenticate?: boolean;
    },
  ) => Response;
}

export const createOb3AccessTokenAuthenticator = <
  ContextType extends AccessTokenRequestContext<BindingsType>,
  BindingsType,
>(
  input: CreateOb3AccessTokenAuthenticatorInput<ContextType, BindingsType>,
) => {
  return async (
    context: ContextType,
    requiredScope: string,
  ): Promise<Ob3AccessTokenContext | Response> => {
    const bearerToken = parseBearerAuthorizationHeader(context.req.header('authorization'));

    if (bearerToken === null) {
      return input.ob3ErrorJson(context, 401, 'Bearer access token is required', {
        includeWwwAuthenticate: true,
      });
    }

    const accessTokenHash = await input.sha256Hex(bearerToken);
    const accessToken = await findActiveOAuthAccessTokenByHash(input.resolveDatabase(context.env), {
      accessTokenHash,
      nowIso: new Date().toISOString(),
    });

    if (accessToken === null) {
      return input.ob3ErrorJson(context, 401, 'Access token is invalid or expired', {
        includeWwwAuthenticate: true,
      });
    }

    const scopes = splitSpaceDelimited(accessToken.scope);

    if (!scopes.includes(requiredScope)) {
      return input.ob3ErrorJson(context, 403, 'Access token does not grant the required scope');
    }

    return {
      userId: accessToken.userId,
      tenantId: accessToken.tenantId,
    };
  };
};

import { logWarn, type JsonObject, type ObservabilityContext } from '@credtrail/core-domain';
import {
  consumeOAuthAuthorizationCode,
  consumeOAuthRefreshToken,
  createOAuthAuthorizationCode,
  createOAuthClient,
  findOAuthClientById,
  findOb3SubjectProfile,
  findUserById,
  listOb3SubjectCredentials,
  revokeOAuthAccessTokenByHash,
  revokeOAuthRefreshTokenByHash,
  upsertOb3SubjectCredential,
  upsertOb3SubjectProfile,
  type SessionRecord,
  type SqlDatabase,
} from '@credtrail/db';
import type { Hono } from 'hono';
import type { AppBindings, AppContext, AppEnv } from '../app';
import {
  OB3_BASE_PATH,
  OB3_DISCOVERY_CACHE_CONTROL,
  OB3_DISCOVERY_PATH,
  OB3_OAUTH_SCOPE_CREDENTIAL_READONLY,
  OB3_OAUTH_SCOPE_CREDENTIAL_UPSERT,
  OB3_OAUTH_SCOPE_PROFILE_READONLY,
  OB3_OAUTH_SCOPE_PROFILE_UPDATE,
  OB3_OAUTH_SUPPORTED_SCOPE_URIS,
  OAUTH_ACCESS_TOKEN_TTL_SECONDS,
  OAUTH_AUTHORIZATION_CODE_TTL_SECONDS,
  OAUTH_GRANT_TYPE_AUTHORIZATION_CODE,
  OAUTH_GRANT_TYPE_REFRESH_TOKEN,
  OAUTH_PKCE_CODE_CHALLENGE_METHOD_S256,
  OAUTH_RESPONSE_TYPE_CODE,
  OAUTH_TOKEN_ENDPOINT_AUTH_METHOD_CLIENT_SECRET_BASIC,
  OAUTH_TOKEN_TYPE_HINT_ACCESS_TOKEN,
  OAUTH_TOKEN_TYPE_HINT_REFRESH_TOKEN,
} from '../ob3/constants';
import {
  allScopesSupported,
  defaultOb3Profile,
  isPkceCodeChallenge,
  isPkceCodeVerifier,
  isSubset,
  normalizeOb3Profile,
  normalizeSinceQueryParam,
  ob3CredentialsLinkHeader,
  oauthRedirectUriWithParams,
  parseOAuthClientMetadata,
  parsePositiveIntegerQueryParam,
  parseStringArray,
  resolveOb3CredentialIdFromCompactJws,
  splitSpaceDelimited,
  validateRedirectUri,
  type OAuthClientMetadata,
} from '../ob3/oauth-utils';
import { asJsonObject, asNonEmptyString } from '../utils/value-parsers';

interface OAuthAccessTokenContext {
  userId: string;
  tenantId: string;
}

interface RegisterOb3RoutesInput {
  app: Hono<AppEnv>;
  resolveDatabase: (bindings: AppBindings) => SqlDatabase;
  resolveSessionFromCookie: (context: AppContext) => Promise<SessionRecord | null>;
  observabilityContext: (bindings: AppBindings) => ObservabilityContext;
  ob3ServiceDescriptionDocument: (context: AppContext) => JsonObject;
  oauthErrorJson: (
    context: AppContext,
    status: 400 | 401 | 403 | 500,
    error: string,
    errorDescription?: string,
  ) => Response;
  oauthTokenErrorJson: (
    context: AppContext,
    status: 400 | 401 | 403 | 500,
    error: string,
    errorDescription?: string,
    includeWwwAuthenticate?: boolean,
  ) => Response;
  oauthTokenSuccessJson: (
    context: AppContext,
    payload: {
      access_token: string;
      token_type: 'Bearer';
      expires_in: number;
      scope: string;
      refresh_token?: string | undefined;
    },
  ) => Response;
  ob3ErrorJson: (
    context: AppContext,
    status: 400 | 401 | 403 | 404 | 500,
    description: string,
    options?: {
      includeWwwAuthenticate?: boolean;
    },
  ) => Response;
  generateOpaqueToken: () => string;
  sha256Hex: (value: string) => Promise<string>;
  sha256Base64Url: (value: string) => Promise<string>;
  addSecondsToIso: (isoTimestamp: string, seconds: number) => string;
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
  authenticateOAuthClient: (
    context: AppContext,
    db: SqlDatabase,
  ) => Promise<
    | Response
    | {
        clientMetadata: OAuthClientMetadata;
      }
  >;
  authenticateOb3AccessToken: (
    context: AppContext,
    requiredScope: string,
  ) => Promise<Response | OAuthAccessTokenContext>;
}

export const registerOb3Routes = (input: RegisterOb3RoutesInput): void => {
  const {
    app,
    resolveDatabase,
    resolveSessionFromCookie,
    observabilityContext,
    ob3ServiceDescriptionDocument,
    oauthErrorJson,
    oauthTokenErrorJson,
    oauthTokenSuccessJson,
    ob3ErrorJson,
    generateOpaqueToken,
    sha256Hex,
    sha256Base64Url,
    addSecondsToIso,
    issueOAuthAccessAndRefreshTokens,
    authenticateOAuthClient,
    authenticateOb3AccessToken,
  } = input;

  app.get(OB3_DISCOVERY_PATH, (c) => {
    c.header('Cache-Control', OB3_DISCOVERY_CACHE_CONTROL);
    return c.json(ob3ServiceDescriptionDocument(c));
  });

  app.post(`${OB3_BASE_PATH}/oauth/register`, async (c) => {
    const payload = await c.req.json<unknown>().catch(() => null);
    const body = asJsonObject(payload);

    if (body === null) {
      return oauthErrorJson(c, 400, 'invalid_client_metadata', 'Request body must be a JSON object');
    }

    const redirectUris = parseStringArray(body.redirect_uris);

    if (redirectUris === null || redirectUris.length === 0) {
      return oauthErrorJson(
        c,
        400,
        'invalid_client_metadata',
        'redirect_uris is required and must be a non-empty array of URLs',
      );
    }

    for (const redirectUri of redirectUris) {
      const validationError = validateRedirectUri(redirectUri);

      if (validationError === 'invalid_scheme') {
        return oauthErrorJson(c, 400, 'invalid_redirect_uri', 'redirect_uris must use http or https');
      }

      if (validationError === 'invalid_url') {
        return oauthErrorJson(
          c,
          400,
          'invalid_redirect_uri',
          'redirect_uris must contain valid URLs',
        );
      }
    }

    const grantTypes =
      body.grant_types === undefined
        ? [OAUTH_GRANT_TYPE_AUTHORIZATION_CODE]
        : parseStringArray(body.grant_types);

    if (grantTypes?.length !== 1 || grantTypes[0] !== OAUTH_GRANT_TYPE_AUTHORIZATION_CODE) {
      return oauthErrorJson(
        c,
        400,
        'invalid_client_metadata',
        'Only authorization_code grant type is currently supported',
      );
    }

    const responseTypes =
      body.response_types === undefined
        ? [OAUTH_RESPONSE_TYPE_CODE]
        : parseStringArray(body.response_types);

    if (responseTypes?.length !== 1 || responseTypes[0] !== OAUTH_RESPONSE_TYPE_CODE) {
      return oauthErrorJson(
        c,
        400,
        'invalid_client_metadata',
        'Only response_type "code" is currently supported',
      );
    }

    const tokenEndpointAuthMethod =
      asNonEmptyString(body.token_endpoint_auth_method) ??
      OAUTH_TOKEN_ENDPOINT_AUTH_METHOD_CLIENT_SECRET_BASIC;

    if (tokenEndpointAuthMethod !== OAUTH_TOKEN_ENDPOINT_AUTH_METHOD_CLIENT_SECRET_BASIC) {
      return oauthErrorJson(
        c,
        400,
        'invalid_client_metadata',
        'Only token_endpoint_auth_method "client_secret_basic" is supported',
      );
    }

    const scopeFromRequest = asNonEmptyString(body.scope);
    const scopeTokens =
      scopeFromRequest === null
        ? [...OB3_OAUTH_SUPPORTED_SCOPE_URIS]
        : splitSpaceDelimited(scopeFromRequest);

    if (scopeTokens.length === 0 || !allScopesSupported(scopeTokens)) {
      return oauthErrorJson(c, 400, 'invalid_scope', 'Requested scope contains unsupported values');
    }

    const clientId = `oc_${generateOpaqueToken()}`;
    const clientSecret = generateOpaqueToken();
    const clientSecretHash = await sha256Hex(clientSecret);
    const createdClient = await createOAuthClient(resolveDatabase(c.env), {
      clientId,
      clientSecretHash,
      clientName: asNonEmptyString(body.client_name) ?? undefined,
      redirectUrisJson: JSON.stringify(redirectUris),
      grantTypesJson: JSON.stringify(grantTypes),
      responseTypesJson: JSON.stringify(responseTypes),
      scope: scopeTokens.join(' '),
      tokenEndpointAuthMethod,
    });
    const issuedAt = Math.floor(Date.parse(createdClient.createdAt) / 1000);

    return c.json(
      {
        client_id: createdClient.clientId,
        client_secret: clientSecret,
        client_id_issued_at: Number.isFinite(issuedAt) ? issuedAt : Math.floor(Date.now() / 1000),
        client_secret_expires_at: 0,
        redirect_uris: redirectUris,
        grant_types: grantTypes,
        response_types: responseTypes,
        token_endpoint_auth_method: tokenEndpointAuthMethod,
        scope: scopeTokens.join(' '),
        ...(createdClient.clientName === null ? {} : { client_name: createdClient.clientName }),
      },
      201,
    );
  });

  app.get(`${OB3_BASE_PATH}/oauth/authorize`, async (c) => {
    const clientId = asNonEmptyString(c.req.query('client_id'));
    const responseType = asNonEmptyString(c.req.query('response_type'));
    const redirectUri = asNonEmptyString(c.req.query('redirect_uri'));
    const state = c.req.query('state');
    const db = resolveDatabase(c.env);

    if (clientId === null) {
      return oauthErrorJson(c, 400, 'invalid_request', 'client_id is required');
    }

    const registeredClient = await findOAuthClientById(db, clientId);

    if (registeredClient === null) {
      return oauthErrorJson(c, 400, 'invalid_client', 'Unknown client_id');
    }

    const clientMetadata = parseOAuthClientMetadata(registeredClient);

    if (clientMetadata === null) {
      return oauthErrorJson(c, 500, 'server_error', 'Stored client metadata is invalid');
    }

    if (redirectUri === null || !clientMetadata.redirectUris.includes(redirectUri)) {
      return oauthErrorJson(
        c,
        400,
        'invalid_redirect_uri',
        'redirect_uri is required and must match a registered redirect URI',
      );
    }

    if (state === undefined || state.length === 0) {
      return oauthErrorJson(c, 400, 'invalid_request', 'state is required');
    }

    if (responseType !== OAUTH_RESPONSE_TYPE_CODE) {
      return c.redirect(
        oauthRedirectUriWithParams(redirectUri, {
          error: 'unsupported_response_type',
          state,
        }),
        302,
      );
    }

    const requestedScopeRaw = asNonEmptyString(c.req.query('scope'));

    if (requestedScopeRaw === null) {
      return c.redirect(
        oauthRedirectUriWithParams(redirectUri, {
          error: 'invalid_scope',
          error_description: 'scope is required',
          state,
        }),
        302,
      );
    }

    const requestedScopeTokens = splitSpaceDelimited(requestedScopeRaw);

    if (
      requestedScopeTokens.length === 0 ||
      !allScopesSupported(requestedScopeTokens) ||
      !isSubset(requestedScopeTokens, clientMetadata.scope)
    ) {
      return c.redirect(
        oauthRedirectUriWithParams(redirectUri, {
          error: 'invalid_scope',
          state,
        }),
        302,
      );
    }

    const codeChallenge = c.req.query('code_challenge');
    const codeChallengeMethod = c.req.query('code_challenge_method');

    if (
      codeChallenge === undefined ||
      codeChallenge.length === 0 ||
      codeChallengeMethod === undefined ||
      codeChallengeMethod.length === 0
    ) {
      return c.redirect(
        oauthRedirectUriWithParams(redirectUri, {
          error: 'invalid_request',
          error_description: 'code_challenge and code_challenge_method are required',
          state,
        }),
        302,
      );
    }

    if (codeChallengeMethod !== OAUTH_PKCE_CODE_CHALLENGE_METHOD_S256) {
      return c.redirect(
        oauthRedirectUriWithParams(redirectUri, {
          error: 'invalid_request',
          error_description: 'code_challenge_method must be S256',
          state,
        }),
        302,
      );
    }

    if (!isPkceCodeChallenge(codeChallenge)) {
      return c.redirect(
        oauthRedirectUriWithParams(redirectUri, {
          error: 'invalid_request',
          error_description: 'code_challenge must be a base64url-encoded SHA-256 digest',
          state,
        }),
        302,
      );
    }

    const session = await resolveSessionFromCookie(c);

    if (session === null) {
      return c.redirect(
        oauthRedirectUriWithParams(redirectUri, {
          error: 'access_denied',
          error_description: 'Resource owner is not authenticated',
          state,
        }),
        302,
      );
    }

    const authorizationCode = generateOpaqueToken();
    const authorizationCodeHash = await sha256Hex(authorizationCode);

    await createOAuthAuthorizationCode(db, {
      clientId: clientMetadata.clientId,
      userId: session.userId,
      tenantId: session.tenantId,
      codeHash: authorizationCodeHash,
      redirectUri,
      scope: requestedScopeTokens.join(' '),
      expiresAt: addSecondsToIso(new Date().toISOString(), OAUTH_AUTHORIZATION_CODE_TTL_SECONDS),
      codeChallenge,
      codeChallengeMethod,
    });

    return c.redirect(
      oauthRedirectUriWithParams(redirectUri, {
        code: authorizationCode,
        scope: requestedScopeTokens.join(' '),
        state,
      }),
      302,
    );
  });

  const handleOAuthTokenRequest = async (
    c: AppContext,
    options?: {
      forceRefreshGrant?: boolean;
    },
  ): Promise<Response> => {
    const db = resolveDatabase(c.env);
    const authResult = await authenticateOAuthClient(c, db);

    if (authResult instanceof Response) {
      return authResult;
    }

    const { clientMetadata } = authResult;
    const rawBody = await c.req.text();
    const formData = new URLSearchParams(rawBody);
    const requestedGrantType = asNonEmptyString(formData.get('grant_type'));
    const forceRefreshGrant = options?.forceRefreshGrant === true;
    const grantType = forceRefreshGrant
      ? (requestedGrantType ?? OAUTH_GRANT_TYPE_REFRESH_TOKEN)
      : requestedGrantType;

    if (grantType === OAUTH_GRANT_TYPE_AUTHORIZATION_CODE) {
      const code = asNonEmptyString(formData.get('code'));
      const redirectUri = asNonEmptyString(formData.get('redirect_uri'));
      const codeVerifier = formData.get('code_verifier');
      const requestedScope = asNonEmptyString(formData.get('scope'));

      if (
        code === null ||
        redirectUri === null ||
        codeVerifier === null ||
        codeVerifier.length === 0
      ) {
        return oauthTokenErrorJson(
          c,
          400,
          'invalid_request',
          'code, redirect_uri, and code_verifier are required',
        );
      }

      if (!isPkceCodeVerifier(codeVerifier)) {
        return oauthTokenErrorJson(c, 400, 'invalid_request', 'code_verifier is invalid');
      }

      const nowIso = new Date().toISOString();
      const consumedAuthorizationCode = await consumeOAuthAuthorizationCode(db, {
        clientId: clientMetadata.clientId,
        codeHash: await sha256Hex(code),
        redirectUri,
        nowIso,
      });

      if (consumedAuthorizationCode === null) {
        return oauthTokenErrorJson(
          c,
          400,
          'invalid_grant',
          'Authorization code is invalid or expired',
        );
      }

      if (
        consumedAuthorizationCode.codeChallenge === null ||
        consumedAuthorizationCode.codeChallengeMethod !== OAUTH_PKCE_CODE_CHALLENGE_METHOD_S256
      ) {
        return oauthTokenErrorJson(
          c,
          400,
          'invalid_grant',
          'Authorization code is missing PKCE binding',
        );
      }

      const computedCodeChallenge = await sha256Base64Url(codeVerifier);

      if (computedCodeChallenge !== consumedAuthorizationCode.codeChallenge) {
        return oauthTokenErrorJson(c, 400, 'invalid_grant', 'PKCE verification failed');
      }

      if (requestedScope === null) {
        return oauthTokenErrorJson(c, 400, 'invalid_request', 'scope is required');
      }

      const originalScopeTokens = splitSpaceDelimited(consumedAuthorizationCode.scope);
      const requestedScopeTokens = splitSpaceDelimited(requestedScope);

      if (
        requestedScopeTokens.length === 0 ||
        !allScopesSupported(requestedScopeTokens) ||
        !isSubset(requestedScopeTokens, originalScopeTokens)
      ) {
        return oauthTokenErrorJson(
          c,
          400,
          'invalid_scope',
          'Requested scope exceeds authorization grant',
        );
      }

      const issuedTokens = await issueOAuthAccessAndRefreshTokens({
        db,
        clientMetadata,
        userId: consumedAuthorizationCode.userId,
        tenantId: consumedAuthorizationCode.tenantId,
        scopeTokens: requestedScopeTokens,
        nowIso,
      });

      return oauthTokenSuccessJson(c, {
        access_token: issuedTokens.accessToken,
        refresh_token: issuedTokens.refreshToken,
        token_type: 'Bearer',
        expires_in: OAUTH_ACCESS_TOKEN_TTL_SECONDS,
        scope: requestedScopeTokens.join(' '),
      });
    }

    if (grantType === OAUTH_GRANT_TYPE_REFRESH_TOKEN) {
      const refreshToken = asNonEmptyString(formData.get('refresh_token'));
      const requestedScope = asNonEmptyString(formData.get('scope'));

      if (refreshToken === null) {
        return oauthTokenErrorJson(c, 400, 'invalid_request', 'refresh_token is required');
      }

      const nowIso = new Date().toISOString();
      const consumedRefreshToken = await consumeOAuthRefreshToken(db, {
        clientId: clientMetadata.clientId,
        refreshTokenHash: await sha256Hex(refreshToken),
        nowIso,
      });

      if (consumedRefreshToken === null) {
        return oauthTokenErrorJson(c, 400, 'invalid_grant', 'Refresh token is invalid or expired');
      }

      const originallyGrantedScopeTokens = splitSpaceDelimited(consumedRefreshToken.scope);
      const grantedScopeTokens =
        requestedScope === null ? originallyGrantedScopeTokens : splitSpaceDelimited(requestedScope);

      if (
        grantedScopeTokens.length === 0 ||
        !allScopesSupported(grantedScopeTokens) ||
        !isSubset(grantedScopeTokens, originallyGrantedScopeTokens)
      ) {
        return oauthTokenErrorJson(
          c,
          400,
          'invalid_scope',
          'Requested scope exceeds refresh token grant',
        );
      }

      const issuedTokens = await issueOAuthAccessAndRefreshTokens({
        db,
        clientMetadata,
        userId: consumedRefreshToken.userId,
        tenantId: consumedRefreshToken.tenantId,
        scopeTokens: grantedScopeTokens,
        nowIso,
      });

      return oauthTokenSuccessJson(c, {
        access_token: issuedTokens.accessToken,
        refresh_token: issuedTokens.refreshToken,
        token_type: 'Bearer',
        expires_in: OAUTH_ACCESS_TOKEN_TTL_SECONDS,
        scope: grantedScopeTokens.join(' '),
      });
    }

    if (
      forceRefreshGrant &&
      requestedGrantType !== null &&
      requestedGrantType !== OAUTH_GRANT_TYPE_REFRESH_TOKEN
    ) {
      return oauthTokenErrorJson(
        c,
        400,
        'invalid_request',
        'grant_type must be refresh_token for this endpoint',
      );
    }

    return oauthTokenErrorJson(
      c,
      400,
      'unsupported_grant_type',
      'Supported grant_type values are authorization_code and refresh_token',
    );
  };

  app.post(`${OB3_BASE_PATH}/oauth/token`, async (c) => {
    return handleOAuthTokenRequest(c);
  });

  app.post(`${OB3_BASE_PATH}/oauth/refresh`, async (c) => {
    return handleOAuthTokenRequest(c, {
      forceRefreshGrant: true,
    });
  });

  app.post(`${OB3_BASE_PATH}/oauth/revoke`, async (c) => {
    const db = resolveDatabase(c.env);
    const authResult = await authenticateOAuthClient(c, db);

    if (authResult instanceof Response) {
      return authResult;
    }

    const { clientMetadata } = authResult;
    const formData = new URLSearchParams(await c.req.text());
    const token = asNonEmptyString(formData.get('token'));
    const tokenTypeHint = asNonEmptyString(formData.get('token_type_hint'));

    if (token === null || tokenTypeHint === null) {
      return oauthTokenErrorJson(c, 400, 'invalid_request', 'token and token_type_hint are required');
    }

    const tokenHash = await sha256Hex(token);
    const revokedAt = new Date().toISOString();

    if (tokenTypeHint === OAUTH_TOKEN_TYPE_HINT_REFRESH_TOKEN) {
      await revokeOAuthRefreshTokenByHash(db, {
        clientId: clientMetadata.clientId,
        refreshTokenHash: tokenHash,
        revokedAt,
      });
      return c.body(null, 200);
    }

    if (tokenTypeHint === OAUTH_TOKEN_TYPE_HINT_ACCESS_TOKEN) {
      await revokeOAuthAccessTokenByHash(db, {
        clientId: clientMetadata.clientId,
        accessTokenHash: tokenHash,
        revokedAt,
      });
      return c.body(null, 200);
    }

    return oauthTokenErrorJson(
      c,
      400,
      'unsupported_token_type',
      'token_type_hint must be access_token or refresh_token',
    );
  });

  app.get(`${OB3_BASE_PATH}/credentials`, async (c) => {
    const accessTokenContext = await authenticateOb3AccessToken(c, OB3_OAUTH_SCOPE_CREDENTIAL_READONLY);

    if (accessTokenContext instanceof Response) {
      return accessTokenContext;
    }

    const parsedLimit = parsePositiveIntegerQueryParam(c.req.query('limit'), {
      minimum: 1,
      fallback: 50,
    });
    const parsedOffset = parsePositiveIntegerQueryParam(c.req.query('offset'), {
      minimum: 0,
      fallback: 0,
    });

    if (parsedLimit === null || parsedOffset === null) {
      return ob3ErrorJson(c, 400, 'limit and offset query parameters must be valid integers');
    }

    const since = normalizeSinceQueryParam(c.req.query('since'));

    if (since === null) {
      return ob3ErrorJson(c, 400, 'since query parameter must be a valid ISO8601 timestamp');
    }

    const limit = Math.min(parsedLimit, 200);
    const offset = parsedOffset;
    const credentialsResult = await listOb3SubjectCredentials(resolveDatabase(c.env), {
      tenantId: accessTokenContext.tenantId,
      userId: accessTokenContext.userId,
      limit,
      offset,
      ...(since === undefined ? {} : { since }),
    });
    const credential: JsonObject[] = [];
    const compactJwsString: string[] = [];

    for (const entry of credentialsResult.credentials) {
      if (entry.payloadJson !== null) {
        try {
          const parsedPayload = asJsonObject(JSON.parse(entry.payloadJson) as unknown);

          if (parsedPayload !== null) {
            credential.push(parsedPayload);
          }
        } catch {
          logWarn(observabilityContext(c.env), 'ob3_credentials_payload_parse_failed', {
            credentialId: entry.credentialId,
          });
        }
        continue;
      }

      if (entry.compactJws !== null) {
        compactJwsString.push(entry.compactJws);
      }
    }

    c.header('X-Total-Count', String(credentialsResult.totalCount));
    c.header(
      'Link',
      ob3CredentialsLinkHeader({
        requestUrl: c.req.url,
        limit,
        offset,
        totalCount: credentialsResult.totalCount,
        since,
      }),
    );

    return c.json({
      credential,
      compactJwsString,
    });
  });

  app.post(`${OB3_BASE_PATH}/credentials`, async (c) => {
    const accessTokenContext = await authenticateOb3AccessToken(c, OB3_OAUTH_SCOPE_CREDENTIAL_UPSERT);

    if (accessTokenContext instanceof Response) {
      return accessTokenContext;
    }

    const contentType = c.req.header('content-type')?.toLowerCase() ?? '';
    const db = resolveDatabase(c.env);
    const isCredentialJsonContentType =
      contentType.includes('application/json') ||
      contentType.includes('application/ld+json') ||
      contentType.includes('application/vc+ld+json');

    if (isCredentialJsonContentType) {
      const requestPayload = await c.req.json<unknown>().catch(() => null);
      const credentialPayload = asJsonObject(requestPayload);

      if (credentialPayload === null) {
        return ob3ErrorJson(c, 400, 'Request body must be a JSON object');
      }

      const credentialId = asNonEmptyString(credentialPayload.id);

      if (credentialId === null) {
        return ob3ErrorJson(c, 400, 'Credential payload must include a non-empty id');
      }

      const upsertResult = await upsertOb3SubjectCredential(db, {
        tenantId: accessTokenContext.tenantId,
        userId: accessTokenContext.userId,
        credentialId,
        payloadJson: JSON.stringify(credentialPayload),
        issuedAt:
          asNonEmptyString(credentialPayload.validFrom) ??
          asNonEmptyString(credentialPayload.awardedDate) ??
          undefined,
      });

      const responseContentType = contentType.includes('application/vc+ld+json')
        ? 'application/vc+ld+json; charset=utf-8'
        : contentType.includes('application/ld+json')
          ? 'application/ld+json; charset=utf-8'
          : 'application/json; charset=utf-8';
      c.header('Content-Type', responseContentType);
      return c.body(JSON.stringify(credentialPayload), upsertResult.status === 'created' ? 201 : 200);
    }

    if (contentType.includes('text/plain')) {
      const compactJws = (await c.req.text()).trim();

      if (!/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*\.[A-Za-z0-9_-]+$/.test(compactJws)) {
        return ob3ErrorJson(c, 400, 'Request body must be a compact JWS string');
      }

      let credentialId: string;

      try {
        credentialId = resolveOb3CredentialIdFromCompactJws(compactJws);
      } catch (error: unknown) {
        return ob3ErrorJson(
          c,
          400,
          error instanceof Error
            ? error.message
            : 'Request body must contain a valid compact JWS payload',
        );
      }

      const upsertResult = await upsertOb3SubjectCredential(db, {
        tenantId: accessTokenContext.tenantId,
        userId: accessTokenContext.userId,
        credentialId,
        compactJws,
      });

      c.header('Content-Type', 'text/plain; charset=utf-8');
      return c.body(compactJws, upsertResult.status === 'created' ? 201 : 200);
    }

    return ob3ErrorJson(
      c,
      400,
      'content-type must be application/json, application/ld+json, application/vc+ld+json, or text/plain',
    );
  });

  app.get(`${OB3_BASE_PATH}/profile`, async (c) => {
    const accessTokenContext = await authenticateOb3AccessToken(c, OB3_OAUTH_SCOPE_PROFILE_READONLY);

    if (accessTokenContext instanceof Response) {
      return accessTokenContext;
    }

    const storedProfile = await findOb3SubjectProfile(resolveDatabase(c.env), {
      tenantId: accessTokenContext.tenantId,
      userId: accessTokenContext.userId,
    });
    const user = await findUserById(resolveDatabase(c.env), accessTokenContext.userId);
    let parsedStoredProfile: JsonObject | null = null;

    if (storedProfile !== null) {
      try {
        parsedStoredProfile = asJsonObject(JSON.parse(storedProfile.profileJson) as unknown);
      } catch {
        parsedStoredProfile = null;
      }
    }

    const baseProfile =
      storedProfile === null
        ? defaultOb3Profile({
            tenantId: accessTokenContext.tenantId,
            userId: accessTokenContext.userId,
            ...(user === null ? {} : { email: user.email }),
          })
        : (parsedStoredProfile ??
          defaultOb3Profile({
            tenantId: accessTokenContext.tenantId,
            userId: accessTokenContext.userId,
            ...(user === null ? {} : { email: user.email }),
          }));

    return c.json(
      normalizeOb3Profile({
        profile: baseProfile,
        tenantId: accessTokenContext.tenantId,
        userId: accessTokenContext.userId,
      }),
    );
  });

  app.put(`${OB3_BASE_PATH}/profile`, async (c) => {
    const accessTokenContext = await authenticateOb3AccessToken(c, OB3_OAUTH_SCOPE_PROFILE_UPDATE);

    if (accessTokenContext instanceof Response) {
      return accessTokenContext;
    }

    const requestPayload = await c.req.json<unknown>().catch(() => null);
    const requestProfile = asJsonObject(requestPayload);

    if (requestProfile === null) {
      return ob3ErrorJson(c, 400, 'Request body must be a JSON object');
    }

    const normalizedProfile = normalizeOb3Profile({
      profile: requestProfile,
      tenantId: accessTokenContext.tenantId,
      userId: accessTokenContext.userId,
    });

    await upsertOb3SubjectProfile(resolveDatabase(c.env), {
      tenantId: accessTokenContext.tenantId,
      userId: accessTokenContext.userId,
      profileJson: JSON.stringify(normalizedProfile),
    });

    return c.json(normalizedProfile);
  });
};

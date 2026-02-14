import type { JsonObject } from '@credtrail/core-domain';
import { asJsonObject, asNonEmptyString } from '../utils/value-parsers';
import {
  OB3_BASE_PATH,
  OB3_OAUTH_SUPPORTED_SCOPE_SET,
  OAUTH_GRANT_TYPE_AUTHORIZATION_CODE,
  OAUTH_PKCE_CODE_CHALLENGE_PATTERN,
  OAUTH_PKCE_CODE_VERIFIER_PATTERN,
  OAUTH_RESPONSE_TYPE_CODE,
  OAUTH_TOKEN_ENDPOINT_AUTH_METHOD_CLIENT_SECRET_BASIC,
} from './constants';

export interface OAuthClientMetadata {
  clientId: string;
  clientSecretHash: string;
  redirectUris: string[];
  grantTypes: string[];
  responseTypes: string[];
  scope: string[];
  tokenEndpointAuthMethod: string;
}

export type RedirectUriValidationError = 'invalid_url' | 'invalid_scheme';

export const isPkceCodeChallenge = (value: string): boolean => {
  return OAUTH_PKCE_CODE_CHALLENGE_PATTERN.test(value);
};

export const isPkceCodeVerifier = (value: string): boolean => {
  return OAUTH_PKCE_CODE_VERIFIER_PATTERN.test(value);
};

export const parseBearerAuthorizationHeader = (
  authorizationHeader: string | undefined,
): string | null => {
  if (authorizationHeader === undefined) {
    return null;
  }

  const [scheme, token] = authorizationHeader.split(/\s+/, 2);

  if (scheme?.toLowerCase() !== 'bearer') {
    return null;
  }

  const normalizedToken = token?.trim();
  return normalizedToken === undefined || normalizedToken.length === 0 ? null : normalizedToken;
};

export const normalizeOb3ProfileType = (value: unknown): string[] => {
  if (Array.isArray(value)) {
    const normalized = value
      .map((entry) => asNonEmptyString(entry))
      .filter((entry): entry is string => entry !== null);
    const deduplicated = Array.from(new Set<string>(normalized));

    if (!deduplicated.includes('Profile')) {
      deduplicated.push('Profile');
    }

    return deduplicated.length === 0 ? ['Profile'] : deduplicated;
  }

  const singularType = asNonEmptyString(value);

  if (singularType === null) {
    return ['Profile'];
  }

  return singularType === 'Profile' ? ['Profile'] : [singularType, 'Profile'];
};

export const ob3ProfileIdForAccessToken = (input: { tenantId: string; userId: string }): string => {
  return `urn:credtrail:profile:${encodeURIComponent(input.tenantId)}:${encodeURIComponent(input.userId)}`;
};

export const normalizeOb3Profile = (input: {
  profile: JsonObject;
  tenantId: string;
  userId: string;
}): JsonObject => {
  const normalizedProfile: JsonObject = {
    ...input.profile,
  };
  const fallbackId = ob3ProfileIdForAccessToken({
    tenantId: input.tenantId,
    userId: input.userId,
  });
  normalizedProfile.id = asNonEmptyString(normalizedProfile.id) ?? fallbackId;
  normalizedProfile.type = normalizeOb3ProfileType(normalizedProfile.type);
  return normalizedProfile;
};

export const defaultOb3Profile = (input: {
  tenantId: string;
  userId: string;
  email?: string | undefined;
}): JsonObject => {
  return {
    id: ob3ProfileIdForAccessToken({
      tenantId: input.tenantId,
      userId: input.userId,
    }),
    type: ['Profile'],
    ...(input.email === undefined ? {} : { email: input.email, name: input.email }),
  };
};

const parseCompactJwsSegmentObject = (segment: string): JsonObject | null => {
  if (segment.length === 0) {
    return null;
  }

  const normalizedBase64 = segment.replace(/-/g, '+').replace(/_/g, '/');
  const paddedBase64 = `${normalizedBase64}${'='.repeat((4 - (normalizedBase64.length % 4)) % 4)}`;

  try {
    const segmentRaw = atob(paddedBase64);
    return asJsonObject(JSON.parse(segmentRaw) as unknown);
  } catch {
    return null;
  }
};

export const parseCompactJwsPayloadObject = (compactJws: string): JsonObject | null => {
  const segments = compactJws.split('.');

  if (segments.length !== 3) {
    return null;
  }

  const payloadSegment = segments[1];

  if (payloadSegment === undefined) {
    return null;
  }

  return parseCompactJwsSegmentObject(payloadSegment);
};

export const parseCompactJwsHeaderObject = (compactJws: string): JsonObject | null => {
  const segments = compactJws.split('.');

  if (segments.length !== 3) {
    return null;
  }

  const headerSegment = segments[0];

  if (headerSegment === undefined) {
    return null;
  }

  return parseCompactJwsSegmentObject(headerSegment);
};

export const resolveOb3CredentialIdFromCompactJws = (compactJws: string): string => {
  const header = parseCompactJwsHeaderObject(compactJws);
  const payload = parseCompactJwsPayloadObject(compactJws);

  if (header === null || payload === null) {
    throw new Error('Compact JWS must contain JSON JOSE header and payload objects');
  }

  const allowedJoseHeaders = new Set(['alg', 'kid', 'jwk', 'typ']);

  for (const headerName of Object.keys(header)) {
    if (!allowedJoseHeaders.has(headerName)) {
      throw new Error(`JOSE header property "${headerName}" is not supported`);
    }
  }

  const alg = asNonEmptyString(header.alg);
  const typ = asNonEmptyString(header.typ);
  const kid = asNonEmptyString(header.kid);
  const jwk = asJsonObject(header.jwk);

  if (alg === null) {
    throw new Error('JOSE header must include a non-empty alg value');
  }

  if (alg.toLowerCase() === 'none') {
    throw new Error('JOSE header alg must not be "none"');
  }

  if (typ !== null && typ !== 'JWT') {
    throw new Error('JOSE header typ must be "JWT" when provided');
  }

  if (kid === null && jwk === null) {
    throw new Error('JOSE header must include kid or jwk');
  }

  if (jwk !== null && asNonEmptyString(jwk.d) !== null) {
    throw new Error('JOSE header jwk must not include private key material');
  }

  const iss = asNonEmptyString(payload.iss);
  const jti = asNonEmptyString(payload.jti);
  const sub = asNonEmptyString(payload.sub);
  const nbf = payload.nbf;
  const exp = payload.exp;

  if (iss === null) {
    throw new Error('JWT payload must include a non-empty iss claim');
  }

  if (jti === null) {
    throw new Error('JWT payload must include a non-empty jti claim');
  }

  if (typeof nbf !== 'number' || !Number.isFinite(nbf)) {
    throw new Error('JWT payload must include a numeric nbf claim');
  }

  if (sub === null) {
    throw new Error('JWT payload must include a non-empty sub claim');
  }

  if (exp !== undefined && (typeof exp !== 'number' || !Number.isFinite(exp))) {
    throw new Error('JWT payload exp must be numeric when provided');
  }

  return jti;
};

export const parsePositiveIntegerQueryParam = (
  value: string | undefined,
  options: {
    minimum: number;
    fallback: number;
  },
): number | null => {
  if (value === undefined) {
    return options.fallback;
  }

  const normalized = Number(value);

  if (
    !Number.isFinite(normalized) ||
    !Number.isInteger(normalized) ||
    normalized < options.minimum
  ) {
    return null;
  }

  return normalized;
};

export const normalizeSinceQueryParam = (rawSince: string | undefined): string | null | undefined => {
  if (rawSince === undefined) {
    return undefined;
  }

  const parsedSince = Date.parse(rawSince);

  if (!Number.isFinite(parsedSince)) {
    return null;
  }

  return new Date(parsedSince).toISOString();
};

const ob3CredentialsPageUrl = (input: {
  requestUrl: string;
  limit: number;
  offset: number;
  since: string | undefined;
}): string => {
  const url = new URL(`${OB3_BASE_PATH}/credentials`, input.requestUrl);
  url.searchParams.set('limit', String(input.limit));
  url.searchParams.set('offset', String(input.offset));

  if (input.since !== undefined) {
    url.searchParams.set('since', input.since);
  }

  return url.toString();
};

export const ob3CredentialsLinkHeader = (input: {
  requestUrl: string;
  limit: number;
  offset: number;
  totalCount: number;
  since: string | undefined;
}): string => {
  const normalizedLastOffset =
    input.totalCount <= 0
      ? 0
      : Math.floor((Math.max(1, input.totalCount) - 1) / input.limit) * input.limit;
  const links: string[] = [];

  if (input.offset + input.limit < input.totalCount) {
    links.push(
      `<${ob3CredentialsPageUrl({
        requestUrl: input.requestUrl,
        limit: input.limit,
        offset: input.offset + input.limit,
        since: input.since,
      })}>; rel="next"`,
    );
  }

  links.push(
    `<${ob3CredentialsPageUrl({
      requestUrl: input.requestUrl,
      limit: input.limit,
      offset: normalizedLastOffset,
      since: input.since,
    })}>; rel="last"`,
  );
  links.push(
    `<${ob3CredentialsPageUrl({
      requestUrl: input.requestUrl,
      limit: input.limit,
      offset: 0,
      since: input.since,
    })}>; rel="first"`,
  );

  if (input.offset > 0) {
    links.push(
      `<${ob3CredentialsPageUrl({
        requestUrl: input.requestUrl,
        limit: input.limit,
        offset: Math.max(input.offset - input.limit, 0),
        since: input.since,
      })}>; rel="prev"`,
    );
  }

  return links.join(', ');
};

export const splitSpaceDelimited = (value: string): string[] => {
  const tokens = value
    .trim()
    .split(/\s+/)
    .map((token) => token.trim())
    .filter((token) => token.length > 0);
  const seen = new Set<string>();
  const uniqueTokens: string[] = [];

  for (const token of tokens) {
    if (!seen.has(token)) {
      seen.add(token);
      uniqueTokens.push(token);
    }
  }

  return uniqueTokens;
};

export const allScopesSupported = (scopes: readonly string[]): boolean => {
  for (const scope of scopes) {
    if (!OB3_OAUTH_SUPPORTED_SCOPE_SET.has(scope)) {
      return false;
    }
  }

  return true;
};

export const isSubset = (subset: readonly string[], superset: readonly string[]): boolean => {
  const supersetSet = new Set<string>(superset);

  for (const value of subset) {
    if (!supersetSet.has(value)) {
      return false;
    }
  }

  return true;
};

export const parseStringArray = (value: unknown): string[] | null => {
  if (!Array.isArray(value)) {
    return null;
  }

  const parsed: string[] = [];

  for (const entry of value) {
    if (typeof entry !== 'string') {
      return null;
    }

    const normalized = entry.trim();

    if (normalized.length === 0) {
      return null;
    }

    parsed.push(normalized);
  }

  return parsed;
};

export const validateRedirectUri = (redirectUri: string): RedirectUriValidationError | null => {
  let parsedRedirectUri: URL;

  try {
    parsedRedirectUri = new URL(redirectUri);
  } catch {
    return 'invalid_url';
  }

  if (parsedRedirectUri.protocol !== 'https:' && parsedRedirectUri.protocol !== 'http:') {
    return 'invalid_scheme';
  }

  return null;
};

export const parseOAuthClientMetadata = (record: {
  clientId: string;
  clientSecretHash: string;
  redirectUrisJson: string;
  grantTypesJson: string;
  responseTypesJson: string;
  scope: string;
  tokenEndpointAuthMethod: string;
}): OAuthClientMetadata | null => {
  let redirectUrisRaw: unknown;
  let grantTypesRaw: unknown;
  let responseTypesRaw: unknown;

  try {
    redirectUrisRaw = JSON.parse(record.redirectUrisJson) as unknown;
    grantTypesRaw = JSON.parse(record.grantTypesJson) as unknown;
    responseTypesRaw = JSON.parse(record.responseTypesJson) as unknown;
  } catch {
    return null;
  }

  const redirectUris = parseStringArray(redirectUrisRaw);
  const grantTypes = parseStringArray(grantTypesRaw);
  const responseTypes = parseStringArray(responseTypesRaw);
  const scope = splitSpaceDelimited(record.scope);

  if (redirectUris === null || redirectUris.length === 0) {
    return null;
  }

  for (const redirectUri of redirectUris) {
    if (validateRedirectUri(redirectUri) !== null) {
      return null;
    }
  }

  if (grantTypes?.length !== 1 || grantTypes[0] !== OAUTH_GRANT_TYPE_AUTHORIZATION_CODE) {
    return null;
  }

  if (responseTypes?.length !== 1 || responseTypes[0] !== OAUTH_RESPONSE_TYPE_CODE) {
    return null;
  }

  if (
    record.tokenEndpointAuthMethod !== OAUTH_TOKEN_ENDPOINT_AUTH_METHOD_CLIENT_SECRET_BASIC ||
    scope.length === 0 ||
    !allScopesSupported(scope)
  ) {
    return null;
  }

  return {
    clientId: record.clientId,
    clientSecretHash: record.clientSecretHash,
    redirectUris,
    grantTypes,
    responseTypes,
    scope,
    tokenEndpointAuthMethod: record.tokenEndpointAuthMethod,
  };
};

export const parseBasicAuthorizationHeader = (
  authorizationHeader: string | undefined,
): { clientId: string; clientSecret: string } | null => {
  if (authorizationHeader === undefined) {
    return null;
  }

  const [scheme, credentials] = authorizationHeader.split(/\s+/, 2);

  if (scheme?.toLowerCase() !== 'basic' || credentials === undefined) {
    return null;
  }

  let decodedCredentials: string;

  try {
    decodedCredentials = atob(credentials);
  } catch {
    return null;
  }

  const separatorIndex = decodedCredentials.indexOf(':');

  if (separatorIndex <= 0) {
    return null;
  }

  const clientId = decodedCredentials.slice(0, separatorIndex).trim();
  const clientSecret = decodedCredentials.slice(separatorIndex + 1);

  if (clientId.length === 0 || clientSecret.length === 0) {
    return null;
  }

  return {
    clientId,
    clientSecret,
  };
};

export const oauthRedirectUriWithParams = (
  redirectUri: string,
  params: Record<string, string | undefined>,
): string => {
  const redirectTarget = new URL(redirectUri);

  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined) {
      redirectTarget.searchParams.set(key, value);
    }
  }

  return redirectTarget.toString();
};

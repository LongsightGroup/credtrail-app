import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('@credtrail/db', async () => {
  const actual = await vi.importActual<typeof import('@credtrail/db')>('@credtrail/db');

  return {
    ...actual,
    consumeOAuthAuthorizationCode: vi.fn(),
    consumeOAuthRefreshToken: vi.fn(),
    createOAuthAccessToken: vi.fn(),
    createOAuthAuthorizationCode: vi.fn(),
    createOAuthClient: vi.fn(),
    createOAuthRefreshToken: vi.fn(),
    findActiveSessionByHash: vi.fn(),
    findOAuthClientById: vi.fn(),
    findUserById: vi.fn(),
    revokeOAuthAccessTokenByHash: vi.fn(),
    revokeOAuthRefreshTokenByHash: vi.fn(),
    touchSession: vi.fn(),
  };
});

vi.mock('@credtrail/db/postgres', () => {
  return {
    createPostgresDatabase: vi.fn(),
  };
});

import {
  consumeOAuthAuthorizationCode,
  consumeOAuthRefreshToken,
  createOAuthAccessToken,
  createOAuthAuthorizationCode,
  createOAuthClient,
  createOAuthRefreshToken,
  findActiveSessionByHash,
  findOAuthClientById,
  findUserById,
  revokeOAuthAccessTokenByHash,
  revokeOAuthRefreshTokenByHash,
  touchSession,
  type OAuthAccessTokenRecord,
  type OAuthAuthorizationCodeRecord,
  type OAuthClientRecord,
  type OAuthRefreshTokenRecord,
  type SessionRecord,
  type SqlDatabase,
} from '@credtrail/db';
import { createPostgresDatabase } from '@credtrail/db/postgres';

import { app } from './index';

interface OAuthErrorResponse {
  error: string;
  error_description?: string | undefined;
}

const mockedFindOAuthClientById = vi.mocked(findOAuthClientById);
const mockedFindActiveSessionByHash = vi.mocked(findActiveSessionByHash);
const mockedFindUserById = vi.mocked(findUserById);
const mockedTouchSession = vi.mocked(touchSession);
const mockedCreateOAuthClient = vi.mocked(createOAuthClient);
const mockedCreateOAuthAuthorizationCode = vi.mocked(createOAuthAuthorizationCode);
const mockedConsumeOAuthAuthorizationCode = vi.mocked(consumeOAuthAuthorizationCode);
const mockedCreateOAuthAccessToken = vi.mocked(createOAuthAccessToken);
const mockedCreateOAuthRefreshToken = vi.mocked(createOAuthRefreshToken);
const mockedConsumeOAuthRefreshToken = vi.mocked(consumeOAuthRefreshToken);
const mockedRevokeOAuthAccessTokenByHash = vi.mocked(revokeOAuthAccessTokenByHash);
const mockedRevokeOAuthRefreshTokenByHash = vi.mocked(revokeOAuthRefreshTokenByHash);
const mockedCreatePostgresDatabase = vi.mocked(createPostgresDatabase);
const fakeDb = {
  prepare: vi.fn(),
} as unknown as SqlDatabase;

const createEnv = (): {
  APP_ENV: string;
  DATABASE_URL: string;
  BADGE_OBJECTS: R2Bucket;
  PLATFORM_DOMAIN: string;
} => {
  return {
    APP_ENV: 'test',
    DATABASE_URL: 'postgres://credtrail-test.local/db',
    BADGE_OBJECTS: {} as R2Bucket,
    PLATFORM_DOMAIN: 'credtrail.test',
  };
};

const sampleSession = (overrides?: { tenantId?: string; userId?: string }): SessionRecord => {
  return {
    id: 'ses_123',
    tenantId: overrides?.tenantId ?? 'tenant_123',
    userId: overrides?.userId ?? 'usr_123',
    sessionTokenHash: 'session-hash',
    expiresAt: '2026-02-11T22:00:00.000Z',
    lastSeenAt: '2026-02-10T22:00:00.000Z',
    revokedAt: null,
    createdAt: '2026-02-10T22:00:00.000Z',
  };
};

const sampleOAuthClientRecord = (overrides?: Partial<OAuthClientRecord>): OAuthClientRecord => {
  return {
    clientId: 'oc_client_123',
    clientSecretHash: 'secret-hash',
    clientName: 'CredTrail Test Client',
    redirectUrisJson: JSON.stringify(['https://client.example/callback']),
    grantTypesJson: JSON.stringify(['authorization_code']),
    responseTypesJson: JSON.stringify(['code']),
    scope:
      'https://purl.imsglobal.org/spec/ob/v3p0/scope/credential.readonly https://purl.imsglobal.org/spec/ob/v3p0/scope/profile.readonly',
    tokenEndpointAuthMethod: 'client_secret_basic',
    createdAt: '2026-02-11T22:00:00.000Z',
    updatedAt: '2026-02-11T22:00:00.000Z',
    ...overrides,
  };
};

const sampleOAuthAuthorizationCodeRecord = (
  overrides?: Partial<OAuthAuthorizationCodeRecord>,
): OAuthAuthorizationCodeRecord => {
  return {
    id: 'oac_123',
    clientId: 'oc_client_123',
    userId: 'usr_123',
    tenantId: 'tenant_123',
    codeHash: 'code-hash',
    redirectUri: 'https://client.example/callback',
    scope:
      'https://purl.imsglobal.org/spec/ob/v3p0/scope/credential.readonly https://purl.imsglobal.org/spec/ob/v3p0/scope/profile.readonly',
    codeChallenge: null,
    codeChallengeMethod: null,
    expiresAt: '2026-02-11T22:05:00.000Z',
    usedAt: null,
    createdAt: '2026-02-11T22:00:00.000Z',
    ...overrides,
  };
};

const sampleOAuthAccessTokenRecord = (
  overrides?: Partial<OAuthAccessTokenRecord>,
): OAuthAccessTokenRecord => {
  return {
    id: 'oat_123',
    clientId: 'oc_client_123',
    userId: 'usr_123',
    tenantId: 'tenant_123',
    accessTokenHash: 'access-token-hash',
    scope:
      'https://purl.imsglobal.org/spec/ob/v3p0/scope/credential.readonly https://purl.imsglobal.org/spec/ob/v3p0/scope/profile.readonly',
    expiresAt: '2026-02-11T23:00:00.000Z',
    revokedAt: null,
    createdAt: '2026-02-11T22:00:00.000Z',
    ...overrides,
  };
};

const sampleOAuthRefreshTokenRecord = (
  overrides?: Partial<OAuthRefreshTokenRecord>,
): OAuthRefreshTokenRecord => {
  return {
    id: 'ort_123',
    clientId: 'oc_client_123',
    userId: 'usr_123',
    tenantId: 'tenant_123',
    refreshTokenHash: 'refresh-token-hash',
    scope:
      'https://purl.imsglobal.org/spec/ob/v3p0/scope/credential.readonly https://purl.imsglobal.org/spec/ob/v3p0/scope/profile.readonly',
    expiresAt: '2026-03-11T22:00:00.000Z',
    revokedAt: null,
    createdAt: '2026-02-11T22:00:00.000Z',
    ...overrides,
  };
};

const bytesToBase64UrlForTest = (bytes: Uint8Array): string => {
  let raw = '';

  for (const byte of bytes) {
    raw += String.fromCharCode(byte);
  }

  return btoa(raw).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
};

const sha256HexForTest = async (value: string): Promise<string> => {
  const encoded = new TextEncoder().encode(value);
  const digest = await crypto.subtle.digest('SHA-256', encoded);
  const digestBytes = new Uint8Array(digest);
  const hexParts: string[] = [];

  for (const byte of digestBytes) {
    hexParts.push(byte.toString(16).padStart(2, '0'));
  }

  return hexParts.join('');
};

const pkceS256CodeChallengeForTest = async (codeVerifier: string): Promise<string> => {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(codeVerifier));
  return bytesToBase64UrlForTest(new Uint8Array(digest));
};

beforeEach(() => {
  mockedCreatePostgresDatabase.mockReset();
  mockedCreatePostgresDatabase.mockReturnValue(fakeDb);
  mockedFindOAuthClientById.mockReset();
  mockedFindActiveSessionByHash.mockReset();
  mockedTouchSession.mockReset();
  mockedCreateOAuthClient.mockReset();
  mockedCreateOAuthAuthorizationCode.mockReset();
  mockedConsumeOAuthAuthorizationCode.mockReset();
  mockedCreateOAuthAccessToken.mockReset();
  mockedCreateOAuthRefreshToken.mockReset();
  mockedConsumeOAuthRefreshToken.mockReset();
  mockedRevokeOAuthAccessTokenByHash.mockReset();
  mockedRevokeOAuthRefreshTokenByHash.mockReset();
  mockedFindUserById.mockReset();
  mockedFindUserById.mockResolvedValue({
    id: 'usr_123',
    email: 'learner@example.edu',
  });
});
describe('OB3 OAuth2 endpoints', () => {
  it('registers OAuth clients and returns client credentials', async () => {
    mockedCreateOAuthClient.mockResolvedValue(
      sampleOAuthClientRecord({
        clientId: 'oc_registered_client',
      }),
    );

    const response = await app.request(
      '/ims/ob/v3p0/oauth/register',
      {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
        },
        body: JSON.stringify({
          client_name: 'CredTrail Integration',
          redirect_uris: ['https://client.example/callback'],
          grant_types: ['authorization_code'],
          response_types: ['code'],
          token_endpoint_auth_method: 'client_secret_basic',
          scope:
            'https://purl.imsglobal.org/spec/ob/v3p0/scope/credential.readonly https://purl.imsglobal.org/spec/ob/v3p0/scope/profile.readonly',
        }),
      },
      createEnv(),
    );
    const body = await response.json<Record<string, unknown>>();

    expect(response.status).toBe(201);
    expect(body.client_id).toBe('oc_registered_client');
    expect(typeof body.client_secret).toBe('string');
    expect(body.client_secret_expires_at).toBe(0);
    expect(body.token_endpoint_auth_method).toBe('client_secret_basic');
    expect(body.grant_types).toEqual(['authorization_code']);
    expect(body.response_types).toEqual(['code']);
    expect(body.redirect_uris).toEqual(['https://client.example/callback']);

    const firstCall = mockedCreateOAuthClient.mock.calls[0];
    const createInput = firstCall?.[1];
    expect(firstCall?.[0]).toBe(fakeDb);
    expect(createInput?.clientId.startsWith('oc_')).toBe(true);
    expect(createInput?.clientSecretHash).toMatch(/^[a-f0-9]{64}$/);
    expect(createInput?.redirectUrisJson).toBe('["https://client.example/callback"]');
  });

  it('rejects registration requests with invalid redirect_uris payload', async () => {
    const response = await app.request(
      '/ims/ob/v3p0/oauth/register',
      {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
        },
        body: JSON.stringify({
          client_name: 'Broken Client',
        }),
      },
      createEnv(),
    );
    const body = await response.json<OAuthErrorResponse>();

    expect(response.status).toBe(400);
    expect(body.error).toBe('invalid_client_metadata');
    expect(mockedCreateOAuthClient).not.toHaveBeenCalled();
  });

  it('issues authorization codes to authenticated resource owners', async () => {
    mockedFindOAuthClientById.mockResolvedValue(sampleOAuthClientRecord());
    mockedFindActiveSessionByHash.mockResolvedValue(sampleSession());
    mockedCreateOAuthAuthorizationCode.mockResolvedValue(sampleOAuthAuthorizationCodeRecord());
    const codeVerifier = 'test-pkce-code-verifier-abcdefghijklmnopqrstuvwxyz0123456789AB';
    const codeChallenge = await pkceS256CodeChallengeForTest(codeVerifier);

    const response = await app.request(
      `/ims/ob/v3p0/oauth/authorize?response_type=code&client_id=oc_client_123&redirect_uri=https%3A%2F%2Fclient.example%2Fcallback&scope=https%3A%2F%2Fpurl.imsglobal.org%2Fspec%2Fob%2Fv3p0%2Fscope%2Fcredential.readonly&state=state123&code_challenge=${encodeURIComponent(codeChallenge)}&code_challenge_method=S256`,
      {
        headers: {
          Cookie: 'credtrail_session=session-token',
        },
      },
      createEnv(),
    );

    expect(response.status).toBe(302);
    const location = response.headers.get('location');
    expect(location).not.toBeNull();

    if (location === null) {
      throw new Error('Expected location header in authorization response');
    }

    const redirectLocation = new URL(location);
    expect(redirectLocation.origin).toBe('https://client.example');
    expect(redirectLocation.pathname).toBe('/callback');
    expect(redirectLocation.searchParams.get('state')).toBe('state123');
    expect(redirectLocation.searchParams.get('scope')).toBe(
      'https://purl.imsglobal.org/spec/ob/v3p0/scope/credential.readonly',
    );
    expect(typeof redirectLocation.searchParams.get('code')).toBe('string');

    const firstCall = mockedCreateOAuthAuthorizationCode.mock.calls[0];
    const createInput = firstCall?.[1];
    expect(firstCall?.[0]).toBe(fakeDb);
    expect(createInput?.clientId).toBe('oc_client_123');
    expect(createInput?.tenantId).toBe('tenant_123');
    expect(createInput?.userId).toBe('usr_123');
    expect(createInput?.redirectUri).toBe('https://client.example/callback');
    expect(createInput?.codeChallenge).toBe(codeChallenge);
    expect(createInput?.codeChallengeMethod).toBe('S256');
  });

  it('rejects authorization requests that omit state', async () => {
    mockedFindOAuthClientById.mockResolvedValue(sampleOAuthClientRecord());
    const codeVerifier = 'test-pkce-code-verifier-abcdefghijklmnopqrstuvwxyz0123456789AB';
    const codeChallenge = await pkceS256CodeChallengeForTest(codeVerifier);

    const response = await app.request(
      `/ims/ob/v3p0/oauth/authorize?response_type=code&client_id=oc_client_123&redirect_uri=https%3A%2F%2Fclient.example%2Fcallback&scope=https%3A%2F%2Fpurl.imsglobal.org%2Fspec%2Fob%2Fv3p0%2Fscope%2Fcredential.readonly&code_challenge=${encodeURIComponent(codeChallenge)}&code_challenge_method=S256`,
      {},
      createEnv(),
    );
    const body = await response.json<OAuthErrorResponse>();

    expect(response.status).toBe(400);
    expect(body.error).toBe('invalid_request');
    expect(mockedCreateOAuthAuthorizationCode).not.toHaveBeenCalled();
  });

  it('rejects authorization requests when code_challenge_method is not S256', async () => {
    mockedFindOAuthClientById.mockResolvedValue(sampleOAuthClientRecord());

    const response = await app.request(
      '/ims/ob/v3p0/oauth/authorize?response_type=code&client_id=oc_client_123&redirect_uri=https%3A%2F%2Fclient.example%2Fcallback&scope=https%3A%2F%2Fpurl.imsglobal.org%2Fspec%2Fob%2Fv3p0%2Fscope%2Fcredential.readonly&state=state123&code_challenge=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa&code_challenge_method=plain',
      {},
      createEnv(),
    );

    expect(response.status).toBe(302);
    const location = response.headers.get('location');
    expect(location).not.toBeNull();

    if (location === null) {
      throw new Error('Expected location header in authorization error response');
    }

    const redirectLocation = new URL(location);
    expect(redirectLocation.searchParams.get('error')).toBe('invalid_request');
    expect(redirectLocation.searchParams.get('error_description')).toContain('S256');
    expect(redirectLocation.searchParams.get('state')).toBe('state123');
  });

  it('exchanges authorization code for access token with client_secret_basic authentication', async () => {
    const clientSecret = 'oauth-secret';
    const codeVerifier = 'test-pkce-code-verifier-abcdefghijklmnopqrstuvwxyz0123456789AB';
    const codeChallenge = await pkceS256CodeChallengeForTest(codeVerifier);
    const clientSecretHash = await sha256HexForTest(clientSecret);
    mockedFindOAuthClientById.mockResolvedValue(
      sampleOAuthClientRecord({
        clientId: 'oc_client_123',
        clientSecretHash,
      }),
    );
    mockedConsumeOAuthAuthorizationCode.mockResolvedValue(
      sampleOAuthAuthorizationCodeRecord({
        codeChallenge,
        codeChallengeMethod: 'S256',
      }),
    );
    mockedCreateOAuthAccessToken.mockResolvedValue(sampleOAuthAccessTokenRecord());
    mockedCreateOAuthRefreshToken.mockResolvedValue(sampleOAuthRefreshTokenRecord());

    const response = await app.request(
      '/ims/ob/v3p0/oauth/token',
      {
        method: 'POST',
        headers: {
          'content-type': 'application/x-www-form-urlencoded',
          authorization: `Basic ${btoa(`oc_client_123:${clientSecret}`)}`,
        },
        body: `grant_type=authorization_code&code=code-123&redirect_uri=https%3A%2F%2Fclient.example%2Fcallback&scope=${encodeURIComponent('https://purl.imsglobal.org/spec/ob/v3p0/scope/credential.readonly')}&code_verifier=${encodeURIComponent(codeVerifier)}`,
      },
      createEnv(),
    );
    const body = await response.json<Record<string, unknown>>();

    expect(response.status).toBe(200);
    expect(response.headers.get('cache-control')).toBe('no-store');
    expect(response.headers.get('pragma')).toBe('no-cache');
    expect(body.token_type).toBe('Bearer');
    expect(typeof body.access_token).toBe('string');
    expect(typeof body.refresh_token).toBe('string');
    expect(body.expires_in).toBe(3600);
    expect(typeof body.scope).toBe('string');

    const consumeCall = mockedConsumeOAuthAuthorizationCode.mock.calls[0];
    const consumeInput = consumeCall?.[1];
    expect(consumeCall?.[0]).toBe(fakeDb);
    expect(consumeInput?.clientId).toBe('oc_client_123');
    expect(consumeInput?.redirectUri).toBe('https://client.example/callback');
    expect(consumeInput?.codeHash).toMatch(/^[a-f0-9]{64}$/);

    const createAccessTokenCall = mockedCreateOAuthAccessToken.mock.calls[0];
    expect(createAccessTokenCall?.[0]).toBe(fakeDb);
    const createRefreshTokenCall = mockedCreateOAuthRefreshToken.mock.calls[0];
    expect(createRefreshTokenCall?.[0]).toBe(fakeDb);
  });

  it('accepts case-insensitive basic auth scheme at token endpoint', async () => {
    const clientSecret = 'oauth-secret';
    const codeVerifier = 'test-pkce-code-verifier-abcdefghijklmnopqrstuvwxyz0123456789AB';
    const codeChallenge = await pkceS256CodeChallengeForTest(codeVerifier);
    const clientSecretHash = await sha256HexForTest(clientSecret);
    mockedFindOAuthClientById.mockResolvedValue(
      sampleOAuthClientRecord({
        clientId: 'oc_client_123',
        clientSecretHash,
      }),
    );
    mockedConsumeOAuthAuthorizationCode.mockResolvedValue(
      sampleOAuthAuthorizationCodeRecord({
        codeChallenge,
        codeChallengeMethod: 'S256',
      }),
    );
    mockedCreateOAuthAccessToken.mockResolvedValue(sampleOAuthAccessTokenRecord());
    mockedCreateOAuthRefreshToken.mockResolvedValue(sampleOAuthRefreshTokenRecord());

    const response = await app.request(
      '/ims/ob/v3p0/oauth/token',
      {
        method: 'POST',
        headers: {
          'content-type': 'application/x-www-form-urlencoded',
          authorization: `basic ${btoa(`oc_client_123:${clientSecret}`)}`,
        },
        body: `grant_type=authorization_code&code=code-123&redirect_uri=https%3A%2F%2Fclient.example%2Fcallback&scope=${encodeURIComponent('https://purl.imsglobal.org/spec/ob/v3p0/scope/credential.readonly')}&code_verifier=${encodeURIComponent(codeVerifier)}`,
      },
      createEnv(),
    );

    expect(response.status).toBe(200);
    expect(mockedCreateOAuthAccessToken).toHaveBeenCalledTimes(1);
    expect(mockedCreateOAuthRefreshToken).toHaveBeenCalledTimes(1);
  });

  it('returns invalid_client when token endpoint request omits client_secret_basic auth', async () => {
    const response = await app.request(
      '/ims/ob/v3p0/oauth/token',
      {
        method: 'POST',
        headers: {
          'content-type': 'application/x-www-form-urlencoded',
        },
        body: `grant_type=authorization_code&code=code-123&redirect_uri=https%3A%2F%2Fclient.example%2Fcallback&scope=${encodeURIComponent('https://purl.imsglobal.org/spec/ob/v3p0/scope/credential.readonly')}&code_verifier=${encodeURIComponent('test-pkce-code-verifier-abcdefghijklmnopqrstuvwxyz0123456789AB')}`,
      },
      createEnv(),
    );
    const body = await response.json<OAuthErrorResponse>();

    expect(response.status).toBe(401);
    expect(response.headers.get('www-authenticate')).toContain('Basic');
    expect(body.error).toBe('invalid_client');
  });

  it('requires code_verifier for token exchange requests', async () => {
    const clientSecret = 'oauth-secret';
    const clientSecretHash = await sha256HexForTest(clientSecret);
    mockedFindOAuthClientById.mockResolvedValue(
      sampleOAuthClientRecord({
        clientId: 'oc_client_123',
        clientSecretHash,
      }),
    );

    const response = await app.request(
      '/ims/ob/v3p0/oauth/token',
      {
        method: 'POST',
        headers: {
          'content-type': 'application/x-www-form-urlencoded',
          authorization: `Basic ${btoa(`oc_client_123:${clientSecret}`)}`,
        },
        body: `grant_type=authorization_code&code=code-123&redirect_uri=https%3A%2F%2Fclient.example%2Fcallback&scope=${encodeURIComponent('https://purl.imsglobal.org/spec/ob/v3p0/scope/credential.readonly')}`,
      },
      createEnv(),
    );
    const body = await response.json<OAuthErrorResponse>();

    expect(response.status).toBe(400);
    expect(body.error).toBe('invalid_request');
    expect(mockedConsumeOAuthAuthorizationCode).not.toHaveBeenCalled();
  });

  it('rejects token exchange when code_verifier does not match the code_challenge', async () => {
    const clientSecret = 'oauth-secret';
    const codeVerifier = 'test-pkce-code-verifier-abcdefghijklmnopqrstuvwxyz0123456789AB';
    const clientSecretHash = await sha256HexForTest(clientSecret);
    mockedFindOAuthClientById.mockResolvedValue(
      sampleOAuthClientRecord({
        clientId: 'oc_client_123',
        clientSecretHash,
      }),
    );
    mockedConsumeOAuthAuthorizationCode.mockResolvedValue(
      sampleOAuthAuthorizationCodeRecord({
        codeChallenge: 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
        codeChallengeMethod: 'S256',
      }),
    );

    const response = await app.request(
      '/ims/ob/v3p0/oauth/token',
      {
        method: 'POST',
        headers: {
          'content-type': 'application/x-www-form-urlencoded',
          authorization: `Basic ${btoa(`oc_client_123:${clientSecret}`)}`,
        },
        body: `grant_type=authorization_code&code=code-123&redirect_uri=https%3A%2F%2Fclient.example%2Fcallback&scope=${encodeURIComponent('https://purl.imsglobal.org/spec/ob/v3p0/scope/credential.readonly')}&code_verifier=${encodeURIComponent(codeVerifier)}`,
      },
      createEnv(),
    );
    const body = await response.json<OAuthErrorResponse>();

    expect(response.status).toBe(400);
    expect(body.error).toBe('invalid_grant');
    expect(mockedCreateOAuthAccessToken).not.toHaveBeenCalled();
  });

  it('rejects replayed or expired authorization codes', async () => {
    const clientSecret = 'oauth-secret';
    const codeVerifier = 'test-pkce-code-verifier-abcdefghijklmnopqrstuvwxyz0123456789AB';
    const clientSecretHash = await sha256HexForTest(clientSecret);
    mockedFindOAuthClientById.mockResolvedValue(
      sampleOAuthClientRecord({
        clientId: 'oc_client_123',
        clientSecretHash,
      }),
    );
    mockedConsumeOAuthAuthorizationCode.mockResolvedValue(null);

    const response = await app.request(
      '/ims/ob/v3p0/oauth/token',
      {
        method: 'POST',
        headers: {
          'content-type': 'application/x-www-form-urlencoded',
          authorization: `Basic ${btoa(`oc_client_123:${clientSecret}`)}`,
        },
        body: `grant_type=authorization_code&code=code-123&redirect_uri=https%3A%2F%2Fclient.example%2Fcallback&scope=${encodeURIComponent('https://purl.imsglobal.org/spec/ob/v3p0/scope/credential.readonly')}&code_verifier=${encodeURIComponent(codeVerifier)}`,
      },
      createEnv(),
    );
    const body = await response.json<OAuthErrorResponse>();

    expect(response.status).toBe(400);
    expect(body.error).toBe('invalid_grant');
    expect(mockedCreateOAuthAccessToken).not.toHaveBeenCalled();
  });

  it('supports refresh_token grant at token endpoint with scope constraints', async () => {
    const clientSecret = 'oauth-secret';
    const refreshToken = 'refresh-token-123';
    const clientSecretHash = await sha256HexForTest(clientSecret);
    mockedFindOAuthClientById.mockResolvedValue(
      sampleOAuthClientRecord({
        clientId: 'oc_client_123',
        clientSecretHash,
      }),
    );
    mockedConsumeOAuthRefreshToken.mockResolvedValue(sampleOAuthRefreshTokenRecord());
    mockedCreateOAuthAccessToken.mockResolvedValue(sampleOAuthAccessTokenRecord());
    mockedCreateOAuthRefreshToken.mockResolvedValue(sampleOAuthRefreshTokenRecord());

    const response = await app.request(
      '/ims/ob/v3p0/oauth/token',
      {
        method: 'POST',
        headers: {
          'content-type': 'application/x-www-form-urlencoded',
          authorization: `Basic ${btoa(`oc_client_123:${clientSecret}`)}`,
        },
        body: `grant_type=refresh_token&refresh_token=${encodeURIComponent(refreshToken)}&scope=${encodeURIComponent('https://purl.imsglobal.org/spec/ob/v3p0/scope/credential.readonly')}`,
      },
      createEnv(),
    );
    const body = await response.json<Record<string, unknown>>();

    expect(response.status).toBe(200);
    expect(body.token_type).toBe('Bearer');
    expect(typeof body.access_token).toBe('string');
    expect(typeof body.refresh_token).toBe('string');
    expect(body.expires_in).toBe(3600);
    expect(body.scope).toBe('https://purl.imsglobal.org/spec/ob/v3p0/scope/credential.readonly');

    const consumeCall = mockedConsumeOAuthRefreshToken.mock.calls[0];
    const consumeInput = consumeCall?.[1];
    expect(consumeCall?.[0]).toBe(fakeDb);
    expect(consumeInput?.clientId).toBe('oc_client_123');
    expect(consumeInput?.refreshTokenHash).toBe(await sha256HexForTest(refreshToken));
  });

  it('rejects refresh_token grant when requested scope exceeds original grant', async () => {
    const clientSecret = 'oauth-secret';
    const clientSecretHash = await sha256HexForTest(clientSecret);
    mockedFindOAuthClientById.mockResolvedValue(
      sampleOAuthClientRecord({
        clientId: 'oc_client_123',
        clientSecretHash,
      }),
    );
    mockedConsumeOAuthRefreshToken.mockResolvedValue(
      sampleOAuthRefreshTokenRecord({
        scope: 'https://purl.imsglobal.org/spec/ob/v3p0/scope/credential.readonly',
      }),
    );

    const response = await app.request(
      '/ims/ob/v3p0/oauth/token',
      {
        method: 'POST',
        headers: {
          'content-type': 'application/x-www-form-urlencoded',
          authorization: `Basic ${btoa(`oc_client_123:${clientSecret}`)}`,
        },
        body: `grant_type=refresh_token&refresh_token=${encodeURIComponent('refresh-token-123')}&scope=${encodeURIComponent('https://purl.imsglobal.org/spec/ob/v3p0/scope/profile.update')}`,
      },
      createEnv(),
    );
    const body = await response.json<OAuthErrorResponse>();

    expect(response.status).toBe(400);
    expect(body.error).toBe('invalid_scope');
    expect(mockedCreateOAuthAccessToken).not.toHaveBeenCalled();
    expect(mockedCreateOAuthRefreshToken).not.toHaveBeenCalled();
  });

  it('supports dedicated refresh endpoint with implicit refresh_token grant', async () => {
    const clientSecret = 'oauth-secret';
    const clientSecretHash = await sha256HexForTest(clientSecret);
    mockedFindOAuthClientById.mockResolvedValue(
      sampleOAuthClientRecord({
        clientId: 'oc_client_123',
        clientSecretHash,
      }),
    );
    mockedConsumeOAuthRefreshToken.mockResolvedValue(sampleOAuthRefreshTokenRecord());
    mockedCreateOAuthAccessToken.mockResolvedValue(sampleOAuthAccessTokenRecord());
    mockedCreateOAuthRefreshToken.mockResolvedValue(sampleOAuthRefreshTokenRecord());

    const response = await app.request(
      '/ims/ob/v3p0/oauth/refresh',
      {
        method: 'POST',
        headers: {
          'content-type': 'application/x-www-form-urlencoded',
          authorization: `Basic ${btoa(`oc_client_123:${clientSecret}`)}`,
        },
        body: `refresh_token=${encodeURIComponent('refresh-token-123')}&scope=${encodeURIComponent('https://purl.imsglobal.org/spec/ob/v3p0/scope/credential.readonly')}`,
      },
      createEnv(),
    );

    expect(response.status).toBe(200);
    expect(mockedConsumeOAuthRefreshToken).toHaveBeenCalledTimes(1);
  });

  it('revokes refresh tokens through oauth/revoke endpoint', async () => {
    const clientSecret = 'oauth-secret';
    const token = 'refresh-token-123';
    const clientSecretHash = await sha256HexForTest(clientSecret);
    mockedFindOAuthClientById.mockResolvedValue(
      sampleOAuthClientRecord({
        clientId: 'oc_client_123',
        clientSecretHash,
      }),
    );

    const response = await app.request(
      '/ims/ob/v3p0/oauth/revoke',
      {
        method: 'POST',
        headers: {
          'content-type': 'application/x-www-form-urlencoded',
          authorization: `Basic ${btoa(`oc_client_123:${clientSecret}`)}`,
        },
        body: `token=${encodeURIComponent(token)}&token_type_hint=refresh_token`,
      },
      createEnv(),
    );

    expect(response.status).toBe(200);
    const revokeCall = mockedRevokeOAuthRefreshTokenByHash.mock.calls[0];
    const revokeInput = revokeCall?.[1];
    expect(revokeCall?.[0]).toBe(fakeDb);
    expect(revokeInput?.clientId).toBe('oc_client_123');
    expect(revokeInput?.refreshTokenHash).toBe(await sha256HexForTest(token));
  });

  it('revokes access tokens through oauth/revoke endpoint', async () => {
    const clientSecret = 'oauth-secret';
    const token = 'access-token-123';
    const clientSecretHash = await sha256HexForTest(clientSecret);
    mockedFindOAuthClientById.mockResolvedValue(
      sampleOAuthClientRecord({
        clientId: 'oc_client_123',
        clientSecretHash,
      }),
    );

    const response = await app.request(
      '/ims/ob/v3p0/oauth/revoke',
      {
        method: 'POST',
        headers: {
          'content-type': 'application/x-www-form-urlencoded',
          authorization: `Basic ${btoa(`oc_client_123:${clientSecret}`)}`,
        },
        body: `token=${encodeURIComponent(token)}&token_type_hint=access_token`,
      },
      createEnv(),
    );

    expect(response.status).toBe(200);
    const revokeCall = mockedRevokeOAuthAccessTokenByHash.mock.calls[0];
    const revokeInput = revokeCall?.[1];
    expect(revokeCall?.[0]).toBe(fakeDb);
    expect(revokeInput?.clientId).toBe('oc_client_123');
    expect(revokeInput?.accessTokenHash).toBe(await sha256HexForTest(token));
  });

  it('returns unsupported_token_type when token_type_hint is invalid', async () => {
    const clientSecret = 'oauth-secret';
    const clientSecretHash = await sha256HexForTest(clientSecret);
    mockedFindOAuthClientById.mockResolvedValue(
      sampleOAuthClientRecord({
        clientId: 'oc_client_123',
        clientSecretHash,
      }),
    );

    const response = await app.request(
      '/ims/ob/v3p0/oauth/revoke',
      {
        method: 'POST',
        headers: {
          'content-type': 'application/x-www-form-urlencoded',
          authorization: `Basic ${btoa(`oc_client_123:${clientSecret}`)}`,
        },
        body: `token=${encodeURIComponent('token-123')}&token_type_hint=${encodeURIComponent('id_token')}`,
      },
      createEnv(),
    );
    const body = await response.json<OAuthErrorResponse>();

    expect(response.status).toBe(400);
    expect(body.error).toBe('unsupported_token_type');
    expect(mockedRevokeOAuthAccessTokenByHash).not.toHaveBeenCalled();
    expect(mockedRevokeOAuthRefreshTokenByHash).not.toHaveBeenCalled();
  });
});


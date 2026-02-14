import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('@credtrail/db', async () => {
  const actual = await vi.importActual<typeof import('@credtrail/db')>('@credtrail/db');

  return {
    ...actual,
    addLearnerIdentityAlias: vi.fn(),
    createSession: vi.fn(),
    ensureTenantMembership: vi.fn(),
    findLearnerProfileByIdentity: vi.fn(),
    findUserById: vi.fn(),
    listLtiIssuerRegistrations: vi.fn(),
    resolveLearnerProfileForIdentity: vi.fn(),
    upsertTenantMembershipRole: vi.fn(),
    upsertUserByEmail: vi.fn(),
  };
});

vi.mock('@credtrail/db/postgres', () => {
  return {
    createPostgresDatabase: vi.fn(),
  };
});

import {
  addLearnerIdentityAlias,
  createSession,
  ensureTenantMembership,
  findLearnerProfileByIdentity,
  listLtiIssuerRegistrations,
  resolveLearnerProfileForIdentity,
  upsertTenantMembershipRole,
  upsertUserByEmail,
  type LearnerProfileRecord,
  type LtiIssuerRegistrationRecord,
  type SessionRecord,
  type SqlDatabase,
  type TenantMembershipRecord,
} from '@credtrail/db';
import { createPostgresDatabase } from '@credtrail/db/postgres';

import { app } from './index';

interface ErrorResponse {
  error: string;
}

const mockedAddLearnerIdentityAlias = vi.mocked(addLearnerIdentityAlias);
const mockedCreateSession = vi.mocked(createSession);
const mockedEnsureTenantMembership = vi.mocked(ensureTenantMembership);
const mockedFindLearnerProfileByIdentity = vi.mocked(findLearnerProfileByIdentity);
const mockedListLtiIssuerRegistrations = vi.mocked(listLtiIssuerRegistrations);
const mockedResolveLearnerProfileForIdentity = vi.mocked(resolveLearnerProfileForIdentity);
const mockedUpsertTenantMembershipRole = vi.mocked(upsertTenantMembershipRole);
const mockedUpsertUserByEmail = vi.mocked(upsertUserByEmail);
const mockedCreatePostgresDatabase = vi.mocked(createPostgresDatabase);
const fakeDb = {
  prepare: vi.fn(),
} as unknown as SqlDatabase;

const createEnv = (): {
  APP_ENV: string;
  DATABASE_URL: string;
  BADGE_OBJECTS: R2Bucket;
  PLATFORM_DOMAIN: string;
  LTI_ISSUER_REGISTRY_JSON?: string;
  LTI_STATE_SIGNING_SECRET?: string;
} => {
  return {
    APP_ENV: 'test',
    DATABASE_URL: 'postgres://credtrail-test.local/db',
    BADGE_OBJECTS: {} as R2Bucket,
    PLATFORM_DOMAIN: 'credtrail.test',
  };
};

const sampleUserRecord = (overrides?: {
  id?: string;
  email?: string;
}): { id: string; email: string } => {
  return {
    id: overrides?.id ?? 'usr_123',
    email: overrides?.email ?? 'learner@example.edu',
  };
};

const sampleLtiIssuerRegistration = (
  overrides?: Partial<LtiIssuerRegistrationRecord>,
): LtiIssuerRegistrationRecord => {
  return {
    issuer: 'https://canvas.example.edu',
    tenantId: 'tenant_123',
    authorizationEndpoint: 'https://canvas.example.edu/api/lti/authorize_redirect',
    clientId: 'canvas-client-123',
    allowUnsignedIdToken: false,
    createdAt: '2026-02-10T22:00:00.000Z',
    updatedAt: '2026-02-10T22:00:00.000Z',
    ...overrides,
  };
};

const sampleLearnerProfile = (overrides?: Partial<LearnerProfileRecord>): LearnerProfileRecord => {
  return {
    id: 'lpr_123',
    tenantId: 'tenant_123',
    subjectId: 'urn:credtrail:learner:tenant_123:lpr_123',
    displayName: null,
    createdAt: '2026-02-10T22:00:00.000Z',
    updatedAt: '2026-02-10T22:00:00.000Z',
    ...overrides,
  };
};

const sampleTenantMembership = (
  overrides?: Partial<TenantMembershipRecord>,
): TenantMembershipRecord => {
  return {
    tenantId: 'tenant_123',
    userId: 'usr_123',
    role: 'issuer',
    createdAt: '2026-02-10T22:00:00.000Z',
    updatedAt: '2026-02-10T22:00:00.000Z',
    ...overrides,
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

const bytesToBase64UrlForTest = (bytes: Uint8Array): string => {
  let raw = '';

  for (const byte of bytes) {
    raw += String.fromCharCode(byte);
  }

  return btoa(raw).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
};

const compactJwsForTest = (input: {
  header: Record<string, unknown>;
  payload: Record<string, unknown>;
}): string => {
  const headerSegment = bytesToBase64UrlForTest(
    new TextEncoder().encode(JSON.stringify(input.header)),
  );
  const payloadSegment = bytesToBase64UrlForTest(
    new TextEncoder().encode(JSON.stringify(input.payload)),
  );
  return `${headerSegment}.${payloadSegment}.signature`;
};

describe('LTI 1.3 core launch flow', () => {
  const issuer = 'https://canvas.example.edu';
  const authorizationEndpoint = 'https://canvas.example.edu/api/lti/authorize_redirect';
  const clientId = 'canvas-client-123';
  const tenantId = 'tenant_123';
  const targetLinkUri = 'https://tool.example.edu/v1/lti/launch';
  const deploymentId = 'deployment-123';
  const linkedUserId = 'usr_lti_123';

  beforeEach(() => {
    mockedCreatePostgresDatabase.mockReset();
    mockedCreatePostgresDatabase.mockReturnValue(fakeDb);
    mockedListLtiIssuerRegistrations.mockReset();
    mockedListLtiIssuerRegistrations.mockResolvedValue([]);
    mockedResolveLearnerProfileForIdentity.mockReset();
    mockedResolveLearnerProfileForIdentity.mockResolvedValue(sampleLearnerProfile());
    mockedFindLearnerProfileByIdentity.mockReset();
    mockedFindLearnerProfileByIdentity.mockResolvedValue(null);
    mockedAddLearnerIdentityAlias.mockReset();
    mockedUpsertUserByEmail.mockReset();
    mockedUpsertUserByEmail.mockResolvedValue(
      sampleUserRecord({
        id: linkedUserId,
      }),
    );
    mockedEnsureTenantMembership.mockReset();
    mockedEnsureTenantMembership.mockResolvedValue({
      membership: sampleTenantMembership({
        tenantId,
        userId: linkedUserId,
        role: 'viewer',
      }),
      created: true,
    });
    mockedUpsertTenantMembershipRole.mockReset();
    mockedUpsertTenantMembershipRole.mockResolvedValue({
      membership: sampleTenantMembership({
        tenantId,
        userId: linkedUserId,
        role: 'issuer',
      }),
      previousRole: 'viewer',
      changed: true,
    });
    mockedCreateSession.mockReset();
    mockedCreateSession.mockImplementation((_db, input) => {
      return Promise.resolve(
        sampleSession({
          tenantId: input.tenantId,
          userId: input.userId,
        }),
      );
    });
  });

  const createLtiEnv = (options?: {
    allowUnsignedIdToken?: boolean;
  }): ReturnType<typeof createEnv> => {
    const env = createEnv();
    env.LTI_ISSUER_REGISTRY_JSON = JSON.stringify({
      [issuer]: {
        authorizationEndpoint,
        clientId,
        tenantId,
        allowUnsignedIdToken: options?.allowUnsignedIdToken ?? true,
      },
    });
    env.LTI_STATE_SIGNING_SECRET = 'test-lti-state-secret';
    return env;
  };

  it('redirects OIDC login initiation to issuer authorization endpoint with required parameters', async () => {
    const env = createLtiEnv();
    const response = await app.request(
      `/v1/lti/oidc/login?iss=${encodeURIComponent(issuer)}&login_hint=${encodeURIComponent(
        'opaque-login-hint',
      )}&target_link_uri=${encodeURIComponent(targetLinkUri)}&lti_deployment_id=${encodeURIComponent(
        deploymentId,
      )}`,
      undefined,
      env,
    );

    expect(response.status).toBe(302);
    const location = response.headers.get('location');
    expect(location).not.toBeNull();

    const redirectUrl = new URL(location ?? '');
    expect(`${redirectUrl.origin}${redirectUrl.pathname}`).toBe(authorizationEndpoint);
    expect(redirectUrl.searchParams.get('scope')).toBe('openid');
    expect(redirectUrl.searchParams.get('response_type')).toBe('id_token');
    expect(redirectUrl.searchParams.get('response_mode')).toBe('form_post');
    expect(redirectUrl.searchParams.get('prompt')).toBe('none');
    expect(redirectUrl.searchParams.get('client_id')).toBe(clientId);
    expect(redirectUrl.searchParams.get('redirect_uri')).toBe('http://localhost/v1/lti/launch');
    expect(redirectUrl.searchParams.get('state')).toBeTruthy();
    expect(redirectUrl.searchParams.get('nonce')).toBeTruthy();
  });

  it('uses DB-backed issuer registrations when env registry is not configured', async () => {
    const env = createEnv();
    env.LTI_STATE_SIGNING_SECRET = 'test-lti-state-secret';
    mockedListLtiIssuerRegistrations.mockResolvedValue([
      sampleLtiIssuerRegistration({
        issuer,
        tenantId,
        clientId,
        authorizationEndpoint,
        allowUnsignedIdToken: true,
      }),
    ]);

    const response = await app.request(
      `/v1/lti/oidc/login?iss=${encodeURIComponent(issuer)}&login_hint=${encodeURIComponent(
        'opaque-login-hint',
      )}&target_link_uri=${encodeURIComponent(targetLinkUri)}`,
      undefined,
      env,
    );

    expect(response.status).toBe(302);
    const location = response.headers.get('location');
    expect(location).not.toBeNull();

    const redirectUrl = new URL(location ?? '');
    expect(`${redirectUrl.origin}${redirectUrl.pathname}`).toBe(authorizationEndpoint);
    expect(redirectUrl.searchParams.get('client_id')).toBe(clientId);
  });

  it('prefers DB issuer registrations over env defaults for the same issuer', async () => {
    const dbClientId = 'db-client-777';
    const dbAuthorizationEndpoint = 'https://canvas.example.edu/db/authorize_redirect';
    const env = createLtiEnv();
    env.LTI_ISSUER_REGISTRY_JSON = JSON.stringify({
      [issuer]: {
        authorizationEndpoint: 'https://canvas.example.edu/env/authorize_redirect',
        clientId: 'env-client-123',
        tenantId,
        allowUnsignedIdToken: true,
      },
    });
    mockedListLtiIssuerRegistrations.mockResolvedValue([
      sampleLtiIssuerRegistration({
        issuer,
        tenantId,
        clientId: dbClientId,
        authorizationEndpoint: dbAuthorizationEndpoint,
        allowUnsignedIdToken: true,
      }),
    ]);

    const response = await app.request(
      `/v1/lti/oidc/login?iss=${encodeURIComponent(issuer)}&login_hint=${encodeURIComponent(
        'opaque-login-hint',
      )}&target_link_uri=${encodeURIComponent(targetLinkUri)}&client_id=${encodeURIComponent(dbClientId)}`,
      undefined,
      env,
    );

    expect(response.status).toBe(302);
    const location = response.headers.get('location');
    expect(location).not.toBeNull();

    const redirectUrl = new URL(location ?? '');
    expect(`${redirectUrl.origin}${redirectUrl.pathname}`).toBe(dbAuthorizationEndpoint);
    expect(redirectUrl.searchParams.get('client_id')).toBe(dbClientId);
  });

  it('accepts an instructor launch and renders launch completion page', async () => {
    const env = createLtiEnv();
    const loginResponse = await app.request(
      `/v1/lti/oidc/login?iss=${encodeURIComponent(issuer)}&login_hint=${encodeURIComponent(
        'opaque-login-hint',
      )}&target_link_uri=${encodeURIComponent(targetLinkUri)}&lti_deployment_id=${encodeURIComponent(
        deploymentId,
      )}`,
      undefined,
      env,
    );
    const loginLocation = loginResponse.headers.get('location');
    const loginUrl = new URL(loginLocation ?? '');
    const state = loginUrl.searchParams.get('state') ?? '';
    const nonce = loginUrl.searchParams.get('nonce') ?? '';
    const nowEpochSeconds = Math.floor(Date.now() / 1000);
    const idToken = compactJwsForTest({
      header: {
        alg: 'RS256',
        typ: 'JWT',
      },
      payload: {
        iss: issuer,
        sub: 'user-123',
        aud: clientId,
        exp: nowEpochSeconds + 300,
        iat: nowEpochSeconds - 10,
        nonce,
        'https://purl.imsglobal.org/spec/lti/claim/deployment_id': deploymentId,
        'https://purl.imsglobal.org/spec/lti/claim/message_type': 'LtiResourceLinkRequest',
        'https://purl.imsglobal.org/spec/lti/claim/version': '1.3.0',
        'https://purl.imsglobal.org/spec/lti/claim/target_link_uri': targetLinkUri,
        'https://purl.imsglobal.org/spec/lti/claim/resource_link': {
          id: 'resource-link-123',
        },
        'https://purl.imsglobal.org/spec/lti/claim/roles': [
          'http://purl.imsglobal.org/vocab/lis/v2/membership#Instructor',
        ],
      },
    });

    const response = await app.request(
      '/v1/lti/launch',
      {
        method: 'POST',
        headers: {
          'content-type': 'application/x-www-form-urlencoded',
        },
        body: new URLSearchParams({
          id_token: idToken,
          state,
        }).toString(),
      },
      env,
    );
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(response.headers.get('cache-control')).toBe('no-store');
    expect(response.headers.get('set-cookie')).toContain('credtrail_session=');
    expect(body).toContain('LTI 1.3 launch complete');
    expect(body).toContain('Instructor');
    expect(body).toContain('issuer');
    expect(body).toContain('LtiResourceLinkRequest');
    expect(body).toContain('/tenants/tenant_123/learner/dashboard');
    expect(mockedResolveLearnerProfileForIdentity).toHaveBeenCalledWith(fakeDb, {
      tenantId,
      identityType: 'saml_subject',
      identityValue: 'https://canvas.example.edu::user-123',
    });
    expect(mockedUpsertUserByEmail).toHaveBeenCalledWith(
      fakeDb,
      expect.stringContaining('@credtrail-lti.local'),
    );
    expect(mockedEnsureTenantMembership).toHaveBeenCalledWith(fakeDb, tenantId, linkedUserId);
    expect(mockedUpsertTenantMembershipRole).toHaveBeenCalledWith(fakeDb, {
      tenantId,
      userId: linkedUserId,
      role: 'issuer',
    });
    expect(mockedCreateSession).toHaveBeenCalledWith(
      fakeDb,
      expect.objectContaining({
        tenantId,
        userId: linkedUserId,
      }),
    );
  });

  it('accepts a learner launch and links local account session with email claim', async () => {
    const env = createLtiEnv();
    const loginResponse = await app.request(
      `/v1/lti/oidc/login?iss=${encodeURIComponent(issuer)}&login_hint=${encodeURIComponent(
        'opaque-login-hint',
      )}&target_link_uri=${encodeURIComponent(targetLinkUri)}`,
      undefined,
      env,
    );
    const loginLocation = loginResponse.headers.get('location');
    const loginUrl = new URL(loginLocation ?? '');
    const state = loginUrl.searchParams.get('state') ?? '';
    const nonce = loginUrl.searchParams.get('nonce') ?? '';
    const nowEpochSeconds = Math.floor(Date.now() / 1000);
    const idToken = compactJwsForTest({
      header: {
        alg: 'RS256',
        typ: 'JWT',
      },
      payload: {
        iss: issuer,
        sub: 'user-456',
        aud: clientId,
        exp: nowEpochSeconds + 300,
        iat: nowEpochSeconds - 10,
        nonce,
        email: 'Learner@Example.edu',
        'https://purl.imsglobal.org/spec/lti/claim/lis': {
          person_sourcedid: 'sourced-learner-456',
        },
        'https://purl.imsglobal.org/spec/lti/claim/deployment_id': deploymentId,
        'https://purl.imsglobal.org/spec/lti/claim/message_type': 'LtiResourceLinkRequest',
        'https://purl.imsglobal.org/spec/lti/claim/version': '1.3.0',
        'https://purl.imsglobal.org/spec/lti/claim/target_link_uri': targetLinkUri,
        'https://purl.imsglobal.org/spec/lti/claim/resource_link': {
          id: 'resource-link-456',
        },
        'https://purl.imsglobal.org/spec/lti/claim/roles': [
          'http://purl.imsglobal.org/vocab/lis/v2/membership#Learner',
        ],
      },
    });

    const response = await app.request(
      '/v1/lti/launch',
      {
        method: 'POST',
        headers: {
          'content-type': 'application/x-www-form-urlencoded',
        },
        body: new URLSearchParams({
          id_token: idToken,
          state,
        }).toString(),
      },
      env,
    );
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(body).toContain('Learner');
    expect(body).toContain('viewer');
    expect(mockedUpsertUserByEmail).toHaveBeenCalledWith(fakeDb, 'Learner@Example.edu');
    expect(mockedAddLearnerIdentityAlias).toHaveBeenCalledWith(
      fakeDb,
      expect.objectContaining({
        tenantId,
        learnerProfileId: 'lpr_123',
        identityType: 'sourced_id',
        identityValue: 'sourced-learner-456',
      }),
    );
    expect(mockedUpsertTenantMembershipRole).not.toHaveBeenCalled();
  });

  it('rejects launch when unsigned-id-token mode is disabled for issuer config', async () => {
    const env = createLtiEnv({
      allowUnsignedIdToken: false,
    });
    const loginResponse = await app.request(
      `/v1/lti/oidc/login?iss=${encodeURIComponent(issuer)}&login_hint=${encodeURIComponent(
        'opaque-login-hint',
      )}&target_link_uri=${encodeURIComponent(targetLinkUri)}`,
      undefined,
      env,
    );
    const loginLocation = loginResponse.headers.get('location');
    const loginUrl = new URL(loginLocation ?? '');
    const state = loginUrl.searchParams.get('state') ?? '';
    const nonce = loginUrl.searchParams.get('nonce') ?? '';
    const nowEpochSeconds = Math.floor(Date.now() / 1000);
    const idToken = compactJwsForTest({
      header: {
        alg: 'RS256',
      },
      payload: {
        iss: issuer,
        sub: 'user-789',
        aud: clientId,
        exp: nowEpochSeconds + 300,
        iat: nowEpochSeconds - 10,
        nonce,
        'https://purl.imsglobal.org/spec/lti/claim/deployment_id': deploymentId,
        'https://purl.imsglobal.org/spec/lti/claim/message_type': 'LtiResourceLinkRequest',
        'https://purl.imsglobal.org/spec/lti/claim/version': '1.3.0',
        'https://purl.imsglobal.org/spec/lti/claim/target_link_uri': targetLinkUri,
        'https://purl.imsglobal.org/spec/lti/claim/resource_link': {
          id: 'resource-link-789',
        },
      },
    });

    const response = await app.request(
      '/v1/lti/launch',
      {
        method: 'POST',
        headers: {
          'content-type': 'application/x-www-form-urlencoded',
        },
        body: new URLSearchParams({
          id_token: idToken,
          state,
        }).toString(),
      },
      env,
    );
    const body = await response.json<ErrorResponse>();

    expect(response.status).toBe(501);
    expect(body.error).toContain('requires signature verification');
  });
});

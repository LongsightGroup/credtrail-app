import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('@credtrail/db', async () => {
  const actual = await vi.importActual<typeof import('@credtrail/db')>('@credtrail/db');

  return {
    ...actual,
    addLearnerIdentityAlias: vi.fn(),
    findActiveSessionByHash: vi.fn(),
    findLearnerProfileByIdentity: vi.fn(),
    findUserById: vi.fn(),
    listLearnerBadgeSummaries: vi.fn(),
    listLearnerIdentitiesByProfile: vi.fn(),
    removeLearnerIdentityAliasesByType: vi.fn(),
    resolveLearnerProfileForIdentity: vi.fn(),
    touchSession: vi.fn(),
  };
});

vi.mock('@credtrail/db/postgres', () => {
  return {
    createPostgresDatabase: vi.fn(),
  };
});

import {
  addLearnerIdentityAlias,
  findActiveSessionByHash,
  findLearnerProfileByIdentity,
  findUserById,
  listLearnerBadgeSummaries,
  listLearnerIdentitiesByProfile,
  removeLearnerIdentityAliasesByType,
  resolveLearnerProfileForIdentity,
  touchSession,
  type LearnerBadgeSummaryRecord,
  type LearnerProfileRecord,
  type SessionRecord,
  type SqlDatabase,
} from '@credtrail/db';
import { createPostgresDatabase } from '@credtrail/db/postgres';

import { app } from './index';

interface ErrorResponse {
  error: string;
}

const mockedAddLearnerIdentityAlias = vi.mocked(addLearnerIdentityAlias);
const mockedFindActiveSessionByHash = vi.mocked(findActiveSessionByHash);
const mockedFindLearnerProfileByIdentity = vi.mocked(findLearnerProfileByIdentity);
const mockedFindUserById = vi.mocked(findUserById);
const mockedListLearnerBadgeSummaries = vi.mocked(listLearnerBadgeSummaries);
const mockedListLearnerIdentitiesByProfile = vi.mocked(listLearnerIdentitiesByProfile);
const mockedRemoveLearnerIdentityAliasesByType = vi.mocked(removeLearnerIdentityAliasesByType);
const mockedResolveLearnerProfileForIdentity = vi.mocked(resolveLearnerProfileForIdentity);
const mockedTouchSession = vi.mocked(touchSession);
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

const sampleUserRecord = (overrides?: {
  id?: string;
  email?: string;
}): { id: string; email: string } => {
  return {
    id: overrides?.id ?? 'usr_123',
    email: overrides?.email ?? 'learner@example.edu',
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

const sampleLearnerBadge = (
  overrides?: Partial<LearnerBadgeSummaryRecord>,
): LearnerBadgeSummaryRecord => {
  return {
    assertionId: 'tenant_123:assertion_456',
    assertionPublicId: '40a6dc92-85ec-4cb0-8a50-afb2ae700e22',
    tenantId: 'tenant_123',
    badgeTemplateId: 'badge_template_001',
    badgeTitle: 'TypeScript Foundations',
    badgeDescription: 'Awarded for completing TS basics.',
    issuedAt: '2026-02-10T22:00:00.000Z',
    revokedAt: null,
    ...overrides,
  };
};

beforeEach(() => {
  mockedCreatePostgresDatabase.mockReset();
  mockedCreatePostgresDatabase.mockReturnValue(fakeDb);
});

describe('GET /tenants/:tenantId/learner/dashboard', () => {
  beforeEach(() => {
    mockedFindActiveSessionByHash.mockReset();
    mockedTouchSession.mockReset();
    mockedFindUserById.mockReset();
    mockedFindUserById.mockResolvedValue(sampleUserRecord());
    mockedResolveLearnerProfileForIdentity.mockReset();
    mockedResolveLearnerProfileForIdentity.mockResolvedValue(sampleLearnerProfile());
    mockedListLearnerIdentitiesByProfile.mockReset();
    mockedListLearnerIdentitiesByProfile.mockResolvedValue([]);
    mockedListLearnerBadgeSummaries.mockReset();
  });

  it('returns 401 when no learner session is present', async () => {
    const env = createEnv();
    const response = await app.request('/tenants/tenant_123/learner/dashboard', undefined, env);
    const body = await response.json<ErrorResponse>();

    expect(response.status).toBe(401);
    expect(body.error).toBe('Not authenticated');
    expect(mockedFindActiveSessionByHash).not.toHaveBeenCalled();
  });

  it('returns 403 for tenant mismatch between session and path', async () => {
    const env = createEnv();

    mockedFindActiveSessionByHash.mockResolvedValue(
      sampleSession({
        tenantId: 'tenant_other',
      }),
    );
    mockedTouchSession.mockResolvedValue();

    const response = await app.request(
      '/tenants/tenant_123/learner/dashboard',
      {
        headers: {
          Cookie: 'credtrail_session=session-token',
        },
      },
      env,
    );
    const body = await response.json<ErrorResponse>();

    expect(response.status).toBe(403);
    expect(body.error).toBe('Forbidden for requested tenant');
    expect(mockedListLearnerBadgeSummaries).not.toHaveBeenCalled();
  });

  it('renders learner badge list with share links', async () => {
    const env = createEnv();

    mockedFindActiveSessionByHash.mockResolvedValue(sampleSession());
    mockedTouchSession.mockResolvedValue();
    mockedListLearnerBadgeSummaries.mockResolvedValue([
      sampleLearnerBadge(),
      sampleLearnerBadge({
        assertionId: 'tenant_123:assertion_999',
        assertionPublicId: 'public_assertion_999',
        badgeTitle: 'Advanced TypeScript',
        revokedAt: '2026-02-11T01:00:00.000Z',
      }),
    ]);

    const response = await app.request(
      '/tenants/tenant_123/learner/dashboard',
      {
        headers: {
          Cookie: 'credtrail_session=session-token',
        },
      },
      env,
    );
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(response.headers.get('content-type')).toContain('text/html');
    expect(response.headers.get('cache-control')).toBe('no-store');
    expect(body).toContain('Your badges');
    expect(body).toContain('TypeScript Foundations');
    expect(body).toContain('Advanced TypeScript');
    expect(body).toContain('/badges/40a6dc92-85ec-4cb0-8a50-afb2ae700e22');
    expect(body).toContain('/badges/public_assertion_999');
    expect(body).toContain('Verified');
    expect(body).toContain('Revoked');
    expect(body).toContain('Profile settings');
    expect(body).toContain('No learner DID is currently configured.');
    expect(mockedListLearnerIdentitiesByProfile).toHaveBeenCalledWith(
      fakeDb,
      'tenant_123',
      'lpr_123',
    );
    expect(mockedListLearnerBadgeSummaries).toHaveBeenCalledWith(fakeDb, {
      tenantId: 'tenant_123',
      userId: 'usr_123',
    });
  });

  it('renders configured learner DID and status notice', async () => {
    const env = createEnv();

    mockedFindActiveSessionByHash.mockResolvedValue(sampleSession());
    mockedTouchSession.mockResolvedValue();
    mockedListLearnerIdentitiesByProfile.mockResolvedValue([
      {
        id: 'lid_did_123',
        tenantId: 'tenant_123',
        learnerProfileId: 'lpr_123',
        identityType: 'did',
        identityValue: 'did:key:z6MkhLearnerDidExample',
        isPrimary: false,
        isVerified: true,
        createdAt: '2026-02-10T22:00:00.000Z',
        updatedAt: '2026-02-10T22:00:00.000Z',
      },
    ]);
    mockedListLearnerBadgeSummaries.mockResolvedValue([]);

    const response = await app.request(
      '/tenants/tenant_123/learner/dashboard?didStatus=updated',
      {
        headers: {
          Cookie: 'credtrail_session=session-token',
        },
      },
      env,
    );
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(body).toContain(
      'Learner DID updated. Newly issued badges will use this DID as credentialSubject.id.',
    );
    expect(body).toContain('Current DID:');
    expect(body).toContain('did:key:z6MkhLearnerDidExample');
  });

  it('renders empty state when learner has no earned badges yet', async () => {
    const env = createEnv();

    mockedFindActiveSessionByHash.mockResolvedValue(sampleSession());
    mockedTouchSession.mockResolvedValue();
    mockedListLearnerBadgeSummaries.mockResolvedValue([]);

    const response = await app.request(
      '/tenants/tenant_123/learner/dashboard',
      {
        headers: {
          Cookie: 'credtrail_session=session-token',
        },
      },
      env,
    );
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(body).toContain('No badges have been issued to this learner account yet.');
  });
});

describe('POST /tenants/:tenantId/learner/settings/did', () => {
  beforeEach(() => {
    mockedFindActiveSessionByHash.mockReset();
    mockedTouchSession.mockReset();
    mockedFindUserById.mockReset();
    mockedResolveLearnerProfileForIdentity.mockReset();
    mockedFindLearnerProfileByIdentity.mockReset();
    mockedRemoveLearnerIdentityAliasesByType.mockReset();
    mockedAddLearnerIdentityAlias.mockReset();
  });

  it('returns 401 when no learner session is present', async () => {
    const env = createEnv();
    const response = await app.request(
      '/tenants/tenant_123/learner/settings/did',
      {
        method: 'POST',
        headers: {
          'content-type': 'application/x-www-form-urlencoded',
        },
        body: new URLSearchParams({
          did: 'did:key:z6MkhLearnerDidExample',
        }).toString(),
      },
      env,
    );
    const body = await response.json<ErrorResponse>();

    expect(response.status).toBe(401);
    expect(body.error).toBe('Not authenticated');
  });

  it('saves learner DID and redirects with updated status', async () => {
    const env = createEnv();

    mockedFindActiveSessionByHash.mockResolvedValue(sampleSession());
    mockedTouchSession.mockResolvedValue();
    mockedFindUserById.mockResolvedValue(sampleUserRecord());
    mockedResolveLearnerProfileForIdentity.mockResolvedValue(sampleLearnerProfile());
    mockedFindLearnerProfileByIdentity.mockResolvedValue(null);
    mockedRemoveLearnerIdentityAliasesByType.mockResolvedValue(0);

    const response = await app.request(
      '/tenants/tenant_123/learner/settings/did',
      {
        method: 'POST',
        headers: {
          'content-type': 'application/x-www-form-urlencoded',
          Cookie: 'credtrail_session=session-token',
        },
        body: new URLSearchParams({
          did: 'did:key:z6MkhLearnerDidExample',
        }).toString(),
      },
      env,
    );

    expect(response.status).toBe(303);
    const location = response.headers.get('location');
    expect(location).not.toBeNull();

    const redirectUrl = new URL(location ?? '', 'http://localhost');
    expect(redirectUrl.pathname).toBe('/tenants/tenant_123/learner/dashboard');
    expect(redirectUrl.searchParams.get('didStatus')).toBe('updated');
    expect(mockedRemoveLearnerIdentityAliasesByType).toHaveBeenCalledWith(fakeDb, {
      tenantId: 'tenant_123',
      learnerProfileId: 'lpr_123',
      identityType: 'did',
    });
    expect(mockedAddLearnerIdentityAlias).toHaveBeenCalledWith(fakeDb, {
      tenantId: 'tenant_123',
      learnerProfileId: 'lpr_123',
      identityType: 'did',
      identityValue: 'did:key:z6MkhLearnerDidExample',
      isPrimary: false,
      isVerified: true,
    });
  });

  it('clears learner DID and redirects with cleared status', async () => {
    const env = createEnv();

    mockedFindActiveSessionByHash.mockResolvedValue(sampleSession());
    mockedTouchSession.mockResolvedValue();
    mockedFindUserById.mockResolvedValue(sampleUserRecord());
    mockedResolveLearnerProfileForIdentity.mockResolvedValue(sampleLearnerProfile());
    mockedRemoveLearnerIdentityAliasesByType.mockResolvedValue(1);

    const response = await app.request(
      '/tenants/tenant_123/learner/settings/did',
      {
        method: 'POST',
        headers: {
          'content-type': 'application/x-www-form-urlencoded',
          Cookie: 'credtrail_session=session-token',
        },
        body: new URLSearchParams({
          did: '',
        }).toString(),
      },
      env,
    );

    expect(response.status).toBe(303);
    const location = response.headers.get('location');
    expect(location).not.toBeNull();

    const redirectUrl = new URL(location ?? '', 'http://localhost');
    expect(redirectUrl.pathname).toBe('/tenants/tenant_123/learner/dashboard');
    expect(redirectUrl.searchParams.get('didStatus')).toBe('cleared');
    expect(mockedRemoveLearnerIdentityAliasesByType).toHaveBeenCalledWith(fakeDb, {
      tenantId: 'tenant_123',
      learnerProfileId: 'lpr_123',
      identityType: 'did',
    });
    expect(mockedAddLearnerIdentityAlias).not.toHaveBeenCalled();
    expect(mockedFindLearnerProfileByIdentity).not.toHaveBeenCalled();
  });

  it('rejects DID already linked to another learner profile', async () => {
    const env = createEnv();

    mockedFindActiveSessionByHash.mockResolvedValue(sampleSession());
    mockedTouchSession.mockResolvedValue();
    mockedFindUserById.mockResolvedValue(sampleUserRecord());
    mockedResolveLearnerProfileForIdentity.mockResolvedValue(sampleLearnerProfile());
    mockedFindLearnerProfileByIdentity.mockResolvedValue(
      sampleLearnerProfile({
        id: 'lpr_other',
      }),
    );

    const response = await app.request(
      '/tenants/tenant_123/learner/settings/did',
      {
        method: 'POST',
        headers: {
          'content-type': 'application/x-www-form-urlencoded',
          Cookie: 'credtrail_session=session-token',
        },
        body: new URLSearchParams({
          did: 'did:key:z6MkhConflictingDid',
        }).toString(),
      },
      env,
    );

    expect(response.status).toBe(303);
    const location = response.headers.get('location');
    expect(location).not.toBeNull();

    const redirectUrl = new URL(location ?? '', 'http://localhost');
    expect(redirectUrl.pathname).toBe('/tenants/tenant_123/learner/dashboard');
    expect(redirectUrl.searchParams.get('didStatus')).toBe('conflict');
    expect(mockedRemoveLearnerIdentityAliasesByType).not.toHaveBeenCalled();
    expect(mockedAddLearnerIdentityAlias).not.toHaveBeenCalled();
  });

  it('rejects invalid DID values and redirects with invalid status', async () => {
    const env = createEnv();

    mockedFindActiveSessionByHash.mockResolvedValue(sampleSession());
    mockedTouchSession.mockResolvedValue();

    const response = await app.request(
      '/tenants/tenant_123/learner/settings/did',
      {
        method: 'POST',
        headers: {
          'content-type': 'application/x-www-form-urlencoded',
          Cookie: 'credtrail_session=session-token',
        },
        body: new URLSearchParams({
          did: 'did:example:unsupported',
        }).toString(),
      },
      env,
    );

    expect(response.status).toBe(303);
    const location = response.headers.get('location');
    expect(location).not.toBeNull();

    const redirectUrl = new URL(location ?? '', 'http://localhost');
    expect(redirectUrl.pathname).toBe('/tenants/tenant_123/learner/dashboard');
    expect(redirectUrl.searchParams.get('didStatus')).toBe('invalid');
    expect(mockedFindUserById).not.toHaveBeenCalled();
    expect(mockedRemoveLearnerIdentityAliasesByType).not.toHaveBeenCalled();
    expect(mockedAddLearnerIdentityAlias).not.toHaveBeenCalled();
  });
});

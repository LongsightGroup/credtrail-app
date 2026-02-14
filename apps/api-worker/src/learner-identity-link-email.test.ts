import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('@credtrail/db', async () => {
  const actual = await vi.importActual<typeof import('@credtrail/db')>('@credtrail/db');

  return {
    ...actual,
    addLearnerIdentityAlias: vi.fn(),
    createLearnerIdentityLinkProof: vi.fn(),
    findActiveSessionByHash: vi.fn(),
    findLearnerIdentityLinkProofByHash: vi.fn(),
    findLearnerProfileByIdentity: vi.fn(),
    findUserById: vi.fn(),
    markLearnerIdentityLinkProofUsed: vi.fn(),
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
  createLearnerIdentityLinkProof,
  findActiveSessionByHash,
  findLearnerIdentityLinkProofByHash,
  findLearnerProfileByIdentity,
  findUserById,
  markLearnerIdentityLinkProofUsed,
  resolveLearnerProfileForIdentity,
  touchSession,
  type LearnerIdentityLinkProofRecord,
  type LearnerProfileRecord,
  type SessionRecord,
  type SqlDatabase,
} from '@credtrail/db';
import { createPostgresDatabase } from '@credtrail/db/postgres';

import { app } from './index';

interface ErrorResponse {
  error: string;
}

interface IdentityLinkRequestResponse {
  status: 'sent' | 'already_linked';
  tenantId: string;
  identityType: 'email';
  identityValue: string;
  learnerProfileId?: string | undefined;
  expiresAt?: string | undefined;
  token?: string | undefined;
}

interface IdentityLinkVerifyResponse {
  status: 'linked' | 'already_linked';
  tenantId: string;
  learnerProfileId: string;
  identityType: 'email';
  identityValue: string;
}

const mockedAddLearnerIdentityAlias = vi.mocked(addLearnerIdentityAlias);
const mockedCreateLearnerIdentityLinkProof = vi.mocked(createLearnerIdentityLinkProof);
const mockedFindActiveSessionByHash = vi.mocked(findActiveSessionByHash);
const mockedFindLearnerIdentityLinkProofByHash = vi.mocked(findLearnerIdentityLinkProofByHash);
const mockedFindLearnerProfileByIdentity = vi.mocked(findLearnerProfileByIdentity);
const mockedFindUserById = vi.mocked(findUserById);
const mockedMarkLearnerIdentityLinkProofUsed = vi.mocked(markLearnerIdentityLinkProofUsed);
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

const sampleIdentityLinkProof = (
  overrides?: Partial<LearnerIdentityLinkProofRecord>,
): LearnerIdentityLinkProofRecord => {
  return {
    id: 'lip_123',
    tenantId: 'tenant_123',
    learnerProfileId: 'lpr_123',
    requestedByUserId: 'usr_123',
    identityType: 'email',
    identityValue: 'learner@gmail.com',
    tokenHash: 'proof-token-hash',
    expiresAt: '2099-01-01T00:00:00.000Z',
    usedAt: null,
    createdAt: '2026-02-10T22:00:00.000Z',
    ...overrides,
  };
};

beforeEach(() => {
  mockedCreatePostgresDatabase.mockReset();
  mockedCreatePostgresDatabase.mockReturnValue(fakeDb);
});

describe('POST /v1/tenants/:tenantId/learner/identity-links/email', () => {
  beforeEach(() => {
    mockedFindActiveSessionByHash.mockReset();
    mockedTouchSession.mockReset();
    mockedFindUserById.mockReset();
    mockedResolveLearnerProfileForIdentity.mockReset();
    mockedFindLearnerProfileByIdentity.mockReset();
    mockedCreateLearnerIdentityLinkProof.mockReset();
    mockedFindLearnerIdentityLinkProofByHash.mockReset();
    mockedAddLearnerIdentityAlias.mockReset();
    mockedMarkLearnerIdentityLinkProofUsed.mockReset();
  });

  it('links a new verified email alias after proof verification', async () => {
    const env = {
      ...createEnv(),
      APP_ENV: 'development',
    };

    mockedFindActiveSessionByHash.mockResolvedValue(sampleSession());
    mockedTouchSession.mockResolvedValue();
    mockedFindUserById.mockResolvedValue({
      id: 'usr_123',
      email: 'student@umich.edu',
    });
    mockedResolveLearnerProfileForIdentity.mockResolvedValue(sampleLearnerProfile());
    mockedFindLearnerProfileByIdentity.mockResolvedValueOnce(null).mockResolvedValueOnce(null);
    mockedCreateLearnerIdentityLinkProof.mockResolvedValue(sampleIdentityLinkProof());
    mockedFindLearnerIdentityLinkProofByHash.mockResolvedValue(sampleIdentityLinkProof());
    mockedAddLearnerIdentityAlias.mockResolvedValue({
      id: 'lid_new',
      tenantId: 'tenant_123',
      learnerProfileId: 'lpr_123',
      identityType: 'email',
      identityValue: 'learner@gmail.com',
      isPrimary: true,
      isVerified: true,
      createdAt: '2026-02-10T22:00:00.000Z',
      updatedAt: '2026-02-10T22:00:00.000Z',
    });
    mockedMarkLearnerIdentityLinkProofUsed.mockResolvedValue();

    const requestResponse = await app.request(
      '/v1/tenants/tenant_123/learner/identity-links/email/request',
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Cookie: 'credtrail_session=session-token',
        },
        body: JSON.stringify({
          email: 'Learner@Gmail.com',
        }),
      },
      env,
    );
    const requestBody = await requestResponse.json<IdentityLinkRequestResponse>();

    expect(requestResponse.status).toBe(202);
    expect(requestBody.status).toBe('sent');
    expect(requestBody.identityValue).toBe('learner@gmail.com');
    expect(typeof requestBody.token).toBe('string');
    expect(mockedCreateLearnerIdentityLinkProof).toHaveBeenCalledWith(
      fakeDb,
      expect.objectContaining({
        tenantId: 'tenant_123',
        learnerProfileId: 'lpr_123',
        identityType: 'email',
        identityValue: 'learner@gmail.com',
      }),
    );

    if (requestBody.token === undefined) {
      throw new Error('Expected proof token in development environment');
    }

    const verifyResponse = await app.request(
      '/v1/tenants/tenant_123/learner/identity-links/email/verify',
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Cookie: 'credtrail_session=session-token',
        },
        body: JSON.stringify({
          token: requestBody.token,
        }),
      },
      env,
    );
    const verifyBody = await verifyResponse.json<IdentityLinkVerifyResponse>();

    expect(verifyResponse.status).toBe(200);
    expect(verifyBody.status).toBe('linked');
    expect(verifyBody.identityValue).toBe('learner@gmail.com');
    expect(mockedAddLearnerIdentityAlias).toHaveBeenCalledWith(fakeDb, {
      tenantId: 'tenant_123',
      learnerProfileId: 'lpr_123',
      identityType: 'email',
      identityValue: 'learner@gmail.com',
      isPrimary: true,
      isVerified: true,
    });
    expect(mockedMarkLearnerIdentityLinkProofUsed).toHaveBeenCalledWith(
      fakeDb,
      'lip_123',
      expect.any(String),
    );
  });

  it('rejects verification when token does not belong to authenticated user', async () => {
    const env = createEnv();

    mockedFindActiveSessionByHash.mockResolvedValue(sampleSession());
    mockedTouchSession.mockResolvedValue();
    mockedFindLearnerIdentityLinkProofByHash.mockResolvedValue(
      sampleIdentityLinkProof({
        requestedByUserId: 'usr_other',
      }),
    );

    const response = await app.request(
      '/v1/tenants/tenant_123/learner/identity-links/email/verify',
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Cookie: 'credtrail_session=session-token',
        },
        body: JSON.stringify({
          token: '0123456789012345678901234567890123456789',
        }),
      },
      env,
    );
    const body = await response.json<ErrorResponse>();

    expect(response.status).toBe(403);
    expect(body.error).toBe('Forbidden identity link token');
    expect(mockedAddLearnerIdentityAlias).not.toHaveBeenCalled();
    expect(mockedMarkLearnerIdentityLinkProofUsed).not.toHaveBeenCalled();
  });
});

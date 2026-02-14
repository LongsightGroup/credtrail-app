import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('@credtrail/db', async () => {
  const actual = await vi.importActual<typeof import('@credtrail/db')>('@credtrail/db');

  return {
    ...actual,
    createAssertion: vi.fn(),
    createAuditLog: vi.fn(),
    findActiveDelegatedIssuingAuthorityGrantForAction: vi.fn(),
    findActiveSessionByHash: vi.fn(),
    findAssertionByIdempotencyKey: vi.fn(),
    findBadgeTemplateById: vi.fn(),
    findTenantMembership: vi.fn(),
    findTenantSigningRegistrationByDid: vi.fn(),
    findUserById: vi.fn(),
    hasTenantMembershipOrgUnitAccess: vi.fn(),
    hasTenantMembershipOrgUnitScopeAssignments: vi.fn(),
    listLearnerIdentitiesByProfile: vi.fn(),
    nextAssertionStatusListIndex: vi.fn(),
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
  type JsonObject,
  generateTenantDidSigningMaterial,
  signCredentialWithEd25519Signature2020,
} from '@credtrail/core-domain';
import {
  createAssertion,
  createAuditLog,
  findActiveDelegatedIssuingAuthorityGrantForAction,
  findActiveSessionByHash,
  findAssertionByIdempotencyKey,
  findBadgeTemplateById,
  findTenantMembership,
  findTenantSigningRegistrationByDid,
  findUserById,
  hasTenantMembershipOrgUnitAccess,
  hasTenantMembershipOrgUnitScopeAssignments,
  listLearnerIdentitiesByProfile,
  nextAssertionStatusListIndex,
  resolveLearnerProfileForIdentity,
  touchSession,
  type AssertionRecord,
  type AuditLogRecord,
  type BadgeTemplateRecord,
  type DelegatedIssuingAuthorityGrantRecord,
  type LearnerProfileRecord,
  type SessionRecord,
  type SqlDatabase,
  type TenantMembershipRecord,
} from '@credtrail/db';
import { createPostgresDatabase } from '@credtrail/db/postgres';

import { app } from './index';

interface ErrorResponse {
  error: string;
}

interface ManualIssueResponse {
  status: 'issued' | 'already_issued';
  assertionId: string;
  tenantId: string;
  credential: JsonObject;
}

const mockedFindAssertionByIdempotencyKey = vi.mocked(findAssertionByIdempotencyKey);
const mockedFindBadgeTemplateById = vi.mocked(findBadgeTemplateById);
const mockedFindActiveDelegatedIssuingAuthorityGrantForAction = vi.mocked(
  findActiveDelegatedIssuingAuthorityGrantForAction,
);
const mockedFindTenantMembership = vi.mocked(findTenantMembership);
const mockedFindTenantSigningRegistrationByDid = vi.mocked(findTenantSigningRegistrationByDid);
const mockedFindActiveSessionByHash = vi.mocked(findActiveSessionByHash);
const mockedFindUserById = vi.mocked(findUserById);
const mockedHasTenantMembershipOrgUnitAccess = vi.mocked(hasTenantMembershipOrgUnitAccess);
const mockedHasTenantMembershipOrgUnitScopeAssignments = vi.mocked(
  hasTenantMembershipOrgUnitScopeAssignments,
);
const mockedResolveLearnerProfileForIdentity = vi.mocked(resolveLearnerProfileForIdentity);
const mockedCreateAssertion = vi.mocked(createAssertion);
const mockedNextAssertionStatusListIndex = vi.mocked(nextAssertionStatusListIndex);
const mockedTouchSession = vi.mocked(touchSession);
const mockedListLearnerIdentitiesByProfile = vi.mocked(listLearnerIdentitiesByProfile);
const mockedCreateAuditLog = vi.mocked(createAuditLog);
const mockedCreatePostgresDatabase = vi.mocked(createPostgresDatabase);
const fakeDb = {
  prepare: vi.fn(),
} as unknown as SqlDatabase;

const createEnv = (): {
  APP_ENV: string;
  DATABASE_URL: string;
  BADGE_OBJECTS: R2Bucket;
  PLATFORM_DOMAIN: string;
  MARKETING_SITE_ORIGIN?: string;
  TENANT_SIGNING_KEY_HISTORY_JSON?: string;
  TENANT_REMOTE_SIGNER_REGISTRY_JSON?: string;
  JOB_PROCESSOR_TOKEN?: string;
  BOOTSTRAP_ADMIN_TOKEN?: string;
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

beforeEach(() => {
  mockedCreatePostgresDatabase.mockReset();
  mockedCreatePostgresDatabase.mockReturnValue(fakeDb);
  mockedFindTenantMembership.mockReset();
  mockedFindTenantMembership.mockResolvedValue(sampleTenantMembership());
  mockedFindTenantSigningRegistrationByDid.mockReset();
  mockedFindTenantSigningRegistrationByDid.mockResolvedValue(null);
  mockedFindUserById.mockReset();
  mockedFindUserById.mockResolvedValue({
    id: 'usr_123',
    email: 'learner@example.edu',
  });
  mockedHasTenantMembershipOrgUnitAccess.mockReset();
  mockedHasTenantMembershipOrgUnitAccess.mockResolvedValue(false);
  mockedHasTenantMembershipOrgUnitScopeAssignments.mockReset();
  mockedHasTenantMembershipOrgUnitScopeAssignments.mockResolvedValue(false);
  mockedFindActiveDelegatedIssuingAuthorityGrantForAction.mockReset();
  mockedFindActiveDelegatedIssuingAuthorityGrantForAction.mockResolvedValue(null);
  mockedListLearnerIdentitiesByProfile.mockReset();
  mockedListLearnerIdentitiesByProfile.mockResolvedValue([]);
  mockedFindActiveSessionByHash.mockReset();
  mockedTouchSession.mockReset();
  mockedFindBadgeTemplateById.mockReset();
  mockedFindBadgeTemplateById.mockResolvedValue(sampleBadgeTemplate());
  mockedFindAssertionByIdempotencyKey.mockReset();
  mockedResolveLearnerProfileForIdentity.mockReset();
  mockedNextAssertionStatusListIndex.mockReset();
  mockedCreateAssertion.mockReset();
  mockedCreateAuditLog.mockReset();
  mockedCreateAuditLog.mockResolvedValue(sampleAuditLogRecord());
});

const sampleAssertion = (overrides?: {
  revokedAt?: string | null;
  statusListIndex?: number | null;
}): AssertionRecord => {
  return {
    id: 'tenant_123:assertion_456',
    tenantId: 'tenant_123',
    publicId: '40a6dc92-85ec-4cb0-8a50-afb2ae700e22',
    learnerProfileId: 'lpr_123',
    badgeTemplateId: 'badge_template_001',
    recipientIdentity: 'learner@example.edu',
    recipientIdentityType: 'email',
    vcR2Key: 'tenants/tenant_123/assertions/tenant_123%3Aassertion_456.jsonld',
    statusListIndex: overrides?.statusListIndex === undefined ? 0 : overrides.statusListIndex,
    idempotencyKey: 'idem_abc',
    issuedAt: '2026-02-10T22:00:00.000Z',
    issuedByUserId: 'usr_123',
    revokedAt: overrides?.revokedAt ?? null,
    createdAt: '2026-02-10T22:00:00.000Z',
    updatedAt: '2026-02-10T22:00:00.000Z',
  };
};

const asJsonObject = (value: unknown): JsonObject | null => {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    return null;
  }

  return value as JsonObject;
};

const asString = (value: unknown): string | null => {
  return typeof value === 'string' ? value : null;
};

const jsonObjectFromRequestInitBody = (init: RequestInit | undefined): JsonObject => {
  if (typeof init?.body !== 'string') {
    return {};
  }

  try {
    const parsed = JSON.parse(init.body) as unknown;
    return asJsonObject(parsed) ?? {};
  } catch {
    return {};
  }
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

const sampleBadgeTemplate = (overrides?: Partial<BadgeTemplateRecord>): BadgeTemplateRecord => {
  return {
    id: 'badge_template_001',
    tenantId: 'tenant_123',
    slug: 'typescript-foundations',
    title: 'TypeScript Foundations',
    description: 'Awarded for completing TS basics.',
    criteriaUri: null,
    imageUri: null,
    createdByUserId: 'usr_issuer',
    ownerOrgUnitId: 'tenant_123:org:institution',
    governanceMetadataJson: '{"stability":"institution_registry"}',
    isArchived: false,
    createdAt: '2026-02-10T22:00:00.000Z',
    updatedAt: '2026-02-10T22:00:00.000Z',
    ...overrides,
  };
};

const sampleDelegatedIssuingAuthorityGrant = (
  overrides?: Partial<DelegatedIssuingAuthorityGrantRecord>,
): DelegatedIssuingAuthorityGrantRecord => {
  return {
    id: 'dag_123',
    tenantId: 'tenant_123',
    delegateUserId: 'usr_delegate',
    delegatedByUserId: 'usr_admin',
    orgUnitId: 'tenant_123:org:department-math',
    allowedActions: ['issue_badge'],
    badgeTemplateIds: ['badge_template_001'],
    startsAt: '2026-02-13T00:00:00.000Z',
    endsAt: '2026-03-13T00:00:00.000Z',
    revokedAt: null,
    revokedByUserId: null,
    revokedReason: null,
    status: 'active',
    createdAt: '2026-02-13T00:00:00.000Z',
    updatedAt: '2026-02-13T00:00:00.000Z',
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

const sampleAuditLogRecord = (overrides?: Partial<AuditLogRecord>): AuditLogRecord => {
  return {
    id: 'aud_123',
    tenantId: 'tenant_123',
    actorUserId: 'usr_123',
    action: 'assertion.issued',
    targetType: 'assertion',
    targetId: 'tenant_123:assertion_456',
    metadataJson: null,
    occurredAt: '2026-02-10T22:00:00.000Z',
    createdAt: '2026-02-10T22:00:00.000Z',
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

const createInMemoryBadgeObjects = (): R2Bucket => {
  const objects = new Map<string, string>();

  return {
    head: vi.fn((key: string) => {
      if (!objects.has(key)) {
        return Promise.resolve(null);
      }

      return Promise.resolve({ key });
    }),
    get: vi.fn((key: string) => {
      const value = objects.get(key);

      if (value === undefined) {
        return Promise.resolve(null);
      }

      return Promise.resolve({
        text: () => Promise.resolve(value),
      });
    }),
    put: vi.fn((key: string, value: unknown) => {
      if (typeof value !== 'string') {
        throw new Error('Expected string value for R2 put in test bucket');
      }

      objects.set(key, value);
      return Promise.resolve({
        key,
        etag: 'etag-test',
        version: 'version-test',
        size: value.length,
        uploaded: new Date(),
      });
    }),
  } as unknown as R2Bucket;
};

describe('POST /v1/tenants/:tenantId/assertions/manual-issue', () => {
  beforeEach(() => {
    mockedFindActiveSessionByHash.mockReset();
    mockedFindTenantMembership.mockReset();
    mockedFindTenantMembership.mockResolvedValue(sampleTenantMembership());
    mockedTouchSession.mockReset();
    mockedFindBadgeTemplateById.mockReset();
    mockedFindBadgeTemplateById.mockResolvedValue(sampleBadgeTemplate());
    mockedFindAssertionByIdempotencyKey.mockReset();
    mockedResolveLearnerProfileForIdentity.mockReset();
    mockedNextAssertionStatusListIndex.mockReset();
    mockedCreateAssertion.mockReset();
    mockedCreateAuditLog.mockReset();
    mockedCreateAuditLog.mockResolvedValue(sampleAuditLogRecord());
  });

  it('uses stable learner subject identifiers across old and new recipient emails', async () => {
    const signingMaterial = await generateTenantDidSigningMaterial({
      did: 'did:web:credtrail.test:tenant_123',
    });
    const env = {
      ...createEnv(),
      BADGE_OBJECTS: createInMemoryBadgeObjects(),
      TENANT_SIGNING_REGISTRY_JSON: JSON.stringify({
        'did:web:credtrail.test:tenant_123': {
          tenantId: 'tenant_123',
          keyId: signingMaterial.keyId,
          publicJwk: signingMaterial.publicJwk,
          privateJwk: signingMaterial.privateJwk,
        },
      }),
    };

    mockedFindActiveSessionByHash.mockResolvedValue(sampleSession());
    mockedTouchSession.mockResolvedValue();
    mockedFindBadgeTemplateById.mockResolvedValue(sampleBadgeTemplate());
    mockedFindAssertionByIdempotencyKey.mockResolvedValue(null);
    mockedResolveLearnerProfileForIdentity.mockResolvedValue(sampleLearnerProfile());
    mockedNextAssertionStatusListIndex.mockResolvedValueOnce(0).mockResolvedValueOnce(1);
    mockedCreateAssertion.mockResolvedValue(sampleAssertion());

    const firstIssueResponse = await app.request(
      '/v1/tenants/tenant_123/assertions/manual-issue',
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Cookie: 'credtrail_session=session-token',
        },
        body: JSON.stringify({
          badgeTemplateId: 'badge_template_001',
          recipientIdentity: 'student@umich.edu',
          recipientIdentityType: 'email',
          idempotencyKey: 'idem-1',
        }),
      },
      env,
    );
    const firstBody = await firstIssueResponse.json<ManualIssueResponse>();

    const secondIssueResponse = await app.request(
      '/v1/tenants/tenant_123/assertions/manual-issue',
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Cookie: 'credtrail_session=session-token',
        },
        body: JSON.stringify({
          badgeTemplateId: 'badge_template_001',
          recipientIdentity: 'student@gmail.com',
          recipientIdentityType: 'email',
          idempotencyKey: 'idem-2',
        }),
      },
      env,
    );
    const secondBody = await secondIssueResponse.json<ManualIssueResponse>();

    const firstSubjectId = asString(asJsonObject(firstBody.credential.credentialSubject)?.id);
    const secondSubjectId = asString(asJsonObject(secondBody.credential.credentialSubject)?.id);
    const firstIdentifierEntries = asJsonObject(firstBody.credential.credentialSubject)?.identifier;

    expect(firstIssueResponse.status).toBe(201);
    expect(secondIssueResponse.status).toBe(201);
    expect(firstSubjectId).toBe('urn:credtrail:learner:tenant_123:lpr_123');
    expect(secondSubjectId).toBe('urn:credtrail:learner:tenant_123:lpr_123');
    expect(Array.isArray(firstIdentifierEntries)).toBe(true);
    expect(firstIdentifierEntries).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          type: 'studentId',
          identifier: 'lpr_123',
        }),
        expect.objectContaining({
          type: 'emailAddress',
          identifier: 'student@umich.edu',
        }),
      ]),
    );
    expect(mockedResolveLearnerProfileForIdentity).toHaveBeenNthCalledWith(1, fakeDb, {
      tenantId: 'tenant_123',
      identityType: 'email',
      identityValue: 'student@umich.edu',
    });
    expect(mockedResolveLearnerProfileForIdentity).toHaveBeenNthCalledWith(2, fakeDb, {
      tenantId: 'tenant_123',
      identityType: 'email',
      identityValue: 'student@gmail.com',
    });
    expect(mockedCreateAssertion).toHaveBeenNthCalledWith(
      1,
      fakeDb,
      expect.objectContaining({
        tenantId: 'tenant_123',
        learnerProfileId: 'lpr_123',
        recipientIdentity: 'student@umich.edu',
      }),
    );
    const firstCreateAssertionCall = mockedCreateAssertion.mock.calls.at(0);

    if (firstCreateAssertionCall === undefined) {
      throw new Error('Expected first createAssertion call');
    }

    const firstCreateAssertionInput = firstCreateAssertionCall[1] as {
      recipientIdentifiers?: unknown;
    };

    expect(Array.isArray(firstCreateAssertionInput.recipientIdentifiers)).toBe(true);
    expect(firstCreateAssertionInput.recipientIdentifiers).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          identifierType: 'studentId',
          identifierValue: 'lpr_123',
        }),
        expect.objectContaining({
          identifierType: 'emailAddress',
          identifierValue: 'student@umich.edu',
        }),
      ]),
    );
    expect(mockedCreateAssertion).toHaveBeenNthCalledWith(
      2,
      fakeDb,
      expect.objectContaining({
        tenantId: 'tenant_123',
        learnerProfileId: 'lpr_123',
        recipientIdentity: 'student@gmail.com',
      }),
    );
    expect(mockedCreateAuditLog).toHaveBeenCalledWith(
      fakeDb,
      expect.objectContaining({
        tenantId: 'tenant_123',
        action: 'assertion.issued',
        targetType: 'assertion',
      }),
    );
  });

  it('uses learner DID alias as credentialSubject.id when configured', async () => {
    const signingMaterial = await generateTenantDidSigningMaterial({
      did: 'did:web:credtrail.test:tenant_123',
    });
    const env = {
      ...createEnv(),
      BADGE_OBJECTS: createInMemoryBadgeObjects(),
      TENANT_SIGNING_REGISTRY_JSON: JSON.stringify({
        'did:web:credtrail.test:tenant_123': {
          tenantId: 'tenant_123',
          keyId: signingMaterial.keyId,
          publicJwk: signingMaterial.publicJwk,
          privateJwk: signingMaterial.privateJwk,
        },
      }),
    };

    mockedFindActiveSessionByHash.mockResolvedValue(sampleSession());
    mockedTouchSession.mockResolvedValue();
    mockedFindBadgeTemplateById.mockResolvedValue(sampleBadgeTemplate());
    mockedFindAssertionByIdempotencyKey.mockResolvedValue(null);
    mockedResolveLearnerProfileForIdentity.mockResolvedValue(sampleLearnerProfile());
    mockedListLearnerIdentitiesByProfile.mockResolvedValue([
      {
        id: 'lid_did_subject_123',
        tenantId: 'tenant_123',
        learnerProfileId: 'lpr_123',
        identityType: 'did',
        identityValue: 'did:key:z6MkhLearnerSubjectDid',
        isPrimary: false,
        isVerified: true,
        createdAt: '2026-02-10T22:00:00.000Z',
        updatedAt: '2026-02-10T22:00:00.000Z',
      },
    ]);
    mockedNextAssertionStatusListIndex.mockResolvedValue(0);
    mockedCreateAssertion.mockResolvedValue(sampleAssertion());

    const response = await app.request(
      '/v1/tenants/tenant_123/assertions/manual-issue',
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Cookie: 'credtrail_session=session-token',
        },
        body: JSON.stringify({
          badgeTemplateId: 'badge_template_001',
          recipientIdentity: 'student@umich.edu',
          recipientIdentityType: 'email',
          idempotencyKey: 'idem-did-subject',
        }),
      },
      env,
    );
    const body = await response.json<ManualIssueResponse>();
    const subjectId = asString(asJsonObject(body.credential.credentialSubject)?.id);

    expect(response.status).toBe(201);
    expect(subjectId).toBe('did:key:z6MkhLearnerSubjectDid');
  });

  it('issues badges with remote signer custody when tenant private keys are not present in runtime', async () => {
    const signingMaterial = await generateTenantDidSigningMaterial({
      did: 'did:web:credtrail.test:tenant_123',
      keyId: 'key-remote',
    });
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation(async (_url, init) => {
      const request = jsonObjectFromRequestInitBody(init);
      const unsignedCredential = asJsonObject(request.credential);
      const verificationMethod = asString(request.verificationMethod);
      const createdAt = asString(request.createdAt);

      if (unsignedCredential === null || verificationMethod === null) {
        return new Response(
          JSON.stringify({
            error: 'invalid signer request',
          }),
          {
            status: 400,
            headers: {
              'content-type': 'application/json',
            },
          },
        );
      }

      const signedCredential = await signCredentialWithEd25519Signature2020({
        credential: unsignedCredential,
        privateJwk: signingMaterial.privateJwk,
        verificationMethod,
        ...(createdAt === null ? {} : { createdAt }),
      });

      return new Response(
        JSON.stringify({
          credential: signedCredential,
        }),
        {
          status: 200,
          headers: {
            'content-type': 'application/json',
          },
        },
      );
    });
    const env = {
      ...createEnv(),
      BADGE_OBJECTS: createInMemoryBadgeObjects(),
      TENANT_SIGNING_REGISTRY_JSON: JSON.stringify({
        'did:web:credtrail.test:tenant_123': {
          tenantId: 'tenant_123',
          keyId: signingMaterial.keyId,
          publicJwk: signingMaterial.publicJwk,
        },
      }),
      TENANT_REMOTE_SIGNER_REGISTRY_JSON: JSON.stringify({
        'did:web:credtrail.test:tenant_123': {
          url: 'https://kms.credtrail.test/sign',
        },
      }),
    };

    mockedFindActiveSessionByHash.mockResolvedValue(sampleSession());
    mockedTouchSession.mockResolvedValue();
    mockedFindBadgeTemplateById.mockResolvedValue(sampleBadgeTemplate());
    mockedFindAssertionByIdempotencyKey.mockResolvedValue(null);
    mockedResolveLearnerProfileForIdentity.mockResolvedValue(sampleLearnerProfile());
    mockedNextAssertionStatusListIndex.mockResolvedValue(0);
    mockedCreateAssertion.mockResolvedValue(sampleAssertion());

    const response = await app.request(
      '/v1/tenants/tenant_123/assertions/manual-issue',
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Cookie: 'credtrail_session=session-token',
        },
        body: JSON.stringify({
          badgeTemplateId: 'badge_template_001',
          recipientIdentity: 'student@umich.edu',
          recipientIdentityType: 'email',
          idempotencyKey: 'idem-remote-signer',
        }),
      },
      env,
    );
    const body = await response.json<ManualIssueResponse>();

    expect(response.status).toBe(201);
    expect(asJsonObject(body.credential.proof)).not.toBeNull();
    expect(fetchSpy).toHaveBeenCalledTimes(1);
    expect(fetchSpy.mock.calls[0]?.[0]).toBe('https://kms.credtrail.test/sign');

    fetchSpy.mockRestore();
  });

  it('allows viewer role manual issuance when delegated authority grant is active', async () => {
    const signingMaterial = await generateTenantDidSigningMaterial({
      did: 'did:web:credtrail.test:tenant_123',
    });
    const env = {
      ...createEnv(),
      BADGE_OBJECTS: createInMemoryBadgeObjects(),
      TENANT_SIGNING_REGISTRY_JSON: JSON.stringify({
        'did:web:credtrail.test:tenant_123': {
          tenantId: 'tenant_123',
          keyId: signingMaterial.keyId,
          publicJwk: signingMaterial.publicJwk,
          privateJwk: signingMaterial.privateJwk,
        },
      }),
    };

    mockedFindActiveSessionByHash.mockResolvedValue(sampleSession());
    mockedFindTenantMembership.mockResolvedValue(
      sampleTenantMembership({
        role: 'viewer',
      }),
    );
    mockedTouchSession.mockResolvedValue();
    mockedFindBadgeTemplateById.mockResolvedValue(sampleBadgeTemplate());
    mockedFindActiveDelegatedIssuingAuthorityGrantForAction.mockResolvedValue(
      sampleDelegatedIssuingAuthorityGrant({
        delegateUserId: 'usr_123',
        allowedActions: ['issue_badge'],
        badgeTemplateIds: ['badge_template_001'],
      }),
    );
    mockedFindAssertionByIdempotencyKey.mockResolvedValue(null);
    mockedResolveLearnerProfileForIdentity.mockResolvedValue(sampleLearnerProfile());
    mockedNextAssertionStatusListIndex.mockResolvedValue(0);
    mockedCreateAssertion.mockResolvedValue(sampleAssertion());

    const response = await app.request(
      '/v1/tenants/tenant_123/assertions/manual-issue',
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Cookie: 'credtrail_session=session-token',
        },
        body: JSON.stringify({
          badgeTemplateId: 'badge_template_001',
          recipientIdentity: 'student@umich.edu',
          recipientIdentityType: 'email',
          idempotencyKey: 'idem-viewer-grant',
        }),
      },
      env,
    );

    expect(response.status).toBe(201);
    expect(mockedFindActiveDelegatedIssuingAuthorityGrantForAction).toHaveBeenCalledWith(
      fakeDb,
      expect.objectContaining({
        tenantId: 'tenant_123',
        userId: 'usr_123',
        requiredAction: 'issue_badge',
        badgeTemplateId: 'badge_template_001',
      }),
    );
    expect(mockedCreateAssertion).toHaveBeenCalledTimes(1);
  });

  it('returns 403 when role is viewer for manual issuance', async () => {
    const env = createEnv();

    mockedFindActiveSessionByHash.mockResolvedValue(sampleSession());
    mockedFindTenantMembership.mockResolvedValue(
      sampleTenantMembership({
        role: 'viewer',
      }),
    );
    mockedTouchSession.mockResolvedValue();

    const response = await app.request(
      '/v1/tenants/tenant_123/assertions/manual-issue',
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Cookie: 'credtrail_session=session-token',
        },
        body: JSON.stringify({
          badgeTemplateId: 'badge_template_001',
          recipientIdentity: 'student@umich.edu',
          recipientIdentityType: 'email',
          idempotencyKey: 'idem-viewer',
        }),
      },
      env,
    );
    const body = await response.json<ErrorResponse>();

    expect(response.status).toBe(403);
    expect(body.error).toBe('Insufficient role for requested action');
    expect(mockedCreateAssertion).not.toHaveBeenCalled();
  });
});

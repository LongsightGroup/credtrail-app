import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('@credtrail/db', async () => {
  const actual = await vi.importActual<typeof import('@credtrail/db')>('@credtrail/db');

  return {
    ...actual,
    addLearnerIdentityAlias: vi.fn(),
    completeJobQueueMessage: vi.fn(),
    createAssertion: vi.fn(),
    createLearnerIdentityLinkProof: vi.fn(),
    enqueueJobQueueMessage: vi.fn(),
    failJobQueueMessage: vi.fn(),
    findAssertionById: vi.fn(),
    findAssertionByPublicId: vi.fn(),
    findAssertionByIdempotencyKey: vi.fn(),
    findBadgeTemplateById: vi.fn(),
    findActiveSessionByHash: vi.fn(),
    findLearnerProfileById: vi.fn(),
    findLearnerIdentityLinkProofByHash: vi.fn(),
    findLearnerProfileByIdentity: vi.fn(),
    findUserById: vi.fn(),
    listAssertionStatusListEntries: vi.fn(),
    touchSession: vi.fn(),
    listLearnerBadgeSummaries: vi.fn(),
    leaseJobQueueMessages: vi.fn(),
    markLearnerIdentityLinkProofUsed: vi.fn(),
    nextAssertionStatusListIndex: vi.fn(),
    recordAssertionRevocation: vi.fn(),
    resolveLearnerProfileForIdentity: vi.fn(),
  };
});

vi.mock('@credtrail/core-domain', async () => {
  const actual = await vi.importActual<typeof import('@credtrail/core-domain')>('@credtrail/core-domain');

  return {
    ...actual,
    getImmutableCredentialObject: vi.fn(),
  };
});

import {
  type JsonObject,
  generateTenantDidSigningMaterial,
  getImmutableCredentialObject,
} from '@credtrail/core-domain';
import {
  type AssertionRecord,
  type AssertionStatusListEntryRecord,
  type BadgeTemplateRecord,
  type LearnerIdentityLinkProofRecord,
  type LearnerBadgeSummaryRecord,
  type LearnerProfileRecord,
  type SessionRecord,
  addLearnerIdentityAlias,
  completeJobQueueMessage,
  createAssertion,
  createLearnerIdentityLinkProof,
  enqueueJobQueueMessage,
  failJobQueueMessage,
  findActiveSessionByHash,
  findAssertionById,
  findAssertionByPublicId,
  findAssertionByIdempotencyKey,
  findBadgeTemplateById,
  findLearnerIdentityLinkProofByHash,
  findLearnerProfileById,
  findLearnerProfileByIdentity,
  findUserById,
  listAssertionStatusListEntries,
  listLearnerBadgeSummaries,
  leaseJobQueueMessages,
  markLearnerIdentityLinkProofUsed,
  nextAssertionStatusListIndex,
  recordAssertionRevocation,
  resolveLearnerProfileForIdentity,
  touchSession,
  type JobQueueMessageRecord,
} from '@credtrail/db';

import worker, { app, sendIssuanceEmailNotification } from './index';

interface VerificationResponse {
  assertionId: string;
  tenantId: string;
  issuedAt: string;
  verification: {
    status: 'valid' | 'revoked';
    revokedAt: string | null;
    statusList: {
      id: string;
      type: string;
      statusPurpose: 'revocation';
      statusListIndex: string;
      statusListCredential: string;
    } | null;
  };
  credential: JsonObject;
}

interface ErrorResponse {
  error: string;
}

interface ManualIssueResponse {
  status: 'issued' | 'already_issued';
  assertionId: string;
  tenantId: string;
  credential: JsonObject;
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

const mockedFindAssertionById = vi.mocked(findAssertionById);
const mockedFindAssertionByPublicId = vi.mocked(findAssertionByPublicId);
const mockedFindAssertionByIdempotencyKey = vi.mocked(findAssertionByIdempotencyKey);
const mockedFindBadgeTemplateById = vi.mocked(findBadgeTemplateById);
const mockedGetImmutableCredentialObject = vi.mocked(getImmutableCredentialObject);
const mockedFindActiveSessionByHash = vi.mocked(findActiveSessionByHash);
const mockedFindUserById = vi.mocked(findUserById);
const mockedFindLearnerProfileById = vi.mocked(findLearnerProfileById);
const mockedFindLearnerProfileByIdentity = vi.mocked(findLearnerProfileByIdentity);
const mockedResolveLearnerProfileForIdentity = vi.mocked(resolveLearnerProfileForIdentity);
const mockedCreateAssertion = vi.mocked(createAssertion);
const mockedNextAssertionStatusListIndex = vi.mocked(nextAssertionStatusListIndex);
const mockedListAssertionStatusListEntries = vi.mocked(listAssertionStatusListEntries);
const mockedTouchSession = vi.mocked(touchSession);
const mockedListLearnerBadgeSummaries = vi.mocked(listLearnerBadgeSummaries);
const mockedCreateLearnerIdentityLinkProof = vi.mocked(createLearnerIdentityLinkProof);
const mockedFindLearnerIdentityLinkProofByHash = vi.mocked(findLearnerIdentityLinkProofByHash);
const mockedAddLearnerIdentityAlias = vi.mocked(addLearnerIdentityAlias);
const mockedMarkLearnerIdentityLinkProofUsed = vi.mocked(markLearnerIdentityLinkProofUsed);
const mockedEnqueueJobQueueMessage = vi.mocked(enqueueJobQueueMessage);
const mockedLeaseJobQueueMessages = vi.mocked(leaseJobQueueMessages);
const mockedCompleteJobQueueMessage = vi.mocked(completeJobQueueMessage);
const mockedFailJobQueueMessage = vi.mocked(failJobQueueMessage);
const mockedRecordAssertionRevocation = vi.mocked(recordAssertionRevocation);

const createEnv = (): {
  APP_ENV: string;
  DB: D1Database;
  BADGE_OBJECTS: R2Bucket;
  PLATFORM_DOMAIN: string;
  MARKETING_SITE_ORIGIN?: string;
  JOB_PROCESSOR_TOKEN?: string;
} => {
  return {
    APP_ENV: 'test',
    DB: {} as D1Database,
    BADGE_OBJECTS: {} as R2Bucket,
    PLATFORM_DOMAIN: 'credtrail.test',
  };
};

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

const base64UrlToBytes = (value: string): Uint8Array => {
  const base64 = value.replace(/-/g, '+').replace(/_/g, '/');
  const padded = `${base64}${'='.repeat((4 - (base64.length % 4)) % 4)}`;
  const raw = atob(padded);
  const bytes = new Uint8Array(raw.length);

  for (let index = 0; index < raw.length; index += 1) {
    bytes[index] = raw.charCodeAt(index);
  }

  return bytes;
};

const gunzip = async (bytes: Uint8Array): Promise<Uint8Array> => {
  const normalizedBytes = Uint8Array.from(bytes);
  const sourceStream = new ReadableStream<BufferSource>({
    start(controller): void {
      controller.enqueue(normalizedBytes);
      controller.close();
    },
  });
  const decompressedStream = sourceStream.pipeThrough(new DecompressionStream('gzip'));
  const decompressedBuffer = await new Response(decompressedStream).arrayBuffer();
  return new Uint8Array(decompressedBuffer);
};

const isBitSet = (bytes: Uint8Array, bitIndex: number): boolean => {
  const byteIndex = Math.floor(bitIndex / 8);
  const bitOffset = bitIndex % 8;
  const byte = bytes[byteIndex];

  if (byte === undefined) {
    return false;
  }

  return (byte & (1 << bitOffset)) !== 0;
};

const sampleSession = (overrides?: { tenantId?: string }): SessionRecord => {
  return {
    id: 'ses_123',
    tenantId: overrides?.tenantId ?? 'tenant_123',
    userId: 'usr_123',
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
    isArchived: false,
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

const sampleLeasedQueueMessage = (
  overrides?: Partial<JobQueueMessageRecord>,
): JobQueueMessageRecord => {
  return {
    id: 'job_123',
    tenantId: 'tenant_123',
    jobType: 'rebuild_verification_cache',
    payloadJson: '{}',
    idempotencyKey: 'idem_job_123',
    attemptCount: 1,
    maxAttempts: 8,
    availableAt: '2026-02-10T22:00:00.000Z',
    leasedUntil: '2026-02-10T22:00:30.000Z',
    leaseToken: 'lease_123',
    lastError: null,
    completedAt: null,
    failedAt: null,
    status: 'processing',
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

describe('marketing landing proxy', () => {
  it('proxies root requests to MARKETING_SITE_ORIGIN when configured', async () => {
    const env = {
      ...createEnv(),
      MARKETING_SITE_ORIGIN: 'https://marketing.credtrail.test',
    };
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response('<html>landing</html>', {
        status: 200,
        headers: {
          'content-type': 'text/html; charset=UTF-8',
        },
      }),
    );

    const response = await app.fetch(new Request('https://credtrail.test/'), env);
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(body).toContain('landing');

    const firstCall = fetchSpy.mock.calls[0];
    const firstRequest = firstCall?.[0];

    expect(firstRequest).toBeInstanceOf(Request);
    if (!(firstRequest instanceof Request)) {
      throw new Error('Expected first fetch argument to be a Request');
    }
    expect(firstRequest.url).toBe('https://marketing.credtrail.test/');

    fetchSpy.mockRestore();
  });
});

describe('canonical host redirects', () => {
  it('redirects www host requests to the canonical platform domain', async () => {
    const env = createEnv();
    const response = await app.fetch(
      new Request('https://www.credtrail.test/badges/40a6dc92-85ec-4cb0-8a50-afb2ae700e22?utm=test'),
      env,
    );

    expect(response.status).toBe(308);
    expect(response.headers.get('location')).toBe(
      'https://credtrail.test/badges/40a6dc92-85ec-4cb0-8a50-afb2ae700e22?utm=test',
    );
  });

  it('redirects legacy badges subdomain requests to the canonical platform domain', async () => {
    const env = createEnv();
    const response = await app.fetch(new Request('https://badges.credtrail.test/healthz'), env);

    expect(response.status).toBe(308);
    expect(response.headers.get('location')).toBe('https://credtrail.test/healthz');
  });
});

describe('POST /v1/issue and /v1/revoke', () => {
  beforeEach(() => {
    mockedEnqueueJobQueueMessage.mockReset();
  });

  it('stores issue requests as DB-backed queue messages', async () => {
    const env = createEnv();

    const response = await app.request(
      '/v1/issue',
      {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
        },
        body: JSON.stringify({
          tenantId: 'tenant_123',
          badgeTemplateId: 'badge_template_001',
          recipientIdentity: 'learner@example.edu',
          recipientIdentityType: 'email',
          requestedByUserId: 'usr_issuer',
        }),
      },
      env,
    );
    const body = await response.json<Record<string, unknown>>();

    expect(response.status).toBe(202);
    expect(body.status).toBe('queued');
    expect(body.jobType).toBe('issue_badge');
    expect(typeof body.assertionId).toBe('string');
    expect(mockedEnqueueJobQueueMessage).toHaveBeenCalledTimes(1);
    expect(mockedEnqueueJobQueueMessage).toHaveBeenCalledWith(
      env.DB,
      expect.objectContaining({
        tenantId: 'tenant_123',
        jobType: 'issue_badge',
      }),
    );
  });

  it('stores revoke requests as DB-backed queue messages', async () => {
    const env = createEnv();

    const response = await app.request(
      '/v1/revoke',
      {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
        },
        body: JSON.stringify({
          tenantId: 'tenant_123',
          assertionId: 'tenant_123:assertion_456',
          reason: 'Requested by issuer',
          requestedByUserId: 'usr_issuer',
        }),
      },
      env,
    );
    const body = await response.json<Record<string, unknown>>();

    expect(response.status).toBe(202);
    expect(body.status).toBe('queued');
    expect(body.jobType).toBe('revoke_badge');
    expect(typeof body.revocationId).toBe('string');
    expect(mockedEnqueueJobQueueMessage).toHaveBeenCalledTimes(1);
    expect(mockedEnqueueJobQueueMessage).toHaveBeenCalledWith(
      env.DB,
      expect.objectContaining({
        tenantId: 'tenant_123',
        jobType: 'revoke_badge',
      }),
    );
  });
});

describe('POST /v1/jobs/process', () => {
  beforeEach(() => {
    mockedLeaseJobQueueMessages.mockReset();
    mockedCompleteJobQueueMessage.mockReset();
    mockedFailJobQueueMessage.mockReset();
    mockedRecordAssertionRevocation.mockReset();
  });

  it('processes leased jobs and marks them completed', async () => {
    const env = createEnv();

    mockedLeaseJobQueueMessages.mockResolvedValue([sampleLeasedQueueMessage()]);

    const response = await app.request(
      '/v1/jobs/process',
      {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
        },
        body: JSON.stringify({}),
      },
      env,
    );
    const body = await response.json<Record<string, unknown>>();

    expect(response.status).toBe(200);
    expect(body.status).toBe('ok');
    expect(body.leased).toBe(1);
    expect(body.succeeded).toBe(1);
    expect(mockedCompleteJobQueueMessage).toHaveBeenCalledTimes(1);
    expect(mockedFailJobQueueMessage).not.toHaveBeenCalled();
  });

  it('requires bearer auth when JOB_PROCESSOR_TOKEN is configured', async () => {
    const env = {
      ...createEnv(),
      JOB_PROCESSOR_TOKEN: 'processor-secret',
    };

    const response = await app.request(
      '/v1/jobs/process',
      {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
        },
        body: JSON.stringify({}),
      },
      env,
    );
    const body = await response.json<ErrorResponse>();

    expect(response.status).toBe(401);
    expect(body.error).toBe('Unauthorized');
    expect(mockedLeaseJobQueueMessages).not.toHaveBeenCalled();
  });

  it('requeues failed jobs when fail handler marks pending', async () => {
    const env = createEnv();

    mockedLeaseJobQueueMessages.mockResolvedValue([
      sampleLeasedQueueMessage({
        jobType: 'issue_badge',
        payloadJson: '{"invalid-json"',
      }),
    ]);
    mockedFailJobQueueMessage.mockResolvedValue('pending');

    const response = await app.request(
      '/v1/jobs/process',
      {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
        },
        body: JSON.stringify({}),
      },
      env,
    );
    const body = await response.json<Record<string, unknown>>();

    expect(response.status).toBe(200);
    expect(body.retried).toBe(1);
    expect(body.deadLettered).toBe(0);
    expect(mockedCompleteJobQueueMessage).not.toHaveBeenCalled();
  });
});

describe('scheduled queue processor trigger', () => {
  beforeEach(() => {
    mockedLeaseJobQueueMessages.mockReset();
  });

  it('invokes queue processing endpoint on schedule', async () => {
    const env = {
      ...createEnv(),
      JOB_PROCESSOR_TOKEN: 'processor-secret',
    };

    mockedLeaseJobQueueMessages.mockResolvedValue([]);

    await worker.scheduled?.(
      {
        cron: '* * * * *',
        scheduledTime: Date.now(),
        type: 'scheduled',
        noRetry: vi.fn(),
      } as unknown as ScheduledController,
      env,
      {
        waitUntil: vi.fn(),
        passThroughOnException: vi.fn(),
      } as unknown as ExecutionContext,
    );

    expect(mockedLeaseJobQueueMessages).toHaveBeenCalledTimes(1);
  });
});

describe('GET /credentials/v1/:credentialId', () => {
  beforeEach(() => {
    mockedFindAssertionById.mockReset();
    mockedGetImmutableCredentialObject.mockReset();
  });

  it('returns credential verification details for a valid credential', async () => {
    const env = createEnv();
    const credential: JsonObject = {
      '@context': ['https://www.w3.org/ns/credentials/v2'],
      id: 'urn:credtrail:assertion:tenant_123%3Aassertion_456',
      type: ['VerifiableCredential', 'OpenBadgeCredential'],
    };

    mockedFindAssertionById.mockResolvedValue(sampleAssertion());
    mockedGetImmutableCredentialObject.mockResolvedValue(credential);

    const response = await app.request('/credentials/v1/tenant_123%3Aassertion_456', undefined, env);
    const body = await response.json<VerificationResponse>();

    expect(response.status).toBe(200);
    expect(response.headers.get('cache-control')).toBe('no-store');
    expect(body.verification.status).toBe('valid');
    expect(body.verification.revokedAt).toBeNull();
    expect(body.verification.statusList?.statusPurpose).toBe('revocation');
    expect(body.verification.statusList?.statusListIndex).toBe('0');
    expect(body.verification.statusList?.statusListCredential).toBe(
      'http://localhost/credentials/v1/status-lists/tenant_123/revocation',
    );
    expect(body.credential).toEqual(credential);
    expect(mockedFindAssertionById).toHaveBeenCalledWith(
      env.DB,
      'tenant_123',
      'tenant_123:assertion_456',
    );
    expect(mockedGetImmutableCredentialObject).toHaveBeenCalledWith(env.BADGE_OBJECTS, {
      tenantId: 'tenant_123',
      assertionId: 'tenant_123:assertion_456',
    });
  });

  it('marks credential status as revoked when assertion is revoked', async () => {
    const env = createEnv();
    const credential: JsonObject = {
      id: 'urn:credtrail:assertion:tenant_123%3Aassertion_456',
      type: ['VerifiableCredential'],
    };

    mockedFindAssertionById.mockResolvedValue(
      sampleAssertion({
        revokedAt: '2026-02-11T01:00:00.000Z',
      }),
    );
    mockedGetImmutableCredentialObject.mockResolvedValue(credential);

    const response = await app.request('/credentials/v1/tenant_123%3Aassertion_456', undefined, env);
    const body = await response.json<VerificationResponse>();

    expect(response.status).toBe(200);
    expect(body.verification.status).toBe('revoked');
    expect(body.verification.revokedAt).toBe('2026-02-11T01:00:00.000Z');
  });

  it('returns null status list metadata when assertion has no status list index', async () => {
    const env = createEnv();
    const credential: JsonObject = {
      id: 'urn:credtrail:assertion:tenant_123%3Aassertion_456',
      type: ['VerifiableCredential'],
    };

    mockedFindAssertionById.mockResolvedValue(
      sampleAssertion({
        statusListIndex: null,
      }),
    );
    mockedGetImmutableCredentialObject.mockResolvedValue(credential);

    const response = await app.request('/credentials/v1/tenant_123%3Aassertion_456', undefined, env);
    const body = await response.json<VerificationResponse>();

    expect(response.status).toBe(200);
    expect(body.verification.statusList).toBeNull();
  });

  it('returns 400 for non-tenant-scoped credential identifiers', async () => {
    const env = createEnv();
    const response = await app.request('/credentials/v1/assertion_456', undefined, env);
    const body = await response.json<ErrorResponse>();

    expect(response.status).toBe(400);
    expect(body.error).toBe('Invalid credential identifier');
    expect(mockedFindAssertionById).not.toHaveBeenCalled();
  });

  it('returns 404 when credential metadata is not found', async () => {
    const env = createEnv();

    mockedFindAssertionById.mockResolvedValue(null);

    const response = await app.request('/credentials/v1/tenant_123%3Aassertion_456', undefined, env);
    const body = await response.json<ErrorResponse>();

    expect(response.status).toBe(404);
    expect(body.error).toBe('Credential not found');
    expect(mockedGetImmutableCredentialObject).not.toHaveBeenCalled();
  });
});

describe('GET /credentials/v1/status-lists/:tenantId/revocation', () => {
  beforeEach(() => {
    mockedListAssertionStatusListEntries.mockReset();
  });

  it('returns a signed bitstring status list credential for tenant revocations', async () => {
    const env = createEnv();
    const signingMaterial = await generateTenantDidSigningMaterial({
      did: 'did:web:credtrail.test:tenant_123',
    });
    const assertionStatuses: AssertionStatusListEntryRecord[] = [
      {
        statusListIndex: 0,
        revokedAt: null,
      },
      {
        statusListIndex: 1,
        revokedAt: '2026-02-11T01:00:00.000Z',
      },
      {
        statusListIndex: 8,
        revokedAt: '2026-02-11T01:05:00.000Z',
      },
    ];

    mockedListAssertionStatusListEntries.mockResolvedValue(assertionStatuses);

    const response = await app.request(
      '/credentials/v1/status-lists/tenant_123/revocation',
      undefined,
      {
        ...env,
        TENANT_SIGNING_REGISTRY_JSON: JSON.stringify({
          'did:web:credtrail.test:tenant_123': {
            tenantId: 'tenant_123',
            keyId: signingMaterial.keyId,
            publicJwk: signingMaterial.publicJwk,
            privateJwk: signingMaterial.privateJwk,
          },
        }),
      },
    );
    const body = await response.text();
    const credential = JSON.parse(body) as JsonObject;
    const credentialSubject = asJsonObject(credential.credentialSubject);
    const encodedList = asString(credentialSubject?.encodedList);

    expect(response.status).toBe(200);
    expect(response.headers.get('cache-control')).toBe('no-store');
    expect(response.headers.get('content-type')).toContain('application/ld+json');
    expect(asString(credential.id)).toBe(
      'http://localhost/credentials/v1/status-lists/tenant_123/revocation',
    );
    expect(credential.type).toEqual(['VerifiableCredential', 'BitstringStatusListCredential']);
    expect(credential.proof).toBeDefined();
    expect(asString(credentialSubject?.statusPurpose)).toBe('revocation');
    expect(encodedList?.startsWith('u')).toBe(true);

    if (encodedList?.startsWith('u') !== true) {
      throw new Error('Expected a multibase base64url-encoded bitstring list');
    }

    const compressedListBytes = base64UrlToBytes(encodedList.slice(1));
    const listBytes = await gunzip(compressedListBytes);

    expect(isBitSet(listBytes, 0)).toBe(false);
    expect(isBitSet(listBytes, 1)).toBe(true);
    expect(isBitSet(listBytes, 8)).toBe(true);
  });

  it('returns 404 when tenant signing config is missing', async () => {
    const env = createEnv();
    const response = await app.request(
      '/credentials/v1/status-lists/tenant_123/revocation',
      undefined,
      env,
    );
    const body = await response.json<ErrorResponse>();

    expect(response.status).toBe(404);
    expect(body.error).toBe('No signing configuration for tenant DID');
    expect(mockedListAssertionStatusListEntries).not.toHaveBeenCalled();
  });
});

describe('sendIssuanceEmailNotification', () => {
  it('sends notification through Mailtrap API when configured', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response('', {
        status: 200,
      }),
    );

    await sendIssuanceEmailNotification({
      mailtrapApiToken: 'token-123',
      mailtrapInboxId: '4374730',
      recipientEmail: 'learner@example.edu',
      badgeTitle: 'TypeScript Foundations',
      assertionId: 'tenant_123:assertion_456',
      tenantId: 'tenant_123',
      issuedAtIso: '2026-02-10T22:00:00.000Z',
      publicBadgeUrl: 'https://credtrail.test/badges/tenant_123%3Aassertion_456',
      verificationUrl: 'https://credtrail.test/credentials/v1/tenant_123%3Aassertion_456',
      credentialDownloadUrl:
        'https://credtrail.test/credentials/v1/tenant_123%3Aassertion_456/download',
    });

    expect(fetchSpy).toHaveBeenCalledTimes(1);
    const firstCall = fetchSpy.mock.calls[0];
    expect(firstCall?.[0]).toBe('https://sandbox.api.mailtrap.io/api/send/4374730');

    const requestInit = firstCall?.[1];
    expect(requestInit?.method).toBe('POST');
    expect(requestInit?.headers).toEqual({
      Authorization: 'Bearer token-123',
      'Content-Type': 'application/json',
    });

    fetchSpy.mockRestore();
  });

  it('skips sending when Mailtrap config is missing', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch');

    await sendIssuanceEmailNotification({
      recipientEmail: 'learner@example.edu',
      badgeTitle: 'TypeScript Foundations',
      assertionId: 'tenant_123:assertion_456',
      tenantId: 'tenant_123',
      issuedAtIso: '2026-02-10T22:00:00.000Z',
      publicBadgeUrl: 'https://credtrail.test/badges/tenant_123%3Aassertion_456',
      verificationUrl: 'https://credtrail.test/credentials/v1/tenant_123%3Aassertion_456',
      credentialDownloadUrl:
        'https://credtrail.test/credentials/v1/tenant_123%3Aassertion_456/download',
    });

    expect(fetchSpy).not.toHaveBeenCalled();

    fetchSpy.mockRestore();
  });
});

describe('GET /credentials/v1/:credentialId/download', () => {
  beforeEach(() => {
    mockedFindAssertionById.mockReset();
    mockedGetImmutableCredentialObject.mockReset();
  });

  it('returns downloadable JSON-LD for a credential', async () => {
    const env = createEnv();
    const credential: JsonObject = {
      '@context': ['https://www.w3.org/ns/credentials/v2'],
      id: 'urn:credtrail:assertion:tenant_123%3Aassertion_456',
      type: ['VerifiableCredential', 'OpenBadgeCredential'],
    };

    mockedFindAssertionById.mockResolvedValue(sampleAssertion());
    mockedGetImmutableCredentialObject.mockResolvedValue(credential);

    const response = await app.request(
      '/credentials/v1/tenant_123%3Aassertion_456/download',
      undefined,
      env,
    );
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(response.headers.get('cache-control')).toBe('no-store');
    expect(response.headers.get('content-type')).toContain('application/ld+json');
    expect(response.headers.get('content-disposition')).toContain('attachment; filename=');
    expect(body).toContain('"OpenBadgeCredential"');
  });

  it('returns 400 for invalid credential identifier', async () => {
    const env = createEnv();
    const response = await app.request('/credentials/v1/assertion_456/download', undefined, env);
    const body = await response.json<ErrorResponse>();

    expect(response.status).toBe(400);
    expect(body.error).toBe('Invalid credential identifier');
    expect(mockedFindAssertionById).not.toHaveBeenCalled();
  });

  it('returns 404 when credential does not exist', async () => {
    const env = createEnv();
    mockedFindAssertionById.mockResolvedValue(null);

    const response = await app.request(
      '/credentials/v1/tenant_123%3Aassertion_456/download',
      undefined,
      env,
    );
    const body = await response.json<ErrorResponse>();

    expect(response.status).toBe(404);
    expect(body.error).toBe('Credential not found');
  });
});

describe('GET /credentials/v1/:credentialId/jsonld', () => {
  beforeEach(() => {
    mockedFindAssertionById.mockReset();
    mockedGetImmutableCredentialObject.mockReset();
  });

  it('returns non-attachment OB3 JSON-LD for a credential', async () => {
    const env = createEnv();
    const credential: JsonObject = {
      '@context': ['https://www.w3.org/ns/credentials/v2'],
      id: 'urn:credtrail:assertion:tenant_123%3Aassertion_456',
      type: ['VerifiableCredential', 'OpenBadgeCredential'],
    };

    mockedFindAssertionById.mockResolvedValue(sampleAssertion());
    mockedGetImmutableCredentialObject.mockResolvedValue(credential);

    const response = await app.request(
      '/credentials/v1/tenant_123%3Aassertion_456/jsonld',
      undefined,
      env,
    );
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(response.headers.get('cache-control')).toBe('no-store');
    expect(response.headers.get('content-type')).toContain('application/ld+json');
    expect(response.headers.get('content-disposition')).toBeNull();
    expect(body).toContain('"OpenBadgeCredential"');
  });

  it('returns 400 for invalid credential identifier', async () => {
    const env = createEnv();
    const response = await app.request('/credentials/v1/assertion_456/jsonld', undefined, env);
    const body = await response.json<ErrorResponse>();

    expect(response.status).toBe(400);
    expect(body.error).toBe('Invalid credential identifier');
    expect(mockedFindAssertionById).not.toHaveBeenCalled();
  });
});

describe('GET /badges/:badgeIdentifier', () => {
  beforeEach(() => {
    mockedFindAssertionByPublicId.mockReset();
    mockedFindAssertionById.mockReset();
    mockedGetImmutableCredentialObject.mockReset();
    mockedFindLearnerProfileById.mockReset();
  });

  it('renders a public badge page with verified status for canonical public permalink', async () => {
    const env = createEnv();
    const credential: JsonObject = {
      '@context': ['https://www.w3.org/ns/credentials/v2'],
      id: 'urn:credtrail:assertion:tenant_123%3Aassertion_456',
      type: ['VerifiableCredential', 'OpenBadgeCredential'],
      issuer: {
        id: 'did:web:credtrail.test:tenant_123',
        name: 'Example University',
        url: 'https://example.edu',
      },
      credentialSubject: {
        id: 'mailto:learner@example.edu',
        achievement: {
          name: 'TypeScript Foundations',
          description: 'Awarded for completing TypeScript fundamentals.',
          criteria: {
            id: 'https://example.edu/badges/typescript-foundations/criteria',
          },
          image: {
            id: 'https://example.edu/badges/typescript-foundations/image.png',
          },
        },
        evidence: [
          {
            id: 'https://example.edu/evidence/123',
            name: 'Capstone Submission',
            description: 'Final capstone reviewed by instructor.',
          },
          'https://example.edu/evidence/gradebook/123',
        ],
      },
    };

    mockedFindAssertionByPublicId.mockResolvedValue(sampleAssertion());
    mockedFindLearnerProfileById.mockResolvedValue(
      sampleLearnerProfile({
        displayName: 'Ada Lovelace',
      }),
    );
    mockedGetImmutableCredentialObject.mockResolvedValue(credential);

    const response = await app.request(
      '/badges/40a6dc92-85ec-4cb0-8a50-afb2ae700e22',
      undefined,
      env,
    );
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(response.headers.get('content-type')).toContain('text/html');
    expect(response.headers.get('cache-control')).toBe('no-store');
    expect(body).toContain('TypeScript Foundations');
    expect(body).toContain('Verified');
    expect(body).toContain('Example University');
    expect(body).toContain('https://example.edu');
    expect(body).toContain('Ada Lovelace');
    expect(body).toContain('/credentials/v1/tenant_123%3Aassertion_456');
    expect(body).toContain('Copy URL');
    expect(body).toContain('/credentials/v1/tenant_123%3Aassertion_456/download');
    expect(body).toContain('/credentials/v1/tenant_123%3Aassertion_456/jsonld');
    expect(body).toContain('Share on LinkedIn');
    expect(body).toContain('linkedin.com/sharing/share-offsite');
    expect(body).toContain('Open Badges 3.0 JSON');
    expect(body).toContain(
      '<link rel="alternate" type="application/ld+json" href="/credentials/v1/tenant_123%3Aassertion_456/jsonld"',
    );
    expect(body).toContain('Awarded for completing TypeScript fundamentals.');
    expect(body).toContain('https://example.edu/badges/typescript-foundations/criteria');
    expect(body).toContain('https://example.edu/badges/typescript-foundations/image.png');
    expect(body).toContain('Capstone Submission');
    expect(body).toContain('https://example.edu/evidence/gradebook/123');
    expect(body).toContain('/badges/40a6dc92-85ec-4cb0-8a50-afb2ae700e22');
    expect(body).toContain('<link rel="canonical" href="http://localhost/badges/40a6dc92-85ec-4cb0-8a50-afb2ae700e22"');
  });

  it('redirects legacy tenant-scoped badge URLs to canonical public permalink', async () => {
    const env = createEnv();

    mockedFindAssertionByPublicId.mockResolvedValue(null);
    mockedFindAssertionById.mockResolvedValue(sampleAssertion());

    const response = await app.request('/badges/tenant_123%3Aassertion_456', undefined, env);

    expect(response.status).toBe(308);
    expect(response.headers.get('location')).toBe('/badges/40a6dc92-85ec-4cb0-8a50-afb2ae700e22');
    expect(mockedGetImmutableCredentialObject).not.toHaveBeenCalled();
  });

  it('redirects /public_url alias path to canonical public permalink', async () => {
    const env = createEnv();
    const response = await app.request(
      '/badges/40a6dc92-85ec-4cb0-8a50-afb2ae700e22/public_url',
      undefined,
      env,
    );

    expect(response.status).toBe(308);
    expect(response.headers.get('location')).toBe('/badges/40a6dc92-85ec-4cb0-8a50-afb2ae700e22');
  });

  it('renders revoked state for revoked credentials', async () => {
    const env = createEnv();
    const credential: JsonObject = {
      id: 'urn:credtrail:assertion:tenant_123%3Aassertion_456',
      credentialSubject: {
        achievement: {
          name: 'TypeScript Foundations',
        },
      },
    };

    mockedFindAssertionByPublicId.mockResolvedValue(
      sampleAssertion({
        revokedAt: '2026-02-11T01:00:00.000Z',
      }),
    );
    mockedGetImmutableCredentialObject.mockResolvedValue(credential);

    const response = await app.request(
      '/badges/40a6dc92-85ec-4cb0-8a50-afb2ae700e22',
      undefined,
      env,
    );
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(body).toContain('Revoked');
    expect(body).toContain('Revoked at');
    expect(body).not.toContain('Evidence</h2>');
  });

  it('returns not found page when credential does not exist', async () => {
    const env = createEnv();
    mockedFindAssertionByPublicId.mockResolvedValue(null);
    mockedFindAssertionById.mockResolvedValue(null);

    const response = await app.request('/badges/tenant_123%3Aassertion_456', undefined, env);
    const body = await response.text();

    expect(response.status).toBe(404);
    expect(body).toContain('Badge not found');
    expect(mockedGetImmutableCredentialObject).not.toHaveBeenCalled();
  });

  it('returns not found page for unknown public badge identifiers', async () => {
    const env = createEnv();
    mockedFindAssertionByPublicId.mockResolvedValue(null);

    const response = await app.request('/badges/assertion_456', undefined, env);
    const body = await response.text();

    expect(response.status).toBe(404);
    expect(body).toContain('Badge not found');
    expect(mockedFindAssertionById).not.toHaveBeenCalled();
  });

  it('returns not found page when public_url alias is empty', async () => {
    const env = createEnv();
    const response = await app.request('/badges/%20/public_url', undefined, env);
    const body = await response.text();

    expect(response.status).toBe(404);
    expect(body).toContain('Badge not found');
    expect(mockedFindAssertionById).not.toHaveBeenCalled();
  });
});

describe('GET /tenants/:tenantId/learner/dashboard', () => {
  beforeEach(() => {
    mockedFindActiveSessionByHash.mockReset();
    mockedTouchSession.mockReset();
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
    expect(mockedListLearnerBadgeSummaries).toHaveBeenCalledWith(env.DB, {
      tenantId: 'tenant_123',
      userId: 'usr_123',
    });
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

describe('POST /v1/tenants/:tenantId/assertions/manual-issue', () => {
  beforeEach(() => {
    mockedFindActiveSessionByHash.mockReset();
    mockedTouchSession.mockReset();
    mockedFindBadgeTemplateById.mockReset();
    mockedFindAssertionByIdempotencyKey.mockReset();
    mockedResolveLearnerProfileForIdentity.mockReset();
    mockedNextAssertionStatusListIndex.mockReset();
    mockedCreateAssertion.mockReset();
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

    expect(firstIssueResponse.status).toBe(201);
    expect(secondIssueResponse.status).toBe(201);
    expect(firstSubjectId).toBe('urn:credtrail:learner:tenant_123:lpr_123');
    expect(secondSubjectId).toBe('urn:credtrail:learner:tenant_123:lpr_123');
    expect(mockedResolveLearnerProfileForIdentity).toHaveBeenNthCalledWith(1, env.DB, {
      tenantId: 'tenant_123',
      identityType: 'email',
      identityValue: 'student@umich.edu',
    });
    expect(mockedResolveLearnerProfileForIdentity).toHaveBeenNthCalledWith(2, env.DB, {
      tenantId: 'tenant_123',
      identityType: 'email',
      identityValue: 'student@gmail.com',
    });
    expect(mockedCreateAssertion).toHaveBeenNthCalledWith(
      1,
      env.DB,
      expect.objectContaining({
        tenantId: 'tenant_123',
        learnerProfileId: 'lpr_123',
        recipientIdentity: 'student@umich.edu',
      }),
    );
    expect(mockedCreateAssertion).toHaveBeenNthCalledWith(
      2,
      env.DB,
      expect.objectContaining({
        tenantId: 'tenant_123',
        learnerProfileId: 'lpr_123',
        recipientIdentity: 'student@gmail.com',
      }),
    );
  });
});

describe('POST /v1/tenants/:tenantId/assertions/sakai-commit-issue', () => {
  beforeEach(() => {
    mockedFindActiveSessionByHash.mockReset();
    mockedTouchSession.mockReset();
    mockedFindBadgeTemplateById.mockReset();
    mockedFindAssertionByIdempotencyKey.mockReset();
    mockedResolveLearnerProfileForIdentity.mockReset();
    mockedNextAssertionStatusListIndex.mockReset();
    mockedCreateAssertion.mockReset();
  });

  it('issues badge when GitHub commit threshold is met', async () => {
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
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response(JSON.stringify([{ login: 'student-dev', contributions: 1201 }]), {
        status: 200,
      }),
    );

    mockedFindActiveSessionByHash.mockResolvedValue(sampleSession());
    mockedTouchSession.mockResolvedValue();
    mockedFindBadgeTemplateById.mockResolvedValue(sampleBadgeTemplate());
    mockedFindAssertionByIdempotencyKey.mockResolvedValue(null);
    mockedResolveLearnerProfileForIdentity.mockResolvedValue(sampleLearnerProfile());
    mockedNextAssertionStatusListIndex.mockResolvedValue(0);
    mockedCreateAssertion.mockResolvedValue(sampleAssertion());

    const response = await app.request(
      '/v1/tenants/tenant_123/assertions/sakai-commit-issue',
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Cookie: 'credtrail_session=session-token',
        },
        body: JSON.stringify({
          badgeTemplateId: 'badge_template_001',
          githubUsername: 'student-dev',
        }),
      },
      env,
    );
    const body = await response.json<ManualIssueResponse & { commitCount: number; repository: string }>();

    expect(response.status).toBe(201);
    expect(body.status).toBe('issued');
    expect(body.commitCount).toBe(1201);
    expect(body.repository).toBe('sakaiproject/sakai');
    expect(asString(asJsonObject(body.credential.issuer)?.name)).toBe('Sakai Project');
    expect(asString(asJsonObject(body.credential.issuer)?.url)).toBe('https://www.sakaiproject.org/');
    expect(mockedResolveLearnerProfileForIdentity).toHaveBeenCalledWith(env.DB, {
      tenantId: 'tenant_123',
      identityType: 'url',
      identityValue: 'https://github.com/student-dev',
      displayName: '@student-dev',
    });
    expect(mockedCreateAssertion).toHaveBeenCalledWith(
      env.DB,
      expect.objectContaining({
        tenantId: 'tenant_123',
        learnerProfileId: 'lpr_123',
        recipientIdentityType: 'url',
        recipientIdentity: 'https://github.com/student-dev',
      }),
    );

    fetchSpy.mockRestore();
  });

  it('returns 422 when GitHub commit threshold is not met', async () => {
    const env = createEnv();
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response(JSON.stringify([{ login: 'student-dev', contributions: 42 }]), {
        status: 200,
      }),
    );

    mockedFindActiveSessionByHash.mockResolvedValue(sampleSession());
    mockedTouchSession.mockResolvedValue();

    const response = await app.request(
      '/v1/tenants/tenant_123/assertions/sakai-commit-issue',
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Cookie: 'credtrail_session=session-token',
        },
        body: JSON.stringify({
          badgeTemplateId: 'badge_template_001',
          githubUsername: 'student-dev',
        }),
      },
      env,
    );
    const body = await response.json<{
      error: string;
      githubUsername: string;
      repository: string;
      commitCount: number;
      requiredCommitCount: number;
    }>();

    expect(response.status).toBe(422);
    expect(body.error).toBe('GitHub commit threshold not met');
    expect(body.githubUsername).toBe('student-dev');
    expect(body.repository).toBe('sakaiproject/sakai');
    expect(body.commitCount).toBe(42);
    expect(body.requiredCommitCount).toBe(1000);
    expect(mockedFindBadgeTemplateById).not.toHaveBeenCalled();
    expect(mockedCreateAssertion).not.toHaveBeenCalled();

    fetchSpy.mockRestore();
  });
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
      env.DB,
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
    expect(mockedAddLearnerIdentityAlias).toHaveBeenCalledWith(env.DB, {
      tenantId: 'tenant_123',
      learnerProfileId: 'lpr_123',
      identityType: 'email',
      identityValue: 'learner@gmail.com',
      isPrimary: true,
      isVerified: true,
    });
    expect(mockedMarkLearnerIdentityLinkProofUsed).toHaveBeenCalledWith(
      env.DB,
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

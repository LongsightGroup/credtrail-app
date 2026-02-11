import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('@credtrail/db', async () => {
  const actual = await vi.importActual<typeof import('@credtrail/db')>('@credtrail/db');

  return {
    ...actual,
    addLearnerIdentityAlias: vi.fn(),
    completeJobQueueMessage: vi.fn(),
    createAuditLog: vi.fn(),
    createAssertion: vi.fn(),
    createLearnerIdentityLinkProof: vi.fn(),
    createOAuthAccessToken: vi.fn(),
    createOAuthAuthorizationCode: vi.fn(),
    createOAuthClient: vi.fn(),
    createOAuthRefreshToken: vi.fn(),
    enqueueJobQueueMessage: vi.fn(),
    failJobQueueMessage: vi.fn(),
    findOAuthClientById: vi.fn(),
    findActiveOAuthAccessTokenByHash: vi.fn(),
    findAssertionById: vi.fn(),
    findAssertionByPublicId: vi.fn(),
    findAssertionByIdempotencyKey: vi.fn(),
    findBadgeTemplateById: vi.fn(),
    findTenantMembership: vi.fn(),
    findTenantSigningRegistrationByDid: vi.fn(),
    findActiveSessionByHash: vi.fn(),
    findLearnerProfileById: vi.fn(),
    findLearnerIdentityLinkProofByHash: vi.fn(),
    findLearnerProfileByIdentity: vi.fn(),
    findUserById: vi.fn(),
    listAssertionStatusListEntries: vi.fn(),
    listPublicBadgeWallEntries: vi.fn(),
    touchSession: vi.fn(),
    listLearnerBadgeSummaries: vi.fn(),
    listOb3SubjectCredentials: vi.fn(),
    leaseJobQueueMessages: vi.fn(),
    markLearnerIdentityLinkProofUsed: vi.fn(),
    nextAssertionStatusListIndex: vi.fn(),
    consumeOAuthAuthorizationCode: vi.fn(),
    consumeOAuthRefreshToken: vi.fn(),
    recordAssertionRevocation: vi.fn(),
    revokeOAuthAccessTokenByHash: vi.fn(),
    revokeOAuthRefreshTokenByHash: vi.fn(),
    resolveLearnerProfileForIdentity: vi.fn(),
    upsertBadgeTemplateById: vi.fn(),
    upsertTenantMembershipRole: vi.fn(),
    upsertTenant: vi.fn(),
    upsertTenantSigningRegistration: vi.fn(),
    upsertOb3SubjectCredential: vi.fn(),
    findOb3SubjectProfile: vi.fn(),
    upsertOb3SubjectProfile: vi.fn(),
  };
});

vi.mock('@credtrail/core-domain', async () => {
  const actual = await vi.importActual<typeof import('@credtrail/core-domain')>('@credtrail/core-domain');

  return {
    ...actual,
    getImmutableCredentialObject: vi.fn(),
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
  getImmutableCredentialObject,
} from '@credtrail/core-domain';
import {
  type AuditLogRecord,
  type AssertionRecord,
  type AssertionStatusListEntryRecord,
  type BadgeTemplateRecord,
  type LearnerIdentityLinkProofRecord,
  type LearnerBadgeSummaryRecord,
  type LearnerProfileRecord,
  type PublicBadgeWallEntryRecord,
  type SessionRecord,
  type OAuthAccessTokenRecord,
  type OAuthAuthorizationCodeRecord,
  type OAuthClientRecord,
  type OAuthRefreshTokenRecord,
  type Ob3SubjectCredentialRecord,
  type Ob3SubjectProfileRecord,
  type TenantRecord,
  type TenantSigningRegistrationRecord,
  type SqlDatabase,
  type TenantMembershipRecord,
  addLearnerIdentityAlias,
  completeJobQueueMessage,
  createAuditLog,
  createAssertion,
  createLearnerIdentityLinkProof,
  createOAuthAccessToken,
  createOAuthAuthorizationCode,
  createOAuthClient,
  createOAuthRefreshToken,
  consumeOAuthAuthorizationCode,
  consumeOAuthRefreshToken,
  enqueueJobQueueMessage,
  failJobQueueMessage,
  findActiveOAuthAccessTokenByHash,
  findActiveSessionByHash,
  findAssertionById,
  findAssertionByPublicId,
  findAssertionByIdempotencyKey,
  findBadgeTemplateById,
  findTenantMembership,
  findTenantSigningRegistrationByDid,
  findLearnerIdentityLinkProofByHash,
  findLearnerProfileById,
  findLearnerProfileByIdentity,
  findOAuthClientById,
  findOb3SubjectProfile,
  findUserById,
  listAssertionStatusListEntries,
  listPublicBadgeWallEntries,
  listLearnerBadgeSummaries,
  listOb3SubjectCredentials,
  leaseJobQueueMessages,
  markLearnerIdentityLinkProofUsed,
  nextAssertionStatusListIndex,
  recordAssertionRevocation,
  revokeOAuthAccessTokenByHash,
  revokeOAuthRefreshTokenByHash,
  resolveLearnerProfileForIdentity,
  touchSession,
  type JobQueueMessageRecord,
  upsertBadgeTemplateById,
  upsertOb3SubjectCredential,
  upsertOb3SubjectProfile,
  upsertTenantMembershipRole,
  upsertTenant,
  upsertTenantSigningRegistration,
} from '@credtrail/db';
import { createPostgresDatabase } from '@credtrail/db/postgres';

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

interface OAuthErrorResponse {
  error: string;
  error_description?: string | undefined;
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
const mockedFindTenantMembership = vi.mocked(findTenantMembership);
const mockedFindTenantSigningRegistrationByDid = vi.mocked(findTenantSigningRegistrationByDid);
const mockedGetImmutableCredentialObject = vi.mocked(getImmutableCredentialObject);
const mockedFindActiveSessionByHash = vi.mocked(findActiveSessionByHash);
const mockedFindUserById = vi.mocked(findUserById);
const mockedFindLearnerProfileById = vi.mocked(findLearnerProfileById);
const mockedFindLearnerProfileByIdentity = vi.mocked(findLearnerProfileByIdentity);
const mockedResolveLearnerProfileForIdentity = vi.mocked(resolveLearnerProfileForIdentity);
const mockedListPublicBadgeWallEntries = vi.mocked(listPublicBadgeWallEntries);
const mockedCreateAssertion = vi.mocked(createAssertion);
const mockedNextAssertionStatusListIndex = vi.mocked(nextAssertionStatusListIndex);
const mockedListAssertionStatusListEntries = vi.mocked(listAssertionStatusListEntries);
const mockedTouchSession = vi.mocked(touchSession);
const mockedListLearnerBadgeSummaries = vi.mocked(listLearnerBadgeSummaries);
const mockedCreateLearnerIdentityLinkProof = vi.mocked(createLearnerIdentityLinkProof);
const mockedFindLearnerIdentityLinkProofByHash = vi.mocked(findLearnerIdentityLinkProofByHash);
const mockedFindOAuthClientById = vi.mocked(findOAuthClientById);
const mockedAddLearnerIdentityAlias = vi.mocked(addLearnerIdentityAlias);
const mockedMarkLearnerIdentityLinkProofUsed = vi.mocked(markLearnerIdentityLinkProofUsed);
const mockedCreateOAuthClient = vi.mocked(createOAuthClient);
const mockedCreateOAuthAuthorizationCode = vi.mocked(createOAuthAuthorizationCode);
const mockedConsumeOAuthAuthorizationCode = vi.mocked(consumeOAuthAuthorizationCode);
const mockedCreateOAuthAccessToken = vi.mocked(createOAuthAccessToken);
const mockedCreateOAuthRefreshToken = vi.mocked(createOAuthRefreshToken);
const mockedConsumeOAuthRefreshToken = vi.mocked(consumeOAuthRefreshToken);
const mockedRevokeOAuthAccessTokenByHash = vi.mocked(revokeOAuthAccessTokenByHash);
const mockedRevokeOAuthRefreshTokenByHash = vi.mocked(revokeOAuthRefreshTokenByHash);
const mockedFindActiveOAuthAccessTokenByHash = vi.mocked(findActiveOAuthAccessTokenByHash);
const mockedListOb3SubjectCredentials = vi.mocked(listOb3SubjectCredentials);
const mockedUpsertOb3SubjectCredential = vi.mocked(upsertOb3SubjectCredential);
const mockedFindOb3SubjectProfile = vi.mocked(findOb3SubjectProfile);
const mockedUpsertOb3SubjectProfile = vi.mocked(upsertOb3SubjectProfile);
const mockedEnqueueJobQueueMessage = vi.mocked(enqueueJobQueueMessage);
const mockedLeaseJobQueueMessages = vi.mocked(leaseJobQueueMessages);
const mockedCompleteJobQueueMessage = vi.mocked(completeJobQueueMessage);
const mockedFailJobQueueMessage = vi.mocked(failJobQueueMessage);
const mockedRecordAssertionRevocation = vi.mocked(recordAssertionRevocation);
const mockedCreateAuditLog = vi.mocked(createAuditLog);
const mockedUpsertTenant = vi.mocked(upsertTenant);
const mockedUpsertTenantSigningRegistration = vi.mocked(upsertTenantSigningRegistration);
const mockedUpsertBadgeTemplateById = vi.mocked(upsertBadgeTemplateById);
const mockedUpsertTenantMembershipRole = vi.mocked(upsertTenantMembershipRole);
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
  JOB_PROCESSOR_TOKEN?: string;
  BOOTSTRAP_ADMIN_TOKEN?: string;
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
  mockedFindTenantMembership.mockResolvedValue(sampleTenantMembership());
  mockedFindTenantSigningRegistrationByDid.mockResolvedValue(null);
  mockedFindOAuthClientById.mockReset();
  mockedCreateOAuthClient.mockReset();
  mockedCreateOAuthAuthorizationCode.mockReset();
  mockedConsumeOAuthAuthorizationCode.mockReset();
  mockedCreateOAuthAccessToken.mockReset();
  mockedCreateOAuthRefreshToken.mockReset();
  mockedConsumeOAuthRefreshToken.mockReset();
  mockedRevokeOAuthAccessTokenByHash.mockReset();
  mockedRevokeOAuthRefreshTokenByHash.mockReset();
  mockedFindActiveOAuthAccessTokenByHash.mockReset();
  mockedListOb3SubjectCredentials.mockReset();
  mockedUpsertOb3SubjectCredential.mockReset();
  mockedFindOb3SubjectProfile.mockReset();
  mockedUpsertOb3SubjectProfile.mockReset();
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

const sampleOAuthClientRecord = (
  overrides?: Partial<OAuthClientRecord>,
): OAuthClientRecord => {
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

const sampleOb3SubjectCredentialRecord = (
  overrides?: Partial<Ob3SubjectCredentialRecord>,
): Ob3SubjectCredentialRecord => {
  return {
    id: 'ob3c_123',
    tenantId: 'tenant_123',
    userId: 'usr_123',
    credentialId: 'urn:credtrail:credential:123',
    payloadJson: JSON.stringify({
      id: 'urn:credtrail:credential:123',
      type: ['VerifiableCredential', 'OpenBadgeCredential'],
    }),
    compactJws: null,
    issuedAt: '2026-02-11T22:00:00.000Z',
    createdAt: '2026-02-11T22:00:00.000Z',
    updatedAt: '2026-02-11T22:00:00.000Z',
    ...overrides,
  };
};

const sampleOb3SubjectProfileRecord = (
  overrides?: Partial<Ob3SubjectProfileRecord>,
): Ob3SubjectProfileRecord => {
  return {
    tenantId: 'tenant_123',
    userId: 'usr_123',
    profileJson: JSON.stringify({
      id: 'urn:credtrail:profile:tenant_123:usr_123',
      type: ['Profile'],
      name: 'Learner One',
      email: 'learner@example.edu',
    }),
    createdAt: '2026-02-11T22:00:00.000Z',
    updatedAt: '2026-02-11T22:00:00.000Z',
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

const samplePublicBadgeWallEntry = (
  overrides?: Partial<PublicBadgeWallEntryRecord>,
): PublicBadgeWallEntryRecord => {
  return {
    assertionId: 'sakai:assertion_001',
    assertionPublicId: 'a77ab5e5-bd08-40c3-accd-cf29ed1fdbbf',
    tenantId: 'sakai',
    badgeTemplateId: 'badge_template_sakai_1000',
    badgeTitle: 'Sakai 1000+ Commits Contributor',
    badgeDescription: 'Awarded for 1000+ commits.',
    badgeImageUri: null,
    recipientIdentity: 'https://github.com/ottenhoff',
    recipientIdentityType: 'url',
    issuedAt: '2026-02-11T16:29:14.571Z',
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

const sampleTenant = (overrides?: Partial<TenantRecord>): TenantRecord => {
  return {
    id: 'sakai',
    slug: 'sakai',
    displayName: 'Sakai Project',
    planTier: 'team',
    issuerDomain: 'sakai.credtrail.test',
    didWeb: 'did:web:credtrail.test:sakai',
    isActive: true,
    createdAt: '2026-02-10T22:00:00.000Z',
    updatedAt: '2026-02-10T22:00:00.000Z',
    ...overrides,
  };
};

const sampleTenantSigningRegistration = (
  overrides?: Partial<TenantSigningRegistrationRecord>,
): TenantSigningRegistrationRecord => {
  return {
    tenantId: 'sakai',
    did: 'did:web:credtrail.test:sakai',
    keyId: 'key-1',
    publicJwkJson: JSON.stringify({
      kty: 'OKP',
      crv: 'Ed25519',
      x: 'A'.repeat(32),
    }),
    privateJwkJson: JSON.stringify({
      kty: 'OKP',
      crv: 'Ed25519',
      x: 'A'.repeat(32),
      d: 'B'.repeat(32),
    }),
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

describe('GET /ims/ob/v3p0/discovery', () => {
  it('returns a public OB3 service description document with OAuth metadata', async () => {
    const env = createEnv();
    const response = await app.fetch(new Request('https://credtrail.test/ims/ob/v3p0/discovery'), env);
    const body = await response.json<JsonObject>();

    expect(response.status).toBe(200);
    expect(response.headers.get('content-type')).toContain('application/json');
    expect(response.headers.get('cache-control')).toBe('public, max-age=300');
    expect(asString(body.openapi)).toBe('3.0.1');

    const info = asJsonObject(body.info);
    expect(asString(info?.title)).toBe('CredTrail Open Badges API');
    expect(asString(info?.termsOfService)).toBe('https://credtrail.test/terms');
    expect(asString(info?.['x-imssf-privacyPolicyUrl'])).toBe('https://credtrail.test/privacy');
    expect(asString(info?.['x-imssf-image'])).toBe('https://credtrail.test/credtrail-logo.png');

    const servers = body.servers;
    expect(Array.isArray(servers)).toBe(true);
    const firstServer =
      Array.isArray(servers) && servers.length > 0 && typeof servers[0] === 'object'
        ? asJsonObject(servers[0])
        : null;
    expect(asString(firstServer?.url)).toBe('https://credtrail.test/ims/ob/v3p0');

    const paths = asJsonObject(body.paths);
    expect(asJsonObject(paths?.['/discovery'])).not.toBeNull();
    expect(asJsonObject(paths?.['/credentials'])).not.toBeNull();
    expect(asJsonObject(paths?.['/profile'])).not.toBeNull();

    const components = asJsonObject(body.components);
    const securitySchemes = asJsonObject(components?.securitySchemes);
    const oauthScheme = asJsonObject(securitySchemes?.OAuth2ACG);
    expect(asString(oauthScheme?.type)).toBe('oauth2');
    expect(asString(oauthScheme?.['x-imssf-registrationUrl'])).toBe(
      'https://credtrail.test/ims/ob/v3p0/oauth/register',
    );

    const flows = asJsonObject(oauthScheme?.flows);
    const authorizationCode = asJsonObject(flows?.authorizationCode);
    expect(asString(authorizationCode?.authorizationUrl)).toBe(
      'https://credtrail.test/ims/ob/v3p0/oauth/authorize',
    );
    expect(asString(authorizationCode?.tokenUrl)).toBe('https://credtrail.test/ims/ob/v3p0/oauth/token');
    expect(asString(authorizationCode?.refreshUrl)).toBe(
      'https://credtrail.test/ims/ob/v3p0/oauth/refresh',
    );

    const scopes = asJsonObject(authorizationCode?.scopes);
    expect(
      asString(scopes?.['https://purl.imsglobal.org/spec/ob/v3p0/scope/credential.readonly']),
    ).toContain('Permission');
    expect(
      asString(scopes?.['https://purl.imsglobal.org/spec/ob/v3p0/scope/credential.upsert']),
    ).toContain('Permission');
    expect(
      asString(scopes?.['https://purl.imsglobal.org/spec/ob/v3p0/scope/profile.readonly']),
    ).toContain('Permission');
    expect(asString(scopes?.['https://purl.imsglobal.org/spec/ob/v3p0/scope/profile.update'])).toContain(
      'Permission',
    );
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

describe('OB3 secure REST resource endpoints', () => {
  beforeEach(() => {
    mockedFindActiveOAuthAccessTokenByHash.mockReset();
    mockedListOb3SubjectCredentials.mockReset();
    mockedUpsertOb3SubjectCredential.mockReset();
    mockedFindOb3SubjectProfile.mockReset();
    mockedUpsertOb3SubjectProfile.mockReset();
  });

  it('requires bearer tokens for GET /ims/ob/v3p0/credentials', async () => {
    const response = await app.request('/ims/ob/v3p0/credentials', undefined, createEnv());
    const body = await response.json<Record<string, unknown>>();

    expect(response.status).toBe(401);
    expect(body.imsx_codeMajor).toBe('failure');
    expect(response.headers.get('www-authenticate')).toContain('Bearer');
    expect(mockedFindActiveOAuthAccessTokenByHash).not.toHaveBeenCalled();
  });

  it('enforces credential.readonly scope for GET /ims/ob/v3p0/credentials', async () => {
    mockedFindActiveOAuthAccessTokenByHash.mockResolvedValue(
      sampleOAuthAccessTokenRecord({
        scope: 'https://purl.imsglobal.org/spec/ob/v3p0/scope/profile.readonly',
      }),
    );

    const response = await app.request(
      '/ims/ob/v3p0/credentials',
      {
        headers: {
          authorization: 'Bearer access-token-read',
        },
      },
      createEnv(),
    );
    const body = await response.json<Record<string, unknown>>();

    expect(response.status).toBe(403);
    expect(body.imsx_codeMajor).toBe('failure');
    expect(mockedListOb3SubjectCredentials).not.toHaveBeenCalled();
  });

  it('returns paginated credential payloads with X-Total-Count and Link headers', async () => {
    mockedFindActiveOAuthAccessTokenByHash.mockResolvedValue(
      sampleOAuthAccessTokenRecord({
        scope: 'https://purl.imsglobal.org/spec/ob/v3p0/scope/credential.readonly',
      }),
    );
    mockedListOb3SubjectCredentials.mockResolvedValue({
      totalCount: 3,
      credentials: [
        sampleOb3SubjectCredentialRecord({
          id: 'ob3c_json',
          credentialId: 'urn:credtrail:credential:json',
        }),
        sampleOb3SubjectCredentialRecord({
          id: 'ob3c_jws',
          credentialId: 'urn:credtrail:credential:jws',
          payloadJson: null,
          compactJws: 'eyJhbGciOiJIUzI1NiJ9.e30.signature',
        }),
      ],
    });

    const response = await app.request(
      '/ims/ob/v3p0/credentials?limit=1&offset=1&since=2026-02-10T00:00:00.000Z',
      {
        headers: {
          authorization: 'Bearer access-token-read',
        },
      },
      createEnv(),
    );
    const body = await response.json<Record<string, unknown>>();
    const credentials = Array.isArray(body.credential) ? body.credential : [];
    const compactJwsStrings = Array.isArray(body.compactJwsString) ? body.compactJwsString : [];

    expect(response.status).toBe(200);
    expect(response.headers.get('x-total-count')).toBe('3');
    expect(response.headers.get('link')).toContain('rel="next"');
    expect(response.headers.get('link')).toContain('rel="last"');
    expect(response.headers.get('link')).toContain('rel="first"');
    expect(response.headers.get('link')).toContain('rel="prev"');
    expect(credentials).toHaveLength(1);
    expect(compactJwsStrings).toHaveLength(1);
    expect(mockedListOb3SubjectCredentials).toHaveBeenCalledWith(fakeDb, {
      tenantId: 'tenant_123',
      userId: 'usr_123',
      limit: 1,
      offset: 1,
      since: '2026-02-10T00:00:00.000Z',
    });
  });

  it('supports JSON credential upsert with 201/200 semantics', async () => {
    mockedFindActiveOAuthAccessTokenByHash.mockResolvedValue(
      sampleOAuthAccessTokenRecord({
        scope: 'https://purl.imsglobal.org/spec/ob/v3p0/scope/credential.upsert',
      }),
    );
    mockedUpsertOb3SubjectCredential.mockResolvedValue({
      status: 'created',
      credential: sampleOb3SubjectCredentialRecord(),
    });

    const response = await app.request(
      '/ims/ob/v3p0/credentials',
      {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          authorization: 'Bearer access-token-upsert',
        },
        body: JSON.stringify({
          id: 'urn:credtrail:credential:created',
          type: ['VerifiableCredential', 'OpenBadgeCredential'],
        }),
      },
      createEnv(),
    );
    const body = await response.json<Record<string, unknown>>();

    expect(response.status).toBe(201);
    expect(body.id).toBe('urn:credtrail:credential:created');
    expect(mockedUpsertOb3SubjectCredential).toHaveBeenCalledWith(
      fakeDb,
      expect.objectContaining({
        tenantId: 'tenant_123',
        userId: 'usr_123',
        credentialId: 'urn:credtrail:credential:created',
      }),
    );
  });

  it('supports compact JWS credential upsert responses', async () => {
    mockedFindActiveOAuthAccessTokenByHash.mockResolvedValue(
      sampleOAuthAccessTokenRecord({
        scope: 'https://purl.imsglobal.org/spec/ob/v3p0/scope/credential.upsert',
      }),
    );
    mockedUpsertOb3SubjectCredential.mockResolvedValue({
      status: 'updated',
      credential: sampleOb3SubjectCredentialRecord({
        payloadJson: null,
        compactJws: 'eyJhbGciOiJIUzI1NiJ9.e30.signature',
      }),
    });

    const response = await app.request(
      '/ims/ob/v3p0/credentials',
      {
        method: 'POST',
        headers: {
          'content-type': 'text/plain',
          authorization: 'Bearer access-token-upsert',
        },
        body: 'eyJhbGciOiJIUzI1NiJ9.e30.signature',
      },
      createEnv(),
    );
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(response.headers.get('content-type')).toContain('text/plain');
    expect(body).toBe('eyJhbGciOiJIUzI1NiJ9.e30.signature');
  });

  it('returns and updates profile with scope-based authz', async () => {
    mockedFindActiveOAuthAccessTokenByHash
      .mockResolvedValueOnce(
        sampleOAuthAccessTokenRecord({
          scope: 'https://purl.imsglobal.org/spec/ob/v3p0/scope/profile.readonly',
        }),
      )
      .mockResolvedValueOnce(
        sampleOAuthAccessTokenRecord({
          scope: 'https://purl.imsglobal.org/spec/ob/v3p0/scope/profile.update',
        }),
      );
    mockedFindOb3SubjectProfile.mockResolvedValue(sampleOb3SubjectProfileRecord());
    mockedUpsertOb3SubjectProfile.mockResolvedValue(
      sampleOb3SubjectProfileRecord({
        profileJson: JSON.stringify({
          id: 'urn:credtrail:profile:tenant_123:usr_123',
          type: ['Profile'],
          name: 'Updated Learner',
        }),
      }),
    );

    const getResponse = await app.request(
      '/ims/ob/v3p0/profile',
      {
        headers: {
          authorization: 'Bearer access-token-profile-read',
        },
      },
      createEnv(),
    );
    const getBody = await getResponse.json<Record<string, unknown>>();

    expect(getResponse.status).toBe(200);
    expect(getBody.id).toBe('urn:credtrail:profile:tenant_123:usr_123');

    const putResponse = await app.request(
      '/ims/ob/v3p0/profile',
      {
        method: 'PUT',
        headers: {
          'content-type': 'application/json',
          authorization: 'Bearer access-token-profile-update',
        },
        body: JSON.stringify({
          name: 'Updated Learner',
        }),
      },
      createEnv(),
    );
    const putBody = await putResponse.json<Record<string, unknown>>();

    expect(putResponse.status).toBe(200);
    expect(Array.isArray(putBody.type)).toBe(true);
    expect(putBody.id).toBe('urn:credtrail:profile:tenant_123:usr_123');
    expect(mockedUpsertOb3SubjectProfile).toHaveBeenCalledWith(
      fakeDb,
      expect.objectContaining({
        tenantId: 'tenant_123',
        userId: 'usr_123',
      }),
    );
  });
});

describe('PUT /v1/admin/tenants/:tenantId', () => {
  beforeEach(() => {
    mockedUpsertTenant.mockReset();
  });

  it('returns 503 when bootstrap admin token is not configured', async () => {
    const response = await app.request(
      '/v1/admin/tenants/sakai',
      {
        method: 'PUT',
        headers: {
          'content-type': 'application/json',
          authorization: 'Bearer any-token',
        },
        body: JSON.stringify({
          slug: 'sakai',
          displayName: 'Sakai Project',
        }),
      },
      createEnv(),
    );
    const body = await response.json<ErrorResponse>();

    expect(response.status).toBe(503);
    expect(body.error).toBe('Bootstrap admin API is not configured');
    expect(mockedUpsertTenant).not.toHaveBeenCalled();
  });

  it('returns 401 when bootstrap bearer token does not match', async () => {
    const env = {
      ...createEnv(),
      BOOTSTRAP_ADMIN_TOKEN: 'bootstrap-secret',
    };
    const response = await app.request(
      '/v1/admin/tenants/sakai',
      {
        method: 'PUT',
        headers: {
          'content-type': 'application/json',
          authorization: 'Bearer wrong-secret',
        },
        body: JSON.stringify({
          slug: 'sakai',
          displayName: 'Sakai Project',
        }),
      },
      env,
    );
    const body = await response.json<ErrorResponse>();

    expect(response.status).toBe(401);
    expect(body.error).toBe('Unauthorized');
    expect(mockedUpsertTenant).not.toHaveBeenCalled();
  });

  it('upserts tenant metadata through the admin API', async () => {
    const env = {
      ...createEnv(),
      BOOTSTRAP_ADMIN_TOKEN: 'bootstrap-secret',
    };
    mockedUpsertTenant.mockResolvedValue(sampleTenant());

    const response = await app.request(
      '/v1/admin/tenants/sakai',
      {
        method: 'PUT',
        headers: {
          'content-type': 'application/json',
          authorization: 'Bearer bootstrap-secret',
        },
        body: JSON.stringify({
          slug: 'sakai',
          displayName: 'Sakai Project',
        }),
      },
      env,
    );
    const body = await response.json<{ tenant: TenantRecord }>();

    expect(response.status).toBe(201);
    expect(body.tenant.id).toBe('sakai');
    expect(body.tenant.didWeb).toBe('did:web:credtrail.test:sakai');
    expect(mockedUpsertTenant).toHaveBeenCalledWith(fakeDb, {
      id: 'sakai',
      slug: 'sakai',
      displayName: 'Sakai Project',
      planTier: 'team',
      issuerDomain: 'sakai.credtrail.test',
      didWeb: 'did:web:credtrail.test:sakai',
      isActive: undefined,
    });
  });

  it('returns 409 when tenant slug/domain uniqueness is violated', async () => {
    const env = {
      ...createEnv(),
      BOOTSTRAP_ADMIN_TOKEN: 'bootstrap-secret',
    };
    mockedUpsertTenant.mockRejectedValue(
      new Error('duplicate key value violates unique constraint "tenants_slug_key"'),
    );

    const response = await app.request(
      '/v1/admin/tenants/sakai',
      {
        method: 'PUT',
        headers: {
          'content-type': 'application/json',
          authorization: 'Bearer bootstrap-secret',
        },
        body: JSON.stringify({
          slug: 'sakai',
          displayName: 'Sakai Project',
        }),
      },
      env,
    );
    const body = await response.json<ErrorResponse>();

    expect(response.status).toBe(409);
    expect(body.error).toBe('Tenant slug or issuer domain is already in use');
  });
});

describe('PUT /v1/admin/tenants/:tenantId/signing-registration', () => {
  beforeEach(() => {
    mockedUpsertTenantSigningRegistration.mockReset();
  });

  it('stores tenant signing registration via admin API', async () => {
    const env = {
      ...createEnv(),
      BOOTSTRAP_ADMIN_TOKEN: 'bootstrap-secret',
    };
    const signingMaterial = await generateTenantDidSigningMaterial({
      did: 'did:web:credtrail.test:sakai',
      keyId: 'key-1',
    });
    mockedUpsertTenantSigningRegistration.mockResolvedValue(
      sampleTenantSigningRegistration({
        did: signingMaterial.did,
        keyId: signingMaterial.keyId,
        publicJwkJson: JSON.stringify(signingMaterial.publicJwk),
        privateJwkJson: JSON.stringify(signingMaterial.privateJwk),
      }),
    );

    const response = await app.request(
      '/v1/admin/tenants/sakai/signing-registration',
      {
        method: 'PUT',
        headers: {
          'content-type': 'application/json',
          authorization: 'Bearer bootstrap-secret',
        },
        body: JSON.stringify({
          keyId: signingMaterial.keyId,
          publicJwk: signingMaterial.publicJwk,
          privateJwk: signingMaterial.privateJwk,
        }),
      },
      env,
    );
    const body = await response.json<{
      tenantId: string;
      did: string;
      keyId: string;
      hasPrivateKey: boolean;
    }>();

    expect(response.status).toBe(201);
    expect(body.tenantId).toBe('sakai');
    expect(body.did).toBe('did:web:credtrail.test:sakai');
    expect(body.keyId).toBe('key-1');
    expect(body.hasPrivateKey).toBe(true);
    const firstCall = mockedUpsertTenantSigningRegistration.mock.calls[0];
    const input = firstCall?.[1];

    expect(firstCall?.[0]).toBe(fakeDb);
    expect(input?.tenantId).toBe('sakai');
    expect(input?.did).toBe('did:web:credtrail.test:sakai');
    expect(input?.keyId).toBe(signingMaterial.keyId);
    expect(JSON.parse(input?.publicJwkJson ?? '{}')).toEqual(signingMaterial.publicJwk);
    expect(JSON.parse(input?.privateJwkJson ?? '{}')).toEqual(signingMaterial.privateJwk);
  });
});

describe('PUT /v1/admin/tenants/:tenantId/badge-templates/:badgeTemplateId', () => {
  beforeEach(() => {
    mockedUpsertBadgeTemplateById.mockReset();
  });

  it('upserts a template through the admin API', async () => {
    const env = {
      ...createEnv(),
      BOOTSTRAP_ADMIN_TOKEN: 'bootstrap-secret',
    };
    mockedUpsertBadgeTemplateById.mockResolvedValue(
      sampleBadgeTemplate({
        id: 'badge_template_sakai_1000',
        tenantId: 'sakai',
        slug: 'sakai-1000-commits-contributor',
      }),
    );

    const response = await app.request(
      '/v1/admin/tenants/sakai/badge-templates/badge_template_sakai_1000',
      {
        method: 'PUT',
        headers: {
          'content-type': 'application/json',
          authorization: 'Bearer bootstrap-secret',
        },
        body: JSON.stringify({
          slug: 'sakai-1000-commits-contributor',
          title: 'Sakai 1000+ Commits Contributor',
          description: 'Awarded for contributing 1000+ commits to Sakai.',
          criteriaUri: 'https://github.com/sakaiproject/sakai',
          imageUri: 'https://avatars.githubusercontent.com/u/429529?s=200&v=4',
        }),
      },
      env,
    );
    const body = await response.json<{ tenantId: string; template: BadgeTemplateRecord }>();

    expect(response.status).toBe(201);
    expect(body.tenantId).toBe('sakai');
    expect(body.template.id).toBe('badge_template_sakai_1000');
    expect(mockedUpsertBadgeTemplateById).toHaveBeenCalledWith(fakeDb, {
      id: 'badge_template_sakai_1000',
      tenantId: 'sakai',
      slug: 'sakai-1000-commits-contributor',
      title: 'Sakai 1000+ Commits Contributor',
      description: 'Awarded for contributing 1000+ commits to Sakai.',
      criteriaUri: 'https://github.com/sakaiproject/sakai',
      imageUri: 'https://avatars.githubusercontent.com/u/429529?s=200&v=4',
    });
  });
});

describe('PUT /v1/admin/tenants/:tenantId/users/:userId/role', () => {
  beforeEach(() => {
    mockedUpsertTenantMembershipRole.mockReset();
    mockedCreateAuditLog.mockReset();
    mockedCreateAuditLog.mockResolvedValue(sampleAuditLogRecord());
  });

  it('upserts membership role via bootstrap admin API and writes audit log', async () => {
    const env = {
      ...createEnv(),
      BOOTSTRAP_ADMIN_TOKEN: 'bootstrap-secret',
    };

    mockedUpsertTenantMembershipRole.mockResolvedValue({
      membership: sampleTenantMembership({
        tenantId: 'sakai',
        userId: 'usr_admin',
        role: 'admin',
      }),
      previousRole: 'viewer',
      changed: true,
    });

    const response = await app.request(
      '/v1/admin/tenants/sakai/users/usr_admin/role',
      {
        method: 'PUT',
        headers: {
          'content-type': 'application/json',
          authorization: 'Bearer bootstrap-secret',
        },
        body: JSON.stringify({
          role: 'admin',
        }),
      },
      env,
    );
    const body = await response.json<{
      tenantId: string;
      userId: string;
      role: string;
      previousRole: string | null;
      changed: boolean;
    }>();

    expect(response.status).toBe(201);
    expect(body.tenantId).toBe('sakai');
    expect(body.userId).toBe('usr_admin');
    expect(body.role).toBe('admin');
    expect(body.previousRole).toBe('viewer');
    expect(body.changed).toBe(true);
    expect(mockedUpsertTenantMembershipRole).toHaveBeenCalledWith(fakeDb, {
      tenantId: 'sakai',
      userId: 'usr_admin',
      role: 'admin',
    });
    expect(mockedCreateAuditLog).toHaveBeenCalledWith(
      fakeDb,
      expect.objectContaining({
        tenantId: 'sakai',
        action: 'membership.role_changed',
        targetType: 'membership',
        targetId: 'sakai:usr_admin',
      }),
    );
  });
});

describe('GET /showcase/:tenantId', () => {
  beforeEach(() => {
    mockedListPublicBadgeWallEntries.mockReset();
  });

  it('renders public tenant badge wall entries with badge URLs', async () => {
    const env = createEnv();
    mockedListPublicBadgeWallEntries.mockResolvedValue([
      samplePublicBadgeWallEntry(),
      samplePublicBadgeWallEntry({
        assertionPublicId: '620b51c5-c6f8-4506-8a5c-2daaa2eb6f04',
        recipientIdentity: 'https://github.com/steveswinsburg',
        badgeTitle: 'Sakai Distinguished Contributor',
      }),
    ]);

    const response = await app.request('/showcase/sakai', undefined, env);
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(response.headers.get('cache-control')).toBe('no-store');
    expect(body).toContain('Badge Wall · sakai');
    expect(body).toContain('2 issued badges');
    expect(body).toContain('/badges/a77ab5e5-bd08-40c3-accd-cf29ed1fdbbf');
    expect(body).toContain('/badges/620b51c5-c6f8-4506-8a5c-2daaa2eb6f04');
    expect(body).toContain('http://localhost/badges/a77ab5e5-bd08-40c3-accd-cf29ed1fdbbf');
    expect(body).toContain('@ottenhoff');
    expect(body).toContain('Sakai 1000+ Commits Contributor');
    expect(body).toContain('Sakai Distinguished Contributor');
    expect(body).toContain('github.com/ottenhoff.png');
    expect(mockedListPublicBadgeWallEntries).toHaveBeenCalledWith(fakeDb, {
      tenantId: 'sakai',
      badgeTemplateId: 'badge_template_sakai_1000',
    });
  });

  it('applies badgeTemplateId filter when provided', async () => {
    const env = createEnv();
    mockedListPublicBadgeWallEntries.mockResolvedValue([]);

    const response = await app.request(
      '/showcase/sakai?badgeTemplateId=badge_template_sakai_1000',
      undefined,
      env,
    );
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(body).toContain('badge template &quot;badge_template_sakai_1000&quot;');
    expect(mockedListPublicBadgeWallEntries).toHaveBeenCalledWith(fakeDb, {
      tenantId: 'sakai',
      badgeTemplateId: 'badge_template_sakai_1000',
    });
  });

  it('renders empty state when no badges are present', async () => {
    const env = createEnv();
    mockedListPublicBadgeWallEntries.mockResolvedValue([]);

    const response = await app.request('/showcase/sakai', undefined, env);
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(body).toContain('0 issued badges');
    expect(body).toContain('No public badges found for this showcase.');
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
      fakeDb,
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
      fakeDb,
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
    mockedCreateAuditLog.mockReset();
    mockedCreateAuditLog.mockResolvedValue(sampleAuditLogRecord());
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

  it('writes audit logs for processed revoke jobs', async () => {
    const env = createEnv();

    mockedLeaseJobQueueMessages.mockResolvedValue([
      sampleLeasedQueueMessage({
        jobType: 'revoke_badge',
        tenantId: 'tenant_123',
        payloadJson: JSON.stringify({
          revocationId: 'rev_123',
          assertionId: 'tenant_123:assertion_456',
          reason: 'Policy violation',
          requestedAt: '2026-02-10T22:00:00.000Z',
          requestedByUserId: 'usr_123',
        }),
      }),
    ]);
    mockedRecordAssertionRevocation.mockResolvedValue({
      status: 'revoked',
      revokedAt: '2026-02-10T22:01:00.000Z',
    });

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

    expect(response.status).toBe(200);
    expect(mockedRecordAssertionRevocation).toHaveBeenCalledTimes(1);
    expect(mockedCreateAuditLog).toHaveBeenCalledWith(
      fakeDb,
      expect.objectContaining({
        tenantId: 'tenant_123',
        actorUserId: 'usr_123',
        action: 'assertion.revoked',
        targetType: 'assertion',
        targetId: 'tenant_123:assertion_456',
      }),
    );
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
      fakeDb,
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

describe('DID signing resolution from Postgres registration', () => {
  beforeEach(() => {
    mockedFindTenantSigningRegistrationByDid.mockReset();
  });

  it('serves did.json from DB-backed signing registration', async () => {
    const env = createEnv();
    const signingMaterial = await generateTenantDidSigningMaterial({
      did: 'did:web:localhost',
      keyId: 'key-root',
    });

    mockedFindTenantSigningRegistrationByDid.mockResolvedValue(
      sampleTenantSigningRegistration({
        tenantId: 'platform',
        did: signingMaterial.did,
        keyId: signingMaterial.keyId,
        publicJwkJson: JSON.stringify(signingMaterial.publicJwk),
        privateJwkJson: JSON.stringify(signingMaterial.privateJwk),
      }),
    );

    const response = await app.request('/.well-known/did.json', undefined, env);
    const body = await response.json<JsonObject>();

    expect(response.status).toBe(200);
    expect(asString(body.id)).toBe('did:web:localhost');
    expect(mockedFindTenantSigningRegistrationByDid).toHaveBeenCalledWith(fakeDb, 'did:web:localhost');
  });
});

describe('GET /credentials/v1/status-lists/:tenantId/revocation', () => {
  beforeEach(() => {
    mockedFindTenantSigningRegistrationByDid.mockReset();
    mockedFindTenantSigningRegistrationByDid.mockResolvedValue(null);
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

  it('builds status list credential from DB-backed signing registration', async () => {
    const env = createEnv();
    const signingMaterial = await generateTenantDidSigningMaterial({
      did: 'did:web:credtrail.test:tenant_123',
      keyId: 'key-db',
    });

    mockedFindTenantSigningRegistrationByDid.mockResolvedValue(
      sampleTenantSigningRegistration({
        tenantId: 'tenant_123',
        did: signingMaterial.did,
        keyId: signingMaterial.keyId,
        publicJwkJson: JSON.stringify(signingMaterial.publicJwk),
        privateJwkJson: JSON.stringify(signingMaterial.privateJwk),
      }),
    );
    mockedListAssertionStatusListEntries.mockResolvedValue([]);

    const response = await app.request(
      '/credentials/v1/status-lists/tenant_123/revocation',
      undefined,
      env,
    );
    const body = await response.json<JsonObject>();

    expect(response.status).toBe(200);
    expect(asString(body.issuer)).toBe('did:web:credtrail.test:tenant_123');
    expect(mockedFindTenantSigningRegistrationByDid).toHaveBeenCalledWith(
      fakeDb,
      'did:web:credtrail.test:tenant_123',
    );
  });
});

describe('POST /v1/signing/credentials', () => {
  beforeEach(() => {
    mockedFindTenantSigningRegistrationByDid.mockReset();
  });

  it('signs credentials using DB-backed signing registrations', async () => {
    const env = createEnv();
    const signingMaterial = await generateTenantDidSigningMaterial({
      did: 'did:web:credtrail.test:sakai',
      keyId: 'key-db-sign',
    });

    mockedFindTenantSigningRegistrationByDid.mockResolvedValue(
      sampleTenantSigningRegistration({
        tenantId: 'sakai',
        did: signingMaterial.did,
        keyId: signingMaterial.keyId,
        publicJwkJson: JSON.stringify(signingMaterial.publicJwk),
        privateJwkJson: JSON.stringify(signingMaterial.privateJwk),
      }),
    );

    const response = await app.request(
      '/v1/signing/credentials',
      {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
        },
        body: JSON.stringify({
          did: signingMaterial.did,
          credential: {
            '@context': ['https://www.w3.org/ns/credentials/v2'],
            type: ['VerifiableCredential'],
            issuer: signingMaterial.did,
            credentialSubject: {
              id: 'urn:credtrail:subject:test',
            },
          },
        }),
      },
      env,
    );
    const body = await response.json<JsonObject>();
    const signedCredential = asJsonObject(body.credential);

    expect(response.status).toBe(201);
    expect(asString(body.did)).toBe(signingMaterial.did);
    expect(asJsonObject(signedCredential?.proof)).not.toBeNull();
    expect(mockedFindTenantSigningRegistrationByDid).toHaveBeenCalledWith(fakeDb, signingMaterial.did);
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
          id: 'https://example.edu/badges/typescript-foundations',
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
    expect(body).toContain('Add to LinkedIn Profile');
    expect(body).toContain('linkedin.com/profile/add');
    expect(body).toContain('startTask=CERTIFICATION_NAME');
    expect(body).toContain('name=TypeScript+Foundations');
    expect(body).toContain('organizationName=Example+University');
    expect(body).toContain('issueYear=2026');
    expect(body).toContain('issueMonth=2');
    expect(body).toContain('certUrl=http%3A%2F%2Flocalhost%2Fbadges%2F40a6dc92-85ec-4cb0-8a50-afb2ae700e22');
    expect(body).toContain('certId=urn%3Acredtrail%3Aassertion%3Atenant_123%253Aassertion_456');
    expect(body).toContain('Share on LinkedIn Feed');
    expect(body).toContain('linkedin.com/sharing/share-offsite');
    expect(body).toContain('Validate Assertion (IMS)');
    expect(body).toContain('Validate Badge Class (IMS)');
    expect(body).toContain('Validate Issuer (IMS)');
    expect(body).toContain('openbadgesvalidator.imsglobal.org/?url=');
    expect(body).toContain('api.qrserver.com/v1/create-qr-code');
    expect(body).toContain('QR code for this badge URL');
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
    expect(mockedListLearnerBadgeSummaries).toHaveBeenCalledWith(fakeDb, {
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
    mockedFindTenantMembership.mockReset();
    mockedFindTenantMembership.mockResolvedValue(sampleTenantMembership());
    mockedTouchSession.mockReset();
    mockedFindBadgeTemplateById.mockReset();
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

    expect(firstIssueResponse.status).toBe(201);
    expect(secondIssueResponse.status).toBe(201);
    expect(firstSubjectId).toBe('urn:credtrail:learner:tenant_123:lpr_123');
    expect(secondSubjectId).toBe('urn:credtrail:learner:tenant_123:lpr_123');
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

describe('POST /v1/tenants/:tenantId/assertions/sakai-commit-issue', () => {
  beforeEach(() => {
    mockedFindActiveSessionByHash.mockReset();
    mockedFindTenantMembership.mockReset();
    mockedFindTenantMembership.mockResolvedValue(sampleTenantMembership());
    mockedTouchSession.mockReset();
    mockedFindBadgeTemplateById.mockReset();
    mockedFindAssertionByIdempotencyKey.mockReset();
    mockedResolveLearnerProfileForIdentity.mockReset();
    mockedNextAssertionStatusListIndex.mockReset();
    mockedCreateAssertion.mockReset();
    mockedCreateAuditLog.mockReset();
    mockedCreateAuditLog.mockResolvedValue(sampleAuditLogRecord());
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
    expect(mockedResolveLearnerProfileForIdentity).toHaveBeenCalledWith(fakeDb, {
      tenantId: 'tenant_123',
      identityType: 'url',
      identityValue: 'https://github.com/student-dev',
      displayName: '@student-dev',
    });
    expect(mockedCreateAssertion).toHaveBeenCalledWith(
      fakeDb,
      expect.objectContaining({
        tenantId: 'tenant_123',
        learnerProfileId: 'lpr_123',
        recipientIdentityType: 'url',
        recipientIdentity: 'https://github.com/student-dev',
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

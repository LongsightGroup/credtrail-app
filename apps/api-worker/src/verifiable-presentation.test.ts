import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('@credtrail/db', async () => {
  const actual = await vi.importActual<typeof import('@credtrail/db')>('@credtrail/db');

  return {
    ...actual,
    findActiveSessionByHash: vi.fn(),
    findAssertionById: vi.fn(),
    findTenantSigningRegistrationByDid: vi.fn(),
    findUserById: vi.fn(),
    listLearnerBadgeSummaries: vi.fn(),
    touchSession: vi.fn(),
  };
});

vi.mock('@credtrail/core-domain', async () => {
  const actual =
    await vi.importActual<typeof import('@credtrail/core-domain')>('@credtrail/core-domain');

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
  type P256PrivateJwk,
  type P256PublicJwk,
  encodeJwkPublicKeyMultibase,
  generateTenantDidSigningMaterial,
  getImmutableCredentialObject,
  signCredentialWithDataIntegrityProof,
  signCredentialWithEd25519Signature2020,
} from '@credtrail/core-domain';
import {
  findActiveSessionByHash,
  findAssertionById,
  findTenantSigningRegistrationByDid,
  findUserById,
  listLearnerBadgeSummaries,
  touchSession,
  type AssertionRecord,
  type LearnerBadgeSummaryRecord,
  type SessionRecord,
  type SqlDatabase,
} from '@credtrail/db';
import { createPostgresDatabase } from '@credtrail/db/postgres';

import { app } from './index';

interface ErrorResponse {
  error: string;
}

const mockedFindActiveSessionByHash = vi.mocked(findActiveSessionByHash);
const mockedFindAssertionById = vi.mocked(findAssertionById);
const mockedFindTenantSigningRegistrationByDid = vi.mocked(findTenantSigningRegistrationByDid);
const mockedFindUserById = vi.mocked(findUserById);
const mockedGetImmutableCredentialObject = vi.mocked(getImmutableCredentialObject);
const mockedListLearnerBadgeSummaries = vi.mocked(listLearnerBadgeSummaries);
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
  mockedFindUserById.mockReset();
  mockedFindUserById.mockResolvedValue({
    id: 'usr_123',
    email: 'learner@example.edu',
  });
  mockedFindTenantSigningRegistrationByDid.mockReset();
  mockedFindTenantSigningRegistrationByDid.mockResolvedValue(null);
  mockedFindActiveSessionByHash.mockReset();
  mockedTouchSession.mockReset();
  mockedListLearnerBadgeSummaries.mockReset();
  mockedFindAssertionById.mockReset();
  mockedGetImmutableCredentialObject.mockReset();
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

const requireJwkString = (value: string | undefined, field: string): string => {
  if (typeof value !== 'string' || value.length === 0) {
    throw new Error(`Missing ${field} in exported JWK`);
  }

  return value;
};

const generateP256SigningMaterial = async (
  kid = 'key-p256',
): Promise<{ publicJwk: P256PublicJwk; privateJwk: P256PrivateJwk }> => {
  const generated = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, [
    'sign',
    'verify',
  ]);
  const exportedPublicJwk = await crypto.subtle.exportKey('jwk', generated.publicKey);
  const exportedPrivateJwk = await crypto.subtle.exportKey('jwk', generated.privateKey);

  const publicJwk: P256PublicJwk = {
    kty: 'EC',
    crv: 'P-256',
    x: requireJwkString(exportedPublicJwk.x, 'x'),
    y: requireJwkString(exportedPublicJwk.y, 'y'),
    kid,
  };
  const privateJwk: P256PrivateJwk = {
    ...publicJwk,
    d: requireJwkString(exportedPrivateJwk.d, 'd'),
  };

  return {
    publicJwk,
    privateJwk,
  };
};

const createDidKeyHolderMaterial = async (): Promise<{
  did: string;
  verificationMethod: string;
  privateJwk: {
    kty: 'OKP';
    crv: 'Ed25519';
    x: string;
    d: string;
    kid?: string;
  };
}> => {
  const signingMaterial = await generateTenantDidSigningMaterial({
    did: 'did:web:credtrail.test:holder',
  });
  const multibase = encodeJwkPublicKeyMultibase(signingMaterial.publicJwk);
  const did = `did:key:${multibase}`;

  return {
    did,
    verificationMethod: `${did}#${multibase}`,
    privateJwk: signingMaterial.privateJwk,
  };
};

describe('Verifiable Presentation endpoints', () => {
  beforeEach(() => {
    mockedFindActiveSessionByHash.mockReset();
    mockedTouchSession.mockReset();
    mockedListLearnerBadgeSummaries.mockReset();
    mockedFindAssertionById.mockReset();
    mockedGetImmutableCredentialObject.mockReset();
  });

  it('creates a signed VP for authenticated learner-selected credentials', async () => {
    const env = createEnv();
    const holder = await createDidKeyHolderMaterial();

    mockedFindActiveSessionByHash.mockResolvedValue(sampleSession());
    mockedTouchSession.mockResolvedValue();
    mockedListLearnerBadgeSummaries.mockResolvedValue([sampleLearnerBadge()]);
    mockedFindAssertionById.mockResolvedValue(sampleAssertion());
    mockedGetImmutableCredentialObject.mockResolvedValue({
      '@context': ['https://www.w3.org/ns/credentials/v2'],
      type: ['VerifiableCredential', 'OpenBadgeCredential'],
      id: 'urn:credtrail:assertion:tenant_123%3Aassertion_456',
      issuer: 'did:web:credtrail.test:tenant_123',
      validFrom: '2026-02-10T22:00:00.000Z',
      credentialSubject: {
        id: holder.did,
        achievement: {
          type: ['Achievement'],
          name: 'TypeScript Foundations',
        },
      },
    });

    const response = await app.request(
      '/v1/presentations/create',
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Cookie: 'credtrail_session=session-token',
        },
        body: JSON.stringify({
          holderDid: holder.did,
          holderPrivateJwk: holder.privateJwk,
          credentialIds: ['tenant_123:assertion_456'],
        }),
      },
      env,
    );
    const body = await response.json<Record<string, unknown>>();
    const presentation = asJsonObject(body.presentation);

    expect(response.status).toBe(200);
    expect(body.credentialCount).toBe(1);
    expect(body.holderDid).toBe(holder.did);
    expect(asString(presentation?.holder)).toBe(holder.did);
    expect(asJsonObject(presentation?.proof)).not.toBeNull();
  });

  it('rejects VP creation when credential is not owned by authenticated learner', async () => {
    const env = createEnv();
    const holder = await createDidKeyHolderMaterial();

    mockedFindActiveSessionByHash.mockResolvedValue(sampleSession());
    mockedTouchSession.mockResolvedValue();
    mockedListLearnerBadgeSummaries.mockResolvedValue([]);

    const response = await app.request(
      '/v1/presentations/create',
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Cookie: 'credtrail_session=session-token',
        },
        body: JSON.stringify({
          holderDid: holder.did,
          holderPrivateJwk: holder.privateJwk,
          credentialIds: ['tenant_123:assertion_456'],
        }),
      },
      env,
    );
    const body = await response.json<ErrorResponse>();

    expect(response.status).toBe(403);
    expect(body.error).toContain('not accessible');
    expect(mockedFindAssertionById).not.toHaveBeenCalled();
  });

  it('verifies VP holder proof and mixed EdDSA/ECDSA credential proofs', async () => {
    const holder = await createDidKeyHolderMaterial();
    const ed25519Issuer = await generateTenantDidSigningMaterial({
      did: 'did:web:credtrail.test:tenant_123',
    });
    const p256IssuerKeys = await generateP256SigningMaterial('key-p256');
    const p256IssuerDid = 'did:web:credtrail.test:tenant_123:p256';

    const ed25519Credential = await signCredentialWithEd25519Signature2020({
      credential: {
        '@context': ['https://www.w3.org/ns/credentials/v2'],
        type: ['VerifiableCredential', 'OpenBadgeCredential'],
        id: 'urn:credtrail:credential:ed25519',
        issuer: ed25519Issuer.did,
        validFrom: '2026-02-10T22:00:00.000Z',
        credentialSubject: {
          id: holder.did,
          achievement: {
            type: ['Achievement'],
            name: 'Ed25519 Badge',
          },
        },
      },
      privateJwk: ed25519Issuer.privateJwk,
      verificationMethod: ed25519Issuer.did + '#' + ed25519Issuer.keyId,
    });

    const ecdsaCredential = await signCredentialWithDataIntegrityProof({
      credential: {
        '@context': ['https://www.w3.org/ns/credentials/v2'],
        type: ['VerifiableCredential', 'OpenBadgeCredential'],
        id: 'urn:credtrail:credential:ecdsa',
        issuer: p256IssuerDid,
        validFrom: '2026-02-10T22:00:00.000Z',
        credentialSubject: {
          id: holder.did,
          achievement: {
            type: ['Achievement'],
            name: 'ECDSA Badge',
          },
        },
      },
      privateJwk: p256IssuerKeys.privateJwk,
      verificationMethod: p256IssuerDid + '#key-p256',
      cryptosuite: 'ecdsa-sd-2023',
    });

    const presentation = await signCredentialWithEd25519Signature2020({
      credential: {
        '@context': ['https://www.w3.org/ns/credentials/v2'],
        type: ['VerifiablePresentation'],
        holder: holder.did,
        verifiableCredential: [ed25519Credential, ecdsaCredential],
      },
      privateJwk: holder.privateJwk,
      verificationMethod: holder.verificationMethod,
    });

    const env = {
      ...createEnv(),
      TENANT_SIGNING_REGISTRY_JSON: JSON.stringify({
        [ed25519Issuer.did]: {
          tenantId: 'tenant_123',
          keyId: ed25519Issuer.keyId,
          publicJwk: ed25519Issuer.publicJwk,
        },
        [p256IssuerDid]: {
          tenantId: 'tenant_123',
          keyId: 'key-p256',
          publicJwk: p256IssuerKeys.publicJwk,
        },
      }),
    };

    const response = await app.request(
      '/v1/presentations/verify',
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          presentation,
        }),
      },
      env,
    );
    const body = await response.json<Record<string, unknown>>();
    const credentials = Array.isArray(body.credentials)
      ? body.credentials.map((entry) => asJsonObject(entry))
      : [];
    const proofFormats = credentials
      .map((entry) => asJsonObject(entry?.proof))
      .map((proof) => asString(proof?.format))
      .filter((format): format is string => format !== null);

    expect(response.status).toBe(200);
    expect(body.status).toBe('valid');
    expect(body.credentialCount).toBe(2);
    expect(asString(asJsonObject(asJsonObject(body.holder)?.proof)?.status)).toBe('valid');
    expect(proofFormats).toEqual(
      expect.arrayContaining(['Ed25519Signature2020', 'DataIntegrityProof']),
    );
    expect(credentials.every((entry) => asString(entry?.status) === 'valid')).toBe(true);
  });

  it('returns invalid when VP credential subject does not match holder DID', async () => {
    const holder = await createDidKeyHolderMaterial();
    const issuer = await generateTenantDidSigningMaterial({
      did: 'did:web:credtrail.test:tenant_123',
    });

    const credential = await signCredentialWithEd25519Signature2020({
      credential: {
        '@context': ['https://www.w3.org/ns/credentials/v2'],
        type: ['VerifiableCredential', 'OpenBadgeCredential'],
        id: 'urn:credtrail:credential:mismatch',
        issuer: issuer.did,
        validFrom: '2026-02-10T22:00:00.000Z',
        credentialSubject: {
          id: 'did:key:z6MkpresentationMismatchHolder',
          achievement: {
            type: ['Achievement'],
            name: 'Mismatch Badge',
          },
        },
      },
      privateJwk: issuer.privateJwk,
      verificationMethod: issuer.did + '#' + issuer.keyId,
    });

    const presentation = await signCredentialWithEd25519Signature2020({
      credential: {
        '@context': ['https://www.w3.org/ns/credentials/v2'],
        type: ['VerifiablePresentation'],
        holder: holder.did,
        verifiableCredential: [credential],
      },
      privateJwk: holder.privateJwk,
      verificationMethod: holder.verificationMethod,
    });

    const env = {
      ...createEnv(),
      TENANT_SIGNING_REGISTRY_JSON: JSON.stringify({
        [issuer.did]: {
          tenantId: 'tenant_123',
          keyId: issuer.keyId,
          publicJwk: issuer.publicJwk,
        },
      }),
    };

    const response = await app.request(
      '/v1/presentations/verify',
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          presentation,
        }),
      },
      env,
    );
    const body = await response.json<Record<string, unknown>>();
    const credentials = Array.isArray(body.credentials)
      ? body.credentials.map((entry) => asJsonObject(entry))
      : [];
    const firstBindingStatus = asString(asJsonObject(credentials[0]?.binding)?.status);

    expect(response.status).toBe(200);
    expect(body.status).toBe('invalid');
    expect(firstBindingStatus).toBe('invalid');
  });
});

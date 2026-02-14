import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('@credtrail/db', async () => {
  const actual = await vi.importActual<typeof import('@credtrail/db')>('@credtrail/db');

  return {
    ...actual,
    findAssertionById: vi.fn(),
    findTenantSigningRegistrationByDid: vi.fn(),
    listAssertionStatusListEntries: vi.fn(),
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
  generateTenantDidSigningMaterial,
  getImmutableCredentialObject,
  signCredentialWithDataIntegrityProof,
  signCredentialWithEd25519Signature2020,
} from '@credtrail/core-domain';
import {
  findAssertionById,
  findTenantSigningRegistrationByDid,
  listAssertionStatusListEntries,
  type AssertionRecord,
  type SqlDatabase,
  type TenantSigningRegistrationRecord,
} from '@credtrail/db';
import { createPostgresDatabase } from '@credtrail/db/postgres';

import { app } from './index';

interface VerificationResponse {
  assertionId: string;
  tenantId: string;
  issuedAt: string;
  verification: {
    status: 'active' | 'expired' | 'revoked';
    reason: string | null;
    checkedAt: string;
    expiresAt: string | null;
    revokedAt: string | null;
    statusList: {
      id: string;
      type: string;
      statusPurpose: 'revocation';
      statusListIndex: string;
      statusListCredential: string;
    } | null;
    checks: {
      jsonLdSafeMode: {
        status: 'valid' | 'invalid' | 'unchecked';
        reason: string | null;
      };
      credentialSchema: {
        status: 'valid' | 'invalid' | 'unchecked';
        reason: string | null;
      };
      credentialSubject: {
        status: 'valid' | 'invalid' | 'unchecked';
        reason: string | null;
      };
      dates: {
        status: 'valid' | 'invalid' | 'unchecked';
        reason: string | null;
        validFrom: string | null;
        validUntil: string | null;
      };
      credentialStatus: {
        status: 'valid' | 'invalid' | 'unchecked';
        reason: string | null;
        type: string | null;
        statusPurpose: string | null;
        statusListIndex: string | null;
        statusListCredential: string | null;
        revoked: boolean | null;
      };
    };
    proof: {
      status: 'valid' | 'invalid' | 'unchecked';
      format: string | null;
      cryptosuite: string | null;
      verificationMethod: string | null;
      reason: string | null;
    };
  };
  credential: JsonObject;
}

interface ErrorResponse {
  error: string;
}

const mockedFindAssertionById = vi.mocked(findAssertionById);
const mockedFindTenantSigningRegistrationByDid = vi.mocked(findTenantSigningRegistrationByDid);
const mockedGetImmutableCredentialObject = vi.mocked(getImmutableCredentialObject);
const mockedListAssertionStatusListEntries = vi.mocked(listAssertionStatusListEntries);
const mockedCreatePostgresDatabase = vi.mocked(createPostgresDatabase);
const fakeDb = {
  prepare: vi.fn(),
} as unknown as SqlDatabase;

const createEnv = (): {
  APP_ENV: string;
  DATABASE_URL: string;
  BADGE_OBJECTS: R2Bucket;
  PLATFORM_DOMAIN: string;
  TENANT_SIGNING_KEY_HISTORY_JSON?: string;
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
  mockedFindTenantSigningRegistrationByDid.mockResolvedValue(null);
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
describe('GET /credentials/v1/:credentialId', () => {
  beforeEach(() => {
    mockedFindAssertionById.mockReset();
    mockedGetImmutableCredentialObject.mockReset();
    mockedListAssertionStatusListEntries.mockReset();
  });

  it('returns credential verification details for a valid credential', async () => {
    const env = createEnv();
    const statusListSigningMaterial = await generateTenantDidSigningMaterial({
      did: 'did:web:credtrail.test:tenant_123',
      keyId: 'key-status-list',
    });
    const credential: JsonObject = {
      '@context': ['https://www.w3.org/ns/credentials/v2'],
      id: 'urn:credtrail:assertion:tenant_123%3Aassertion_456',
      type: ['VerifiableCredential', 'OpenBadgeCredential'],
      issuer: 'did:web:credtrail.test:tenant_123',
      validFrom: '2026-02-10T22:00:00.000Z',
      credentialSubject: {
        id: 'mailto:learner@example.edu',
        achievement: {
          id: 'urn:credtrail:badge:001',
          type: ['Achievement'],
          name: 'Sakai Contributor',
        },
      },
      credentialStatus: {
        id: 'http://localhost/credentials/v1/status-lists/tenant_123/revocation#0',
        type: 'BitstringStatusListEntry',
        statusPurpose: 'revocation',
        statusListIndex: '0',
        statusListCredential: 'http://localhost/credentials/v1/status-lists/tenant_123/revocation',
      },
    };

    mockedFindAssertionById.mockResolvedValue(sampleAssertion());
    mockedGetImmutableCredentialObject.mockResolvedValue(credential);
    mockedFindTenantSigningRegistrationByDid.mockResolvedValue(
      sampleTenantSigningRegistration({
        tenantId: 'tenant_123',
        did: statusListSigningMaterial.did,
        keyId: statusListSigningMaterial.keyId,
        publicJwkJson: JSON.stringify(statusListSigningMaterial.publicJwk),
        privateJwkJson: JSON.stringify(statusListSigningMaterial.privateJwk),
      }),
    );
    mockedListAssertionStatusListEntries.mockResolvedValue([
      {
        statusListIndex: 0,
        revokedAt: null,
      },
    ]);

    const response = await app.request(
      '/credentials/v1/tenant_123%3Aassertion_456',
      undefined,
      env,
    );
    const body = await response.json<VerificationResponse>();

    expect(response.status).toBe(200);
    expect(response.headers.get('cache-control')).toBe('no-store');
    expect(body.verification.status).toBe('active');
    expect(body.verification.reason).toBeNull();
    expect(body.verification.checkedAt.length).toBeGreaterThan(0);
    expect(body.verification.expiresAt).toBeNull();
    expect(body.verification.revokedAt).toBeNull();
    expect(body.verification.statusList?.statusPurpose).toBe('revocation');
    expect(body.verification.statusList?.statusListIndex).toBe('0');
    expect(body.verification.statusList?.statusListCredential).toBe(
      'http://localhost/credentials/v1/status-lists/tenant_123/revocation',
    );
    expect(body.verification.checks.jsonLdSafeMode.status).toBe('valid');
    expect(body.verification.checks.credentialSchema.status).toBe('unchecked');
    expect(body.verification.checks.credentialSubject.status).toBe('valid');
    expect(body.verification.checks.dates.status).toBe('valid');
    expect(body.verification.checks.dates.validFrom).toBe('2026-02-10T22:00:00.000Z');
    expect(body.verification.checks.credentialStatus.status).toBe('valid');
    expect(body.verification.checks.credentialStatus.revoked).toBe(false);
    expect(body.verification.proof.status).toBe('unchecked');
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

    const response = await app.request(
      '/credentials/v1/tenant_123%3Aassertion_456',
      undefined,
      env,
    );
    const body = await response.json<VerificationResponse>();

    expect(response.status).toBe(200);
    expect(body.verification.status).toBe('revoked');
    expect(body.verification.reason).toBe('credential has been revoked by issuer');
    expect(body.verification.revokedAt).toBe('2026-02-11T01:00:00.000Z');
    expect(body.verification.proof.status).toBe('unchecked');
  });

  it('marks credential status as revoked when status list entry is revoked', async () => {
    const env = createEnv();
    const statusListSigningMaterial = await generateTenantDidSigningMaterial({
      did: 'did:web:credtrail.test:tenant_123',
      keyId: 'key-status-list',
    });
    const credential: JsonObject = {
      '@context': ['https://www.w3.org/ns/credentials/v2'],
      id: 'urn:credtrail:assertion:tenant_123%3Aassertion_456',
      type: ['VerifiableCredential', 'OpenBadgeCredential'],
      issuer: 'did:web:credtrail.test:tenant_123',
      validFrom: '2026-02-10T22:00:00.000Z',
      credentialSubject: {
        id: 'mailto:learner@example.edu',
      },
      credentialStatus: {
        id: 'http://localhost/credentials/v1/status-lists/tenant_123/revocation#1',
        type: 'BitstringStatusListEntry',
        statusPurpose: 'revocation',
        statusListIndex: '1',
        statusListCredential: 'http://localhost/credentials/v1/status-lists/tenant_123/revocation',
      },
    };

    mockedFindAssertionById.mockResolvedValue(
      sampleAssertion({
        statusListIndex: 1,
        revokedAt: null,
      }),
    );
    mockedGetImmutableCredentialObject.mockResolvedValue(credential);
    mockedFindTenantSigningRegistrationByDid.mockResolvedValue(
      sampleTenantSigningRegistration({
        tenantId: 'tenant_123',
        did: statusListSigningMaterial.did,
        keyId: statusListSigningMaterial.keyId,
        publicJwkJson: JSON.stringify(statusListSigningMaterial.publicJwk),
        privateJwkJson: JSON.stringify(statusListSigningMaterial.privateJwk),
      }),
    );
    mockedListAssertionStatusListEntries.mockResolvedValue([
      {
        statusListIndex: 0,
        revokedAt: null,
      },
      {
        statusListIndex: 1,
        revokedAt: '2026-02-11T01:00:00.000Z',
      },
    ]);

    const response = await app.request(
      '/credentials/v1/tenant_123%3Aassertion_456',
      undefined,
      env,
    );
    const body = await response.json<VerificationResponse>();

    expect(response.status).toBe(200);
    expect(body.verification.status).toBe('revoked');
    expect(body.verification.reason).toBe('credential has been revoked by issuer');
    expect(body.verification.checks.credentialStatus.status).toBe('valid');
    expect(body.verification.checks.credentialStatus.revoked).toBe(true);
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

    const response = await app.request(
      '/credentials/v1/tenant_123%3Aassertion_456',
      undefined,
      env,
    );
    const body = await response.json<VerificationResponse>();

    expect(response.status).toBe(200);
    expect(body.verification.status).toBe('active');
    expect(body.verification.statusList).toBeNull();
    expect(body.verification.proof.status).toBe('unchecked');
  });

  it('marks credential status as expired when validUntil has passed', async () => {
    const env = createEnv();
    const credential: JsonObject = {
      '@context': ['https://www.w3.org/ns/credentials/v2'],
      id: 'urn:credtrail:assertion:tenant_123%3Aassertion_456',
      type: ['VerifiableCredential', 'OpenBadgeCredential'],
      validUntil: '2025-01-01T00:00:00.000Z',
      credentialSubject: {
        id: 'mailto:learner@example.edu',
      },
    };

    mockedFindAssertionById.mockResolvedValue(sampleAssertion());
    mockedGetImmutableCredentialObject.mockResolvedValue(credential);

    const response = await app.request(
      '/credentials/v1/tenant_123%3Aassertion_456',
      undefined,
      env,
    );
    const body = await response.json<VerificationResponse>();

    expect(response.status).toBe(200);
    expect(body.verification.status).toBe('expired');
    expect(body.verification.reason).toBe('credential validUntil/expirationDate has passed');
    expect(body.verification.expiresAt).toBe('2025-01-01T00:00:00.000Z');
    expect(body.verification.revokedAt).toBeNull();
  });

  it('marks jsonLdSafeMode as invalid when unknown terms are present', async () => {
    const env = createEnv();
    const credential: JsonObject = {
      '@context': ['https://www.w3.org/ns/credentials/v2'],
      id: 'urn:credtrail:assertion:tenant_123%3Aassertion_456',
      type: ['VerifiableCredential', 'OpenBadgeCredential'],
      issuer: 'did:web:credtrail.test:tenant_123',
      validFrom: '2026-02-10T22:00:00.000Z',
      credentialSubject: {
        id: 'mailto:learner@example.edu',
      },
      unknownTerm: 'should-fail-safe-mode',
    };

    mockedFindAssertionById.mockResolvedValue(
      sampleAssertion({
        statusListIndex: null,
      }),
    );
    mockedGetImmutableCredentialObject.mockResolvedValue(credential);

    const response = await app.request(
      '/credentials/v1/tenant_123%3Aassertion_456',
      undefined,
      env,
    );
    const body = await response.json<VerificationResponse>();

    expect(response.status).toBe(200);
    expect(body.verification.checks.jsonLdSafeMode.status).toBe('invalid');
    expect(body.verification.checks.jsonLdSafeMode.reason).toContain('unknownTerm');
  });

  it('marks credentialSchema as invalid when 1EdTech validator type is missing', async () => {
    const env = createEnv();
    const credential: JsonObject = {
      '@context': ['https://www.w3.org/ns/credentials/v2'],
      id: 'urn:credtrail:assertion:tenant_123%3Aassertion_456',
      type: ['VerifiableCredential', 'OpenBadgeCredential'],
      issuer: 'did:web:credtrail.test:tenant_123',
      validFrom: '2026-02-10T22:00:00.000Z',
      credentialSubject: {
        id: 'mailto:learner@example.edu',
      },
      credentialSchema: [
        {
          id: 'https://credtrail.test/schemas/badge-credential.json',
          type: 'JsonSchemaValidator2018',
        },
      ],
    };

    mockedFindAssertionById.mockResolvedValue(
      sampleAssertion({
        statusListIndex: null,
      }),
    );
    mockedGetImmutableCredentialObject.mockResolvedValue(credential);

    const response = await app.request(
      '/credentials/v1/tenant_123%3Aassertion_456',
      undefined,
      env,
    );
    const body = await response.json<VerificationResponse>();

    expect(response.status).toBe(200);
    expect(body.verification.checks.credentialSchema.status).toBe('invalid');
    expect(body.verification.checks.credentialSchema.reason).toContain(
      '1EdTechJsonSchemaValidator2019',
    );
  });

  it('validates credentialSchema required properties when schema is loadable', async () => {
    const env = createEnv();
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response(
        JSON.stringify({
          required: ['issuer', 'credentialSubject'],
        }),
        {
          status: 200,
          headers: {
            'content-type': 'application/schema+json',
          },
        },
      ),
    );
    const credential: JsonObject = {
      '@context': ['https://www.w3.org/ns/credentials/v2'],
      id: 'urn:credtrail:assertion:tenant_123%3Aassertion_456',
      type: ['VerifiableCredential', 'OpenBadgeCredential'],
      issuer: 'did:web:credtrail.test:tenant_123',
      validFrom: '2026-02-10T22:00:00.000Z',
      credentialSubject: {
        id: 'mailto:learner@example.edu',
      },
      credentialSchema: [
        {
          id: 'https://schema.credtrail.test/achievement-credential.schema.json',
          type: '1EdTechJsonSchemaValidator2019',
        },
      ],
    };

    mockedFindAssertionById.mockResolvedValue(
      sampleAssertion({
        statusListIndex: null,
      }),
    );
    mockedGetImmutableCredentialObject.mockResolvedValue(credential);

    const response = await app.request(
      '/credentials/v1/tenant_123%3Aassertion_456',
      undefined,
      env,
    );
    const body = await response.json<VerificationResponse>();

    expect(response.status).toBe(200);
    expect(body.verification.checks.credentialSchema.status).toBe('valid');

    fetchSpy.mockRestore();
  });

  it('marks credentialSchema invalid when required schema fields are missing from credential', async () => {
    const env = createEnv();
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response(
        JSON.stringify({
          required: ['customEvidence'],
        }),
        {
          status: 200,
          headers: {
            'content-type': 'application/schema+json',
          },
        },
      ),
    );
    const credential: JsonObject = {
      '@context': ['https://www.w3.org/ns/credentials/v2'],
      id: 'urn:credtrail:assertion:tenant_123%3Aassertion_456',
      type: ['VerifiableCredential', 'OpenBadgeCredential'],
      issuer: 'did:web:credtrail.test:tenant_123',
      validFrom: '2026-02-10T22:00:00.000Z',
      credentialSubject: {
        id: 'mailto:learner@example.edu',
      },
      credentialSchema: [
        {
          id: 'https://schema.credtrail.test/achievement-credential.schema.json',
          type: '1EdTechJsonSchemaValidator2019',
        },
      ],
    };

    mockedFindAssertionById.mockResolvedValue(
      sampleAssertion({
        statusListIndex: null,
      }),
    );
    mockedGetImmutableCredentialObject.mockResolvedValue(credential);

    const response = await app.request(
      '/credentials/v1/tenant_123%3Aassertion_456',
      undefined,
      env,
    );
    const body = await response.json<VerificationResponse>();

    expect(response.status).toBe(200);
    expect(body.verification.checks.credentialSchema.status).toBe('invalid');
    expect(body.verification.checks.credentialSchema.reason).toContain('customEvidence');

    fetchSpy.mockRestore();
  });

  it('marks credentialSubject as invalid when id and identifier are missing', async () => {
    const env = createEnv();
    const credential: JsonObject = {
      '@context': ['https://www.w3.org/ns/credentials/v2'],
      id: 'urn:credtrail:assertion:tenant_123%3Aassertion_456',
      type: ['VerifiableCredential', 'OpenBadgeCredential'],
      issuer: 'did:web:credtrail.test:tenant_123',
      validFrom: '2026-02-10T22:00:00.000Z',
      credentialSubject: {
        achievement: {
          id: 'urn:credtrail:badge:001',
          type: ['Achievement'],
          name: 'Sakai Contributor',
        },
      },
    };

    mockedFindAssertionById.mockResolvedValue(
      sampleAssertion({
        statusListIndex: null,
      }),
    );
    mockedGetImmutableCredentialObject.mockResolvedValue(credential);

    const response = await app.request(
      '/credentials/v1/tenant_123%3Aassertion_456',
      undefined,
      env,
    );
    const body = await response.json<VerificationResponse>();

    expect(response.status).toBe(200);
    expect(body.verification.checks.credentialSubject.status).toBe('invalid');
    expect(body.verification.checks.credentialSubject.reason).toContain(
      'id or at least one identifier',
    );
  });

  it('marks credentialSubject as invalid when OpenBadgeCredential omits achievement details', async () => {
    const env = createEnv();
    const credential: JsonObject = {
      '@context': ['https://www.w3.org/ns/credentials/v2'],
      id: 'urn:credtrail:assertion:tenant_123%3Aassertion_456',
      type: ['VerifiableCredential', 'OpenBadgeCredential'],
      issuer: 'did:web:credtrail.test:tenant_123',
      validFrom: '2026-02-10T22:00:00.000Z',
      credentialSubject: {
        id: 'mailto:learner@example.edu',
      },
    };

    mockedFindAssertionById.mockResolvedValue(
      sampleAssertion({
        statusListIndex: null,
      }),
    );
    mockedGetImmutableCredentialObject.mockResolvedValue(credential);

    const response = await app.request(
      '/credentials/v1/tenant_123%3Aassertion_456',
      undefined,
      env,
    );
    const body = await response.json<VerificationResponse>();

    expect(response.status).toBe(200);
    expect(body.verification.checks.credentialSubject.status).toBe('invalid');
    expect(body.verification.checks.credentialSubject.reason).toBe(
      'credentialSubject.achievement must be an object for OpenBadgeCredential',
    );
  });

  it('marks dates as invalid when validFrom is in the future', async () => {
    const env = createEnv();
    const credential: JsonObject = {
      '@context': ['https://www.w3.org/ns/credentials/v2'],
      id: 'urn:credtrail:assertion:tenant_123%3Aassertion_456',
      type: ['VerifiableCredential', 'OpenBadgeCredential'],
      issuer: 'did:web:credtrail.test:tenant_123',
      validFrom: '2999-01-01T00:00:00.000Z',
      credentialSubject: {
        id: 'mailto:learner@example.edu',
      },
    };

    mockedFindAssertionById.mockResolvedValue(
      sampleAssertion({
        statusListIndex: null,
      }),
    );
    mockedGetImmutableCredentialObject.mockResolvedValue(credential);

    const response = await app.request(
      '/credentials/v1/tenant_123%3Aassertion_456',
      undefined,
      env,
    );
    const body = await response.json<VerificationResponse>();

    expect(response.status).toBe(200);
    expect(body.verification.checks.dates.status).toBe('invalid');
    expect(body.verification.checks.dates.reason).toBe(
      'credential validFrom/issuanceDate is in the future',
    );
    expect(body.verification.checks.dates.validFrom).toBe('2999-01-01T00:00:00.000Z');
  });

  it('verifies Ed25519Signature2020 proofs when issuer signing keys are resolvable', async () => {
    const env = createEnv();
    const signingMaterial = await generateTenantDidSigningMaterial({
      did: 'did:web:credtrail.test:tenant_123',
      keyId: 'key-1',
    });
    const credential = await signCredentialWithEd25519Signature2020({
      credential: {
        '@context': ['https://www.w3.org/ns/credentials/v2'],
        id: 'urn:credtrail:assertion:tenant_123%3Aassertion_456',
        type: ['VerifiableCredential', 'OpenBadgeCredential'],
        issuer: signingMaterial.did,
        credentialSubject: {
          id: 'mailto:learner@example.edu',
          achievement: {
            id: 'urn:credtrail:badge:001',
            type: ['Achievement'],
            name: 'Sakai Contributor',
          },
        },
      },
      privateJwk: signingMaterial.privateJwk,
      verificationMethod: `${signingMaterial.did}#${signingMaterial.keyId}`,
      createdAt: '2026-02-11T00:00:00.000Z',
    });

    mockedFindAssertionById.mockResolvedValue(sampleAssertion());
    mockedGetImmutableCredentialObject.mockResolvedValue(credential);
    mockedFindTenantSigningRegistrationByDid.mockResolvedValue(
      sampleTenantSigningRegistration({
        tenantId: 'tenant_123',
        did: signingMaterial.did,
        keyId: signingMaterial.keyId,
        publicJwkJson: JSON.stringify(signingMaterial.publicJwk),
        privateJwkJson: JSON.stringify(signingMaterial.privateJwk),
      }),
    );

    const response = await app.request(
      '/credentials/v1/tenant_123%3Aassertion_456',
      undefined,
      env,
    );
    const body = await response.json<VerificationResponse>();

    expect(response.status).toBe(200);
    expect(body.verification.proof.status).toBe('valid');
    expect(body.verification.proof.format).toBe('Ed25519Signature2020');
    expect(body.verification.proof.verificationMethod).toBe(
      'did:web:credtrail.test:tenant_123#key-1',
    );
  });

  it('verifies proof arrays by selecting the assertionMethod proof entry', async () => {
    const env = createEnv();
    const signingMaterial = await generateTenantDidSigningMaterial({
      did: 'did:web:credtrail.test:tenant_123',
      keyId: 'key-1',
    });
    const signedCredential = await signCredentialWithEd25519Signature2020({
      credential: {
        '@context': ['https://www.w3.org/ns/credentials/v2'],
        id: 'urn:credtrail:assertion:tenant_123%3Aassertion_456',
        type: ['VerifiableCredential', 'OpenBadgeCredential'],
        issuer: signingMaterial.did,
        credentialSubject: {
          id: 'mailto:learner@example.edu',
          achievement: {
            id: 'urn:credtrail:badge:001',
            type: ['Achievement'],
            name: 'Sakai Contributor',
          },
        },
      },
      privateJwk: signingMaterial.privateJwk,
      verificationMethod: `${signingMaterial.did}#${signingMaterial.keyId}`,
      createdAt: '2026-02-11T00:00:00.000Z',
    });
    const signedProof = asJsonObject(signedCredential.proof);

    if (signedProof === null) {
      throw new Error('Signed credential proof object was unexpectedly null');
    }

    const credential: JsonObject = {
      ...signedCredential,
      proof: [
        {
          ...signedProof,
          proofPurpose: 'authentication',
        },
        signedProof,
      ],
    };

    mockedFindAssertionById.mockResolvedValue(sampleAssertion());
    mockedGetImmutableCredentialObject.mockResolvedValue(credential);
    mockedFindTenantSigningRegistrationByDid.mockResolvedValue(
      sampleTenantSigningRegistration({
        tenantId: 'tenant_123',
        did: signingMaterial.did,
        keyId: signingMaterial.keyId,
        publicJwkJson: JSON.stringify(signingMaterial.publicJwk),
        privateJwkJson: JSON.stringify(signingMaterial.privateJwk),
      }),
    );

    const response = await app.request(
      '/credentials/v1/tenant_123%3Aassertion_456',
      undefined,
      env,
    );
    const body = await response.json<VerificationResponse>();

    expect(response.status).toBe(200);
    expect(body.verification.proof.status).toBe('valid');
    expect(body.verification.proof.format).toBe('Ed25519Signature2020');
    expect(body.verification.proof.verificationMethod).toBe(
      'did:web:credtrail.test:tenant_123#key-1',
    );
  });

  it('verifies DataIntegrityProof ecdsa-sd-2023 proofs when issuer signing keys are resolvable', async () => {
    const env = createEnv();
    const signingMaterial = await generateP256SigningMaterial('key-p256');
    const did = 'did:web:credtrail.test:tenant_123';
    const credential = await signCredentialWithDataIntegrityProof({
      credential: {
        '@context': ['https://www.w3.org/ns/credentials/v2'],
        id: 'urn:credtrail:assertion:tenant_123%3Aassertion_456',
        type: ['VerifiableCredential', 'OpenBadgeCredential'],
        issuer: did,
        credentialSubject: {
          id: 'mailto:learner@example.edu',
          achievement: {
            id: 'urn:credtrail:badge:001',
            type: ['Achievement'],
            name: 'Sakai Contributor',
          },
        },
      },
      privateJwk: signingMaterial.privateJwk,
      verificationMethod: `${did}#${signingMaterial.publicJwk.kid ?? 'key-p256'}`,
      cryptosuite: 'ecdsa-sd-2023',
      createdAt: '2026-02-11T00:00:00.000Z',
    });

    mockedFindAssertionById.mockResolvedValue(sampleAssertion());
    mockedGetImmutableCredentialObject.mockResolvedValue(credential);
    mockedFindTenantSigningRegistrationByDid.mockResolvedValue(
      sampleTenantSigningRegistration({
        tenantId: 'tenant_123',
        did,
        keyId: signingMaterial.publicJwk.kid ?? 'key-p256',
        publicJwkJson: JSON.stringify(signingMaterial.publicJwk),
        privateJwkJson: JSON.stringify(signingMaterial.privateJwk),
      }),
    );

    const response = await app.request(
      '/credentials/v1/tenant_123%3Aassertion_456',
      undefined,
      env,
    );
    const body = await response.json<VerificationResponse>();

    expect(response.status).toBe(200);
    expect(body.verification.proof.status).toBe('valid');
    expect(body.verification.proof.format).toBe('DataIntegrityProof');
    expect(body.verification.proof.cryptosuite).toBe('ecdsa-sd-2023');
    expect(body.verification.proof.verificationMethod).toBe(
      'did:web:credtrail.test:tenant_123#key-p256',
    );
  });

  it('verifies DataIntegrityProof eddsa-rdfc-2022 proofs when issuer signing keys are resolvable', async () => {
    const env = createEnv();
    const signingMaterial = await generateTenantDidSigningMaterial({
      did: 'did:web:credtrail.test:tenant_123',
      keyId: 'key-1',
    });
    const credential = await signCredentialWithDataIntegrityProof({
      credential: {
        '@context': ['https://www.w3.org/ns/credentials/v2'],
        id: 'urn:credtrail:assertion:tenant_123%3Aassertion_456',
        type: ['VerifiableCredential', 'OpenBadgeCredential'],
        issuer: signingMaterial.did,
        credentialSubject: {
          id: 'mailto:learner@example.edu',
          achievement: {
            id: 'urn:credtrail:badge:001',
            type: ['Achievement'],
            name: 'Sakai Contributor',
          },
        },
      },
      privateJwk: signingMaterial.privateJwk,
      verificationMethod: `${signingMaterial.did}#${signingMaterial.keyId}`,
      cryptosuite: 'eddsa-rdfc-2022',
      createdAt: '2026-02-11T00:00:00.000Z',
    });

    mockedFindAssertionById.mockResolvedValue(sampleAssertion());
    mockedGetImmutableCredentialObject.mockResolvedValue(credential);
    mockedFindTenantSigningRegistrationByDid.mockResolvedValue(
      sampleTenantSigningRegistration({
        tenantId: 'tenant_123',
        did: signingMaterial.did,
        keyId: signingMaterial.keyId,
        publicJwkJson: JSON.stringify(signingMaterial.publicJwk),
        privateJwkJson: JSON.stringify(signingMaterial.privateJwk),
      }),
    );

    const response = await app.request(
      '/credentials/v1/tenant_123%3Aassertion_456',
      undefined,
      env,
    );
    const body = await response.json<VerificationResponse>();

    expect(response.status).toBe(200);
    expect(body.verification.proof.status).toBe('valid');
    expect(body.verification.proof.format).toBe('DataIntegrityProof');
    expect(body.verification.proof.cryptosuite).toBe('eddsa-rdfc-2022');
    expect(body.verification.proof.verificationMethod).toBe(
      'did:web:credtrail.test:tenant_123#key-1',
    );
  });

  it('verifies DataIntegrityProof credentials with both EdDSA and ECDSA cryptosuites through the same endpoint', async () => {
    const env = createEnv();
    const assertDataIntegrityVerification = async (input: {
      credential: JsonObject;
      registration: TenantSigningRegistrationRecord;
      cryptosuite: 'eddsa-rdfc-2022' | 'ecdsa-sd-2023';
    }): Promise<void> => {
      mockedFindAssertionById.mockResolvedValue(sampleAssertion());
      mockedGetImmutableCredentialObject.mockResolvedValue(input.credential);
      mockedFindTenantSigningRegistrationByDid.mockResolvedValue(input.registration);

      const response = await app.request(
        '/credentials/v1/tenant_123%3Aassertion_456',
        undefined,
        env,
      );
      const body = await response.json<VerificationResponse>();

      expect(response.status).toBe(200);
      expect(body.verification.proof.status).toBe('valid');
      expect(body.verification.proof.format).toBe('DataIntegrityProof');
      expect(body.verification.proof.cryptosuite).toBe(input.cryptosuite);
    };

    const did = 'did:web:credtrail.test:tenant_123';
    const ecdsaSigningMaterial = await generateP256SigningMaterial('key-p256-interchangeable');
    const ecdsaCredential = await signCredentialWithDataIntegrityProof({
      credential: {
        '@context': ['https://www.w3.org/ns/credentials/v2'],
        id: 'urn:credtrail:assertion:tenant_123%3Aassertion_456',
        type: ['VerifiableCredential', 'OpenBadgeCredential'],
        issuer: did,
        credentialSubject: {
          id: 'mailto:learner@example.edu',
          achievement: {
            id: 'urn:credtrail:badge:001',
            type: ['Achievement'],
            name: 'Sakai Contributor',
          },
        },
      },
      privateJwk: ecdsaSigningMaterial.privateJwk,
      verificationMethod: `${did}#${ecdsaSigningMaterial.publicJwk.kid ?? 'key-p256-interchangeable'}`,
      cryptosuite: 'ecdsa-sd-2023',
      createdAt: '2026-02-11T00:00:00.000Z',
    });

    await assertDataIntegrityVerification({
      credential: ecdsaCredential,
      registration: sampleTenantSigningRegistration({
        tenantId: 'tenant_123',
        did,
        keyId: ecdsaSigningMaterial.publicJwk.kid ?? 'key-p256-interchangeable',
        publicJwkJson: JSON.stringify(ecdsaSigningMaterial.publicJwk),
        privateJwkJson: JSON.stringify(ecdsaSigningMaterial.privateJwk),
      }),
      cryptosuite: 'ecdsa-sd-2023',
    });

    const eddsaSigningMaterial = await generateTenantDidSigningMaterial({
      did,
      keyId: 'key-ed25519-interchangeable',
    });
    const eddsaCredential = await signCredentialWithDataIntegrityProof({
      credential: {
        '@context': ['https://www.w3.org/ns/credentials/v2'],
        id: 'urn:credtrail:assertion:tenant_123%3Aassertion_456',
        type: ['VerifiableCredential', 'OpenBadgeCredential'],
        issuer: did,
        credentialSubject: {
          id: 'mailto:learner@example.edu',
          achievement: {
            id: 'urn:credtrail:badge:001',
            type: ['Achievement'],
            name: 'Sakai Contributor',
          },
        },
      },
      privateJwk: eddsaSigningMaterial.privateJwk,
      verificationMethod: `${did}#${eddsaSigningMaterial.keyId}`,
      cryptosuite: 'eddsa-rdfc-2022',
      createdAt: '2026-02-11T00:00:00.000Z',
    });

    await assertDataIntegrityVerification({
      credential: eddsaCredential,
      registration: sampleTenantSigningRegistration({
        tenantId: 'tenant_123',
        did,
        keyId: eddsaSigningMaterial.keyId,
        publicJwkJson: JSON.stringify(eddsaSigningMaterial.publicJwk),
        privateJwkJson: JSON.stringify(eddsaSigningMaterial.privateJwk),
      }),
      cryptosuite: 'eddsa-rdfc-2022',
    });
  });

  it('returns invalid when proof verificationMethod DID does not match issuer DID', async () => {
    const env = createEnv();
    const signingMaterial = await generateTenantDidSigningMaterial({
      did: 'did:web:credtrail.test:tenant_123',
      keyId: 'key-1',
    });
    const credential = await signCredentialWithEd25519Signature2020({
      credential: {
        '@context': ['https://www.w3.org/ns/credentials/v2'],
        id: 'urn:credtrail:assertion:tenant_123%3Aassertion_456',
        type: ['VerifiableCredential', 'OpenBadgeCredential'],
        issuer: 'did:web:credtrail.test:tenant_mismatch',
        credentialSubject: {
          id: 'mailto:learner@example.edu',
          achievement: {
            id: 'urn:credtrail:badge:001',
            type: ['Achievement'],
            name: 'Sakai Contributor',
          },
        },
      },
      privateJwk: signingMaterial.privateJwk,
      verificationMethod: `${signingMaterial.did}#${signingMaterial.keyId}`,
      createdAt: '2026-02-11T00:00:00.000Z',
    });

    mockedFindAssertionById.mockResolvedValue(sampleAssertion());
    mockedGetImmutableCredentialObject.mockResolvedValue(credential);
    mockedFindTenantSigningRegistrationByDid.mockResolvedValue(
      sampleTenantSigningRegistration({
        tenantId: 'tenant_123',
        did: signingMaterial.did,
        keyId: signingMaterial.keyId,
        publicJwkJson: JSON.stringify(signingMaterial.publicJwk),
        privateJwkJson: JSON.stringify(signingMaterial.privateJwk),
      }),
    );

    const response = await app.request(
      '/credentials/v1/tenant_123%3Aassertion_456',
      undefined,
      env,
    );
    const body = await response.json<VerificationResponse>();

    expect(response.status).toBe(200);
    expect(body.verification.proof.status).toBe('invalid');
    expect(body.verification.proof.reason).toBe(
      'verificationMethod DID must match credential issuer DID',
    );
  });

  it('returns invalid when proof verificationMethod key fragment does not match resolved signing key id', async () => {
    const env = createEnv();
    const signingMaterial = await generateTenantDidSigningMaterial({
      did: 'did:web:credtrail.test:tenant_123',
      keyId: 'key-1',
    });
    const credential = await signCredentialWithEd25519Signature2020({
      credential: {
        '@context': ['https://www.w3.org/ns/credentials/v2'],
        id: 'urn:credtrail:assertion:tenant_123%3Aassertion_456',
        type: ['VerifiableCredential', 'OpenBadgeCredential'],
        issuer: signingMaterial.did,
        credentialSubject: {
          id: 'mailto:learner@example.edu',
          achievement: {
            id: 'urn:credtrail:badge:001',
            type: ['Achievement'],
            name: 'Sakai Contributor',
          },
        },
      },
      privateJwk: signingMaterial.privateJwk,
      verificationMethod: `${signingMaterial.did}#key-2`,
      createdAt: '2026-02-11T00:00:00.000Z',
    });

    mockedFindAssertionById.mockResolvedValue(sampleAssertion());
    mockedGetImmutableCredentialObject.mockResolvedValue(credential);
    mockedFindTenantSigningRegistrationByDid.mockResolvedValue(
      sampleTenantSigningRegistration({
        tenantId: 'tenant_123',
        did: signingMaterial.did,
        keyId: signingMaterial.keyId,
        publicJwkJson: JSON.stringify(signingMaterial.publicJwk),
        privateJwkJson: JSON.stringify(signingMaterial.privateJwk),
      }),
    );

    const response = await app.request(
      '/credentials/v1/tenant_123%3Aassertion_456',
      undefined,
      env,
    );
    const body = await response.json<VerificationResponse>();

    expect(response.status).toBe(200);
    expect(body.verification.proof.status).toBe('invalid');
    expect(body.verification.proof.reason).toBe(
      'verificationMethod key fragment must match an active or historical signing key id',
    );
  });

  it('verifies proofs signed with historical key ids when key rotation history is configured', async () => {
    const oldSigningMaterial = await generateTenantDidSigningMaterial({
      did: 'did:web:credtrail.test:tenant_123',
      keyId: 'key-old',
    });
    const newSigningMaterial = await generateTenantDidSigningMaterial({
      did: 'did:web:credtrail.test:tenant_123',
      keyId: 'key-new',
    });
    const env = {
      ...createEnv(),
      TENANT_SIGNING_KEY_HISTORY_JSON: JSON.stringify({
        'did:web:credtrail.test:tenant_123': [
          {
            keyId: oldSigningMaterial.keyId,
            publicJwk: oldSigningMaterial.publicJwk,
          },
        ],
      }),
    };
    const credential = await signCredentialWithEd25519Signature2020({
      credential: {
        '@context': ['https://www.w3.org/ns/credentials/v2'],
        id: 'urn:credtrail:assertion:tenant_123%3Aassertion_456',
        type: ['VerifiableCredential', 'OpenBadgeCredential'],
        issuer: oldSigningMaterial.did,
        credentialSubject: {
          id: 'mailto:learner@example.edu',
          achievement: {
            id: 'urn:credtrail:badge:001',
            type: ['Achievement'],
            name: 'Sakai Contributor',
          },
        },
      },
      privateJwk: oldSigningMaterial.privateJwk,
      verificationMethod: `${oldSigningMaterial.did}#${oldSigningMaterial.keyId}`,
      createdAt: '2026-02-11T00:00:00.000Z',
    });

    mockedFindAssertionById.mockResolvedValue(sampleAssertion());
    mockedGetImmutableCredentialObject.mockResolvedValue(credential);
    mockedFindTenantSigningRegistrationByDid.mockResolvedValue(
      sampleTenantSigningRegistration({
        tenantId: 'tenant_123',
        did: newSigningMaterial.did,
        keyId: newSigningMaterial.keyId,
        publicJwkJson: JSON.stringify(newSigningMaterial.publicJwk),
        privateJwkJson: JSON.stringify(newSigningMaterial.privateJwk),
      }),
    );

    const response = await app.request(
      '/credentials/v1/tenant_123%3Aassertion_456',
      undefined,
      env,
    );
    const body = await response.json<VerificationResponse>();

    expect(response.status).toBe(200);
    expect(body.verification.proof.status).toBe('valid');
    expect(body.verification.proof.verificationMethod).toBe(
      'did:web:credtrail.test:tenant_123#key-old',
    );
  });

  it('returns invalid when proof verificationMethod omits key fragment', async () => {
    const env = createEnv();
    const signingMaterial = await generateTenantDidSigningMaterial({
      did: 'did:web:credtrail.test:tenant_123',
      keyId: 'key-1',
    });
    const credential = await signCredentialWithEd25519Signature2020({
      credential: {
        '@context': ['https://www.w3.org/ns/credentials/v2'],
        id: 'urn:credtrail:assertion:tenant_123%3Aassertion_456',
        type: ['VerifiableCredential', 'OpenBadgeCredential'],
        issuer: signingMaterial.did,
        credentialSubject: {
          id: 'mailto:learner@example.edu',
          achievement: {
            id: 'urn:credtrail:badge:001',
            type: ['Achievement'],
            name: 'Sakai Contributor',
          },
        },
      },
      privateJwk: signingMaterial.privateJwk,
      verificationMethod: signingMaterial.did,
      createdAt: '2026-02-11T00:00:00.000Z',
    });

    mockedFindAssertionById.mockResolvedValue(sampleAssertion());
    mockedGetImmutableCredentialObject.mockResolvedValue(credential);
    mockedFindTenantSigningRegistrationByDid.mockResolvedValue(
      sampleTenantSigningRegistration({
        tenantId: 'tenant_123',
        did: signingMaterial.did,
        keyId: signingMaterial.keyId,
        publicJwkJson: JSON.stringify(signingMaterial.publicJwk),
        privateJwkJson: JSON.stringify(signingMaterial.privateJwk),
      }),
    );

    const response = await app.request(
      '/credentials/v1/tenant_123%3Aassertion_456',
      undefined,
      env,
    );
    const body = await response.json<VerificationResponse>();

    expect(response.status).toBe(200);
    expect(body.verification.proof.status).toBe('invalid');
    expect(body.verification.proof.reason).toBe('verificationMethod must include a key fragment');
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

    const response = await app.request(
      '/credentials/v1/tenant_123%3Aassertion_456',
      undefined,
      env,
    );
    const body = await response.json<ErrorResponse>();

    expect(response.status).toBe(404);
    expect(body.error).toBe('Credential not found');
    expect(mockedGetImmutableCredentialObject).not.toHaveBeenCalled();
  });
});


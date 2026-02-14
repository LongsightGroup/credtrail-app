import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('@credtrail/db', async () => {
  const actual = await vi.importActual<typeof import('@credtrail/db')>('@credtrail/db');

  return {
    ...actual,
    findAssertionById: vi.fn(),
    findAssertionByPublicId: vi.fn(),
    findLearnerProfileById: vi.fn(),
    findUserById: vi.fn(),
    listLtiIssuerRegistrations: vi.fn(),
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

import { type JsonObject, getImmutableCredentialObject } from '@credtrail/core-domain';
import {
  findAssertionById,
  findAssertionByPublicId,
  findLearnerProfileById,
  listLtiIssuerRegistrations,
  type AssertionRecord,
  type LearnerProfileRecord,
  type SqlDatabase,
} from '@credtrail/db';
import { createPostgresDatabase } from '@credtrail/db/postgres';

import { app } from './index';

const mockedFindAssertionById = vi.mocked(findAssertionById);
const mockedFindAssertionByPublicId = vi.mocked(findAssertionByPublicId);
const mockedFindLearnerProfileById = vi.mocked(findLearnerProfileById);
const mockedGetImmutableCredentialObject = vi.mocked(getImmutableCredentialObject);
const mockedListLtiIssuerRegistrations = vi.mocked(listLtiIssuerRegistrations);
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

beforeEach(() => {
  mockedCreatePostgresDatabase.mockReset();
  mockedCreatePostgresDatabase.mockReturnValue(fakeDb);
  mockedFindAssertionByPublicId.mockReset();
  mockedFindAssertionById.mockReset();
  mockedFindLearnerProfileById.mockReset();
  mockedGetImmutableCredentialObject.mockReset();
  mockedListLtiIssuerRegistrations.mockReset();
  mockedListLtiIssuerRegistrations.mockResolvedValue([]);
});

describe('GET /badges/:badgeIdentifier', () => {
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
    expect(body).toContain('/credentials/v1/tenant_123%3Aassertion_456/download.pdf');
    expect(body).toContain('/credentials/v1/tenant_123%3Aassertion_456/jsonld');
    expect(body).toContain('Download PDF');
    expect(body).toContain('Add to LinkedIn Profile');
    expect(body).toContain('linkedin.com/profile/add');
    expect(body).toContain('startTask=CERTIFICATION_NAME');
    expect(body).toContain('name=TypeScript+Foundations');
    expect(body).toContain('organizationName=Example+University');
    expect(body).toContain('issueYear=2026');
    expect(body).toContain('issueMonth=2');
    expect(body).toContain(
      'certUrl=http%3A%2F%2Flocalhost%2Fbadges%2F40a6dc92-85ec-4cb0-8a50-afb2ae700e22',
    );
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
    expect(body).toContain(
      '<link rel="canonical" href="http://localhost/badges/40a6dc92-85ec-4cb0-8a50-afb2ae700e22"',
    );
  });

  it('keeps public badge pages available after LMS course deletion', async () => {
    const env = createEnv();
    const credential: JsonObject = {
      id: 'urn:credtrail:assertion:tenant_123%3Aassertion_456',
      credentialSubject: {
        achievement: {
          name: 'TypeScript Foundations',
        },
      },
    };

    mockedFindAssertionByPublicId.mockResolvedValue(sampleAssertion());
    mockedGetImmutableCredentialObject.mockResolvedValue(credential);
    mockedListLtiIssuerRegistrations.mockResolvedValue([]);

    const response = await app.request(
      '/badges/40a6dc92-85ec-4cb0-8a50-afb2ae700e22',
      undefined,
      env,
    );
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(body).toContain('TypeScript Foundations');
    expect(body).toContain('Verified');
    expect(mockedListLtiIssuerRegistrations).not.toHaveBeenCalled();
  });

  it('rebuilds canonical and LinkedIn links for the current platform host after platform move', async () => {
    const env = createEnv();
    const credential: JsonObject = {
      id: 'urn:credtrail:assertion:tenant_123%3Aassertion_456',
      issuer: {
        name: 'Example University',
      },
      credentialSubject: {
        achievement: {
          name: 'TypeScript Foundations',
        },
      },
    };

    mockedFindAssertionByPublicId.mockResolvedValue(sampleAssertion());
    mockedGetImmutableCredentialObject.mockResolvedValue(credential);

    const response = await app.request(
      'http://badges.newcredtrail.test/badges/40a6dc92-85ec-4cb0-8a50-afb2ae700e22',
      undefined,
      env,
    );
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(body).toContain(
      '<link rel="canonical" href="http://badges.newcredtrail.test/badges/40a6dc92-85ec-4cb0-8a50-afb2ae700e22"',
    );
    expect(body).toContain(
      'certUrl=http%3A%2F%2Fbadges.newcredtrail.test%2Fbadges%2F40a6dc92-85ec-4cb0-8a50-afb2ae700e22',
    );
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

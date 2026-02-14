import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('@credtrail/db', async () => {
  const actual = await vi.importActual<typeof import('@credtrail/db')>('@credtrail/db');

  return {
    ...actual,
    findActiveOAuthAccessTokenByHash: vi.fn(),
    findOb3SubjectProfile: vi.fn(),
    findUserById: vi.fn(),
    listOb3SubjectCredentials: vi.fn(),
    upsertOb3SubjectCredential: vi.fn(),
    upsertOb3SubjectProfile: vi.fn(),
  };
});

vi.mock('@credtrail/db/postgres', () => {
  return {
    createPostgresDatabase: vi.fn(),
  };
});

import {
  findActiveOAuthAccessTokenByHash,
  findOb3SubjectProfile,
  findUserById,
  listOb3SubjectCredentials,
  upsertOb3SubjectCredential,
  upsertOb3SubjectProfile,
  type Ob3SubjectCredentialRecord,
  type Ob3SubjectProfileRecord,
  type OAuthAccessTokenRecord,
  type SqlDatabase,
} from '@credtrail/db';
import { createPostgresDatabase } from '@credtrail/db/postgres';

import { app } from './index';

const mockedFindActiveOAuthAccessTokenByHash = vi.mocked(findActiveOAuthAccessTokenByHash);
const mockedListOb3SubjectCredentials = vi.mocked(listOb3SubjectCredentials);
const mockedUpsertOb3SubjectCredential = vi.mocked(upsertOb3SubjectCredential);
const mockedFindOb3SubjectProfile = vi.mocked(findOb3SubjectProfile);
const mockedFindUserById = vi.mocked(findUserById);
const mockedUpsertOb3SubjectProfile = vi.mocked(upsertOb3SubjectProfile);
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

beforeEach(() => {
  mockedCreatePostgresDatabase.mockReset();
  mockedCreatePostgresDatabase.mockReturnValue(fakeDb);
  mockedFindActiveOAuthAccessTokenByHash.mockReset();
  mockedListOb3SubjectCredentials.mockReset();
  mockedUpsertOb3SubjectCredential.mockReset();
  mockedFindOb3SubjectProfile.mockReset();
  mockedFindUserById.mockReset();
  mockedFindUserById.mockResolvedValue({
    id: 'usr_123',
    email: 'learner@example.edu',
  });
  mockedUpsertOb3SubjectProfile.mockReset();
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
    expect(response.headers.get('content-type')).toContain('application/json');
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

  it('supports JSON-LD credential upserts and mirrors application/ld+json responses', async () => {
    mockedFindActiveOAuthAccessTokenByHash.mockResolvedValue(
      sampleOAuthAccessTokenRecord({
        scope: 'https://purl.imsglobal.org/spec/ob/v3p0/scope/credential.upsert',
      }),
    );
    mockedUpsertOb3SubjectCredential.mockResolvedValue({
      status: 'updated',
      credential: sampleOb3SubjectCredentialRecord(),
    });

    const response = await app.request(
      '/ims/ob/v3p0/credentials',
      {
        method: 'POST',
        headers: {
          'content-type': 'application/ld+json',
          authorization: 'Bearer access-token-upsert',
        },
        body: JSON.stringify({
          id: 'urn:credtrail:credential:jsonld',
          type: ['VerifiableCredential', 'OpenBadgeCredential'],
        }),
      },
      createEnv(),
    );
    const body = await response.json<Record<string, unknown>>();

    expect(response.status).toBe(200);
    expect(response.headers.get('content-type')).toContain('application/ld+json');
    expect(body.id).toBe('urn:credtrail:credential:jsonld');
  });

  it('supports VC JSON-LD credential upserts and mirrors application/vc+ld+json responses', async () => {
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
          'content-type': 'application/vc+ld+json',
          authorization: 'Bearer access-token-upsert',
        },
        body: JSON.stringify({
          id: 'urn:credtrail:credential:vc-jsonld',
          type: ['VerifiableCredential', 'OpenBadgeCredential'],
        }),
      },
      createEnv(),
    );
    const body = await response.json<Record<string, unknown>>();

    expect(response.status).toBe(201);
    expect(response.headers.get('content-type')).toContain('application/vc+ld+json');
    expect(body.id).toBe('urn:credtrail:credential:vc-jsonld');
  });

  it('supports compact JWS credential upsert responses', async () => {
    mockedFindActiveOAuthAccessTokenByHash.mockResolvedValue(
      sampleOAuthAccessTokenRecord({
        scope: 'https://purl.imsglobal.org/spec/ob/v3p0/scope/credential.upsert',
      }),
    );
    const compactJws = compactJwsForTest({
      header: {
        alg: 'RS256',
        kid: 'https://issuer.example.edu/keys#key-1',
        typ: 'JWT',
      },
      payload: {
        iss: 'https://issuer.example.edu',
        jti: 'urn:credtrail:credential:jws',
        nbf: 1762894800,
        sub: 'mailto:learner@example.edu',
      },
    });
    mockedUpsertOb3SubjectCredential.mockResolvedValue({
      status: 'updated',
      credential: sampleOb3SubjectCredentialRecord({
        payloadJson: null,
        compactJws,
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
        body: compactJws,
      },
      createEnv(),
    );
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(response.headers.get('content-type')).toContain('text/plain');
    expect(body).toBe(compactJws);
    expect(mockedUpsertOb3SubjectCredential).toHaveBeenCalledWith(
      fakeDb,
      expect.objectContaining({
        credentialId: 'urn:credtrail:credential:jws',
      }),
    );
  });

  it('rejects compact JWS payloads that miss required VC-JWT claims', async () => {
    mockedFindActiveOAuthAccessTokenByHash.mockResolvedValue(
      sampleOAuthAccessTokenRecord({
        scope: 'https://purl.imsglobal.org/spec/ob/v3p0/scope/credential.upsert',
      }),
    );
    const compactJws = compactJwsForTest({
      header: {
        alg: 'RS256',
        kid: 'https://issuer.example.edu/keys#key-1',
        typ: 'JWT',
      },
      payload: {
        iss: 'https://issuer.example.edu',
        nbf: 1762894800,
        sub: 'mailto:learner@example.edu',
      },
    });

    const response = await app.request(
      '/ims/ob/v3p0/credentials',
      {
        method: 'POST',
        headers: {
          'content-type': 'text/plain',
          authorization: 'Bearer access-token-upsert',
        },
        body: compactJws,
      },
      createEnv(),
    );
    const body = await response.json<Record<string, unknown>>();

    expect(response.status).toBe(400);
    expect(body.imsx_description).toContain('jti');
    expect(mockedUpsertOb3SubjectCredential).not.toHaveBeenCalled();
  });

  it('rejects unsupported credential upsert content types', async () => {
    mockedFindActiveOAuthAccessTokenByHash.mockResolvedValue(
      sampleOAuthAccessTokenRecord({
        scope: 'https://purl.imsglobal.org/spec/ob/v3p0/scope/credential.upsert',
      }),
    );

    const response = await app.request(
      '/ims/ob/v3p0/credentials',
      {
        method: 'POST',
        headers: {
          'content-type': 'application/xml',
          authorization: 'Bearer access-token-upsert',
        },
        body: '<credential/>',
      },
      createEnv(),
    );
    const body = await response.json<Record<string, unknown>>();

    expect(response.status).toBe(400);
    expect(body.imsx_description).toContain('application/vc+ld+json');
    expect(mockedUpsertOb3SubjectCredential).not.toHaveBeenCalled();
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

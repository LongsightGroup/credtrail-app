import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('@credtrail/db', async () => {
  const actual = await vi.importActual<typeof import('@credtrail/db')>('@credtrail/db');

  return {
    ...actual,
    findTenantSigningRegistrationByDid: vi.fn(),
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
} from '@credtrail/core-domain';
import {
  findTenantSigningRegistrationByDid,
  type SqlDatabase,
  type TenantSigningRegistrationRecord,
} from '@credtrail/db';
import { createPostgresDatabase } from '@credtrail/db/postgres';

import { app } from './index';

const mockedFindTenantSigningRegistrationByDid = vi.mocked(findTenantSigningRegistrationByDid);
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
  mockedFindTenantSigningRegistrationByDid.mockReset();
  mockedFindTenantSigningRegistrationByDid.mockResolvedValue(null);
});

const asJsonObject = (value: unknown): JsonObject | null => {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    return null;
  }

  return value as JsonObject;
};

const asString = (value: unknown): string | null => {
  return typeof value === 'string' ? value : null;
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
    const verificationMethods = Array.isArray(body.verificationMethod)
      ? body.verificationMethod
      : [];
    const firstVerificationMethod =
      verificationMethods.length > 0 ? asJsonObject(verificationMethods[0]) : null;

    expect(response.status).toBe(200);
    expect(asString(body.id)).toBe('did:web:localhost');
    expect(asString(firstVerificationMethod?.type)).toBe('Multikey');
    expect(asString(firstVerificationMethod?.publicKeyMultibase)).toBe(
      encodeJwkPublicKeyMultibase(signingMaterial.publicJwk),
    );
    expect(firstVerificationMethod?.publicKeyJwk).toBeUndefined();
    expect(mockedFindTenantSigningRegistrationByDid).toHaveBeenCalledWith(
      fakeDb,
      'did:web:localhost',
    );
  });

  it('serves did.json with JsonWebKey2020 verificationMethod when registration public key is P-256', async () => {
    const env = createEnv();
    const signingMaterial = await generateP256SigningMaterial('key-p256');

    mockedFindTenantSigningRegistrationByDid.mockResolvedValue(
      sampleTenantSigningRegistration({
        tenantId: 'platform',
        did: 'did:web:localhost',
        keyId: 'key-p256',
        publicJwkJson: JSON.stringify(signingMaterial.publicJwk),
        privateJwkJson: JSON.stringify(signingMaterial.privateJwk),
      }),
    );

    const response = await app.request('/.well-known/did.json', undefined, env);
    const body = await response.json<JsonObject>();
    const verificationMethods = Array.isArray(body.verificationMethod)
      ? body.verificationMethod
      : [];
    const firstVerificationMethod =
      verificationMethods.length > 0 ? asJsonObject(verificationMethods[0]) : null;
    const publicKeyJwk = asJsonObject(firstVerificationMethod?.publicKeyJwk);

    expect(response.status).toBe(200);
    expect(asString(body.id)).toBe('did:web:localhost');
    expect(asString(firstVerificationMethod?.type)).toBe('JsonWebKey2020');
    expect(asString(firstVerificationMethod?.id)).toBe('did:web:localhost#key-p256');
    expect(asString(publicKeyJwk?.kty)).toBe('EC');
    expect(asString(publicKeyJwk?.crv)).toBe('P-256');
    expect(asString(publicKeyJwk?.x)).toBe(signingMaterial.publicJwk.x);
    expect(asString(publicKeyJwk?.y)).toBe(signingMaterial.publicJwk.y);
  });

  it('serves jwks.json from DB-backed signing registration', async () => {
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

    const response = await app.request('/.well-known/jwks.json', undefined, env);
    const body = await response.json<JsonObject>();
    const keys = Array.isArray(body.keys) ? body.keys : [];
    const firstKey = keys.length > 0 ? asJsonObject(keys[0]) : null;

    expect(response.status).toBe(200);
    expect(asString(firstKey?.kty)).toBe('OKP');
    expect(asString(firstKey?.crv)).toBe('Ed25519');
    expect(asString(firstKey?.kid)).toBe('key-root');
  });

  it('serves tenant-path jwks.json with P-256 key material', async () => {
    const env = createEnv();
    const signingMaterial = await generateP256SigningMaterial('key-p256');

    mockedFindTenantSigningRegistrationByDid.mockResolvedValue(
      sampleTenantSigningRegistration({
        tenantId: 'sakai',
        did: 'did:web:localhost:sakai',
        keyId: 'key-p256',
        publicJwkJson: JSON.stringify(signingMaterial.publicJwk),
        privateJwkJson: JSON.stringify(signingMaterial.privateJwk),
      }),
    );

    const response = await app.request('/sakai/jwks.json', undefined, env);
    const body = await response.json<JsonObject>();
    const keys = Array.isArray(body.keys) ? body.keys : [];
    const firstKey = keys.length > 0 ? asJsonObject(keys[0]) : null;

    expect(response.status).toBe(200);
    expect(asString(firstKey?.kty)).toBe('EC');
    expect(asString(firstKey?.crv)).toBe('P-256');
    expect(asString(firstKey?.kid)).toBe('key-p256');
    expect(asString(firstKey?.x)).toBe(signingMaterial.publicJwk.x);
    expect(asString(firstKey?.y)).toBe(signingMaterial.publicJwk.y);
    expect(mockedFindTenantSigningRegistrationByDid).toHaveBeenCalledWith(
      fakeDb,
      'did:web:localhost:sakai',
    );
  });

  it('includes historical public keys in JWKS output to preserve verification continuity after rotation', async () => {
    const activeSigningMaterial = await generateTenantDidSigningMaterial({
      did: 'did:web:localhost',
      keyId: 'key-new',
    });
    const historicalSigningMaterial = await generateTenantDidSigningMaterial({
      did: 'did:web:localhost',
      keyId: 'key-old',
    });
    const env = {
      ...createEnv(),
      TENANT_SIGNING_KEY_HISTORY_JSON: JSON.stringify({
        'did:web:localhost': [
          {
            keyId: historicalSigningMaterial.keyId,
            publicJwk: historicalSigningMaterial.publicJwk,
          },
        ],
      }),
    };

    mockedFindTenantSigningRegistrationByDid.mockResolvedValue(
      sampleTenantSigningRegistration({
        tenantId: 'platform',
        did: activeSigningMaterial.did,
        keyId: activeSigningMaterial.keyId,
        publicJwkJson: JSON.stringify(activeSigningMaterial.publicJwk),
        privateJwkJson: JSON.stringify(activeSigningMaterial.privateJwk),
      }),
    );

    const response = await app.request('/.well-known/jwks.json', undefined, env);
    const body = await response.json<JsonObject>();
    const keys = Array.isArray(body.keys) ? body.keys : [];
    const keyIds = keys
      .map((entry) => asJsonObject(entry))
      .map((entry) => asString(entry?.kid))
      .filter((entry): entry is string => entry !== null);

    expect(response.status).toBe(200);
    expect(keyIds).toContain('key-new');
    expect(keyIds).toContain('key-old');
  });
});


import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('@credtrail/db', async () => {
  const actual = await vi.importActual<typeof import('@credtrail/db')>('@credtrail/db');

  return {
    ...actual,
    createAuditLog: vi.fn(),
    upsertTenantSigningRegistration: vi.fn(),
  };
});

vi.mock('@credtrail/db/postgres', () => {
  return {
    createPostgresDatabase: vi.fn(),
  };
});

import { generateTenantDidSigningMaterial } from '@credtrail/core-domain';
import {
  createAuditLog,
  upsertTenantSigningRegistration,
  type AuditLogRecord,
  type SqlDatabase,
  type TenantSigningRegistrationRecord,
} from '@credtrail/db';
import { createPostgresDatabase } from '@credtrail/db/postgres';

import { app } from './index';

const mockedCreateAuditLog = vi.mocked(createAuditLog);
const mockedUpsertTenantSigningRegistration = vi.mocked(upsertTenantSigningRegistration);
const mockedCreatePostgresDatabase = vi.mocked(createPostgresDatabase);
const fakeDb = {
  prepare: vi.fn(),
} as unknown as SqlDatabase;

const createEnv = (): {
  APP_ENV: string;
  DATABASE_URL: string;
  BADGE_OBJECTS: R2Bucket;
  PLATFORM_DOMAIN: string;
  BOOTSTRAP_ADMIN_TOKEN?: string;
} => {
  return {
    APP_ENV: 'test',
    DATABASE_URL: 'postgres://credtrail-test.local/db',
    BADGE_OBJECTS: {} as R2Bucket,
    PLATFORM_DOMAIN: 'credtrail.test',
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

const sampleAuditLogRecord = (overrides?: Partial<AuditLogRecord>): AuditLogRecord => {
  return {
    ...overrides,
    id: 'aud_123',
    tenantId: 'sakai',
    actorUserId: null,
    action: 'tenant.signing_registration_upserted',
    targetType: 'tenant',
    targetId: 'sakai',
    metadataJson: null,
    occurredAt: '2026-02-10T22:00:00.000Z',
    createdAt: '2026-02-10T22:00:00.000Z',
  };
};

beforeEach(() => {
  mockedCreatePostgresDatabase.mockReset();
  mockedCreatePostgresDatabase.mockReturnValue(fakeDb);
});

describe('PUT /v1/admin/tenants/:tenantId/signing-registration', () => {
  beforeEach(() => {
    mockedCreateAuditLog.mockReset();
    mockedCreateAuditLog.mockResolvedValue(sampleAuditLogRecord());
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

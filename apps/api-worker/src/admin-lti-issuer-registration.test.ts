import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('@credtrail/db', async () => {
  const actual = await vi.importActual<typeof import('@credtrail/db')>('@credtrail/db');

  return {
    ...actual,
    createAuditLog: vi.fn(),
    deleteLtiIssuerRegistrationByIssuer: vi.fn(),
    listLtiIssuerRegistrations: vi.fn(),
    upsertLtiIssuerRegistration: vi.fn(),
  };
});

vi.mock('@credtrail/db/postgres', () => {
  return {
    createPostgresDatabase: vi.fn(),
  };
});

import {
  createAuditLog,
  deleteLtiIssuerRegistrationByIssuer,
  listLtiIssuerRegistrations,
  upsertLtiIssuerRegistration,
  type AuditLogRecord,
  type LtiIssuerRegistrationRecord,
  type SqlDatabase,
} from '@credtrail/db';
import { createPostgresDatabase } from '@credtrail/db/postgres';

import { app } from './index';

const mockedCreateAuditLog = vi.mocked(createAuditLog);
const mockedDeleteLtiIssuerRegistrationByIssuer = vi.mocked(deleteLtiIssuerRegistrationByIssuer);
const mockedListLtiIssuerRegistrations = vi.mocked(listLtiIssuerRegistrations);
const mockedUpsertLtiIssuerRegistration = vi.mocked(upsertLtiIssuerRegistration);
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

const sampleAuditLogRecord = (overrides?: Partial<AuditLogRecord>): AuditLogRecord => {
  return {
    ...overrides,
    id: 'audit_123',
    tenantId: 'tenant_123',
    actorUserId: 'usr_123',
    action: 'test.action',
    targetType: 'test_target',
    targetId: 'target_123',
    metadataJson: null,
    occurredAt: '2026-02-10T22:00:00.000Z',
    createdAt: '2026-02-10T22:00:00.000Z',
  };
};

const sampleLtiIssuerRegistration = (
  overrides?: Partial<LtiIssuerRegistrationRecord>,
): LtiIssuerRegistrationRecord => {
  return {
    issuer: 'https://canvas.example.edu',
    tenantId: 'tenant_123',
    authorizationEndpoint: 'https://canvas.example.edu/api/lti/authorize_redirect',
    clientId: 'canvas-client-123',
    allowUnsignedIdToken: false,
    createdAt: '2026-02-10T22:00:00.000Z',
    updatedAt: '2026-02-10T22:00:00.000Z',
    ...overrides,
  };
};

beforeEach(() => {
  mockedCreatePostgresDatabase.mockReset();
  mockedCreatePostgresDatabase.mockReturnValue(fakeDb);
});

describe('admin LTI issuer registration configuration', () => {
  beforeEach(() => {
    mockedListLtiIssuerRegistrations.mockReset();
    mockedListLtiIssuerRegistrations.mockResolvedValue([]);
    mockedUpsertLtiIssuerRegistration.mockReset();
    mockedDeleteLtiIssuerRegistrationByIssuer.mockReset();
    mockedCreateAuditLog.mockReset();
    mockedCreateAuditLog.mockResolvedValue(sampleAuditLogRecord());
  });

  it('lists LTI issuer registrations via bootstrap admin API', async () => {
    const env = {
      ...createEnv(),
      BOOTSTRAP_ADMIN_TOKEN: 'bootstrap-secret',
    };
    mockedListLtiIssuerRegistrations.mockResolvedValue([sampleLtiIssuerRegistration()]);

    const response = await app.request(
      '/v1/admin/lti/issuer-registrations',
      {
        headers: {
          authorization: 'Bearer bootstrap-secret',
        },
      },
      env,
    );
    const body = await response.json<{
      registrations: LtiIssuerRegistrationRecord[];
    }>();

    expect(response.status).toBe(200);
    expect(body.registrations[0]?.issuer).toBe('https://canvas.example.edu');
    expect(mockedListLtiIssuerRegistrations).toHaveBeenCalledWith(fakeDb);
  });

  it('upserts LTI issuer registrations via bootstrap admin API', async () => {
    const env = {
      ...createEnv(),
      BOOTSTRAP_ADMIN_TOKEN: 'bootstrap-secret',
    };
    mockedUpsertLtiIssuerRegistration.mockResolvedValue(
      sampleLtiIssuerRegistration({
        allowUnsignedIdToken: true,
      }),
    );

    const response = await app.request(
      '/v1/admin/lti/issuer-registrations',
      {
        method: 'PUT',
        headers: {
          'content-type': 'application/json',
          authorization: 'Bearer bootstrap-secret',
        },
        body: JSON.stringify({
          issuer: 'https://canvas.example.edu',
          tenantId: 'tenant_123',
          authorizationEndpoint: 'https://canvas.example.edu/api/lti/authorize_redirect',
          clientId: 'canvas-client-123',
          allowUnsignedIdToken: true,
        }),
      },
      env,
    );
    const body = await response.json<{
      registration: LtiIssuerRegistrationRecord;
    }>();

    expect(response.status).toBe(201);
    expect(body.registration.allowUnsignedIdToken).toBe(true);
    expect(mockedUpsertLtiIssuerRegistration).toHaveBeenCalledWith(fakeDb, {
      issuer: 'https://canvas.example.edu',
      tenantId: 'tenant_123',
      authorizationEndpoint: 'https://canvas.example.edu/api/lti/authorize_redirect',
      clientId: 'canvas-client-123',
      allowUnsignedIdToken: true,
    });
  });

  it('renders manual LTI registration UI and accepts form upserts', async () => {
    const env = {
      ...createEnv(),
      BOOTSTRAP_ADMIN_TOKEN: 'bootstrap-secret',
    };
    mockedUpsertLtiIssuerRegistration.mockResolvedValue(sampleLtiIssuerRegistration());

    const pageResponse = await app.request(
      '/admin/lti/issuer-registrations?token=bootstrap-secret',
      undefined,
      env,
    );
    const pageBody = await pageResponse.text();

    expect(pageResponse.status).toBe(200);
    expect(pageBody).toContain('Manual LTI issuer registration configuration');

    const postResponse = await app.request(
      '/admin/lti/issuer-registrations',
      {
        method: 'POST',
        headers: {
          'content-type': 'application/x-www-form-urlencoded',
        },
        body: new URLSearchParams({
          token: 'bootstrap-secret',
          issuer: 'https://canvas.example.edu',
          tenantId: 'tenant_123',
          authorizationEndpoint: 'https://canvas.example.edu/api/lti/authorize_redirect',
          clientId: 'canvas-client-123',
          allowUnsignedIdToken: 'on',
        }).toString(),
      },
      env,
    );

    expect(postResponse.status).toBe(303);
    expect(postResponse.headers.get('location')).toBe(
      '/admin/lti/issuer-registrations?token=bootstrap-secret',
    );
    expect(mockedUpsertLtiIssuerRegistration).toHaveBeenCalledWith(fakeDb, {
      issuer: 'https://canvas.example.edu',
      tenantId: 'tenant_123',
      authorizationEndpoint: 'https://canvas.example.edu/api/lti/authorize_redirect',
      clientId: 'canvas-client-123',
      allowUnsignedIdToken: true,
    });
  });

  it('deletes LTI issuer registrations via admin UI form', async () => {
    const env = {
      ...createEnv(),
      BOOTSTRAP_ADMIN_TOKEN: 'bootstrap-secret',
    };
    mockedListLtiIssuerRegistrations.mockResolvedValue([sampleLtiIssuerRegistration()]);
    mockedDeleteLtiIssuerRegistrationByIssuer.mockResolvedValue(true);

    const response = await app.request(
      '/admin/lti/issuer-registrations/delete',
      {
        method: 'POST',
        headers: {
          'content-type': 'application/x-www-form-urlencoded',
        },
        body: new URLSearchParams({
          token: 'bootstrap-secret',
          issuer: 'https://canvas.example.edu',
        }).toString(),
      },
      env,
    );

    expect(response.status).toBe(303);
    expect(mockedDeleteLtiIssuerRegistrationByIssuer).toHaveBeenCalledWith(
      fakeDb,
      'https://canvas.example.edu',
    );
  });
});

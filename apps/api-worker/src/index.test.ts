import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('@credtrail/db', async () => {
  const actual = await vi.importActual<typeof import('@credtrail/db')>('@credtrail/db');

  return {
    ...actual,
    createAuditLog: vi.fn(),
    upsertBadgeTemplateById: vi.fn(),
    upsertTenant: vi.fn(),
  };
});

vi.mock('@credtrail/db/postgres', () => {
  return {
    createPostgresDatabase: vi.fn(),
  };
});

import {
  type AuditLogRecord,
  type BadgeTemplateRecord,
  type SqlDatabase,
  type TenantRecord,
  createAuditLog,
  upsertBadgeTemplateById,
  upsertTenant,
} from '@credtrail/db';
import { createPostgresDatabase } from '@credtrail/db/postgres';

import { app } from './index';

interface ErrorResponse {
  error: string;
}

const mockedUpsertTenant = vi.mocked(upsertTenant);
const mockedUpsertBadgeTemplateById = vi.mocked(upsertBadgeTemplateById);
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

const sampleAuditLogRecord = (overrides?: Partial<AuditLogRecord>): AuditLogRecord => {
  return {
    id: 'aud_123',
    tenantId: 'sakai',
    actorUserId: null,
    action: 'tenant.updated',
    targetType: 'tenant',
    targetId: 'sakai',
    metadataJson: null,
    occurredAt: '2026-02-10T22:00:00.000Z',
    createdAt: '2026-02-10T22:00:00.000Z',
    ...overrides,
  };
};

beforeEach(() => {
  mockedCreatePostgresDatabase.mockReset();
  mockedCreatePostgresDatabase.mockReturnValue(fakeDb);
  mockedCreateAuditLog.mockReset();
  mockedCreateAuditLog.mockResolvedValue(sampleAuditLogRecord());
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
    expect(mockedUpsertBadgeTemplateById).toHaveBeenCalledWith(
      fakeDb,
      expect.objectContaining({
        id: 'badge_template_sakai_1000',
        tenantId: 'sakai',
        slug: 'sakai-1000-commits-contributor',
        title: 'Sakai 1000+ Commits Contributor',
        description: 'Awarded for contributing 1000+ commits to Sakai.',
        criteriaUri: 'https://github.com/sakaiproject/sakai',
        imageUri: 'https://avatars.githubusercontent.com/u/429529?s=200&v=4',
      }),
    );
  });
});

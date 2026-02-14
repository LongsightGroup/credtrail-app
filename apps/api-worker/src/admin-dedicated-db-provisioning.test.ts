import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('@credtrail/db', async () => {
  const actual = await vi.importActual<typeof import('@credtrail/db')>('@credtrail/db');

  return {
    ...actual,
    createAuditLog: vi.fn(),
    createDedicatedDbProvisioningRequest: vi.fn(),
    listDedicatedDbProvisioningRequests: vi.fn(),
    resolveDedicatedDbProvisioningRequest: vi.fn(),
  };
});

vi.mock('@credtrail/db/postgres', () => {
  return {
    createPostgresDatabase: vi.fn(),
  };
});

import {
  createAuditLog,
  createDedicatedDbProvisioningRequest,
  listDedicatedDbProvisioningRequests,
  resolveDedicatedDbProvisioningRequest,
  type AuditLogRecord,
  type DedicatedDbProvisioningRequestRecord,
  type SqlDatabase,
} from '@credtrail/db';
import { createPostgresDatabase } from '@credtrail/db/postgres';

import { app } from './index';

const mockedCreateAuditLog = vi.mocked(createAuditLog);
const mockedCreateDedicatedDbProvisioningRequest = vi.mocked(createDedicatedDbProvisioningRequest);
const mockedListDedicatedDbProvisioningRequests = vi.mocked(listDedicatedDbProvisioningRequests);
const mockedResolveDedicatedDbProvisioningRequest = vi.mocked(resolveDedicatedDbProvisioningRequest);
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
    id: 'audit_123',
    tenantId: 'tenant_123',
    actorUserId: null,
    action: 'tenant.dedicated_db_provisioning_requested',
    targetType: 'tenant_dedicated_db_provisioning_request',
    targetId: 'dpr_123',
    metadataJson: null,
    occurredAt: '2026-02-14T22:00:00.000Z',
    createdAt: '2026-02-14T22:00:00.000Z',
    ...overrides,
  };
};

const sampleProvisioningRequest = (
  overrides?: Partial<DedicatedDbProvisioningRequestRecord>,
): DedicatedDbProvisioningRequestRecord => {
  return {
    id: 'dpr_123',
    tenantId: 'tenant_123',
    requestedByUserId: null,
    targetRegion: 'us-east-1',
    status: 'pending',
    dedicatedDatabaseUrl: null,
    notes: 'Enterprise migration window approved',
    requestedAt: '2026-02-14T22:00:00.000Z',
    resolvedAt: null,
    createdAt: '2026-02-14T22:00:00.000Z',
    updatedAt: '2026-02-14T22:00:00.000Z',
    ...overrides,
  };
};

beforeEach(() => {
  mockedCreatePostgresDatabase.mockReset();
  mockedCreatePostgresDatabase.mockReturnValue(fakeDb);

  mockedCreateAuditLog.mockReset();
  mockedCreateAuditLog.mockResolvedValue(sampleAuditLogRecord());

  mockedCreateDedicatedDbProvisioningRequest.mockReset();
  mockedCreateDedicatedDbProvisioningRequest.mockResolvedValue(sampleProvisioningRequest());

  mockedListDedicatedDbProvisioningRequests.mockReset();
  mockedListDedicatedDbProvisioningRequests.mockResolvedValue([]);

  mockedResolveDedicatedDbProvisioningRequest.mockReset();
  mockedResolveDedicatedDbProvisioningRequest.mockResolvedValue(
    sampleProvisioningRequest({
      status: 'provisioned',
      dedicatedDatabaseUrl: 'postgres://dedicated.example.edu/tenant_123',
      resolvedAt: '2026-02-15T00:00:00.000Z',
    }),
  );
});

describe('admin dedicated DB provisioning routes', () => {
  it('lists dedicated DB provisioning requests', async () => {
    const env = {
      ...createEnv(),
      BOOTSTRAP_ADMIN_TOKEN: 'bootstrap-secret',
    };
    mockedListDedicatedDbProvisioningRequests.mockResolvedValue([sampleProvisioningRequest()]);

    const response = await app.request(
      '/v1/admin/tenants/tenant_123/dedicated-db/provisioning-requests?status=pending',
      {
        headers: {
          authorization: 'Bearer bootstrap-secret',
        },
      },
      env,
    );
    const body = await response.json<{ requests: DedicatedDbProvisioningRequestRecord[] }>();

    expect(response.status).toBe(200);
    expect(body.requests).toHaveLength(1);
    expect(mockedListDedicatedDbProvisioningRequests).toHaveBeenCalledWith(fakeDb, {
      tenantId: 'tenant_123',
      status: 'pending',
    });
  });

  it('creates dedicated DB provisioning requests', async () => {
    const env = {
      ...createEnv(),
      BOOTSTRAP_ADMIN_TOKEN: 'bootstrap-secret',
    };

    const response = await app.request(
      '/v1/admin/tenants/tenant_123/dedicated-db/provisioning-requests',
      {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          authorization: 'Bearer bootstrap-secret',
        },
        body: JSON.stringify({
          targetRegion: 'us-east-1',
          notes: 'Enterprise migration window approved',
        }),
      },
      env,
    );

    expect(response.status).toBe(201);
    expect(mockedCreateDedicatedDbProvisioningRequest).toHaveBeenCalledWith(fakeDb, {
      tenantId: 'tenant_123',
      targetRegion: 'us-east-1',
      notes: 'Enterprise migration window approved',
    });
  });

  it('resolves dedicated DB provisioning requests', async () => {
    const env = {
      ...createEnv(),
      BOOTSTRAP_ADMIN_TOKEN: 'bootstrap-secret',
    };

    const response = await app.request(
      '/v1/admin/tenants/tenant_123/dedicated-db/provisioning-requests/dpr_123/resolve',
      {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          authorization: 'Bearer bootstrap-secret',
        },
        body: JSON.stringify({
          status: 'provisioned',
          dedicatedDatabaseUrl: 'postgres://dedicated.example.edu/tenant_123',
          notes: 'Provisioned and smoke tested',
          resolvedAt: '2026-02-15T00:00:00.000Z',
        }),
      },
      env,
    );

    expect(response.status).toBe(200);
    expect(mockedResolveDedicatedDbProvisioningRequest).toHaveBeenCalledWith(fakeDb, {
      tenantId: 'tenant_123',
      requestId: 'dpr_123',
      status: 'provisioned',
      dedicatedDatabaseUrl: 'postgres://dedicated.example.edu/tenant_123',
      notes: 'Provisioned and smoke tested',
      resolvedAt: '2026-02-15T00:00:00.000Z',
    });
  });
});

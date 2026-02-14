import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('@credtrail/db', async () => {
  const actual = await vi.importActual<typeof import('@credtrail/db')>('@credtrail/db');

  return {
    ...actual,
    createAuditLog: vi.fn(),
    upsertTenantMembershipRole: vi.fn(),
  };
});

vi.mock('@credtrail/db/postgres', () => {
  return {
    createPostgresDatabase: vi.fn(),
  };
});

import {
  createAuditLog,
  upsertTenantMembershipRole,
  type AuditLogRecord,
  type SqlDatabase,
  type TenantMembershipRecord,
} from '@credtrail/db';
import { createPostgresDatabase } from '@credtrail/db/postgres';

import { app } from './index';

const mockedCreateAuditLog = vi.mocked(createAuditLog);
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

beforeEach(() => {
  mockedCreatePostgresDatabase.mockReset();
  mockedCreatePostgresDatabase.mockReturnValue(fakeDb);
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

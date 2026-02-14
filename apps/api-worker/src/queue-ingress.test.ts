import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('@credtrail/db', async () => {
  const actual = await vi.importActual<typeof import('@credtrail/db')>('@credtrail/db');

  return {
    ...actual,
    enqueueJobQueueMessage: vi.fn(),
    findActiveTenantApiKeyByHash: vi.fn(),
    findUserById: vi.fn(),
    touchTenantApiKeyLastUsedAt: vi.fn(),
  };
});

vi.mock('@credtrail/db/postgres', () => {
  return {
    createPostgresDatabase: vi.fn(),
  };
});

import {
  enqueueJobQueueMessage,
  findActiveTenantApiKeyByHash,
  touchTenantApiKeyLastUsedAt,
  type SqlDatabase,
  type TenantApiKeyRecord,
} from '@credtrail/db';
import { createPostgresDatabase } from '@credtrail/db/postgres';

import { app } from './index';

const mockedEnqueueJobQueueMessage = vi.mocked(enqueueJobQueueMessage);
const mockedFindActiveTenantApiKeyByHash = vi.mocked(findActiveTenantApiKeyByHash);
const mockedTouchTenantApiKeyLastUsedAt = vi.mocked(touchTenantApiKeyLastUsedAt);
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

beforeEach(() => {
  mockedCreatePostgresDatabase.mockReset();
  mockedCreatePostgresDatabase.mockReturnValue(fakeDb);
  mockedEnqueueJobQueueMessage.mockReset();
  mockedFindActiveTenantApiKeyByHash.mockReset();
  mockedFindActiveTenantApiKeyByHash.mockResolvedValue(null);
  mockedTouchTenantApiKeyLastUsedAt.mockReset();
});

describe('POST /v1/issue and /v1/revoke', () => {
  it('stores issue requests as DB-backed queue messages', async () => {
    const env = createEnv();

    const response = await app.request(
      '/v1/issue',
      {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
        },
        body: JSON.stringify({
          tenantId: 'tenant_123',
          badgeTemplateId: 'badge_template_001',
          recipientIdentity: 'learner@example.edu',
          recipientIdentityType: 'email',
          recipientIdentifiers: [
            {
              identifierType: 'studentId',
              identifier: 'student-123',
            },
          ],
          requestedByUserId: 'usr_issuer',
        }),
      },
      env,
    );
    const body = await response.json<Record<string, unknown>>();

    expect(response.status).toBe(202);
    expect(body.status).toBe('queued');
    expect(body.jobType).toBe('issue_badge');
    expect(typeof body.assertionId).toBe('string');
    expect(mockedEnqueueJobQueueMessage).toHaveBeenCalledTimes(1);
    expect(mockedEnqueueJobQueueMessage).toHaveBeenCalledWith(
      fakeDb,
      expect.objectContaining({
        tenantId: 'tenant_123',
        jobType: 'issue_badge',
      }),
    );
    expect(mockedEnqueueJobQueueMessage.mock.calls[0]?.[1]).toMatchObject({
      payload: {
        recipientIdentifiers: [
          {
            identifierType: 'studentId',
            identifier: 'student-123',
          },
        ],
      },
    });
  });

  it('stores revoke requests as DB-backed queue messages', async () => {
    const env = createEnv();

    const response = await app.request(
      '/v1/revoke',
      {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
        },
        body: JSON.stringify({
          tenantId: 'tenant_123',
          assertionId: 'tenant_123:assertion_456',
          reason: 'Requested by issuer',
          requestedByUserId: 'usr_issuer',
        }),
      },
      env,
    );
    const body = await response.json<Record<string, unknown>>();

    expect(response.status).toBe(202);
    expect(body.status).toBe('queued');
    expect(body.jobType).toBe('revoke_badge');
    expect(typeof body.revocationId).toBe('string');
    expect(mockedEnqueueJobQueueMessage).toHaveBeenCalledTimes(1);
    expect(mockedEnqueueJobQueueMessage).toHaveBeenCalledWith(
      fakeDb,
      expect.objectContaining({
        tenantId: 'tenant_123',
        jobType: 'revoke_badge',
      }),
    );
  });
});

describe('POST /v1/programmatic/issue and /v1/programmatic/revoke', () => {
  const sampleTenantApiKeyRecord = (
    overrides?: Partial<TenantApiKeyRecord>,
  ): TenantApiKeyRecord => {
    return {
      id: 'tak_123',
      tenantId: 'tenant_123',
      label: 'Integration key',
      keyPrefix: 'ctak_abc12345',
      keyHash: 'hash_123',
      scopesJson: '["queue.issue","queue.revoke"]',
      createdByUserId: 'usr_admin',
      expiresAt: null,
      lastUsedAt: null,
      revokedAt: null,
      createdAt: '2026-02-14T15:00:00.000Z',
      updatedAt: '2026-02-14T15:00:00.000Z',
      ...overrides,
    };
  };

  it('queues issue requests with valid API key scope', async () => {
    const env = createEnv();
    mockedFindActiveTenantApiKeyByHash.mockResolvedValue(sampleTenantApiKeyRecord());

    const response = await app.request(
      '/v1/programmatic/issue',
      {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          'x-api-key': 'ctak_example_secret',
        },
        body: JSON.stringify({
          tenantId: 'tenant_123',
          badgeTemplateId: 'badge_template_001',
          recipientIdentity: 'learner@example.edu',
          recipientIdentityType: 'email',
        }),
      },
      env,
    );
    const body = await response.json<Record<string, unknown>>();

    expect(response.status).toBe(202);
    expect(body.channel).toBe('programmatic_api_key');
    expect(mockedEnqueueJobQueueMessage).toHaveBeenCalledTimes(1);
    expect(mockedTouchTenantApiKeyLastUsedAt).toHaveBeenCalledTimes(1);
  });

  it('rejects programmatic requests when API key is missing', async () => {
    const env = createEnv();

    const response = await app.request(
      '/v1/programmatic/revoke',
      {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
        },
        body: JSON.stringify({
          tenantId: 'tenant_123',
          assertionId: 'tenant_123:assertion_456',
          reason: 'Requested by issuer',
        }),
      },
      env,
    );
    const body = await response.json<Record<string, unknown>>();

    expect(response.status).toBe(401);
    expect(body.error).toContain('x-api-key');
    expect(mockedEnqueueJobQueueMessage).not.toHaveBeenCalled();
  });
});

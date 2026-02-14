import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('@credtrail/db', async () => {
  const actual = await vi.importActual<typeof import('@credtrail/db')>('@credtrail/db');

  return {
    ...actual,
    enqueueJobQueueMessage: vi.fn(),
    findUserById: vi.fn(),
  };
});

vi.mock('@credtrail/db/postgres', () => {
  return {
    createPostgresDatabase: vi.fn(),
  };
});

import { enqueueJobQueueMessage, type SqlDatabase } from '@credtrail/db';
import { createPostgresDatabase } from '@credtrail/db/postgres';

import { app } from './index';

const mockedEnqueueJobQueueMessage = vi.mocked(enqueueJobQueueMessage);
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

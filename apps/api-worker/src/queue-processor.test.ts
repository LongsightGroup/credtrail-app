import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('@credtrail/db', async () => {
  const actual = await vi.importActual<typeof import('@credtrail/db')>('@credtrail/db');

  return {
    ...actual,
    completeJobQueueMessage: vi.fn(),
    createAuditLog: vi.fn(),
    failJobQueueMessage: vi.fn(),
    leaseJobQueueMessages: vi.fn(),
    recordAssertionRevocation: vi.fn(),
  };
});

vi.mock('@credtrail/db/postgres', () => {
  return {
    createPostgresDatabase: vi.fn(),
  };
});

import {
  completeJobQueueMessage,
  createAuditLog,
  failJobQueueMessage,
  leaseJobQueueMessages,
  recordAssertionRevocation,
  type AuditLogRecord,
  type JobQueueMessageRecord,
  type SqlDatabase,
} from '@credtrail/db';
import { createPostgresDatabase } from '@credtrail/db/postgres';

import { app } from './index';

interface ErrorResponse {
  error: string;
}

const mockedCompleteJobQueueMessage = vi.mocked(completeJobQueueMessage);
const mockedCreateAuditLog = vi.mocked(createAuditLog);
const mockedFailJobQueueMessage = vi.mocked(failJobQueueMessage);
const mockedLeaseJobQueueMessages = vi.mocked(leaseJobQueueMessages);
const mockedRecordAssertionRevocation = vi.mocked(recordAssertionRevocation);
const mockedCreatePostgresDatabase = vi.mocked(createPostgresDatabase);
const fakeDb = {
  prepare: vi.fn(),
} as unknown as SqlDatabase;

const createEnv = (): {
  APP_ENV: string;
  DATABASE_URL: string;
  BADGE_OBJECTS: R2Bucket;
  PLATFORM_DOMAIN: string;
  JOB_PROCESSOR_TOKEN?: string;
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

const sampleLeasedQueueMessage = (
  overrides?: Partial<JobQueueMessageRecord>,
): JobQueueMessageRecord => {
  return {
    id: 'job_123',
    tenantId: 'tenant_123',
    jobType: 'rebuild_verification_cache',
    payloadJson: '{}',
    idempotencyKey: 'idem_job_123',
    attemptCount: 1,
    maxAttempts: 8,
    availableAt: '2026-02-10T22:00:00.000Z',
    leasedUntil: '2026-02-10T22:00:30.000Z',
    leaseToken: 'lease_123',
    lastError: null,
    completedAt: null,
    failedAt: null,
    status: 'processing',
    createdAt: '2026-02-10T22:00:00.000Z',
    updatedAt: '2026-02-10T22:00:00.000Z',
    ...overrides,
  };
};

beforeEach(() => {
  mockedCreatePostgresDatabase.mockReset();
  mockedCreatePostgresDatabase.mockReturnValue(fakeDb);
});

describe('POST /v1/jobs/process', () => {
  beforeEach(() => {
    mockedLeaseJobQueueMessages.mockReset();
    mockedCompleteJobQueueMessage.mockReset();
    mockedFailJobQueueMessage.mockReset();
    mockedRecordAssertionRevocation.mockReset();
    mockedCreateAuditLog.mockReset();
    mockedCreateAuditLog.mockResolvedValue(sampleAuditLogRecord());
  });

  it('processes leased jobs and marks them completed', async () => {
    const env = createEnv();

    mockedLeaseJobQueueMessages.mockResolvedValue([sampleLeasedQueueMessage()]);

    const response = await app.request(
      '/v1/jobs/process',
      {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
        },
        body: JSON.stringify({}),
      },
      env,
    );
    const body = await response.json<Record<string, unknown>>();

    expect(response.status).toBe(200);
    expect(body.status).toBe('ok');
    expect(body.leased).toBe(1);
    expect(body.succeeded).toBe(1);
    expect(mockedCompleteJobQueueMessage).toHaveBeenCalledTimes(1);
    expect(mockedFailJobQueueMessage).not.toHaveBeenCalled();
  });

  it('requires bearer auth when JOB_PROCESSOR_TOKEN is configured', async () => {
    const env = {
      ...createEnv(),
      JOB_PROCESSOR_TOKEN: 'processor-secret',
    };

    const response = await app.request(
      '/v1/jobs/process',
      {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
        },
        body: JSON.stringify({}),
      },
      env,
    );
    const body = await response.json<ErrorResponse>();

    expect(response.status).toBe(401);
    expect(body.error).toBe('Unauthorized');
    expect(mockedLeaseJobQueueMessages).not.toHaveBeenCalled();
  });

  it('requeues failed jobs when fail handler marks pending', async () => {
    const env = createEnv();

    mockedLeaseJobQueueMessages.mockResolvedValue([
      sampleLeasedQueueMessage({
        jobType: 'issue_badge',
        payloadJson: '{"invalid-json"',
      }),
    ]);
    mockedFailJobQueueMessage.mockResolvedValue('pending');

    const response = await app.request(
      '/v1/jobs/process',
      {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
        },
        body: JSON.stringify({}),
      },
      env,
    );
    const body = await response.json<Record<string, unknown>>();

    expect(response.status).toBe(200);
    expect(body.retried).toBe(1);
    expect(body.deadLettered).toBe(0);
    expect(mockedCompleteJobQueueMessage).not.toHaveBeenCalled();
  });

  it('writes audit logs for processed revoke jobs', async () => {
    const env = createEnv();

    mockedLeaseJobQueueMessages.mockResolvedValue([
      sampleLeasedQueueMessage({
        jobType: 'revoke_badge',
        tenantId: 'tenant_123',
        payloadJson: JSON.stringify({
          revocationId: 'rev_123',
          assertionId: 'tenant_123:assertion_456',
          reason: 'Policy violation',
          requestedAt: '2026-02-10T22:00:00.000Z',
          requestedByUserId: 'usr_123',
        }),
      }),
    ]);
    mockedRecordAssertionRevocation.mockResolvedValue({
      status: 'revoked',
      revokedAt: '2026-02-10T22:01:00.000Z',
    });

    const response = await app.request(
      '/v1/jobs/process',
      {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
        },
        body: JSON.stringify({}),
      },
      env,
    );

    expect(response.status).toBe(200);
    expect(mockedRecordAssertionRevocation).toHaveBeenCalledTimes(1);
    expect(mockedCreateAuditLog).toHaveBeenCalledWith(
      fakeDb,
      expect.objectContaining({
        tenantId: 'tenant_123',
        actorUserId: 'usr_123',
        action: 'assertion.revoked',
        targetType: 'assertion',
        targetId: 'tenant_123:assertion_456',
      }),
    );
  });
});

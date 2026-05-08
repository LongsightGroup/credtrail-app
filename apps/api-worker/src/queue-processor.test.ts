import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("@credtrail/db", async () => {
  const actual = await vi.importActual<typeof import("@credtrail/db")>("@credtrail/db");

  return {
    ...actual,
    completeJobQueueMessage: vi.fn(),
    createLearnerRecordEntry: vi.fn(),
    createLearnerRecordImportContext: vi.fn(),
    createAuditLog: vi.fn(),
    failJobQueueMessage: vi.fn(),
    leaseJobQueueMessages: vi.fn(),
    recordAssertionRevocation: vi.fn(),
    resolveLearnerProfileForIdentity: vi.fn(),
  };
});

vi.mock("@credtrail/db/postgres", () => {
  return {
    createPostgresDatabase: vi.fn(),
  };
});

import {
  completeJobQueueMessage,
  createLearnerRecordEntry,
  createLearnerRecordImportContext,
  createAuditLog,
  failJobQueueMessage,
  leaseJobQueueMessages,
  recordAssertionRevocation,
  resolveLearnerProfileForIdentity,
  type AuditLogRecord,
  type JobQueueMessageRecord,
  type LearnerProfileRecord,
  type SqlDatabase,
} from "@credtrail/db";
import { createPostgresDatabase } from "@credtrail/db/postgres";

import { app } from "./index";

interface ErrorResponse {
  error: string;
}

const mockedCompleteJobQueueMessage = vi.mocked(completeJobQueueMessage);
const mockedCreateLearnerRecordEntry = vi.mocked(createLearnerRecordEntry);
const mockedCreateLearnerRecordImportContext = vi.mocked(createLearnerRecordImportContext);
const mockedCreateAuditLog = vi.mocked(createAuditLog);
const mockedFailJobQueueMessage = vi.mocked(failJobQueueMessage);
const mockedLeaseJobQueueMessages = vi.mocked(leaseJobQueueMessages);
const mockedRecordAssertionRevocation = vi.mocked(recordAssertionRevocation);
const mockedResolveLearnerProfileForIdentity = vi.mocked(resolveLearnerProfileForIdentity);
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
    APP_ENV: "test",
    DATABASE_URL: "postgres://credtrail-test.local/db",
    BADGE_OBJECTS: {} as R2Bucket,
    PLATFORM_DOMAIN: "credtrail.test",
  };
};

const sampleAuditLogRecord = (overrides?: Partial<AuditLogRecord>): AuditLogRecord => {
  return {
    ...overrides,
    id: "audit_123",
    tenantId: "tenant_123",
    actorUserId: "usr_123",
    action: "test.action",
    targetType: "test_target",
    targetId: "target_123",
    metadataJson: null,
    occurredAt: "2026-02-10T22:00:00.000Z",
    createdAt: "2026-02-10T22:00:00.000Z",
  };
};

const sampleLearnerProfile = (overrides?: Partial<LearnerProfileRecord>): LearnerProfileRecord => {
  return {
    id: "lpr_123",
    tenantId: "tenant_123",
    subjectId: "did:key:z6Mkexample",
    displayName: "Learner Example",
    createdAt: "2026-02-10T22:00:00.000Z",
    updatedAt: "2026-02-10T22:00:00.000Z",
    ...overrides,
  };
};

const sampleLeasedQueueMessage = (
  overrides?: Partial<JobQueueMessageRecord>,
): JobQueueMessageRecord => {
  return {
    id: "job_123",
    tenantId: "tenant_123",
    jobType: "rebuild_verification_cache",
    payloadJson: "{}",
    idempotencyKey: "idem_job_123",
    attemptCount: 1,
    maxAttempts: 8,
    availableAt: "2026-02-10T22:00:00.000Z",
    leasedUntil: "2026-02-10T22:00:30.000Z",
    leaseToken: "lease_123",
    lastError: null,
    completedAt: null,
    failedAt: null,
    status: "processing",
    createdAt: "2026-02-10T22:00:00.000Z",
    updatedAt: "2026-02-10T22:00:00.000Z",
    ...overrides,
  };
};

beforeEach(() => {
  mockedCreatePostgresDatabase.mockReset();
  mockedCreatePostgresDatabase.mockReturnValue(fakeDb);
});

describe("POST /v1/jobs/process", () => {
  beforeEach(() => {
    mockedLeaseJobQueueMessages.mockReset();
    mockedCompleteJobQueueMessage.mockReset();
    mockedCreateLearnerRecordEntry.mockReset();
    mockedCreateLearnerRecordImportContext.mockReset();
    mockedFailJobQueueMessage.mockReset();
    mockedRecordAssertionRevocation.mockReset();
    mockedResolveLearnerProfileForIdentity.mockReset();
    mockedCreateAuditLog.mockReset();
    mockedCreateAuditLog.mockResolvedValue(sampleAuditLogRecord());
    mockedResolveLearnerProfileForIdentity.mockResolvedValue(sampleLearnerProfile());
    mockedCreateLearnerRecordEntry.mockResolvedValue({
      id: "lre_123",
      tenantId: "tenant_123",
      learnerProfileId: "lpr_123",
      trustLevel: "issuer_verified",
      recordType: "course",
      status: "active",
      title: "Clinical Placement Seminar",
      description: null,
      issuerName: "CredTrail University",
      issuerUserId: "usr_issuer",
      sourceSystem: "csv_import",
      sourceRecordId: null,
      issuedAt: "2026-02-10T22:00:00.000Z",
      revisedAt: null,
      revokedAt: null,
      evidenceLinksJson: "[]",
      detailsJson: null,
      createdAt: "2026-02-10T22:00:00.000Z",
      updatedAt: "2026-02-10T22:00:00.000Z",
    });
    mockedCreateLearnerRecordImportContext.mockResolvedValue({
      entryId: "lre_123",
      tenantId: "tenant_123",
      orgUnitId: "tenant_123:org:department-health",
      badgeTemplateId: "badge_template_001",
      pathwayLabel: null,
      inferredFromJson: '["row","badge_template"]',
      createdAt: "2026-02-10T22:00:00.000Z",
      updatedAt: "2026-02-10T22:00:00.000Z",
    });
  });

  it("processes leased jobs and marks them completed", async () => {
    const env = createEnv();

    mockedLeaseJobQueueMessages.mockResolvedValue([sampleLeasedQueueMessage()]);

    const response = await app.request(
      "/v1/jobs/process",
      {
        method: "POST",
        headers: {
          "content-type": "application/json",
        },
        body: JSON.stringify({}),
      },
      env,
    );
    const body = await response.json<Record<string, unknown>>();

    expect(response.status).toBe(200);
    expect(body.status).toBe("ok");
    expect(body.leased).toBe(1);
    expect(body.succeeded).toBe(1);
    expect(mockedCompleteJobQueueMessage).toHaveBeenCalledTimes(1);
    expect(mockedFailJobQueueMessage).not.toHaveBeenCalled();
  });

  it("requires bearer auth when JOB_PROCESSOR_TOKEN is configured", async () => {
    const env = {
      ...createEnv(),
      JOB_PROCESSOR_TOKEN: "processor-secret",
    };

    const response = await app.request(
      "/v1/jobs/process",
      {
        method: "POST",
        headers: {
          "content-type": "application/json",
        },
        body: JSON.stringify({}),
      },
      env,
    );
    const body = await response.json<ErrorResponse>();

    expect(response.status).toBe(401);
    expect(body.error).toBe("Unauthorized");
    expect(mockedLeaseJobQueueMessages).not.toHaveBeenCalled();
  });

  it("requeues failed jobs when fail handler marks pending", async () => {
    const env = createEnv();

    mockedLeaseJobQueueMessages.mockResolvedValue([
      sampleLeasedQueueMessage({
        jobType: "issue_badge",
        payloadJson: '{"invalid-json"',
      }),
    ]);
    mockedFailJobQueueMessage.mockResolvedValue("pending");

    const response = await app.request(
      "/v1/jobs/process",
      {
        method: "POST",
        headers: {
          "content-type": "application/json",
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

  it("writes audit logs for processed revoke jobs", async () => {
    const env = createEnv();

    mockedLeaseJobQueueMessages.mockResolvedValue([
      sampleLeasedQueueMessage({
        jobType: "revoke_badge",
        tenantId: "tenant_123",
        payloadJson: JSON.stringify({
          revocationId: "rev_123",
          assertionId: "tenant_123:assertion_456",
          reason: "Policy violation",
          requestedAt: "2026-02-10T22:00:00.000Z",
          requestedByUserId: "usr_123",
        }),
      }),
    ]);
    mockedRecordAssertionRevocation.mockResolvedValue({
      status: "revoked",
      revokedAt: "2026-02-10T22:01:00.000Z",
    });

    const response = await app.request(
      "/v1/jobs/process",
      {
        method: "POST",
        headers: {
          "content-type": "application/json",
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
        tenantId: "tenant_123",
        actorUserId: "usr_123",
        action: "assertion.revoked",
        targetType: "assertion",
        targetId: "tenant_123:assertion_456",
      }),
    );
  });

  it("applies learner-record import jobs through the shared import seam", async () => {
    const env = createEnv();

    mockedLeaseJobQueueMessages.mockResolvedValue([
      sampleLeasedQueueMessage({
        id: "job_lr_123",
        jobType: "import_learner_record_batch",
        payloadJson: JSON.stringify({
          batchId: "batch_123",
          rowNumber: 1,
          fileName: "learner-records.csv",
          format: "csv",
          requestedAt: "2026-02-10T22:00:00.000Z",
          requestedByUserId: "usr_issuer",
          row: {
            learnerEmail: "learner@example.edu",
            learnerDisplayName: "Learner Example",
            title: "Clinical Placement Seminar",
            recordType: "course",
            issuedAt: "2026-02-10T22:00:00.000Z",
            description: null,
            sourceRecordId: null,
            evidenceLinks: [],
            effectiveTrustLevel: "issuer_verified",
            effectiveIssuerName: "CredTrail University",
            smartContext: {
              orgUnitId: "tenant_123:org:department-health",
              badgeTemplateId: "badge_template_001",
              pathwayLabel: null,
              inferredFrom: ["row", "badge_template"],
            },
          },
        }),
      }),
    ]);

    const response = await app.request(
      "/v1/jobs/process",
      {
        method: "POST",
        headers: {
          "content-type": "application/json",
        },
        body: JSON.stringify({}),
      },
      env,
    );
    const body = await response.json<Record<string, unknown>>();

    expect(response.status).toBe(200);
    expect(body.succeeded).toBe(1);
    expect(mockedResolveLearnerProfileForIdentity).toHaveBeenCalledWith(
      fakeDb,
      expect.objectContaining({
        tenantId: "tenant_123",
        identityType: "email",
        identityValue: "learner@example.edu",
      }),
    );
    expect(mockedCreateLearnerRecordEntry).toHaveBeenCalledWith(
      fakeDb,
      expect.objectContaining({
        tenantId: "tenant_123",
        learnerProfileId: "lpr_123",
        trustLevel: "issuer_verified",
        sourceSystem: "csv_import",
      }),
    );
    expect(mockedCreateLearnerRecordImportContext).toHaveBeenCalledWith(
      fakeDb,
      expect.objectContaining({
        tenantId: "tenant_123",
        entryId: "lre_123",
        orgUnitId: "tenant_123:org:department-health",
        badgeTemplateId: "badge_template_001",
      }),
    );
  });
});

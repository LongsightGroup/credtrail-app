import { beforeEach, describe, expect, it, vi } from "vitest";
import {
  buildBadgeRuleVersionRecord,
  type BadgeRuleVersionRecordOverrides,
} from "./test-support/badge-rule-version";

vi.mock("@credtrail/db", async () => {
  const actual = await vi.importActual<typeof import("@credtrail/db")>("@credtrail/db");

  return {
    ...actual,
    applyLearnerRecordImport: vi.fn(),
    completeJobQueueMessage: vi.fn(),
    createAuditLog: vi.fn(),
    enqueueJobQueueMessageOnce: vi.fn(),
    failJobQueueMessage: vi.fn(),
    findBadgeIssuanceRuleVersionById: vi.fn(),
    findTenantById: vi.fn(),
    findUserById: vi.fn(),
    leaseJobQueueMessages: vi.fn(),
    listBadgeIssuanceRuleVersionApprovalSteps: vi.fn(),
    markAutomatedBadgeRuleEvaluationQueueFailure: vi.fn(),
    recordAssertionRevocation: vi.fn(),
    reevaluateLearnerPathwaysForLearner: vi.fn(),
  };
});

vi.mock("./badges/automated-badge-rule-job", async () => {
  const actual = await vi.importActual<typeof import("./badges/automated-badge-rule-job")>(
    "./badges/automated-badge-rule-job",
  );

  return {
    ...actual,
    processAutomatedBadgeRuleQueueJob: vi.fn(),
  };
});

vi.mock("@credtrail/db/postgres", () => {
  return {
    createPostgresDatabase: vi.fn(),
  };
});

import {
  applyLearnerRecordImport,
  completeJobQueueMessage,
  createAuditLog,
  enqueueJobQueueMessageOnce,
  failJobQueueMessage,
  findBadgeIssuanceRuleVersionById,
  findTenantById,
  findUserById,
  leaseJobQueueMessages,
  listBadgeIssuanceRuleVersionApprovalSteps,
  markAutomatedBadgeRuleEvaluationQueueFailure,
  recordAssertionRevocation,
  reevaluateLearnerPathwaysForLearner,
  type AuditLogRecord,
  type BadgeIssuanceRuleVersionRecord,
  type JobQueueMessageRecord,
  type SqlDatabase,
} from "@credtrail/db";
import { createPostgresDatabase } from "@credtrail/db/postgres";

import { processAutomatedBadgeRuleQueueJob } from "./badges/automated-badge-rule-job";
import { app } from "./index";
import { GradebookProviderError } from "./lms/gradebook-provider-error";

interface ErrorResponse {
  error: string;
}

const mockedApplyLearnerRecordImport = vi.mocked(applyLearnerRecordImport);
const mockedCompleteJobQueueMessage = vi.mocked(completeJobQueueMessage);
const mockedCreateAuditLog = vi.mocked(createAuditLog);
const mockedEnqueueJobQueueMessageOnce = vi.mocked(enqueueJobQueueMessageOnce);
const mockedFailJobQueueMessage = vi.mocked(failJobQueueMessage);
const mockedFindBadgeIssuanceRuleVersionById = vi.mocked(findBadgeIssuanceRuleVersionById);
const mockedFindTenantById = vi.mocked(findTenantById);
const mockedFindUserById = vi.mocked(findUserById);
const mockedLeaseJobQueueMessages = vi.mocked(leaseJobQueueMessages);
const mockedListBadgeIssuanceRuleVersionApprovalSteps = vi.mocked(
  listBadgeIssuanceRuleVersionApprovalSteps,
);
const mockedMarkAutomatedBadgeRuleEvaluationQueueFailure = vi.mocked(
  markAutomatedBadgeRuleEvaluationQueueFailure,
);
const mockedProcessAutomatedBadgeRuleQueueJob = vi.mocked(processAutomatedBadgeRuleQueueJob);
const mockedRecordAssertionRevocation = vi.mocked(recordAssertionRevocation);
const mockedReevaluateLearnerPathwaysForLearner = vi.mocked(reevaluateLearnerPathwaysForLearner);
const mockedCreatePostgresDatabase = vi.mocked(createPostgresDatabase);
const fakeDb = {
  prepare: vi.fn(),
} as unknown as SqlDatabase;

const createEnv = (): {
  APP_ENV: string;
  DATABASE_URL: string;
  BADGE_OBJECTS: R2Bucket;
  PLATFORM_DOMAIN: string;
  PUBLIC_APP_ORIGIN: string;
  JOB_PROCESSOR_TOKEN?: string;
} => {
  return {
    APP_ENV: "test",
    DATABASE_URL: "postgres://credtrail-test.local/db",
    BADGE_OBJECTS: {} as R2Bucket,
    PLATFORM_DOMAIN: "credtrail.test",
    PUBLIC_APP_ORIGIN: "https://credtrail.test",
  };
};

const PROCESSOR_TOKEN = "processor-secret";

const createProcessorEnv = (): ReturnType<typeof createEnv> => {
  return {
    ...createEnv(),
    JOB_PROCESSOR_TOKEN: PROCESSOR_TOKEN,
  };
};

const processorHeaders = (): HeadersInit => {
  return {
    authorization: `Bearer ${PROCESSOR_TOKEN}`,
    "content-type": "application/json",
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

const sampleBadgeIssuanceRuleVersion = (
  overrides: BadgeRuleVersionRecordOverrides = {},
): BadgeIssuanceRuleVersionRecord => {
  return buildBadgeRuleVersionRecord({
    status: "approved",
    ruleJson: "{}",
    changeSummary: null,
    createdByUserId: null,
    submittedAt: "2026-02-10T22:00:00.000Z",
    approvedByUserId: "usr_admin",
    approvedAt: "2026-02-10T22:05:00.000Z",
    createdAt: "2026-02-10T22:00:00.000Z",
    updatedAt: "2026-02-10T22:05:00.000Z",
    ...overrides,
  });
};

const sampleLeasedQueueMessage = (
  overrides?: Partial<JobQueueMessageRecord>,
): JobQueueMessageRecord => {
  return {
    id: "job_123",
    tenantId: "tenant_123",
    jobType: "process_learner_evidence_change",
    payloadJson: JSON.stringify({
      learnerProfileId: "lpr_123",
      trigger: "assertion_issued",
      requestedAt: "2026-02-10T22:00:00.000Z",
    }),
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
    mockedApplyLearnerRecordImport.mockReset();
    mockedFailJobQueueMessage.mockReset();
    mockedFindBadgeIssuanceRuleVersionById.mockReset();
    mockedFindTenantById.mockReset();
    mockedFindUserById.mockReset();
    mockedListBadgeIssuanceRuleVersionApprovalSteps.mockReset();
    mockedMarkAutomatedBadgeRuleEvaluationQueueFailure.mockReset();
    mockedProcessAutomatedBadgeRuleQueueJob.mockReset();
    mockedRecordAssertionRevocation.mockReset();
    mockedCreateAuditLog.mockReset();
    mockedEnqueueJobQueueMessageOnce.mockReset();
    mockedReevaluateLearnerPathwaysForLearner.mockReset();
    mockedCreateAuditLog.mockResolvedValue(sampleAuditLogRecord());
    mockedEnqueueJobQueueMessageOnce.mockResolvedValue(true);
    mockedReevaluateLearnerPathwaysForLearner.mockResolvedValue({
      evaluations: [],
      nextEnrollmentId: null,
    });
    mockedApplyLearnerRecordImport.mockResolvedValue({
      status: "applied",
      learnerProfileId: "lpr_123",
      learnerRecordEntryId: "lre_123",
    });
    mockedFindBadgeIssuanceRuleVersionById.mockResolvedValue(sampleBadgeIssuanceRuleVersion());
    mockedFindTenantById.mockResolvedValue({
      id: "tenant_123",
      slug: "tenant-123",
      displayName: "Tenant 123",
      planTier: "institution",
      issuerDomain: "issuer.example.edu",
      didWeb: "did:web:issuer.example.edu",
      isActive: true,
      createdAt: "2026-02-10T22:00:00.000Z",
      updatedAt: "2026-02-10T22:00:00.000Z",
    });
    mockedFindUserById.mockResolvedValue(null);
    mockedListBadgeIssuanceRuleVersionApprovalSteps.mockResolvedValue([]);
    mockedMarkAutomatedBadgeRuleEvaluationQueueFailure.mockResolvedValue(true);
    mockedProcessAutomatedBadgeRuleQueueJob.mockResolvedValue(undefined);
  });

  it("hides processor route when JOB_PROCESSOR_TOKEN is not configured", async () => {
    const response = await app.request(
      "/v1/jobs/process",
      {
        method: "POST",
        headers: {
          "content-type": "application/json",
        },
        body: JSON.stringify({}),
      },
      createEnv(),
    );
    const body = await response.json<ErrorResponse>();

    expect(response.status).toBe(404);
    expect(body.error).toBe("Route unavailable");
    expect(mockedLeaseJobQueueMessages).not.toHaveBeenCalled();
  });

  it("processes leased jobs and marks them completed", async () => {
    const env = createProcessorEnv();

    mockedLeaseJobQueueMessages.mockResolvedValue([sampleLeasedQueueMessage()]);

    const response = await app.request(
      "/v1/jobs/process",
      {
        method: "POST",
        headers: processorHeaders(),
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

  it("processes learner evidence changes in bounded continuation pages", async () => {
    mockedReevaluateLearnerPathwaysForLearner.mockResolvedValueOnce({
      evaluations: [],
      nextEnrollmentId: "pthe_025",
    });
    mockedLeaseJobQueueMessages.mockResolvedValue([
      sampleLeasedQueueMessage({
        jobType: "process_learner_evidence_change",
        payloadJson: JSON.stringify({
          learnerProfileId: "lpr_123",
          trigger: "assertion_issued",
          requestedAt: "2026-02-10T22:00:00.000Z",
        }),
      }),
    ]);

    const response = await app.request(
      "/v1/jobs/process",
      {
        method: "POST",
        headers: processorHeaders(),
        body: JSON.stringify({}),
      },
      createProcessorEnv(),
    );

    expect(response.status).toBe(200);
    expect(mockedReevaluateLearnerPathwaysForLearner).toHaveBeenCalledWith(fakeDb, {
      tenantId: "tenant_123",
      learnerProfileId: "lpr_123",
      trigger: "assertion_issued",
      limit: 25,
    });
    expect(mockedEnqueueJobQueueMessageOnce).toHaveBeenCalledWith(
      fakeDb,
      expect.objectContaining({
        jobType: "process_learner_evidence_change",
        payload: expect.objectContaining({ afterEnrollmentId: "pthe_025" }),
      }),
    );
    expect(mockedCompleteJobQueueMessage).toHaveBeenCalledTimes(1);
  });

  it("processes badge rule approval notification jobs", async () => {
    const messages: Array<{ readonly subject: string; readonly text: string }> = [];
    const env = {
      ...createProcessorEnv(),
      EMAIL: {
        send: async (message: { readonly subject: string; readonly text: string }) => {
          messages.push(message);
          return { messageId: "email_msg_123" };
        },
      } as unknown as SendEmail,
    };
    mockedFindBadgeIssuanceRuleVersionById.mockResolvedValue(
      sampleBadgeIssuanceRuleVersion({
        snapshot: {
          name: "Immutable clinical skills rule",
        },
        submittedByUserId: "usr_author",
      }),
    );
    mockedFindUserById.mockResolvedValue({
      id: "usr_author",
      email: "author@example.edu",
    });

    mockedLeaseJobQueueMessages.mockResolvedValue([
      sampleLeasedQueueMessage({
        jobType: "send_badge_rule_approval_notification",
        payloadJson: JSON.stringify({
          notificationType: "approval_decision",
          ruleId: "brl_123",
          versionId: "brv_123",
          decision: "approved",
          comment: null,
          nextStepNumber: null,
        }),
        idempotencyKey: "approval-decision:brv_123:2026-02-10T22:05:00.000Z",
      }),
    ]);

    const response = await app.request(
      "/v1/jobs/process",
      {
        method: "POST",
        headers: processorHeaders(),
        body: JSON.stringify({}),
      },
      env,
    );
    const body = await response.json<Record<string, unknown>>();

    expect(response.status).toBe(200);
    expect(body.succeeded).toBe(1);
    expect(mockedFindBadgeIssuanceRuleVersionById).toHaveBeenCalledWith(fakeDb, {
      tenantId: "tenant_123",
      ruleId: "brl_123",
      versionId: "brv_123",
    });
    expect(mockedCompleteJobQueueMessage).toHaveBeenCalledTimes(1);
    expect(mockedFailJobQueueMessage).not.toHaveBeenCalled();
    expect(messages).toHaveLength(1);
    expect(messages[0]?.subject).toBe("Badge rule approved: Immutable clinical skills rule");
    expect(messages[0]?.text).toContain("Rule: Immutable clinical skills rule");
  });

  it("requires bearer auth when JOB_PROCESSOR_TOKEN is configured", async () => {
    const env = createProcessorEnv();

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
    const env = createProcessorEnv();

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
        headers: processorHeaders(),
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

  it("classifies a legacy oversized automated command before LMS work starts", async () => {
    const ruleId = `brl_${"a".repeat(64)}`;
    const versionId = `brv_${"b".repeat(64)}`;
    mockedLeaseJobQueueMessages.mockResolvedValue([
      sampleLeasedQueueMessage({
        jobType: "process_automated_badge_rule",
        payloadJson: JSON.stringify({
          ruleId,
          versionId,
          scheduledFor: "2026-09-02T18:00:00.000Z",
        }),
        idempotencyKey: `automated-rule:${ruleId}:${versionId}:hour:2026-09-02T18`,
      }),
    ]);
    mockedFailJobQueueMessage.mockResolvedValue("pending");

    const response = await app.request(
      "/v1/jobs/process",
      {
        method: "POST",
        headers: processorHeaders(),
        body: JSON.stringify({}),
      },
      createProcessorEnv(),
    );
    const body = await response.json<Record<string, unknown>>();

    expect(response.status).toBe(200);
    expect(body.retried).toBe(1);
    expect(mockedProcessAutomatedBadgeRuleQueueJob).not.toHaveBeenCalled();
    expect(mockedMarkAutomatedBadgeRuleEvaluationQueueFailure).toHaveBeenCalledWith(fakeDb, {
      tenantId: "tenant_123",
      commandId: "job_123",
      failedAt: expect.any(String),
      terminal: false,
      failureTag: "invalid_command",
    });
  });

  it("classifies an LMS adapter failure without exposing provider details", async () => {
    mockedLeaseJobQueueMessages.mockResolvedValue([
      sampleLeasedQueueMessage({
        jobType: "process_automated_badge_rule",
        payloadJson: JSON.stringify({
          ruleId: "brl_123",
          versionId: "brv_123",
          scheduledFor: "2026-09-02T18:00:00.000Z",
        }),
        idempotencyKey: "automated-rule:brv_123:hour:2026-09-02T18",
      }),
    ]);
    mockedProcessAutomatedBadgeRuleQueueJob.mockRejectedValue(
      new GradebookProviderError({
        providerKind: "sakai",
        operation: "learner_search",
        reason: "request_failed",
        statusCode: null,
        message: "Sanitized provider failure",
      }),
    );
    mockedFailJobQueueMessage.mockResolvedValue("failed");

    const response = await app.request(
      "/v1/jobs/process",
      {
        method: "POST",
        headers: processorHeaders(),
        body: JSON.stringify({}),
      },
      createProcessorEnv(),
    );
    const body = await response.json<Record<string, unknown>>();

    expect(response.status).toBe(200);
    expect(body.deadLettered).toBe(1);
    expect(mockedMarkAutomatedBadgeRuleEvaluationQueueFailure).toHaveBeenCalledWith(fakeDb, {
      tenantId: "tenant_123",
      commandId: "job_123",
      failedAt: expect.any(String),
      terminal: true,
      failureTag: "provider_unavailable",
    });
  });

  it("writes audit logs for processed revoke jobs", async () => {
    const env = createProcessorEnv();

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
        headers: processorHeaders(),
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
    const env = createProcessorEnv();

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
        headers: processorHeaders(),
        body: JSON.stringify({}),
      },
      env,
    );
    const body = await response.json<Record<string, unknown>>();

    expect(response.status).toBe(200);
    expect(body.succeeded).toBe(1);
    expect(mockedApplyLearnerRecordImport).toHaveBeenCalledWith(
      fakeDb,
      expect.objectContaining({
        tenantId: "tenant_123",
        batchId: "batch_123",
        rowNumber: 1,
        learnerEmail: "learner@example.edu",
        entry: expect.objectContaining({
          trustLevel: "issuer_verified",
          sourceSystem: "csv_import",
        }),
        context: expect.objectContaining({
          orgUnitId: "tenant_123:org:department-health",
          badgeTemplateId: "badge_template_001",
        }),
      }),
    );
  });
});

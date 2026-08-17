import { beforeEach, describe, expect, it, vi } from "vitest";

import {
  processBadgeRuleLifecycleForTenant,
  type ProcessBadgeRuleLifecycleInput,
} from "./badge-rule-lifecycle-processor";
import type { AppBindings } from "../app/types";
import { sampleBadgeRuleVersionSnapshot } from "../test-support/badge-rule-version";

vi.mock("@credtrail/db", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@credtrail/db")>();

  return {
    ...actual,
    createAuditLog: vi.fn(async () => undefined),
    ensureBadgeRuleRecertificationReview: vi.fn(async () => true),
    enqueueJobQueueMessageOnce: vi.fn(async () => true),
    enqueueOrRetryFailedJobQueueMessage: vi.fn(async () => true),
    expireBadgeIssuanceRuleVersion: vi.fn(async () => ({ id: "brv_123" })),
    findBadgeIssuanceRuleById: vi.fn(async () => ({
      id: "brl_123",
      tenantId: "tenant_123",
      name: "CS101 Excellence Rule",
      description: null,
      badgeTemplateId: "badge_template_123",
      orgUnitId: "tenant_123:org:institution",
      ownerOrgUnitId: "tenant_123:org:institution",
      lmsProviderKind: "canvas",
      lmsConnectionId: "lms_123",
      activeVersionId: "brv_123",
      createdByUserId: "usr_admin",
      createdAt: "2026-01-01T00:00:00.000Z",
      updatedAt: "2026-01-01T00:00:00.000Z",
    })),
    findTenantById: vi.fn(async () => ({
      id: "tenant_123",
      displayName: "Example University",
      normalizedName: "example-university",
      createdAt: "2026-01-01T00:00:00.000Z",
      updatedAt: "2026-01-01T00:00:00.000Z",
    })),
    listBadgeIssuanceRuleVersionsDueForExpiry: vi.fn(async () => [
      {
        id: "brv_123",
        tenantId: "tenant_123",
        ruleId: "brl_123",
        versionNumber: 1,
        status: "active" as const,
        ruleJson: JSON.stringify({
          conditions: {
            type: "grade_threshold",
            courseId: "course-123",
            scoreField: "final_score",
            minScore: 85,
          },
          options: {
            issuanceTiming: "end_of_term",
            reviewOnMissingFacts: true,
          },
        }),
        snapshot: sampleBadgeRuleVersionSnapshot,
        changeSummary: null,
        createdByUserId: "usr_admin",
        submittedByUserId: null,
        submittedAt: null,
        approvedByUserId: null,
        approvedAt: null,
        activatedByUserId: "usr_admin",
        activatedAt: "2026-01-01T00:00:00.000Z",
        effectiveStartsAt: "2026-01-01T00:00:00.000Z",
        expiresAt: "2026-06-01T00:00:00.000Z",
        expiredAt: null,
        suspendedAt: null,
        suspendedByUserId: null,
        suspensionReason: null,
        recertifiedAt: null,
        recertificationDueAt: null,
        expiryReminderSentAt: null,
        recertificationReminderSentAt: null,
        badgeTemplateId: "badge_template_123",
        lmsProviderKind: "canvas",
        lmsConnectionId: "lms_123",
        orgUnitId: "tenant_123:org:institution",
        createdAt: "2026-01-01T00:00:00.000Z",
        updatedAt: "2026-01-01T00:00:00.000Z",
      },
    ]),
    listBadgeIssuanceRuleVersionsDueForExpiryReminder: vi.fn(async () => []),
    listBadgeIssuanceRuleVersionsForAutomatedEvaluation: vi.fn(async () => []),
    listBadgeIssuanceRuleVersionsDueForRecertification: vi.fn(async () => []),
    listBadgeIssuanceRuleVersionsDueForRecertificationReminder: vi.fn(async () => []),
    listTenantMembers: vi.fn(async () => [
      {
        tenantId: "tenant_123",
        userId: "usr_admin",
        email: "admin@example.edu",
        role: "admin" as const,
        createdAt: "2026-01-01T00:00:00.000Z",
        updatedAt: "2026-01-01T00:00:00.000Z",
      },
    ]),
    markBadgeIssuanceRuleVersionExpiryReminderSent: vi.fn(async () => true),
    markBadgeIssuanceRuleVersionRecertificationReminderSent: vi.fn(async () => true),
    suspendBadgeIssuanceRuleVersionForOverdueRecertification: vi.fn(async () => null),
  };
});

describe("processBadgeRuleLifecycleForTenant", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("enqueues end-of-term jobs without expiring the version in the lifecycle pass", async () => {
    const dbModule = await import("@credtrail/db");
    const input: ProcessBadgeRuleLifecycleInput = {
      db: {} as ProcessBadgeRuleLifecycleInput["db"],
      tenantId: "tenant_123",
      nowIso: "2026-06-01T00:00:00.000Z",
      observability: {
        service: "api-worker",
        environment: "development",
      },
    };

    const result = await processBadgeRuleLifecycleForTenant(input);

    expect(result).toEqual({
      dueVersionsProcessed: 1,
      automatedEvaluationJobsEnqueued: 1,
      expiredVersions: 0,
      expiryRemindersSent: 0,
      recertificationRemindersSent: 0,
      recertificationReviewsOpened: 0,
      recertificationAutoSuspensions: 0,
    });
    expect(dbModule.enqueueOrRetryFailedJobQueueMessage).toHaveBeenCalledWith(
      input.db,
      expect.objectContaining({
        jobType: "process_automated_badge_rule",
        tenantId: "tenant_123",
        payload: expect.objectContaining({ versionId: "brv_123" }),
      }),
    );
    expect(dbModule.expireBadgeIssuanceRuleVersion).not.toHaveBeenCalled();
  });

  it("opens recertification reviews, sends reminders, and suspends severely overdue versions", async () => {
    const dbModule = await import("@credtrail/db");
    const dueVersion = {
      id: "brv_recert",
      tenantId: "tenant_123",
      ruleId: "brl_123",
      versionNumber: 3,
      status: "active" as const,
      ruleJson: JSON.stringify({
        conditions: {
          type: "grade_threshold",
          courseId: "course-123",
          scoreField: "final_score",
          minScore: 85,
        },
      }),
      snapshot: sampleBadgeRuleVersionSnapshot,
      changeSummary: null,
      createdByUserId: "usr_admin",
      submittedByUserId: null,
      submittedAt: null,
      approvedByUserId: null,
      approvedAt: null,
      activatedByUserId: "usr_admin",
      activatedAt: "2026-01-01T00:00:00.000Z",
      effectiveStartsAt: "2026-01-01T00:00:00.000Z",
      expiresAt: "2026-08-01T00:00:00.000Z",
      expiredAt: null,
      suspendedAt: null,
      suspendedByUserId: null,
      suspensionReason: null,
      recertifiedAt: null,
      recertificationDueAt: "2026-05-01T00:00:00.000Z",
      expiryReminderSentAt: null,
      recertificationReminderSentAt: null,
      badgeTemplateId: "badge_template_123",
      lmsProviderKind: "canvas",
      lmsConnectionId: "lms_123",
      orgUnitId: "tenant_123:org:institution",
      createdAt: "2026-01-01T00:00:00.000Z",
      updatedAt: "2026-01-01T00:00:00.000Z",
    };
    vi.mocked(dbModule.listBadgeIssuanceRuleVersionsDueForExpiry).mockResolvedValue([]);
    vi.mocked(dbModule.listBadgeIssuanceRuleVersionsDueForExpiryReminder).mockResolvedValue([
      dueVersion,
    ]);
    vi.mocked(
      dbModule.listBadgeIssuanceRuleVersionsDueForRecertificationReminder,
    ).mockResolvedValue([dueVersion]);
    vi.mocked(dbModule.listBadgeIssuanceRuleVersionsDueForRecertification).mockResolvedValue([
      dueVersion,
    ]);
    vi.mocked(dbModule.suspendBadgeIssuanceRuleVersionForOverdueRecertification).mockResolvedValue({
      ...dueVersion,
      status: "suspended",
      suspendedAt: "2026-06-15T00:00:00.000Z",
      suspensionReason: "Automatically suspended because rule recertification is overdue.",
    });

    const emailSend = vi.fn(async () => undefined);
    const input: ProcessBadgeRuleLifecycleInput = {
      db: {} as ProcessBadgeRuleLifecycleInput["db"],
      tenantId: "tenant_123",
      nowIso: "2026-06-15T00:00:00.000Z",
      observability: {
        service: "api-worker",
        environment: "development",
      },
      env: {
        APP_ENV: "test",
        BADGE_OBJECTS: {} as AppBindings["BADGE_OBJECTS"],
        EMAIL: { send: emailSend } as unknown as SendEmail,
        PLATFORM_DOMAIN: "credtrail.org",
        PUBLIC_APP_ORIGIN: "https://credtrail.org",
      },
      adminUrlForTenant: (tenantId) => `https://credtrail.org/tenants/${tenantId}/admin/rules`,
    };

    const result = await processBadgeRuleLifecycleForTenant(input);

    expect(result).toEqual({
      dueVersionsProcessed: 0,
      automatedEvaluationJobsEnqueued: 0,
      expiredVersions: 0,
      expiryRemindersSent: 1,
      recertificationRemindersSent: 1,
      recertificationReviewsOpened: 1,
      recertificationAutoSuspensions: 1,
    });
    expect(emailSend).toHaveBeenCalledTimes(2);
    expect(dbModule.ensureBadgeRuleRecertificationReview).toHaveBeenCalledWith(input.db, {
      tenantId: "tenant_123",
      ruleId: "brl_123",
      versionId: "brv_recert",
      dueAt: "2026-05-01T00:00:00.000Z",
      requestedAt: "2026-06-15T00:00:00.000Z",
    });
    expect(dbModule.suspendBadgeIssuanceRuleVersionForOverdueRecertification).toHaveBeenCalledWith(
      input.db,
      expect.objectContaining({
        tenantId: "tenant_123",
        ruleId: "brl_123",
        versionId: "brv_recert",
        overdueDays: 30,
      }),
    );
  });

  it("does not mark reminders sent when email transport is not configured", async () => {
    const dbModule = await import("@credtrail/db");
    const reminderVersion = {
      id: "brv_reminder",
      tenantId: "tenant_123",
      ruleId: "brl_123",
      versionNumber: 2,
      status: "active" as const,
      ruleJson: JSON.stringify({
        conditions: {
          type: "grade_threshold",
          courseId: "course-123",
          scoreField: "final_score",
          minScore: 85,
        },
      }),
      snapshot: sampleBadgeRuleVersionSnapshot,
      changeSummary: null,
      createdByUserId: "usr_admin",
      submittedByUserId: null,
      submittedAt: null,
      approvedByUserId: null,
      approvedAt: null,
      activatedByUserId: "usr_admin",
      activatedAt: "2026-01-01T00:00:00.000Z",
      effectiveStartsAt: "2026-01-01T00:00:00.000Z",
      expiresAt: "2026-06-20T00:00:00.000Z",
      expiredAt: null,
      suspendedAt: null,
      suspendedByUserId: null,
      suspensionReason: null,
      recertifiedAt: null,
      recertificationDueAt: "2026-06-21T00:00:00.000Z",
      expiryReminderSentAt: null,
      recertificationReminderSentAt: null,
      badgeTemplateId: "badge_template_123",
      lmsProviderKind: "canvas",
      lmsConnectionId: "lms_123",
      orgUnitId: "tenant_123:org:institution",
      createdAt: "2026-01-01T00:00:00.000Z",
      updatedAt: "2026-01-01T00:00:00.000Z",
    };
    vi.mocked(dbModule.listBadgeIssuanceRuleVersionsDueForExpiry).mockResolvedValue([]);
    vi.mocked(dbModule.listBadgeIssuanceRuleVersionsDueForExpiryReminder).mockResolvedValue([
      reminderVersion,
    ]);
    vi.mocked(
      dbModule.listBadgeIssuanceRuleVersionsDueForRecertificationReminder,
    ).mockResolvedValue([reminderVersion]);
    vi.mocked(dbModule.listBadgeIssuanceRuleVersionsDueForRecertification).mockResolvedValue([]);

    const input: ProcessBadgeRuleLifecycleInput = {
      db: {} as ProcessBadgeRuleLifecycleInput["db"],
      tenantId: "tenant_123",
      nowIso: "2026-06-15T00:00:00.000Z",
      observability: {
        service: "api-worker",
        environment: "development",
      },
    };

    const result = await processBadgeRuleLifecycleForTenant(input);

    expect(result.expiryRemindersSent).toBe(0);
    expect(result.recertificationRemindersSent).toBe(0);
    expect(dbModule.markBadgeIssuanceRuleVersionExpiryReminderSent).not.toHaveBeenCalled();
    expect(dbModule.markBadgeIssuanceRuleVersionRecertificationReminderSent).not.toHaveBeenCalled();
  });
});

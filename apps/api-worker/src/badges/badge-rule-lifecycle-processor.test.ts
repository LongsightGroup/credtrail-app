import { describe, expect, it, vi } from "vitest";

import {
  processBadgeRuleLifecycleForTenant,
  type ProcessBadgeRuleLifecycleInput,
} from "./badge-rule-lifecycle-processor";

vi.mock("@credtrail/db", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@credtrail/db")>();

  return {
    ...actual,
    createAuditLog: vi.fn(async () => undefined),
    enqueueJobQueueMessageOnce: vi.fn(async () => true),
    expireBadgeIssuanceRuleVersion: vi.fn(async () => ({ id: "brv_123" })),
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
  };
});

describe("processBadgeRuleLifecycleForTenant", () => {
  it("enqueues end-of-term jobs and expires due active versions", async () => {
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
      endOfTermJobsEnqueued: 1,
      expiredVersions: 1,
    });
    expect(dbModule.enqueueJobQueueMessageOnce).toHaveBeenCalledWith(
      input.db,
      expect.objectContaining({
        jobType: "process_end_of_term_badge_rule",
        tenantId: "tenant_123",
      }),
    );
    expect(dbModule.expireBadgeIssuanceRuleVersion).toHaveBeenCalledWith(input.db, {
      tenantId: "tenant_123",
      ruleId: "brl_123",
      versionId: "brv_123",
      occurredAt: input.nowIso,
    });
  });
});

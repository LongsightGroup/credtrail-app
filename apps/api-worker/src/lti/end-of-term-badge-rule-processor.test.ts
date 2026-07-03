import { describe, expect, it, vi } from "vitest";

import { processEndOfTermBadgeRule } from "./end-of-term-badge-rule-processor";

const {
  mockedFindBadgeIssuanceRuleById,
  mockedFindBadgeIssuanceRuleVersionById,
  mockedFindLtiResourceLinkPlacementForRule,
  mockedListActiveLtiLaunchSessionsForPlatform,
  mockedEnqueueEligibleLtiRosterIssuanceJobs,
} = vi.hoisted(() => ({
  mockedFindBadgeIssuanceRuleById: vi.fn(),
  mockedFindBadgeIssuanceRuleVersionById: vi.fn(),
  mockedFindLtiResourceLinkPlacementForRule: vi.fn(),
  mockedListActiveLtiLaunchSessionsForPlatform: vi.fn(),
  mockedEnqueueEligibleLtiRosterIssuanceJobs: vi.fn(),
}));

vi.mock("@credtrail/db", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@credtrail/db")>();

  return {
    ...actual,
    createAuditLog: vi.fn(async () => undefined),
    expireBadgeIssuanceRuleVersion: vi.fn(async () => null),
    findBadgeIssuanceRuleById: mockedFindBadgeIssuanceRuleById,
    findBadgeIssuanceRuleVersionById: mockedFindBadgeIssuanceRuleVersionById,
    findLtiResourceLinkPlacementForRule: mockedFindLtiResourceLinkPlacementForRule,
    listActiveLtiLaunchSessionsForPlatform: mockedListActiveLtiLaunchSessionsForPlatform,
  };
});

vi.mock("./enqueue-eligible-roster-issuance-jobs", () => ({
  enqueueEligibleLtiRosterIssuanceJobs: mockedEnqueueEligibleLtiRosterIssuanceJobs,
}));

describe("processEndOfTermBadgeRule", () => {
  it("does not issue when the queued version was suspended before processing", async () => {
    mockedFindBadgeIssuanceRuleById.mockResolvedValue({
      id: "brl_123",
      tenantId: "tenant_123",
      name: "End of term",
      description: null,
      badgeTemplateId: "badge_template_123",
      orgUnitId: "tenant_123:org:course",
      ownerOrgUnitId: "tenant_123:org:course",
      lmsProviderKind: "canvas",
      lmsConnectionId: "lms_123",
      activeVersionId: "brv_123",
      createdByUserId: "usr_admin",
      createdAt: "2026-01-01T00:00:00.000Z",
      updatedAt: "2026-01-01T00:00:00.000Z",
    });
    mockedFindBadgeIssuanceRuleVersionById.mockResolvedValue({
      id: "brv_123",
      tenantId: "tenant_123",
      ruleId: "brl_123",
      versionNumber: 1,
      status: "suspended",
      ruleJson: JSON.stringify({
        conditions: {
          type: "grade_threshold",
          courseId: "course-123",
          scoreField: "final_score",
          minScore: 85,
        },
        options: {
          issuanceTiming: "end_of_term",
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
      suspendedAt: "2026-05-31T12:00:00.000Z",
      suspendedByUserId: "usr_admin",
      suspensionReason: "Investigation",
      recertifiedAt: null,
      recertificationDueAt: null,
      expiryReminderSentAt: null,
      recertificationReminderSentAt: null,
      createdAt: "2026-01-01T00:00:00.000Z",
      updatedAt: "2026-05-31T12:00:00.000Z",
    });
    mockedFindLtiResourceLinkPlacementForRule.mockResolvedValue({
      id: "placement_123",
    });

    const result = await processEndOfTermBadgeRule({
      db: {} as Parameters<typeof processEndOfTermBadgeRule>[0]["db"],
      env: {} as Parameters<typeof processEndOfTermBadgeRule>[0]["env"],
      tenantId: "tenant_123",
      payload: {
        ruleId: "brl_123",
        versionId: "brv_123",
        badgeTemplateId: "badge_template_123",
        scheduledFor: "2026-06-01T00:00:00.000Z",
      },
      sha256Hex: async (value) => value,
    });

    expect(result).toEqual({
      status: "unavailable",
      evaluatedLearnerCount: 0,
      issueJobsEnqueued: 0,
      reason: "Rule version is no longer active for end-of-term issuance.",
    });
    expect(mockedListActiveLtiLaunchSessionsForPlatform).not.toHaveBeenCalled();
    expect(mockedEnqueueEligibleLtiRosterIssuanceJobs).not.toHaveBeenCalled();
  });
});

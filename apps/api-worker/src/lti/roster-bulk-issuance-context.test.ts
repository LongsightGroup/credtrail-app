import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("@credtrail/db", async () => {
  const actual = await vi.importActual<typeof import("@credtrail/db")>("@credtrail/db");

  return {
    ...actual,
    findActiveBadgeIssuanceRuleVersion: vi.fn(),
    findBadgeIssuanceRuleById: vi.fn(),
    findLtiResourceLinkPlacement: vi.fn(),
  };
});

vi.mock("../rules/badge-rule-facts-loader", () => ({
  loadRuleFacts: vi.fn(),
}));

import {
  findActiveBadgeIssuanceRuleVersion,
  findBadgeIssuanceRuleById,
  findLtiResourceLinkPlacement,
  type SqlDatabase,
} from "@credtrail/db";
import { loadRuleFacts } from "../rules/badge-rule-facts-loader";
import { ltiRosterIssuanceBehaviorFromRuleDefinition } from "./issuance-behavior";
import {
  ltiRosterIssuanceSkipDetail,
  prepareLtiRosterBulkIssuanceContext,
  prepareLtiRosterRuleIssuanceContext,
} from "./roster-bulk-issuance-context";
import { LTI_ROSTER_NO_RULE_LINKED_DETAIL } from "./roster-eligibility";
import {
  sampleLtiRosterBadgeRule,
  sampleLtiRosterBadgeRuleVersion,
  sampleLtiRosterMember,
  sampleLtiRosterResourceLinkPlacement,
  sampleLtiRosterRuleEvaluationFacts,
} from "./roster-eligibility-test-fixtures";

const mockedFindActiveBadgeIssuanceRuleVersion = vi.mocked(findActiveBadgeIssuanceRuleVersion);
const mockedFindBadgeIssuanceRuleById = vi.mocked(findBadgeIssuanceRuleById);
const mockedFindLtiResourceLinkPlacement = vi.mocked(findLtiResourceLinkPlacement);
const mockedLoadRuleFacts = vi.mocked(loadRuleFacts);

const fakeDb = {} as SqlDatabase;
const nowIso = "2026-02-10T22:00:00.000Z";

const sampleRuleVersionWithTiming = (
  issuanceTiming: "immediate" | "manual" | "end_of_term",
): ReturnType<typeof sampleLtiRosterBadgeRuleVersion> =>
  sampleLtiRosterBadgeRuleVersion({
    ruleJson: JSON.stringify({
      conditions: {
        type: "grade_threshold",
        courseId: "course-123",
        scoreField: "final_score",
        minScore: 85,
      },
      options: {
        issuanceTiming,
        reviewOnMissingFacts: true,
      },
    }),
  });

const bulkContextInput = (
  overrides?: Partial<Parameters<typeof prepareLtiRosterBulkIssuanceContext>[0]>,
): Parameters<typeof prepareLtiRosterBulkIssuanceContext>[0] => ({
  db: fakeDb,
  tenantId: "tenant_123",
  issuer: "https://sakai.example.edu",
  clientId: "client-123",
  deploymentId: "deployment-123",
  resourceLinkId: "resource-link-123",
  launchRuleId: null,
  members: [sampleLtiRosterMember()],
  issuedStatesByUserId: new Map(),
  nowIso,
  ...overrides,
});

describe("LTI roster bulk issuance context", () => {
  beforeEach(() => {
    mockedFindActiveBadgeIssuanceRuleVersion.mockReset();
    mockedFindBadgeIssuanceRuleById.mockReset();
    mockedFindLtiResourceLinkPlacement.mockReset();
    mockedLoadRuleFacts.mockReset();
    mockedFindBadgeIssuanceRuleById.mockResolvedValue(sampleLtiRosterBadgeRule());
    mockedFindActiveBadgeIssuanceRuleVersion.mockResolvedValue(sampleLtiRosterBadgeRuleVersion());
    mockedFindLtiResourceLinkPlacement.mockResolvedValue(sampleLtiRosterResourceLinkPlacement());
    mockedLoadRuleFacts.mockResolvedValue(sampleLtiRosterRuleEvaluationFacts(92));
  });

  describe("ltiRosterIssuanceSkipDetail", () => {
    it("returns already-issued detail", () => {
      const detail = ltiRosterIssuanceSkipDetail({
        issuedState: {
          assertionId: "assertion_123",
          issuedAt: nowIso,
          lifecycleState: null,
        },
        ruleContext: {
          ruleResolution: {
            status: "unavailable",
            detail: "Rule context is not needed for already-issued learners.",
          },
          prepared: null,
          issuanceBehavior: {
            key: "unavailable",
            label: "Unavailable",
            detail: "Rule context is not needed for already-issued learners.",
            manualIssuanceAllowed: false,
          },
        },
      });

      expect(detail).toBe("Badge was already issued for this learner.");
    });

    it("returns unresolved rule detail", () => {
      const detail = ltiRosterIssuanceSkipDetail({
        issuedState: null,
        ruleContext: {
          ruleResolution: {
            status: "unavailable",
            detail: "CredTrail could not load the course placement for this resource link.",
          },
          prepared: null,
          issuanceBehavior: {
            key: "unavailable",
            label: "Unavailable",
            detail: "CredTrail could not load the course placement for this resource link.",
            manualIssuanceAllowed: false,
          },
        },
      });

      expect(detail).toContain("could not load the course placement");
    });

    it("blocks ready automatic rules before per-member evaluation", () => {
      const automaticBehavior = ltiRosterIssuanceBehaviorFromRuleDefinition({
        conditions: {
          type: "grade_threshold",
          courseId: "course-123",
          scoreField: "final_score",
          minScore: 85,
        },
        options: { issuanceTiming: "immediate" },
      });
      const detail = ltiRosterIssuanceSkipDetail({
        issuedState: null,
        ruleContext: {
          ruleResolution: { status: "resolved", ruleId: "brl_123" },
          prepared: {
            status: "ready",
            ruleId: "brl_123",
            versionId: "brv_123",
            lmsProviderKind: "sakai",
            lmsConnectionId: "lms_sakai_001",
            definition: {
              conditions: {
                type: "grade_threshold",
                courseId: "course-123",
                scoreField: "final_score",
                minScore: 85,
              },
              options: { issuanceTiming: "immediate" },
            },
            issuanceBehavior: automaticBehavior,
          },
          issuanceBehavior: automaticBehavior,
        },
      });

      expect(detail).toContain("awarded automatically");
    });

    it("allows manual rules through to per-member eligibility", () => {
      const manualBehavior = ltiRosterIssuanceBehaviorFromRuleDefinition({
        conditions: {
          type: "grade_threshold",
          courseId: "course-123",
          scoreField: "final_score",
          minScore: 85,
        },
        options: { issuanceTiming: "manual" },
      });

      expect(
        ltiRosterIssuanceSkipDetail({
          issuedState: null,
          ruleContext: {
            ruleResolution: { status: "resolved", ruleId: "brl_123" },
            prepared: {
              status: "ready",
              ruleId: "brl_123",
              versionId: "brv_123",
              lmsProviderKind: "sakai",
              lmsConnectionId: "lms_sakai_001",
              definition: {
                conditions: {
                  type: "grade_threshold",
                  courseId: "course-123",
                  scoreField: "final_score",
                  minScore: 85,
                },
                options: { issuanceTiming: "manual" },
              },
              issuanceBehavior: manualBehavior,
            },
            issuanceBehavior: manualBehavior,
          },
        }),
      ).toBeNull();
    });

    it("returns pending prepared rule detail before per-member eligibility", () => {
      const detail = ltiRosterIssuanceSkipDetail({
        issuedState: null,
        ruleContext: {
          ruleResolution: { status: "resolved", ruleId: "brl_123" },
          prepared: {
            status: "rule_pending",
            detail: "Rule is waiting for review and activation.",
            issuanceBehavior: {
              key: "rule_pending",
              label: "Rule pending",
              detail: "Rule is waiting for review and activation.",
              manualIssuanceAllowed: false,
            },
          },
          issuanceBehavior: {
            key: "rule_pending",
            label: "Rule pending",
            detail: "Rule is waiting for review and activation.",
            manualIssuanceAllowed: false,
          },
        },
      });

      expect(detail).toBe("Rule is waiting for review and activation.");
    });
  });

  describe("prepareLtiRosterRuleIssuanceContext", () => {
    it("derives automatic behavior without loading learner facts", async () => {
      mockedFindActiveBadgeIssuanceRuleVersion.mockResolvedValue(
        sampleRuleVersionWithTiming("immediate"),
      );

      const context = await prepareLtiRosterRuleIssuanceContext(bulkContextInput());

      expect(context.issuanceBehavior.key).toBe("immediate");
      expect(mockedLoadRuleFacts).not.toHaveBeenCalled();
    });

    it("uses shared no-rule-linked detail for unresolved placements", async () => {
      mockedFindLtiResourceLinkPlacement.mockResolvedValue(null);

      const context = await prepareLtiRosterRuleIssuanceContext(bulkContextInput());

      expect(context.ruleResolution).toMatchObject({
        status: "rule_pending",
        detail: LTI_ROSTER_NO_RULE_LINKED_DETAIL,
      });
      expect(context.issuanceBehavior.detail).toBe(LTI_ROSTER_NO_RULE_LINKED_DETAIL);
    });
  });

  describe("prepareLtiRosterBulkIssuanceContext", () => {
    it("evaluates member eligibility for rendering even when manual issuance is blocked", async () => {
      mockedFindActiveBadgeIssuanceRuleVersion.mockResolvedValue(
        sampleRuleVersionWithTiming("immediate"),
      );

      const context = await prepareLtiRosterBulkIssuanceContext(bulkContextInput());

      expect(context.eligibilityByUserId.get("learner-001")).toMatchObject({
        status: "eligible",
      });
      expect(mockedLoadRuleFacts).toHaveBeenCalledOnce();
    });

    it("evaluates member eligibility for manual rules", async () => {
      mockedFindActiveBadgeIssuanceRuleVersion.mockResolvedValue(
        sampleRuleVersionWithTiming("manual"),
      );

      const context = await prepareLtiRosterBulkIssuanceContext(bulkContextInput());

      expect(context.eligibilityByUserId.get("learner-001")).toMatchObject({
        status: "eligible",
      });
      expect(mockedLoadRuleFacts).toHaveBeenCalledOnce();
    });

    it("returns unresolved placement eligibility for rendering", async () => {
      mockedFindLtiResourceLinkPlacement.mockResolvedValue(null);

      const context = await prepareLtiRosterBulkIssuanceContext(bulkContextInput());

      expect(context.ruleResolution).toMatchObject({
        status: "rule_pending",
        detail: LTI_ROSTER_NO_RULE_LINKED_DETAIL,
      });
      expect(context.issuanceBehavior.detail).toBe(LTI_ROSTER_NO_RULE_LINKED_DETAIL);
      expect(context.eligibilityByUserId.get("learner-001")).toMatchObject({
        status: "rule_pending",
        detail: LTI_ROSTER_NO_RULE_LINKED_DETAIL,
      });
    });
  });
});

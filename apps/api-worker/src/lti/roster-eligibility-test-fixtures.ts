import type {
  BadgeIssuanceRuleRecord,
  BadgeIssuanceRuleVersionRecord,
  LtiResourceLinkPlacementRecord,
} from "@credtrail/db";
import type { BadgeIssuanceRuleEvaluationFacts } from "../rules/engine";
import type { LtiNrpsMember } from "./nrps";

export const sampleLtiRosterMember = (overrides?: Partial<LtiNrpsMember>): LtiNrpsMember => ({
  userId: "learner-001",
  lisPersonSourcedId: "sourced-learner-001",
  displayName: "Learner One",
  email: "learner-one@example.edu",
  status: "Active",
  roles: ["Learner"],
  isLearner: true,
  isInstructor: false,
  ...overrides,
});

export const sampleLtiRosterBadgeRule = (
  overrides?: Partial<BadgeIssuanceRuleRecord>,
): BadgeIssuanceRuleRecord => ({
  id: "brl_123",
  tenantId: "tenant_123",
  name: "Course rule",
  description: null,
  badgeTemplateId: "badge_template_001",
  orgUnitId: "tenant_123:org:institution",
  ownerOrgUnitId: "tenant_123:org:institution",
  lmsProviderKind: "sakai",
  lmsConnectionId: "lms_sakai_001",
  activeVersionId: "brv_123",
  createdByUserId: "usr_123",
  createdAt: "2026-02-10T22:00:00.000Z",
  updatedAt: "2026-02-10T22:00:00.000Z",
  ...overrides,
});

export const sampleLtiRosterBadgeRuleVersion = (
  overrides?: Partial<BadgeIssuanceRuleVersionRecord>,
): BadgeIssuanceRuleVersionRecord => ({
  id: "brv_123",
  tenantId: "tenant_123",
  ruleId: "brl_123",
  versionNumber: 1,
  status: "active",
  ruleJson: JSON.stringify({
    conditions: {
      type: "grade_threshold",
      courseId: "course-123",
      scoreField: "final_score",
      minScore: 85,
    },
    options: {
      issuanceTiming: "manual",
      reviewOnMissingFacts: true,
    },
  }),
  changeSummary: null,
  createdByUserId: "usr_123",
  submittedByUserId: "usr_123",
  submittedAt: "2026-02-10T21:30:00.000Z",
  approvedByUserId: "usr_admin_123",
  approvedAt: "2026-02-10T22:00:00.000Z",
  activatedByUserId: "usr_admin_123",
  activatedAt: "2026-02-10T22:00:00.000Z",
  createdAt: "2026-02-10T22:00:00.000Z",
  updatedAt: "2026-02-10T22:00:00.000Z",
  ...overrides,
});

export const sampleLtiRosterResourceLinkPlacement = (
  overrides?: Partial<LtiResourceLinkPlacementRecord>,
): LtiResourceLinkPlacementRecord => ({
  id: "lti_place_123",
  tenantId: "tenant_123",
  issuer: "https://sakai.example.edu",
  clientId: "client-123",
  deploymentId: "deployment-123",
  contextId: "course-123",
  resourceLinkId: "resource-link-123",
  badgeTemplateId: "badge_template_001",
  ruleId: "brl_123",
  createdByUserId: "usr_instructor_123",
  createdAt: "2026-02-10T22:00:00.000Z",
  updatedAt: "2026-02-10T22:00:00.000Z",
  ...overrides,
});

export const sampleLtiRosterRuleEvaluationFacts = (
  finalScore: number | null,
): BadgeIssuanceRuleEvaluationFacts => ({
  learnerId: "learner-001",
  nowIso: "2026-02-10T22:00:00.000Z",
  grades:
    finalScore === null
      ? []
      : [
          {
            courseId: "course-123",
            learnerId: "learner-001",
            currentScore: finalScore,
            finalScore,
          },
        ],
  completions: [],
  submissions: [],
  surveyCompletions: [],
  customFields: [],
  earnedBadgeTemplateIds: [],
});

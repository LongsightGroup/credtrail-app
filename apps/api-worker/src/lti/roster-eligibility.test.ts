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

vi.mock("../routes/badge-rule-facts-loader", () => ({
  loadRuleFacts: vi.fn(),
}));

import {
  findActiveBadgeIssuanceRuleVersion,
  findBadgeIssuanceRuleById,
  findLtiResourceLinkPlacement,
  type BadgeIssuanceRuleRecord,
  type BadgeIssuanceRuleVersionRecord,
  type SqlDatabase,
} from "@credtrail/db";
import { loadRuleFacts } from "../routes/badge-rule-facts-loader";
import type { LtiNrpsMember } from "./nrps";
import {
  evaluateLtiRosterMemberEligibility,
  resolveLtiRosterEligibilityRuleContext,
} from "./roster-eligibility";

const mockedFindActiveBadgeIssuanceRuleVersion = vi.mocked(findActiveBadgeIssuanceRuleVersion);
const mockedFindBadgeIssuanceRuleById = vi.mocked(findBadgeIssuanceRuleById);
const mockedFindLtiResourceLinkPlacement = vi.mocked(findLtiResourceLinkPlacement);
const mockedLoadRuleFacts = vi.mocked(loadRuleFacts);

const fakeDb = {} as SqlDatabase;

const sampleMember = (overrides?: Partial<LtiNrpsMember>): LtiNrpsMember => ({
  userId: "learner-001",
  sourcedId: "sourced-learner-001",
  displayName: "Learner One",
  email: "learner-one@example.edu",
  status: "Active",
  pictureUrl: null,
  roles: ["Learner"],
  roleSummary: "Learner",
  isLearner: true,
  ...overrides,
});

const sampleRule = (overrides?: Partial<BadgeIssuanceRuleRecord>): BadgeIssuanceRuleRecord => ({
  id: "brl_123",
  tenantId: "tenant_123",
  name: "Course rule",
  description: null,
  badgeTemplateId: "badge_template_001",
  lmsProviderKind: "sakai",
  lmsConnectionId: "lms_sakai_001",
  activeVersionId: "brv_123",
  createdByUserId: "usr_123",
  createdAt: "2026-02-10T22:00:00.000Z",
  updatedAt: "2026-02-10T22:00:00.000Z",
  ...overrides,
});

const sampleVersion = (
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
      reviewOnMissingFacts: true,
    },
  }),
  changeSummary: null,
  createdByUserId: "usr_123",
  approvedByUserId: "usr_admin_123",
  approvedAt: "2026-02-10T22:00:00.000Z",
  activatedByUserId: "usr_admin_123",
  activatedAt: "2026-02-10T22:00:00.000Z",
  createdAt: "2026-02-10T22:00:00.000Z",
  updatedAt: "2026-02-10T22:00:00.000Z",
  ...overrides,
});

const facts = (finalScore: number | null) => ({
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

describe("LTI roster eligibility", () => {
  beforeEach(() => {
    mockedFindActiveBadgeIssuanceRuleVersion.mockReset();
    mockedFindBadgeIssuanceRuleById.mockReset();
    mockedFindLtiResourceLinkPlacement.mockReset();
    mockedLoadRuleFacts.mockReset();
    mockedFindBadgeIssuanceRuleById.mockResolvedValue(sampleRule());
    mockedFindActiveBadgeIssuanceRuleVersion.mockResolvedValue(sampleVersion());
  });

  it("uses the launch rule id before placement lookup", async () => {
    const result = await resolveLtiRosterEligibilityRuleContext({
      db: fakeDb,
      tenantId: "tenant_123",
      issuer: "https://sakai.example.edu",
      clientId: "client-123",
      deploymentId: "deployment-123",
      resourceLinkId: "resource-link-123",
      launchRuleId: "brl_launch",
    });

    expect(result.ruleId).toBe("brl_launch");
    expect(mockedFindLtiResourceLinkPlacement).not.toHaveBeenCalled();
  });

  it("marks learners with passing rule facts as eligible", async () => {
    mockedLoadRuleFacts.mockResolvedValue(facts(92));

    const result = await evaluateLtiRosterMemberEligibility({
      db: fakeDb,
      tenantId: "tenant_123",
      ruleId: "brl_123",
      member: sampleMember(),
      issuedState: null,
      nowIso: "2026-02-10T22:00:00.000Z",
    });

    expect(result).toMatchObject({
      status: "eligible",
      label: "Eligible",
      eligibleForIssuance: true,
    });
  });

  it("marks learners with failing rule facts as not yet eligible", async () => {
    mockedLoadRuleFacts.mockResolvedValue(facts(72));

    const result = await evaluateLtiRosterMemberEligibility({
      db: fakeDb,
      tenantId: "tenant_123",
      ruleId: "brl_123",
      member: sampleMember(),
      issuedState: null,
      nowIso: "2026-02-10T22:00:00.000Z",
    });

    expect(result).toMatchObject({
      status: "not_yet_eligible",
      label: "Not yet eligible",
      eligibleForIssuance: false,
    });
    expect(result.detail).toContain("below minimum");
  });

  it("marks missing gradebook facts as missing evidence", async () => {
    mockedLoadRuleFacts.mockResolvedValue(facts(null));

    const result = await evaluateLtiRosterMemberEligibility({
      db: fakeDb,
      tenantId: "tenant_123",
      ruleId: "brl_123",
      member: sampleMember(),
      issuedState: null,
      nowIso: "2026-02-10T22:00:00.000Z",
    });

    expect(result).toMatchObject({
      status: "missing_evidence",
      label: "Missing evidence",
      eligibleForIssuance: false,
    });
  });

  it("marks missing active rule versions as pending", async () => {
    mockedFindActiveBadgeIssuanceRuleVersion.mockResolvedValue(null);

    const result = await evaluateLtiRosterMemberEligibility({
      db: fakeDb,
      tenantId: "tenant_123",
      ruleId: "brl_123",
      member: sampleMember(),
      issuedState: null,
      nowIso: "2026-02-10T22:00:00.000Z",
    });

    expect(result).toMatchObject({
      status: "rule_pending",
      label: "Rule pending",
      eligibleForIssuance: false,
    });
  });

  it("keeps already-issued learners unselectable", async () => {
    const result = await evaluateLtiRosterMemberEligibility({
      db: fakeDb,
      tenantId: "tenant_123",
      ruleId: "brl_123",
      member: sampleMember(),
      issuedState: {
        assertionId: "assertion_123",
        issuedAt: "2026-02-10T22:00:00.000Z",
        lifecycleState: null,
      },
      nowIso: "2026-02-10T22:00:00.000Z",
    });

    expect(result).toMatchObject({
      status: "already_issued",
      label: "Already issued",
      eligibleForIssuance: false,
    });
    expect(mockedFindBadgeIssuanceRuleById).not.toHaveBeenCalled();
  });
});

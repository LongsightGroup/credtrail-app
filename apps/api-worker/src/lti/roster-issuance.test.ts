import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("@credtrail/db", async () => {
  const actual = await vi.importActual<typeof import("@credtrail/db")>("@credtrail/db");

  return {
    ...actual,
    findActiveBadgeIssuanceRuleVersion: vi.fn(),
    findBadgeIssuanceRuleById: vi.fn(),
    findLtiResourceLinkPlacement: vi.fn(),
    listAssertionsByIdempotencyKeys: vi.fn(),
    listAssertionLifecycleStatesByAssertionIds: vi.fn(),
  };
});

vi.mock("../routes/badge-rule-facts-loader", () => ({
  loadRuleFacts: vi.fn(),
}));

import {
  findActiveBadgeIssuanceRuleVersion,
  findBadgeIssuanceRuleById,
  findLtiResourceLinkPlacement,
  listAssertionLifecycleStatesByAssertionIds,
  listAssertionsByIdempotencyKeys,
  type BadgeIssuanceRuleRecord,
  type BadgeIssuanceRuleVersionRecord,
  type LtiResourceLinkPlacementRecord,
  type SqlDatabase,
} from "@credtrail/db";
import type { LTISession, LTITool } from "@lti-tool/core";
import { loadRuleFacts } from "../routes/badge-rule-facts-loader";
import { executeLtiRosterIssuance } from "./roster-issuance";

const mockedFindActiveBadgeIssuanceRuleVersion = vi.mocked(findActiveBadgeIssuanceRuleVersion);
const mockedFindBadgeIssuanceRuleById = vi.mocked(findBadgeIssuanceRuleById);
const mockedFindLtiResourceLinkPlacement = vi.mocked(findLtiResourceLinkPlacement);
const mockedListAssertionLifecycleStatesByAssertionIds = vi.mocked(
  listAssertionLifecycleStatesByAssertionIds,
);
const mockedListAssertionsByIdempotencyKeys = vi.mocked(listAssertionsByIdempotencyKeys);
const mockedLoadRuleFacts = vi.mocked(loadRuleFacts);

const fakeDb = {} as SqlDatabase;

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

const samplePlacement = (
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

const ltiSession = {
  id: "lti-session-123",
  context: {
    id: "course-123",
    title: "TypeScript 101",
  },
  platform: {
    issuer: "https://sakai.example.edu",
    clientId: "client-123",
    deploymentId: "deployment-123",
  },
  resourceLink: {
    id: "resource-link-123",
  },
} as LTISession;

const mockedGetMembers = vi.fn();
const ltiTool = {
  getMembers: mockedGetMembers,
} as unknown as LTITool;

const appContext = {} as Parameters<typeof executeLtiRosterIssuance>[0]["c"];

const facts = (finalScore: number) => ({
  learnerId: "learner-001",
  nowIso: "2026-02-10T22:00:00.000Z",
  grades: [
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

describe("executeLtiRosterIssuance eligibility guard", () => {
  beforeEach(() => {
    mockedGetMembers.mockReset();
    mockedGetMembers.mockResolvedValue([
      {
        status: "Active",
        name: "Learner One",
        email: "learner-one@example.edu",
        userId: "learner-001",
        lisPersonSourcedId: "sourced-learner-001",
        roles: ["http://purl.imsglobal.org/vocab/lis/v2/membership#Learner"],
      },
    ]);
    mockedFindActiveBadgeIssuanceRuleVersion.mockReset();
    mockedFindActiveBadgeIssuanceRuleVersion.mockResolvedValue(sampleVersion());
    mockedFindBadgeIssuanceRuleById.mockReset();
    mockedFindBadgeIssuanceRuleById.mockResolvedValue(sampleRule());
    mockedFindLtiResourceLinkPlacement.mockReset();
    mockedFindLtiResourceLinkPlacement.mockResolvedValue(samplePlacement());
    mockedListAssertionLifecycleStatesByAssertionIds.mockReset();
    mockedListAssertionLifecycleStatesByAssertionIds.mockResolvedValue([]);
    mockedListAssertionsByIdempotencyKeys.mockReset();
    mockedListAssertionsByIdempotencyKeys.mockResolvedValue([]);
    mockedLoadRuleFacts.mockReset();
  });

  it("issues eligible selected learners", async () => {
    mockedLoadRuleFacts.mockResolvedValue(facts(92));
    const issueBadgeForTenant = vi.fn().mockResolvedValue({
      status: "issued",
      assertionId: "assertion_123",
    });

    const result = await executeLtiRosterIssuance({
      c: appContext,
      db: fakeDb,
      ltiTool,
      ltiSession,
      issuanceAction: {
        tenantId: "tenant_123",
        ltiSessionId: "lti-session-123",
        issuer: "https://sakai.example.edu",
        clientId: "client-123",
        deploymentId: "deployment-123",
        contextId: "course-123",
        resourceLinkId: "resource-link-123",
        badgeTemplateId: "badge_template_001",
        issuedByUserId: "usr_instructor_123",
        exp: 1780000000,
      },
      selectedLearnerUserIds: ["learner-001"],
      sha256Hex: async () => "digest_123",
      issueBadgeForTenant,
    });

    expect(result.results[0]).toMatchObject({
      status: "issued",
      assertionId: "assertion_123",
    });
    expect(issueBadgeForTenant).toHaveBeenCalledOnce();
  });

  it("skips ineligible selected learners", async () => {
    mockedLoadRuleFacts.mockResolvedValue(facts(72));
    const issueBadgeForTenant = vi.fn();

    const result = await executeLtiRosterIssuance({
      c: appContext,
      db: fakeDb,
      ltiTool,
      ltiSession,
      issuanceAction: {
        tenantId: "tenant_123",
        ltiSessionId: "lti-session-123",
        issuer: "https://sakai.example.edu",
        clientId: "client-123",
        deploymentId: "deployment-123",
        contextId: "course-123",
        resourceLinkId: "resource-link-123",
        badgeTemplateId: "badge_template_001",
        issuedByUserId: "usr_instructor_123",
        exp: 1780000000,
      },
      selectedLearnerUserIds: ["learner-001"],
      sha256Hex: async () => "digest_123",
      issueBadgeForTenant,
    });

    expect(result.results[0]).toMatchObject({
      status: "skipped",
    });
    expect(result.results[0]?.message).toContain("below minimum");
    expect(issueBadgeForTenant).not.toHaveBeenCalled();
  });
});

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

vi.mock("../rules/badge-rule-facts-loader", () => ({
  loadRuleFacts: vi.fn(),
}));

import {
  findActiveBadgeIssuanceRuleVersion,
  findBadgeIssuanceRuleById,
  findLtiResourceLinkPlacement,
  listAssertionLifecycleStatesByAssertionIds,
  listAssertionsByIdempotencyKeys,
  type SqlDatabase,
} from "@credtrail/db";
import type { LTISession } from "@longsightgroup/lti-tool";
import { loadRuleFacts } from "../rules/badge-rule-facts-loader";
import { executeLtiRosterIssuance } from "./roster-issuance";
import { mockLtiToolWithGetMembers } from "./test-support/lti-tool-mocks";
import {
  sampleLtiRosterBadgeRule,
  sampleLtiRosterBadgeRuleVersion,
  sampleLtiRosterResourceLinkPlacement,
  sampleLtiRosterRuleEvaluationFacts,
} from "./roster-eligibility-test-fixtures";

const mockedFindActiveBadgeIssuanceRuleVersion = vi.mocked(findActiveBadgeIssuanceRuleVersion);
const mockedFindBadgeIssuanceRuleById = vi.mocked(findBadgeIssuanceRuleById);
const mockedFindLtiResourceLinkPlacement = vi.mocked(findLtiResourceLinkPlacement);
const mockedListAssertionLifecycleStatesByAssertionIds = vi.mocked(
  listAssertionLifecycleStatesByAssertionIds,
);
const mockedListAssertionsByIdempotencyKeys = vi.mocked(listAssertionsByIdempotencyKeys);
const mockedLoadRuleFacts = vi.mocked(loadRuleFacts);

const fakeDb = {} as SqlDatabase;

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
const ltiTool = mockLtiToolWithGetMembers(mockedGetMembers);

const appContext = {
  get: () => undefined,
} as unknown as Parameters<typeof executeLtiRosterIssuance>[0]["c"];

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

describe("executeLtiRosterIssuance eligibility guard", () => {
  beforeEach(() => {
    mockedGetMembers.mockReset();
    mockedGetMembers.mockResolvedValue({
      success: true,
      data: [
        {
          status: "Active",
          name: "Learner One",
          email: "learner-one@example.edu",
          userId: "learner-001",
          lisPersonSourcedId: "sourced-learner-001",
          roles: ["http://purl.imsglobal.org/vocab/lis/v2/membership#Learner"],
        },
      ],
    });
    mockedFindActiveBadgeIssuanceRuleVersion.mockReset();
    mockedFindActiveBadgeIssuanceRuleVersion.mockResolvedValue(sampleLtiRosterBadgeRuleVersion());
    mockedFindBadgeIssuanceRuleById.mockReset();
    mockedFindBadgeIssuanceRuleById.mockResolvedValue(sampleLtiRosterBadgeRule());
    mockedFindLtiResourceLinkPlacement.mockReset();
    mockedFindLtiResourceLinkPlacement.mockResolvedValue(sampleLtiRosterResourceLinkPlacement());
    mockedListAssertionLifecycleStatesByAssertionIds.mockReset();
    mockedListAssertionLifecycleStatesByAssertionIds.mockResolvedValue([]);
    mockedListAssertionsByIdempotencyKeys.mockReset();
    mockedListAssertionsByIdempotencyKeys.mockResolvedValue([]);
    mockedLoadRuleFacts.mockReset();
  });

  it("issues eligible selected learners", async () => {
    mockedLoadRuleFacts.mockResolvedValue(sampleLtiRosterRuleEvaluationFacts(92));
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
    expect(issueBadgeForTenant).toHaveBeenCalledWith(
      appContext,
      "tenant_123",
      expect.objectContaining({
        issuanceProvenance: expect.objectContaining({
          source: "lti_roster",
          ruleId: expect.any(String),
          versionId: expect.any(String),
          provenanceJson: expect.any(String),
        }),
      }),
      "usr_instructor_123",
      { recipientDisplayName: "Learner One" },
    );
    expect(mockedFindLtiResourceLinkPlacement).toHaveBeenCalledOnce();
    expect(mockedFindBadgeIssuanceRuleById).toHaveBeenCalledOnce();
  });

  it("skips ineligible selected learners", async () => {
    mockedLoadRuleFacts.mockResolvedValue(sampleLtiRosterRuleEvaluationFacts(72));
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

  it("refuses edited form payloads under automatic rules", async () => {
    mockedFindActiveBadgeIssuanceRuleVersion.mockResolvedValue(
      sampleRuleVersionWithTiming("immediate"),
    );
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
    expect(result.results[0]?.message).toContain("awarded automatically");
    expect(issueBadgeForTenant).not.toHaveBeenCalled();
    expect(mockedLoadRuleFacts).not.toHaveBeenCalled();
  });

  it("refuses edited form payloads under end-of-term rules", async () => {
    mockedFindActiveBadgeIssuanceRuleVersion.mockResolvedValue(
      sampleRuleVersionWithTiming("end_of_term"),
    );
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
    expect(result.results[0]?.message).toContain("end-of-term batch");
    expect(issueBadgeForTenant).not.toHaveBeenCalled();
    expect(mockedLoadRuleFacts).not.toHaveBeenCalled();
  });

  it("skips learners without email using eligibility messaging", async () => {
    mockedGetMembers.mockResolvedValue({
      success: true,
      data: [
        {
          status: "Active",
          name: "Learner One",
          userId: "learner-001",
          lisPersonSourcedId: "sourced-learner-001",
          roles: ["http://purl.imsglobal.org/vocab/lis/v2/membership#Learner"],
        },
      ],
    });
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
    expect(result.results[0]?.message).toContain("email address");
    expect(issueBadgeForTenant).not.toHaveBeenCalled();
    expect(mockedLoadRuleFacts).not.toHaveBeenCalled();
  });
});

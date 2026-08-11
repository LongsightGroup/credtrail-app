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
import {
  evaluateLtiRosterMemberEligibility,
  evaluateLtiRosterMembersEligibility,
  ltiBulkIssuanceRosterLoadedMessage,
  prepareLtiRosterEligibilityEvaluationContext,
  resolveLtiRosterEligibilityRuleContext,
} from "./roster-eligibility";
import {
  sampleLtiRosterBadgeRule,
  sampleLtiRosterBadgeRuleVersion,
  sampleLtiRosterMember,
  sampleLtiRosterRuleEvaluationFacts,
} from "./roster-eligibility-test-fixtures";

const mockedFindActiveBadgeIssuanceRuleVersion = vi.mocked(findActiveBadgeIssuanceRuleVersion);
const mockedFindBadgeIssuanceRuleById = vi.mocked(findBadgeIssuanceRuleById);
const mockedFindLtiResourceLinkPlacement = vi.mocked(findLtiResourceLinkPlacement);
const mockedLoadRuleFacts = vi.mocked(loadRuleFacts);

const fakeDb = {} as SqlDatabase;

describe("LTI roster eligibility", () => {
  beforeEach(() => {
    mockedFindActiveBadgeIssuanceRuleVersion.mockReset();
    mockedFindBadgeIssuanceRuleById.mockReset();
    mockedFindLtiResourceLinkPlacement.mockReset();
    mockedLoadRuleFacts.mockReset();
    mockedFindBadgeIssuanceRuleById.mockResolvedValue(sampleLtiRosterBadgeRule());
    mockedFindActiveBadgeIssuanceRuleVersion.mockResolvedValue(sampleLtiRosterBadgeRuleVersion());
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

    expect(result).toEqual({
      status: "resolved",
      ruleId: "brl_launch",
    });
    expect(mockedFindLtiResourceLinkPlacement).not.toHaveBeenCalled();
  });

  it("marks placement lookup failures as unavailable", async () => {
    mockedFindLtiResourceLinkPlacement.mockRejectedValue(new Error("database unavailable"));

    const result = await resolveLtiRosterEligibilityRuleContext({
      db: fakeDb,
      tenantId: "tenant_123",
      issuer: "https://sakai.example.edu",
      clientId: "client-123",
      deploymentId: "deployment-123",
      resourceLinkId: "resource-link-123",
      launchRuleId: null,
    });

    expect(result).toMatchObject({
      status: "unavailable",
    });
  });

  it("marks learners with passing rule facts as eligible", async () => {
    mockedLoadRuleFacts.mockResolvedValue(sampleLtiRosterRuleEvaluationFacts(92));

    const result = await evaluateLtiRosterMemberEligibility({
      db: fakeDb,
      tenantId: "tenant_123",
      ruleResolution: { status: "resolved", ruleId: "brl_123" },
      member: sampleLtiRosterMember(),
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
    mockedLoadRuleFacts.mockResolvedValue(sampleLtiRosterRuleEvaluationFacts(72));

    const result = await evaluateLtiRosterMemberEligibility({
      db: fakeDb,
      tenantId: "tenant_123",
      ruleResolution: { status: "resolved", ruleId: "brl_123" },
      member: sampleLtiRosterMember(),
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
    mockedLoadRuleFacts.mockResolvedValue(sampleLtiRosterRuleEvaluationFacts(null));

    const result = await evaluateLtiRosterMemberEligibility({
      db: fakeDb,
      tenantId: "tenant_123",
      ruleResolution: { status: "resolved", ruleId: "brl_123" },
      member: sampleLtiRosterMember(),
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
      ruleResolution: { status: "resolved", ruleId: "brl_123" },
      member: sampleLtiRosterMember(),
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
      ruleResolution: { status: "resolved", ruleId: "brl_123" },
      member: sampleLtiRosterMember(),
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

  it("prepares rule context once for roster batch evaluation", async () => {
    mockedLoadRuleFacts.mockResolvedValue(sampleLtiRosterRuleEvaluationFacts(92));
    const members = [
      sampleLtiRosterMember({ userId: "learner-001" }),
      sampleLtiRosterMember({ userId: "learner-002", email: "learner-two@example.edu" }),
    ];

    const eligibilityByUserId = await evaluateLtiRosterMembersEligibility({
      db: fakeDb,
      tenantId: "tenant_123",
      ruleResolution: { status: "resolved", ruleId: "brl_123" },
      members,
      issuedStatesByUserId: new Map(),
      nowIso: "2026-02-10T22:00:00.000Z",
    });

    expect(eligibilityByUserId.get("learner-001")).toMatchObject({ status: "eligible" });
    expect(eligibilityByUserId.get("learner-002")).toMatchObject({ status: "eligible" });
    expect(mockedFindBadgeIssuanceRuleById).toHaveBeenCalledTimes(1);
    expect(mockedFindActiveBadgeIssuanceRuleVersion).toHaveBeenCalledTimes(1);
    expect(mockedLoadRuleFacts).toHaveBeenCalledTimes(2);
  });

  it("preserves already-issued learners when placement lookup fails", async () => {
    const eligibilityByUserId = await evaluateLtiRosterMembersEligibility({
      db: fakeDb,
      tenantId: "tenant_123",
      ruleResolution: {
        status: "unavailable",
        detail: "CredTrail could not load the course placement for this resource link.",
      },
      members: [sampleLtiRosterMember()],
      issuedStatesByUserId: new Map([
        [
          "learner-001",
          {
            assertionId: "assertion_123",
            issuedAt: "2026-02-10T22:00:00.000Z",
            lifecycleState: null,
          },
        ],
      ]),
      nowIso: "2026-02-10T22:00:00.000Z",
    });

    expect(eligibilityByUserId.get("learner-001")).toMatchObject({
      status: "already_issued",
    });
    expect(mockedFindBadgeIssuanceRuleById).not.toHaveBeenCalled();
  });

  it("uses provider-agnostic roster loaded messaging when evidence is unavailable", () => {
    const message = ltiBulkIssuanceRosterLoadedMessage({
      learnerCount: 2,
      eligibilityResults: [
        {
          status: "eligible",
          label: "Eligible",
          detail: "Meets the active badge rule.",
          eligibleForIssuance: true,
        },
        {
          status: "unavailable",
          label: "Unavailable",
          detail: "Gradebook unavailable.",
          eligibleForIssuance: false,
        },
      ],
    });

    expect(message).toContain("rule evidence could not be loaded");
    expect(message).not.toContain("Sakai");
  });

  it("prepares evaluation from the active version snapshot instead of mutable rule metadata", async () => {
    mockedFindBadgeIssuanceRuleById.mockResolvedValue(
      sampleLtiRosterBadgeRule({
        lmsProviderKind: "canvas",
        lmsConnectionId: "lms_replacement",
      }),
    );
    mockedFindActiveBadgeIssuanceRuleVersion.mockResolvedValue(
      sampleLtiRosterBadgeRuleVersion({
        snapshot: {
          ...sampleLtiRosterBadgeRuleVersion().snapshot,
          lmsProviderKind: "sakai",
          lmsConnectionId: "lms_historical",
        },
      }),
    );

    await expect(
      prepareLtiRosterEligibilityEvaluationContext({
        db: fakeDb,
        tenantId: "tenant_123",
        ruleId: "brl_123",
      }),
    ).resolves.toMatchObject({
      status: "ready",
      lmsProviderKind: "sakai",
      lmsConnectionId: "lms_historical",
    });
  });
});

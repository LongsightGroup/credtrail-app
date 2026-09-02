import type { SqlDatabase } from "@credtrail/db";
import {
  LTI_CLAIM_DEPLOYMENT_ID,
  LTI_CLAIM_MESSAGE_TYPE,
  LTI_CLAIM_TARGET_LINK_URI,
  LTI_CLAIM_VERSION,
  LTI_MESSAGE_TYPE_RESOURCE_LINK_REQUEST,
  type LTI13JwtPayload as LtiLaunchClaims,
  type LTISession,
} from "@longsightgroup/lti-tool";
import { describe, expect, it } from "vitest";
import {
  createInstructorBulkIssuanceViewResolver,
  emptyInstructorBulkIssuanceView,
  resolveInstructorBulkIssuanceView,
} from "./instructor-bulk-issuance-view";
import type { LtiRosterBulkIssuanceContext } from "./roster-bulk-issuance-context";
import type { LtiRosterIssuanceBehavior } from "./issuance-behavior";
import type { LtiNrpsMember, LtiNrpsRoster } from "./nrps";
import type { ResourceLinkLaunchMessage } from "./resource-link-launch-types";
import type { LtiBadgeSummaryCard } from "./view-models";

const fakeDb: SqlDatabase = {
  prepare(sql: string): never {
    throw new Error(`Unexpected SQL in instructor bulk issuance view test: ${sql}`);
  },
};

const nowIso = "2026-02-10T22:00:00.000Z";
const tenantId = "tenant_123";
const issuer = "https://sakai.example.edu";
const clientId = "client-123";
const deploymentId = "deployment-123";
const contextId = "course-123";
const resourceLinkId = "resource-link-123";

const selectedBadge: LtiBadgeSummaryCard = {
  badgeTemplateId: "badge_template_001",
  title: "TypeScript Foundations",
  summary: "Awarded for completing TypeScript fundamentals.",
  imageUri: "https://example.edu/image.png",
  criteriaPath: "/tenants/tenant_123/badges/badge_template_001/criteria",
};

const learnerMember = (overrides: Partial<LtiNrpsMember> = {}): LtiNrpsMember => {
  return {
    userId: "learner-001",
    lisPersonSourcedId: "sourced-learner-001",
    displayName: "Learner One",
    email: "learner-one@example.edu",
    status: "Active",
    roles: ["Learner"],
    isLearner: true,
    isInstructor: false,
    ...overrides,
  };
};

const roster = (): LtiNrpsRoster => {
  const learner = learnerMember();
  const instructor = learnerMember({
    userId: "instructor-001",
    displayName: "Instructor One",
    email: "instructor@example.edu",
    roles: ["Instructor"],
    isLearner: false,
    isInstructor: true,
  });

  return {
    contextId,
    members: [learner, instructor],
    learnerMembers: [learner],
  };
};

const launchClaims = (): LtiLaunchClaims => {
  return {
    iss: issuer,
    sub: "instructor-001",
    aud: clientId,
    exp: 1_800_000_000,
    iat: 1_700_000_000,
    nonce: "nonce-123",
    [LTI_CLAIM_MESSAGE_TYPE]: LTI_MESSAGE_TYPE_RESOURCE_LINK_REQUEST,
    [LTI_CLAIM_VERSION]: "1.3.0",
    [LTI_CLAIM_DEPLOYMENT_ID]: deploymentId,
    [LTI_CLAIM_TARGET_LINK_URI]: "https://tool.example.edu/v1/lti/launch",
  };
};

const ltiSession = (): LTISession => {
  return {
    jwtPayload: {
      iss: issuer,
      sub: "instructor-001",
      aud: clientId,
      exp: 1_800_000_000,
      iat: 1_700_000_000,
      nonce: "nonce-123",
      [LTI_CLAIM_MESSAGE_TYPE]: LTI_MESSAGE_TYPE_RESOURCE_LINK_REQUEST,
      [LTI_CLAIM_VERSION]: "1.3.0",
      [LTI_CLAIM_DEPLOYMENT_ID]: deploymentId,
      [LTI_CLAIM_TARGET_LINK_URI]: "https://tool.example.edu/v1/lti/launch",
    },
    id: "lti-session-123",
    user: {
      id: "instructor-001",
      roles: ["http://purl.imsglobal.org/vocab/lis/v2/membership#Instructor"],
    },
    context: {
      id: contextId,
      label: "COURSE123",
      title: "Course 123",
    },
    platform: {
      issuer,
      clientId,
      deploymentId,
      name: "Sakai",
    },
    launch: {
      target: "https://tool.example.edu/v1/lti/launch",
    },
    resourceLink: {
      id: resourceLinkId,
    },
    customParameters: {},
    isAdmin: false,
    isInstructor: true,
    isStudent: false,
    isAssignmentAndGradesAvailable: false,
    isDeepLinkingAvailable: false,
    isNameAndRolesAvailable: true,
  };
};

const launchMessage = (): ResourceLinkLaunchMessage => {
  return {
    kind: "resource-link",
    messageType: LTI_MESSAGE_TYPE_RESOURCE_LINK_REQUEST,
    roleKind: "instructor",
    resolvedTargetLinkUri: "https://tool.example.edu/v1/lti/launch",
    resourceLinkId,
    resourceContextId: contextId,
    badgeTemplateId: selectedBadge.badgeTemplateId,
    ruleId: "brl_123",
  };
};

const manualBehavior: LtiRosterIssuanceBehavior = {
  key: "manual",
  label: "Instructor confirmation",
  detail: "Eligible learners can be selected and issued from this course roster.",
  manualIssuanceAllowed: true,
};

const automaticBehavior: LtiRosterIssuanceBehavior = {
  key: "immediate",
  label: "Automatic",
  detail:
    "This badge is awarded automatically when learners meet the active rule. Roster issuing is not available for this placement.",
  manualIssuanceAllowed: false,
};

const bulkContext = (issuanceBehavior: LtiRosterIssuanceBehavior): LtiRosterBulkIssuanceContext => {
  return {
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
          courseId: contextId,
          scoreField: "final_score",
          minScore: 85,
        },
        options: { issuanceTiming: issuanceBehavior.key === "manual" ? "manual" : "immediate" },
      },
      issuanceBehavior,
    },
    issuanceBehavior,
    eligibilityByUserId: new Map([
      [
        "learner-001",
        {
          status: "eligible",
          label: "Eligible",
          detail: "Meets the active badge rule.",
          eligibleForIssuance: true,
        },
      ],
    ]),
    rosterLoadedMessage: "1 learner is eligible for issuance.",
  };
};

const resolveViewInput = (
  overrides: Partial<Parameters<typeof resolveInstructorBulkIssuanceView>[0]> = {},
): Parameters<typeof resolveInstructorBulkIssuanceView>[0] => {
  return {
    db: fakeDb,
    env: { LTI_STATE_SIGNING_SECRET: "test-lti-state-secret" },
    tenantId,
    launchClaims: launchClaims(),
    launchMessage: launchMessage(),
    ltiLaunchSession: ltiSession(),
    roster: roster(),
    issuerClientId: clientId,
    resolvedRuleId: "brl_123",
    linkedUserId: "instructor-user-123",
    selectedBadge,
    courseContextTitle: "Course 123",
    courseContextId: contextId,
    contextMembershipsUrl: "https://sakai.example.edu/roster",
    sha256Hex: async (value: string) => `sha256:${value}`,
    sessionHandoffTtlSeconds: 900,
    nowIso,
    ...overrides,
  };
};

describe("emptyInstructorBulkIssuanceView", () => {
  it("builds a degraded roster view without issuance actions", () => {
    expect(
      emptyInstructorBulkIssuanceView({
        status: "unavailable",
        message: "Roster is unavailable.",
        selectedBadge,
        courseContextTitle: "Course 123",
        courseContextId: contextId,
        contextMembershipsUrl: null,
      }),
    ).toMatchObject({
      status: "unavailable",
      message: "Roster is unavailable.",
      learnerCount: 0,
      totalCount: 0,
      issuanceBehaviorKey: "unavailable",
      manualIssuanceAllowed: false,
      issuanceActionPath: null,
      issuanceActionToken: null,
      members: [],
    });
  });
});

describe("resolveInstructorBulkIssuanceView", () => {
  it("builds a ready roster view without an action token when manual issuance is disallowed", async () => {
    const resolveWithTestDependencies = createInstructorBulkIssuanceViewResolver({
      loadIssuedBadgeStatesByUserId: async (lookup) => {
        expect(lookup.action.contextId).toBe(contextId);
        expect(lookup.learnerMembers.map((member) => member.userId)).toEqual(["learner-001"]);
        return new Map([
          [
            "learner-001",
            {
              assertionId: "assertion-001",
              issuedAt: "2026-02-11T14:00:00.000Z",
              lifecycleState: "active",
            },
          ],
        ]);
      },
      prepareBulkIssuanceContext: async (contextInput) => {
        expect(contextInput.nowIso).toBe(nowIso);
        return bulkContext(automaticBehavior);
      },
      createIssuanceActionToken: async (env, tokenInput) => {
        throw new Error(
          `Unexpected issuance token for ${env.LTI_STATE_SIGNING_SECRET ?? ""}:${tokenInput.badgeTemplateId}`,
        );
      },
    });

    const view = await resolveWithTestDependencies(resolveViewInput());

    expect(view).toMatchObject({
      status: "ready",
      message: "1 learner is eligible for issuance.",
      learnerCount: 1,
      totalCount: 2,
      issuanceBehaviorKey: "immediate",
      manualIssuanceAllowed: false,
      issuanceActionPath: null,
      issuanceActionToken: null,
    });
    expect(view.members).toEqual([
      expect.objectContaining({
        userId: "learner-001",
        eligibilityStatus: "eligible",
        issuedAssertionId: "assertion-001",
        issuanceLifecycleState: "active",
      }),
    ]);
  });

  it("attaches an issuance action when manual issuance is allowed", async () => {
    const resolveWithTestDependencies = createInstructorBulkIssuanceViewResolver({
      loadIssuedBadgeStatesByUserId: async (lookup) => {
        expect(lookup.action.badgeTemplateId).toBe(selectedBadge.badgeTemplateId);
        return new Map();
      },
      prepareBulkIssuanceContext: async (contextInput) => {
        expect(contextInput.launchRuleId).toBe("brl_123");
        return bulkContext(manualBehavior);
      },
      createIssuanceActionToken: async (env, tokenInput) => {
        expect(env.LTI_STATE_SIGNING_SECRET).toBe("test-lti-state-secret");
        expect(tokenInput).toMatchObject({
          tenantId,
          ltiSessionId: "lti-session-123",
          contextId,
          resourceLinkId,
          badgeTemplateId: selectedBadge.badgeTemplateId,
          issuedByUserId: "instructor-user-123",
          ttlSeconds: 900,
        });
        return "issuance-token-123";
      },
    });

    const view = await resolveWithTestDependencies(resolveViewInput());

    expect(view.issuanceActionPath).toBe("/v1/lti/resource-link/issue");
    expect(view.issuanceActionToken).toBe("issuance-token-123");
    expect(view.manualIssuanceAllowed).toBe(true);
  });
});

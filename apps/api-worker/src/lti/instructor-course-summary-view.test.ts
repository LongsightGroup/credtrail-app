import type {
  AssertionRecord,
  BadgeTemplateRecord,
  LtiResourceLinkPlacementRecord,
  SqlDatabase,
} from "@credtrail/db";
import {
  LTI_CLAIM_DEPLOYMENT_ID,
  LTI_CLAIM_MESSAGE_TYPE,
  LTI_CLAIM_TARGET_LINK_URI,
  LTI_CLAIM_VERSION,
  LTI_MESSAGE_TYPE_RESOURCE_LINK_REQUEST,
  type LTI13JwtPayload as LtiLaunchClaims,
} from "@longsightgroup/lti-tool";
import { describe, expect, it } from "vitest";
import type { LtiCourseBadgeTemplatePlacementGroup } from "./course-badge-placements";
import {
  emptyInstructorCourseBadgeSummaryView,
  resolveInstructorCourseBadgeSummaryView,
  type InstructorCourseSummaryViewDependencies,
} from "./instructor-course-summary-view";
import type { LtiNrpsMember, LtiNrpsRoster } from "./nrps";

const fakeDb: SqlDatabase = {
  prepare(sql: string): never {
    throw new Error(`Unexpected SQL in instructor course summary view test: ${sql}`);
  },
};

const tenantId = "tenant_123";
const issuer = "https://sakai.example.edu";
const clientId = "client-123";
const deploymentId = "deployment-123";
const contextId = "course-123";
const resourceLinkId = "resource-link-123";
const badgeTemplateId = "badge_template_001";

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

const badgeTemplate = (overrides: Partial<BadgeTemplateRecord> = {}): BadgeTemplateRecord => {
  return {
    id: badgeTemplateId,
    tenantId,
    slug: "typescript-foundations",
    title: "TypeScript Foundations",
    description: "Awarded for completing TypeScript fundamentals.",
    criteriaUri: "https://example.edu/criteria",
    imageUri: "https://example.edu/image.png",
    createdByUserId: "usr_123",
    ownerOrgUnitId: "tenant_123:org:institution",
    governanceMetadataJson: null,
    isArchived: false,
    createdAt: "2026-02-10T22:00:00.000Z",
    updatedAt: "2026-02-10T22:00:00.000Z",
    ...overrides,
  };
};

const placement = (
  overrides: Partial<LtiResourceLinkPlacementRecord> = {},
): LtiResourceLinkPlacementRecord => {
  return {
    id: "lti_place_123",
    tenantId,
    issuer,
    clientId,
    deploymentId,
    contextId,
    resourceLinkId,
    badgeTemplateId,
    ruleId: "brl_123",
    createdByUserId: "usr_instructor_123",
    createdAt: "2026-02-10T22:00:00.000Z",
    updatedAt: "2026-02-10T22:00:00.000Z",
    ...overrides,
  };
};

const placementGroup = (): LtiCourseBadgeTemplatePlacementGroup => {
  const template = badgeTemplate();
  const primaryPlacement = placement();

  return {
    badgeTemplateId,
    template,
    primaryPlacement,
    placements: [primaryPlacement],
  };
};

const learnerMember = (overrides: Partial<LtiNrpsMember> = {}): LtiNrpsMember => {
  return {
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
  };
};

const roster = (): LtiNrpsRoster => {
  const learnerOne = learnerMember();
  const learnerTwo = learnerMember({
    userId: "learner-002",
    sourcedId: "sourced-learner-002",
    displayName: "Learner Two",
    email: "learner-two@example.edu",
  });

  return {
    contextId,
    members: [learnerOne, learnerTwo],
    learnerMembers: [learnerOne, learnerTwo],
  };
};

const assertion = (overrides: Partial<AssertionRecord> = {}): AssertionRecord => {
  return {
    id: "assertion-001",
    tenantId,
    publicId: "public-assertion-001",
    learnerProfileId: "learner_profile_001",
    badgeTemplateId,
    recipientIdentity: "learner-one@example.edu",
    recipientIdentityType: "email",
    vcR2Key: "credentials/assertion-001.json",
    statusListIndex: 1,
    idempotencyKey: "idempotency-001",
    issuedAt: "2026-02-11T14:00:00.000Z",
    issuedByUserId: "usr_instructor_123",
    revokedAt: null,
    createdAt: "2026-02-11T14:00:00.000Z",
    updatedAt: "2026-02-11T14:00:00.000Z",
    ...overrides,
  };
};

const dependencies = (): InstructorCourseSummaryViewDependencies => {
  const group = placementGroup();

  return {
    resolveCourseBadgePlacements: async (input) => {
      expect(input.contextId).toBe(contextId);
      expect(input.issuerClientId).toBe(clientId);
      return {
        contextId,
        placements: group.placements,
        orderedTemplates: [group.template],
        placementGroups: [group],
      };
    },
    listBadgeTemplateRecipientAssertions: async (db, input) => {
      expect(db).toBe(fakeDb);
      expect(input).toMatchObject({
        tenantId,
        badgeTemplateIds: [badgeTemplateId],
        recipientEmails: ["learner-one@example.edu", "learner-two@example.edu"],
      });
      return [assertion()];
    },
    listAssertionLifecycleStates: async (db, input) => {
      expect(db).toBe(fakeDb);
      expect(input.assertionIds).toEqual(["assertion-001"]);
      return [
        {
          assertionId: "assertion-001",
          state: "active",
          source: "default_active",
          reasonCode: null,
          reason: null,
          transitionedAt: null,
          revokedAt: null,
        },
      ];
    },
  };
};

const resolveViewInput = (
  overrides: Partial<Parameters<typeof resolveInstructorCourseBadgeSummaryView>[1]> = {},
): Parameters<typeof resolveInstructorCourseBadgeSummaryView>[1] => {
  return {
    db: fakeDb,
    tenantId,
    launchClaims: launchClaims(),
    issuerClientId: clientId,
    membershipRole: "owner",
    courseContextTitle: "Course 123",
    summaryContextId: contextId,
    roster: roster(),
    ...overrides,
  };
};

describe("emptyInstructorCourseBadgeSummaryView", () => {
  it("builds a degraded course summary with no rows", () => {
    expect(
      emptyInstructorCourseBadgeSummaryView({
        status: "error",
        message: "Could not load badge progress.",
        courseContextTitle: "Course 123",
      }),
    ).toEqual({
      status: "error",
      message: "Could not load badge progress.",
      courseContextTitle: "Course 123",
      learnerCount: 0,
      badgeCount: 0,
      issuedCount: 0,
      canPlaceBadgesFromLti: false,
      badges: [],
      rows: [],
    });
  });
});

describe("resolveInstructorCourseBadgeSummaryView", () => {
  it("builds issued and not-issued rows with admin links for tenant admins", async () => {
    const view = await resolveInstructorCourseBadgeSummaryView(
      dependencies(),
      resolveViewInput({ membershipRole: "admin" }),
    );

    expect(view).toMatchObject({
      status: "ready",
      message: "Showing progress for 1 badge placement in this course.",
      learnerCount: 2,
      badgeCount: 1,
      issuedCount: 1,
      canPlaceBadgesFromLti: true,
    });
    expect(view.badges).toEqual([
      expect.objectContaining({
        badgeTemplateId,
        title: "TypeScript Foundations",
      }),
    ]);
    expect(view.rows).toEqual([
      expect.objectContaining({
        learnerUserId: "learner-001",
        status: "issued",
        statusLabel: "Issued",
        assertionId: "assertion-001",
        issuedAt: "2026-02-11T14:00:00.000Z",
      }),
      expect.objectContaining({
        learnerUserId: "learner-002",
        status: "not_issued",
        statusLabel: "Not issued",
        assertionId: null,
        issuedAt: null,
      }),
    ]);
    expect(view.rows[0]?.learnerDetailPath).toContain(
      "/tenants/tenant_123/admin/operations/issued-badges?",
    );
    expect(view.rows[0]?.badgeDetailPath).toContain(
      "/tenants/tenant_123/admin/rules/templates/badge_template_001?",
    );
  });

  it("allows issuer placement without exposing admin detail links", async () => {
    const view = await resolveInstructorCourseBadgeSummaryView(
      dependencies(),
      resolveViewInput({ membershipRole: "issuer" }),
    );

    expect(view.canPlaceBadgesFromLti).toBe(true);
    expect(view.rows.map((row) => row.learnerDetailPath)).toEqual([null, null]);
    expect(view.rows.map((row) => row.badgeDetailPath)).toEqual([null, null]);
  });
});

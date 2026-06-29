import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("@credtrail/db", async () => {
  const actual = await vi.importActual<typeof import("@credtrail/db")>("@credtrail/db");

  return {
    ...actual,
    listAssertionEngagementEvents: vi.fn(),
    listAssertionLifecycleStatesByAssertionIds: vi.fn(),
    listLearnerBadgeSummaries: vi.fn(),
  };
});

import {
  listAssertionEngagementEvents,
  listAssertionLifecycleStatesByAssertionIds,
  listLearnerBadgeSummaries,
  type AssertionEngagementEventRecord,
  type BadgeTemplateRecord,
  type LearnerBadgeSummaryRecord,
  type SqlDatabase,
} from "@credtrail/db";
import {
  LTI_MESSAGE_TYPE_RESOURCE_LINK_REQUEST,
  type LTI13JwtPayload as LtiLaunchClaims,
  type LTISession,
} from "@lti-tool/core";
import { resolveLearnerResourceLinkView } from "./learner-launch-views";
import type { ValidatedSelectedResourceLinkLaunch } from "./resource-link-launch-types";

const fakeDb = {
  prepare: vi.fn(),
} as unknown as SqlDatabase;

const mockedListAssertionEngagementEvents = vi.mocked(listAssertionEngagementEvents);
const mockedListAssertionLifecycleStatesByAssertionIds = vi.mocked(
  listAssertionLifecycleStatesByAssertionIds,
);
const mockedListLearnerBadgeSummaries = vi.mocked(listLearnerBadgeSummaries);

const sampleBadgeTemplate = (overrides: Partial<BadgeTemplateRecord> = {}): BadgeTemplateRecord => {
  return {
    id: "badge_template_001",
    tenantId: "tenant_123",
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

const sampleLearnerBadgeSummary = (
  overrides: Partial<LearnerBadgeSummaryRecord> = {},
): LearnerBadgeSummaryRecord => {
  return {
    assertionId: "tenant_123:assertion_existing",
    assertionPublicId: "public_badge_001",
    tenantId: "tenant_123",
    badgeTemplateId: "badge_template_001",
    badgeTitle: "TypeScript Foundations",
    badgeDescription: "Awarded for completing TypeScript fundamentals.",
    issuedAt: "2026-02-11T14:00:00.000Z",
    revokedAt: null,
    ...overrides,
  };
};

const sampleAssertionEngagementEvent = (
  overrides: Partial<AssertionEngagementEventRecord> = {},
): AssertionEngagementEventRecord => {
  return {
    id: "aee_claim_123",
    tenantId: "tenant_123",
    assertionId: "tenant_123:assertion_existing",
    eventType: "learner_claim",
    actorType: "learner",
    channel: "learner_dashboard",
    occurredAt: "2026-02-11T14:05:00.000Z",
    createdAt: "2026-02-11T14:05:00.000Z",
    ...overrides,
  };
};

const sampleSelectedLaunch = (
  badgeTemplate = sampleBadgeTemplate(),
): ValidatedSelectedResourceLinkLaunch => {
  return {
    kind: "selected",
    launchMessage: {
      kind: "resource-link",
      messageType: LTI_MESSAGE_TYPE_RESOURCE_LINK_REQUEST,
      roleKind: "learner",
      resolvedTargetLinkUri:
        "https://tool.example.edu/v1/lti/launch?badgeTemplateId=badge_template_001",
      resourceLinkId: "resource-link-selected-badge",
      resourceContextId: "course-123",
      badgeTemplateId: badgeTemplate.id,
      ruleId: null,
      setupToken: null,
    },
    launchedBadgeTemplate: badgeTemplate,
  };
};

describe("resolveLearnerResourceLinkView", () => {
  beforeEach(() => {
    mockedListLearnerBadgeSummaries.mockReset();
    mockedListLearnerBadgeSummaries.mockResolvedValue([sampleLearnerBadgeSummary()]);
    mockedListAssertionLifecycleStatesByAssertionIds.mockReset();
    mockedListAssertionLifecycleStatesByAssertionIds.mockResolvedValue([
      {
        assertionId: "tenant_123:assertion_existing",
        state: "active",
        source: "default_active",
        reasonCode: null,
        reason: null,
        transitionedAt: null,
        revokedAt: null,
      },
    ]);
    mockedListAssertionEngagementEvents.mockReset();
    mockedListAssertionEngagementEvents.mockResolvedValue([]);
  });

  it("keeps an issued learner badge claimable until a claim event exists", async () => {
    const view = await resolveLearnerResourceLinkView({
      db: fakeDb,
      tenantId: "tenant_123",
      launchClaims: {} as LtiLaunchClaims,
      ltiLaunchSession: {} as LTISession,
      issuerClientId: "canvas-client-123",
      linkedUserId: "usr_lti_123",
      launch: sampleSelectedLaunch(),
    });

    expect(view.badges[0]).toMatchObject({
      claimState: "claimable",
      claimActionPath: "/tenants/tenant_123/learner/badges/tenant_123%3Aassertion_existing/claim",
      sharePath: "/badges/public_badge_001#share-this-credential",
    });
  });

  it("renders an issued learner badge as already claimed after learner claim engagement exists", async () => {
    mockedListAssertionEngagementEvents.mockResolvedValue([
      sampleAssertionEngagementEvent({
        eventType: "learner_claim",
      }),
    ]);

    const view = await resolveLearnerResourceLinkView({
      db: fakeDb,
      tenantId: "tenant_123",
      launchClaims: {} as LtiLaunchClaims,
      ltiLaunchSession: {} as LTISession,
      issuerClientId: "canvas-client-123",
      linkedUserId: "usr_lti_123",
      launch: sampleSelectedLaunch(),
    });

    expect(mockedListAssertionEngagementEvents).toHaveBeenCalledWith(fakeDb, {
      tenantId: "tenant_123",
      assertionId: "tenant_123:assertion_existing",
      limit: 10,
    });
    expect(view.badges[0]).toMatchObject({
      claimState: "claimed",
      claimActionPath: null,
      sharePath: "/badges/public_badge_001#share-this-credential",
    });
  });
});

import {
  listAssertionsByBadgeTemplatesAndRecipientEmails,
  listAssertionLifecycleStatesByAssertionIds,
  normalizeEmail,
  type AssertionLifecycleState,
  type AssertionRecord,
  type SqlDatabase,
  type TenantMembershipRole,
} from "@credtrail/db";
import type { LTI13JwtPayload as LtiLaunchClaims } from "@longsightgroup/lti-tool";
import {
  resolveOrderedCourseBadgeTemplatesForContext,
  type LtiCourseBadgeTemplatePlacementGroup,
} from "./course-badge-placements";
import type { LtiNrpsRoster } from "./nrps";
import { ltiBadgeSummaryCardFromTemplate, newestAssertion } from "./badge-summary-helpers";
import type { LtiCourseBadgeSummaryView } from "./view-models";

type ResolveCourseBadgePlacements = typeof resolveOrderedCourseBadgeTemplatesForContext;
type ListBadgeTemplateRecipientAssertions = typeof listAssertionsByBadgeTemplatesAndRecipientEmails;
type ListAssertionLifecycleStates = typeof listAssertionLifecycleStatesByAssertionIds;

/**
 * Dependencies used to assemble the instructor course badge summary view.
 */
export interface InstructorCourseSummaryViewDependencies {
  readonly resolveCourseBadgePlacements: ResolveCourseBadgePlacements;
  readonly listBadgeTemplateRecipientAssertions: ListBadgeTemplateRecipientAssertions;
  readonly listAssertionLifecycleStates: ListAssertionLifecycleStates;
}

/**
 * Production dependencies for instructor course badge summary view assembly.
 */
export const instructorCourseSummaryViewDependencies: InstructorCourseSummaryViewDependencies = {
  resolveCourseBadgePlacements: resolveOrderedCourseBadgeTemplatesForContext,
  listBadgeTemplateRecipientAssertions: listAssertionsByBadgeTemplatesAndRecipientEmails,
  listAssertionLifecycleStates: listAssertionLifecycleStatesByAssertionIds,
};

/**
 * Builds a degraded instructor course badge summary view.
 */
export const emptyInstructorCourseBadgeSummaryView = (input: {
  status: "unavailable" | "error";
  message: string;
  courseContextTitle: string | null;
}): LtiCourseBadgeSummaryView => {
  return {
    status: input.status,
    message: input.message,
    courseContextTitle: input.courseContextTitle,
    learnerCount: 0,
    badgeCount: 0,
    issuedCount: 0,
    canPlaceBadgesFromLti: false,
    badges: [],
    rows: [],
  };
};

const courseBadgeSummaryStatus = (
  lifecycleState: AssertionLifecycleState | null,
): LtiCourseBadgeSummaryView["rows"][number]["status"] => {
  if (lifecycleState === null || lifecycleState === "active") {
    return "issued";
  }

  return lifecycleState;
};

const courseBadgeSummaryStatusLabel = (
  status: LtiCourseBadgeSummaryView["rows"][number]["status"],
): string => {
  if (status === "not_issued") {
    return "Not issued";
  }

  if (status === "issued") {
    return "Issued";
  }

  return status.charAt(0).toUpperCase() + status.slice(1);
};

const ltiLearnerIssuedBadgesPath = (input: {
  tenantId: string;
  email: string;
  badgeTemplateId?: string;
  assertionId?: string;
}): string => {
  const query = new URLSearchParams({ recipientQuery: input.email });

  if (input.badgeTemplateId !== undefined) {
    query.set("badgeTemplateId", input.badgeTemplateId);
  }

  if (input.assertionId !== undefined) {
    query.set("lifecycle", input.assertionId);
    query.set("lifecycleMode", "audit");
  }

  query.set("source", "lti-course-summary");

  return `/tenants/${encodeURIComponent(input.tenantId)}/admin/operations/issued-badges?${query.toString()}`;
};

const ltiBadgeCourseSetupPath = (input: {
  tenantId: string;
  badgeTemplateId: string;
  contextId: string;
  resourceLinkId: string;
  courseContextTitle: string | null;
}): string => {
  const query = new URLSearchParams({
    ltiContextId: input.contextId,
    ltiResourceLinkId: input.resourceLinkId,
    source: "lti-course-summary",
  });

  if (input.courseContextTitle !== null) {
    query.set("ltiCourse", input.courseContextTitle);
  }

  return `/tenants/${encodeURIComponent(input.tenantId)}/admin/rules/templates/${encodeURIComponent(
    input.badgeTemplateId,
  )}?${query.toString()}`;
};

const ltiBadgeRecipientKey = (badgeTemplateId: string, recipientEmail: string): string => {
  return `${badgeTemplateId}:${normalizeEmail(recipientEmail)}`;
};

const ltiCanOpenAdminDetailLinks = (membershipRole: TenantMembershipRole): boolean => {
  return membershipRole === "owner" || membershipRole === "admin";
};

const ltiCanPlaceBadgesFromLti = (membershipRole: TenantMembershipRole): boolean => {
  return membershipRole === "owner" || membershipRole === "admin" || membershipRole === "issuer";
};

const ltiCourseBadgeOverview = (input: {
  tenantId: string;
  placementGroups: readonly LtiCourseBadgeTemplatePlacementGroup[];
}): LtiCourseBadgeSummaryView["badges"] => {
  return input.placementGroups.map((placementGroup) => {
    return ltiBadgeSummaryCardFromTemplate({
      tenantId: input.tenantId,
      badgeTemplate: placementGroup.template,
    });
  });
};

const ltiCourseBadgeSummaryViewFromRoster = async (
  dependencies: Pick<
    InstructorCourseSummaryViewDependencies,
    "listBadgeTemplateRecipientAssertions" | "listAssertionLifecycleStates"
  >,
  input: {
    db: SqlDatabase;
    tenantId: string;
    contextId: string;
    courseContextTitle: string | null;
    roster: LtiNrpsRoster;
    placementGroups: readonly LtiCourseBadgeTemplatePlacementGroup[];
    canPlaceBadgesFromLti: boolean;
    canOpenAdminLinks: boolean;
  },
): Promise<LtiCourseBadgeSummaryView> => {
  const learnerMembers = input.roster.learnerMembers;
  const placementGroups = input.placementGroups;
  const badges = ltiCourseBadgeOverview({
    tenantId: input.tenantId,
    placementGroups,
  });
  const candidates = placementGroups.flatMap((placementGroup) => {
    return learnerMembers.map((member) => ({
      member,
      placementGroup,
      template: placementGroup.template,
    }));
  });
  const matchingRecipientAssertions = await dependencies.listBadgeTemplateRecipientAssertions(
    input.db,
    {
      tenantId: input.tenantId,
      badgeTemplateIds: placementGroups.map((placementGroup) => placementGroup.badgeTemplateId),
      recipientEmails: learnerMembers
        .map((member) => member.email)
        .filter((email): email is string => email !== null),
    },
  );
  const matchingRecipientAssertionsByBadgeRecipient = new Map<string, AssertionRecord>();

  for (const assertion of matchingRecipientAssertions) {
    const key = ltiBadgeRecipientKey(assertion.badgeTemplateId, assertion.recipientIdentity);

    matchingRecipientAssertionsByBadgeRecipient.set(
      key,
      newestAssertion(matchingRecipientAssertionsByBadgeRecipient.get(key), assertion),
    );
  }
  const lifecycleStates = await dependencies.listAssertionLifecycleStates(input.db, {
    tenantId: input.tenantId,
    assertionIds: Array.from(
      new Set(
        Array.from(matchingRecipientAssertionsByBadgeRecipient.values()).map(
          (assertion) => assertion.id,
        ),
      ),
    ),
  });
  const lifecycleStatesByAssertionId = new Map(
    lifecycleStates.map((lifecycle) => [lifecycle.assertionId, lifecycle]),
  );
  const rows: Array<LtiCourseBadgeSummaryView["rows"][number]> = [];

  for (const candidate of candidates) {
    const matchingRecipientAssertion =
      candidate.member.email === null
        ? null
        : (matchingRecipientAssertionsByBadgeRecipient.get(
            ltiBadgeRecipientKey(candidate.template.id, candidate.member.email),
          ) ?? null);
    const assertion = matchingRecipientAssertion;
    const lifecycle = assertion === null ? null : lifecycleStatesByAssertionId.get(assertion.id);
    const status =
      assertion === null ? "not_issued" : courseBadgeSummaryStatus(lifecycle?.state ?? null);
    const learnerName = candidate.member.displayName;
    const assertionId = assertion?.id;
    const linkedPlacement = candidate.placementGroup.primaryPlacement;
    const placementContextId = linkedPlacement.contextId ?? input.contextId;

    rows.push({
      learnerUserId: candidate.member.userId,
      learnerName,
      learnerEmail: candidate.member.email,
      learnerDetailPath:
        !input.canOpenAdminLinks || candidate.member.email === null
          ? null
          : ltiLearnerIssuedBadgesPath({
              tenantId: input.tenantId,
              email: candidate.member.email,
              badgeTemplateId: candidate.template.id,
              ...(assertionId === undefined ? {} : { assertionId }),
            }),
      badgeTemplateId: candidate.template.id,
      badgeTitle: candidate.template.title,
      badgeDetailPath: input.canOpenAdminLinks
        ? ltiBadgeCourseSetupPath({
            tenantId: input.tenantId,
            badgeTemplateId: candidate.template.id,
            contextId: placementContextId,
            resourceLinkId: linkedPlacement.resourceLinkId,
            courseContextTitle: input.courseContextTitle,
          })
        : null,
      status,
      statusLabel: courseBadgeSummaryStatusLabel(status),
      statusDetail:
        assertion === null
          ? "No issued badge record found for this learner and badge."
          : "Issued for this learner and badge.",
      assertionId: assertionId ?? null,
      issuedAt: assertion?.issuedAt ?? null,
    });
  }

  return {
    status: "ready",
    message:
      placementGroups.length === 0
        ? "No badges have been placed in this LMS course yet."
        : `Showing progress for ${String(placementGroups.length)} badge placement${
            placementGroups.length === 1 ? "" : "s"
          } in this course.`,
    courseContextTitle: input.courseContextTitle,
    learnerCount: learnerMembers.length,
    badgeCount: placementGroups.length,
    issuedCount: rows.filter((row) => row.status === "issued").length,
    canPlaceBadgesFromLti: input.canPlaceBadgesFromLti,
    badges,
    rows,
  };
};

/**
 * Builds the instructor course badge summary view for a course-level resource-link launch.
 */
export const resolveInstructorCourseBadgeSummaryView = async (
  dependencies: InstructorCourseSummaryViewDependencies,
  input: {
    db: SqlDatabase;
    tenantId: string;
    launchClaims: LtiLaunchClaims;
    issuerClientId: string;
    membershipRole: TenantMembershipRole;
    courseContextTitle: string | null;
    summaryContextId: string;
    roster: LtiNrpsRoster;
  },
): Promise<LtiCourseBadgeSummaryView> => {
  const courseBadges = await dependencies.resolveCourseBadgePlacements({
    db: input.db,
    tenantId: input.tenantId,
    launchClaims: input.launchClaims,
    issuerClientId: input.issuerClientId,
    contextId: input.summaryContextId,
  });

  return ltiCourseBadgeSummaryViewFromRoster(dependencies, {
    db: input.db,
    tenantId: input.tenantId,
    contextId: input.summaryContextId,
    courseContextTitle: input.courseContextTitle,
    roster: input.roster,
    placementGroups: courseBadges.placementGroups,
    canPlaceBadgesFromLti: ltiCanPlaceBadgesFromLti(input.membershipRole),
    canOpenAdminLinks: ltiCanOpenAdminDetailLinks(input.membershipRole),
  });
};

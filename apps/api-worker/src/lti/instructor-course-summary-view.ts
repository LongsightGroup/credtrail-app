import {
  listAssertionLifecycleStatesByAssertionIds,
  listAssertionsByBadgeTemplatesAndRecipientEmails,
  normalizeEmail,
  type AssertionLifecycleState,
  type AssertionRecord,
  type SqlDatabase,
  type TenantMembershipRole,
} from "@credtrail/db";
import type { LTI13JwtPayload as LtiLaunchClaims } from "@longsightgroup/lti-tool";
import { canIssueBadgesAsTenantMember, isTenantAdminRole } from "../auth/tenant-role-policy";
import { ltiBadgeSummaryCardFromTemplate, newestAssertion } from "./badge-summary-helpers";
import {
  resolveOrderedCourseBadgeTemplatesForContext,
  type LtiCourseBadgePlacementResolution,
  type LtiCourseBadgeTemplatePlacementGroup,
} from "./course-badge-placements";
import {
  ltiCourseSummaryBadgeSetupPath,
  ltiCourseSummaryIssuedBadgesPath,
} from "./lti-admin-links";
import type { LtiNrpsRoster } from "./nrps";
import type { LtiCourseBadgeSummaryView } from "./view-models";

type InstructorCourseSummaryViewDependencies = {
  readonly resolveCourseBadgePlacements: typeof resolveOrderedCourseBadgeTemplatesForContext;
  readonly listBadgeTemplateRecipientAssertions: typeof listAssertionsByBadgeTemplatesAndRecipientEmails;
  readonly listAssertionLifecycleStates: typeof listAssertionLifecycleStatesByAssertionIds;
};

/**
 * Input for building the instructor course badge summary view for a course-level resource-link launch.
 */
export interface ResolveInstructorCourseBadgeSummaryViewInput {
  db: SqlDatabase;
  tenantId: string;
  launchClaims: LtiLaunchClaims;
  issuerClientId: string;
  membershipRole: TenantMembershipRole;
  courseContextTitle: string | null;
  summaryContextId: string;
  roster: LtiNrpsRoster;
}

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

const ltiBadgeRecipientKey = (badgeTemplateId: string, recipientEmail: string): string => {
  return `${badgeTemplateId}:${normalizeEmail(recipientEmail)}`;
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

const instructorEmptyPlacementMessage = (
  status: Extract<LtiCourseBadgePlacementResolution["status"], { kind: "empty" }>,
): string => {
  switch (status.reason) {
    case "no_placements":
      return "No badges have been placed in this LMS course yet.";
    case "only_retired":
      return "No active badge placements are recorded for this course.";
    case "no_active_rules":
      return "No active badge rules are linked to this course's recorded placements.";
    case "no_available_templates":
      return "No available badge templates are linked to this course's active rules.";
  }
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
    emptyPlacementMessage: string;
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
        .filter((email): email is string => email !== undefined),
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
      candidate.member.email === undefined
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
      learnerEmail: candidate.member.email ?? null,
      learnerDetailPath:
        !input.canOpenAdminLinks || candidate.member.email === undefined
          ? null
          : ltiCourseSummaryIssuedBadgesPath({
              tenantId: input.tenantId,
              email: candidate.member.email,
              badgeTemplateId: candidate.template.id,
              ...(assertionId === undefined ? {} : { assertionId }),
            }),
      badgeTemplateId: candidate.template.id,
      badgeTitle: candidate.template.title,
      badgeDetailPath: input.canOpenAdminLinks
        ? ltiCourseSummaryBadgeSetupPath({
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
        ? input.emptyPlacementMessage
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

const resolveInstructorCourseBadgeSummaryViewWithDependencies = async (
  dependencies: InstructorCourseSummaryViewDependencies,
  input: ResolveInstructorCourseBadgeSummaryViewInput,
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
    emptyPlacementMessage:
      courseBadges.status.kind === "empty"
        ? instructorEmptyPlacementMessage(courseBadges.status)
        : "No active badge placements are available in this course.",
    canPlaceBadgesFromLti: canIssueBadgesAsTenantMember(input.membershipRole),
    canOpenAdminLinks: isTenantAdminRole(input.membershipRole),
  });
};

const defaultInstructorCourseSummaryViewDependencies: InstructorCourseSummaryViewDependencies = {
  resolveCourseBadgePlacements: resolveOrderedCourseBadgeTemplatesForContext,
  listBadgeTemplateRecipientAssertions: listAssertionsByBadgeTemplatesAndRecipientEmails,
  listAssertionLifecycleStates: listAssertionLifecycleStatesByAssertionIds,
};

/**
 * Creates an instructor course badge summary view resolver with explicit dependency replacements.
 */
export const createInstructorCourseBadgeSummaryViewResolver = (
  dependencies: InstructorCourseSummaryViewDependencies,
): ((
  input: ResolveInstructorCourseBadgeSummaryViewInput,
) => Promise<LtiCourseBadgeSummaryView>) => {
  return (input) => resolveInstructorCourseBadgeSummaryViewWithDependencies(dependencies, input);
};

/**
 * Builds the instructor course badge summary view for a course-level resource-link launch.
 */
export const resolveInstructorCourseBadgeSummaryView =
  createInstructorCourseBadgeSummaryViewResolver(defaultInstructorCourseSummaryViewDependencies);

import {
  listAssertionsByBadgeTemplatesAndRecipientEmails,
  listAssertionLifecycleStatesByAssertionIds,
  normalizeEmail,
  type AssertionLifecycleState,
  type AssertionRecord,
  type SqlDatabase,
  type TenantMembershipRole,
} from "@credtrail/db";
import { LTI_CLAIM_CONTEXT, LTI_CLAIM_DEPLOYMENT_ID, type LtiLaunchClaims } from "@credtrail/lti";
import type { LTISession, LTITool } from "@lti-tool/core";
import type { AppBindings } from "../app";
import { asJsonObject, asNonEmptyString } from "../utils/value-parsers";
import { LTI_RESOURCE_LINK_ISSUE_PATH } from "./constants";
import {
  ltiCourseContextIdFromLaunch,
  resolveOrderedCourseBadgeTemplatesForContext,
  type LtiCourseBadgeTemplatePlacementGroup,
} from "./course-badge-placements";
import { createLtiIssuanceActionToken } from "./issuance-action-token";
import { logLtiWarning } from "./log";
import { ltiNrpsRosterFromCoreMembers, parseLtiNrpsNamesRoleServiceClaim } from "./nrps";
import type {
  ResourceLinkLaunchMessage,
  ValidatedResourceLinkLaunch,
} from "./resource-link-launch-types";
import { ltiRosterIssuedBadgeStatesByUserId } from "./roster-issuance-helpers";
import { ltiBadgeSummaryCardFromTemplate, newestAssertion } from "./badge-summary-helpers";
import type {
  InstructorResourceLinkViews,
  LtiBadgeSummaryCard,
  LtiBulkIssuanceView,
  LtiCourseBadgeSummaryView,
} from "./view-models";

interface ResolveInstructorResourceLinkViewsBaseInput {
  db: SqlDatabase;
  env: AppBindings;
  tenantId: string;
  launchClaims: LtiLaunchClaims;
  ltiLaunchSession: LTISession;
  ltiTool: LTITool;
  issuerClientId: string;
  linkedUserId: string;
  membershipRole: TenantMembershipRole;
  sha256Hex: (value: string) => Promise<string>;
  sessionHandoffTtlSeconds: number;
}

export type ResolveInstructorResourceLinkViewsInput =
  ResolveInstructorResourceLinkViewsBaseInput & {
    launch: ValidatedResourceLinkLaunch;
  };

const ltiBulkIssuanceViewFromRoster = (input: {
  roster: ReturnType<typeof ltiNrpsRosterFromCoreMembers>;
  message: string;
  selectedBadge: LtiBadgeSummaryCard;
  courseContextTitle: string | null;
  courseContextId: string | null;
  contextMembershipsUrl: string;
  issuedBadgeStatesByUserId: ReadonlyMap<
    string,
    {
      assertionId: string;
      issuedAt: string;
      lifecycleState: AssertionLifecycleState | null;
    }
  >;
}): LtiBulkIssuanceView => {
  const learnerMembers = input.roster.learnerMembers.map((member) => {
    const issuedState = input.issuedBadgeStatesByUserId.get(member.userId) ?? null;

    return {
      userId: member.userId,
      sourcedId: member.sourcedId,
      displayName: member.displayName,
      email: member.email,
      roleSummary: member.roleSummary,
      status: member.status,
      issuedAssertionId: issuedState?.assertionId ?? null,
      issuedAt: issuedState?.issuedAt ?? null,
      issuanceLifecycleState: issuedState?.lifecycleState ?? null,
    };
  });

  return {
    status: "ready",
    message: input.message,
    selectedBadge: input.selectedBadge,
    courseContextTitle: input.courseContextTitle,
    courseContextId: input.courseContextId ?? input.roster.contextId,
    contextMembershipsUrl: input.contextMembershipsUrl,
    learnerCount: learnerMembers.length,
    totalCount: input.roster.members.length,
    issuanceActionPath: null,
    issuanceActionToken: null,
    members: learnerMembers,
  };
};

const ltiEmptyBulkIssuanceView = (input: {
  status: "unavailable" | "error";
  message: string;
  selectedBadge: LtiBadgeSummaryCard;
  courseContextTitle: string | null;
  courseContextId: string | null;
  contextMembershipsUrl: string | null;
}): LtiBulkIssuanceView => {
  return {
    status: input.status,
    message: input.message,
    selectedBadge: input.selectedBadge,
    courseContextTitle: input.courseContextTitle,
    courseContextId: input.courseContextId,
    contextMembershipsUrl: input.contextMembershipsUrl,
    learnerCount: 0,
    totalCount: 0,
    issuanceActionPath: null,
    issuanceActionToken: null,
    members: [],
  };
};

const ltiBulkIssuanceViewWithAction = (
  view: LtiBulkIssuanceView,
  input: {
    issuanceActionToken: string;
  },
): LtiBulkIssuanceView => {
  return {
    ...view,
    issuanceActionPath: LTI_RESOURCE_LINK_ISSUE_PATH,
    issuanceActionToken: input.issuanceActionToken,
  };
};

const ltiEmptyCourseBadgeSummaryView = (input: {
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

const ltiCourseBadgeSummaryViewFromRoster = async (input: {
  db: SqlDatabase;
  tenantId: string;
  contextId: string;
  courseContextTitle: string | null;
  roster: ReturnType<typeof ltiNrpsRosterFromCoreMembers>;
  placementGroups: readonly LtiCourseBadgeTemplatePlacementGroup[];
  canPlaceBadgesFromLti: boolean;
  canOpenAdminLinks: boolean;
}): Promise<LtiCourseBadgeSummaryView> => {
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
  const matchingRecipientAssertions = await listAssertionsByBadgeTemplatesAndRecipientEmails(
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
  const lifecycleStates = await listAssertionLifecycleStatesByAssertionIds(input.db, {
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
    const learnerName =
      candidate.member.displayName ?? candidate.member.email ?? candidate.member.userId;
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
        : `Showing badge progress for ${String(placementGroups.length)} badge${
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

const resolveBulkIssuanceView = async (input: {
  db: SqlDatabase;
  env: AppBindings;
  tenantId: string;
  launchClaims: LtiLaunchClaims;
  launchMessage: ResourceLinkLaunchMessage;
  ltiLaunchSession: LTISession;
  ltiTool: LTITool;
  issuerClientId: string;
  linkedUserId: string;
  selectedBadge: LtiBadgeSummaryCard;
  courseContextTitle: string | null;
  courseContextId: string | null;
  contextMembershipsUrl: string;
  sha256Hex: (value: string) => Promise<string>;
  sessionHandoffTtlSeconds: number;
}): Promise<LtiBulkIssuanceView> => {
  const members = await input.ltiTool.getMembers(input.ltiLaunchSession);
  const roster = ltiNrpsRosterFromCoreMembers({
    contextId: input.courseContextId ?? input.ltiLaunchSession.context.id ?? null,
    members,
  });
  const issuanceActionContextId = input.courseContextId ?? input.ltiLaunchSession.context.id;
  const issuanceActionInput =
    issuanceActionContextId.length > 0
      ? {
          tenantId: input.tenantId,
          ltiSessionId: input.ltiLaunchSession.id,
          issuer: input.launchClaims.iss,
          clientId: input.issuerClientId,
          deploymentId: input.launchClaims[LTI_CLAIM_DEPLOYMENT_ID],
          contextId: issuanceActionContextId,
          resourceLinkId: input.launchMessage.resourceLinkId,
          badgeTemplateId: input.selectedBadge.badgeTemplateId,
          issuedByUserId: input.linkedUserId,
        }
      : null;
  const issuedBadgeStatesByUserId =
    issuanceActionInput === null
      ? new Map<
          string,
          {
            assertionId: string;
            issuedAt: string;
            lifecycleState: AssertionLifecycleState | null;
          }
        >()
      : await ltiRosterIssuedBadgeStatesByUserId({
          db: input.db,
          sha256Hex: input.sha256Hex,
          action: issuanceActionInput,
          learnerMembers: roster.learnerMembers,
        });
  let bulkIssuanceView = ltiBulkIssuanceViewFromRoster({
    roster,
    message: `Loaded ${String(roster.learnerMembers.length)} learner${
      roster.learnerMembers.length === 1 ? "" : "s"
    } from LMS roster.`,
    selectedBadge: input.selectedBadge,
    courseContextTitle: input.courseContextTitle,
    courseContextId: input.courseContextId,
    contextMembershipsUrl: input.contextMembershipsUrl,
    issuedBadgeStatesByUserId,
  });

  if (issuanceActionInput !== null) {
    bulkIssuanceView = ltiBulkIssuanceViewWithAction(bulkIssuanceView, {
      issuanceActionToken: await createLtiIssuanceActionToken(input.env, {
        ...issuanceActionInput,
        ttlSeconds: input.sessionHandoffTtlSeconds,
      }),
    });
  }

  return bulkIssuanceView;
};

const resolveCourseBadgeSummaryView = async (input: {
  db: SqlDatabase;
  tenantId: string;
  launchClaims: LtiLaunchClaims;
  ltiLaunchSession: LTISession;
  ltiTool: LTITool;
  issuerClientId: string;
  membershipRole: TenantMembershipRole;
  courseContextTitle: string | null;
  summaryContextId: string;
}): Promise<LtiCourseBadgeSummaryView> => {
  const [members, courseBadges] = await Promise.all([
    input.ltiTool.getMembers(input.ltiLaunchSession),
    resolveOrderedCourseBadgeTemplatesForContext({
      db: input.db,
      tenantId: input.tenantId,
      launchClaims: input.launchClaims,
      issuerClientId: input.issuerClientId,
      contextId: input.summaryContextId,
    }),
  ]);
  const roster = ltiNrpsRosterFromCoreMembers({
    contextId: input.summaryContextId,
    members,
  });

  return ltiCourseBadgeSummaryViewFromRoster({
    db: input.db,
    tenantId: input.tenantId,
    contextId: input.summaryContextId,
    courseContextTitle: input.courseContextTitle,
    roster,
    placementGroups: courseBadges.placementGroups,
    canPlaceBadgesFromLti: ltiCanPlaceBadgesFromLti(input.membershipRole),
    canOpenAdminLinks: ltiCanOpenAdminDetailLinks(input.membershipRole),
  });
};

export const resolveInstructorResourceLinkViews = async (
  input: ResolveInstructorResourceLinkViewsInput,
): Promise<InstructorResourceLinkViews> => {
  const nrpsClaim = parseLtiNrpsNamesRoleServiceClaim(input.launchClaims);
  const contextClaim = asJsonObject(input.launchClaims[LTI_CLAIM_CONTEXT]);
  const courseContextTitle =
    asNonEmptyString(contextClaim?.title) ?? asNonEmptyString(contextClaim?.label) ?? null;
  const courseContextId = asNonEmptyString(contextClaim?.id);

  if (input.launch.kind === "selected") {
    const selectedBadge = ltiBadgeSummaryCardFromTemplate({
      tenantId: input.tenantId,
      badgeTemplate: input.launch.launchedBadgeTemplate,
    });

    if (nrpsClaim === null) {
      return {
        kind: "bulk",
        bulkIssuanceView: ltiEmptyBulkIssuanceView({
          status: "unavailable",
          message:
            "This LMS launch did not include a learner roster, so CredTrail cannot issue badges from this tool yet.",
          selectedBadge,
          courseContextTitle,
          courseContextId,
          contextMembershipsUrl: null,
        }),
        courseBadgeSummaryView: null,
      };
    }

    try {
      return {
        kind: "bulk",
        bulkIssuanceView: await resolveBulkIssuanceView({
          db: input.db,
          env: input.env,
          tenantId: input.tenantId,
          launchClaims: input.launchClaims,
          launchMessage: input.launch.launchMessage,
          ltiLaunchSession: input.ltiLaunchSession,
          ltiTool: input.ltiTool,
          issuerClientId: input.issuerClientId,
          linkedUserId: input.linkedUserId,
          selectedBadge,
          courseContextTitle,
          courseContextId,
          contextMembershipsUrl: nrpsClaim.contextMembershipsUrl,
          sha256Hex: input.sha256Hex,
          sessionHandoffTtlSeconds: input.sessionHandoffTtlSeconds,
        }),
        courseBadgeSummaryView: null,
      };
    } catch (error) {
      logLtiWarning("Could not build bulk issuance view from LMS roster", {
        tenantId: input.tenantId,
        badgeTemplateId: selectedBadge.badgeTemplateId,
        detail: error instanceof Error ? error.message : "unknown error",
      });

      return {
        kind: "bulk",
        bulkIssuanceView: ltiEmptyBulkIssuanceView({
          status: "error",
          message:
            "CredTrail could not load the learner roster from the LMS. Check the LMS connection settings.",
          selectedBadge,
          courseContextTitle,
          courseContextId,
          contextMembershipsUrl: nrpsClaim.contextMembershipsUrl,
        }),
        courseBadgeSummaryView: null,
      };
    }
  }

  if (nrpsClaim === null) {
    return {
      kind: "course-summary",
      bulkIssuanceView: null,
      courseBadgeSummaryView: ltiEmptyCourseBadgeSummaryView({
        status: "unavailable",
        message:
          "CredTrail could not load the learner roster from the LMS. Ask an administrator to check the LMS connection settings.",
        courseContextTitle,
      }),
    };
  }

  const summaryContextId = ltiCourseContextIdFromLaunch({
    launchMessage: input.launch.launchMessage,
    ltiLaunchSession: input.ltiLaunchSession,
  });

  if (summaryContextId.length === 0) {
    return {
      kind: "course-summary",
      bulkIssuanceView: null,
      courseBadgeSummaryView: ltiEmptyCourseBadgeSummaryView({
        status: "unavailable",
        message:
          "CredTrail could not identify this LMS course. Ask an administrator to check the LMS tool setup.",
        courseContextTitle,
      }),
    };
  }

  try {
    return {
      kind: "course-summary",
      bulkIssuanceView: null,
      courseBadgeSummaryView: await resolveCourseBadgeSummaryView({
        db: input.db,
        tenantId: input.tenantId,
        launchClaims: input.launchClaims,
        ltiLaunchSession: input.ltiLaunchSession,
        ltiTool: input.ltiTool,
        issuerClientId: input.issuerClientId,
        membershipRole: input.membershipRole,
        courseContextTitle,
        summaryContextId,
      }),
    };
  } catch (error) {
    logLtiWarning("Could not build course badge summary view", {
      tenantId: input.tenantId,
      summaryContextId,
      detail: error instanceof Error ? error.message : "unknown error",
    });

    return {
      kind: "course-summary",
      bulkIssuanceView: null,
      courseBadgeSummaryView: ltiEmptyCourseBadgeSummaryView({
        status: "error",
        message:
          "CredTrail could not load badge progress for this course. Ask an administrator to check the LMS connection settings.",
        courseContextTitle,
      }),
    };
  }
};

import {
  listAssertionsByBadgeTemplatesAndRecipientEmails,
  listAssertionLifecycleStatesByAssertionIds,
  listBadgeTemplatesByIds,
  listLtiResourceLinkPlacementsForContext,
  normalizeEmail,
  type AssertionLifecycleState,
  type AssertionRecord,
  type BadgeTemplateRecord,
  type LtiResourceLinkPlacementRecord,
  type SqlDatabase,
  type TenantMembershipRole,
} from "@credtrail/db";
import { LTI_CLAIM_CONTEXT, LTI_CLAIM_DEPLOYMENT_ID, type LtiLaunchClaims } from "@credtrail/lti";
import type { LTISession, LTITool } from "@lti-tool/core";
import type { AppBindings } from "../app";
import { asJsonObject, asNonEmptyString } from "../utils/value-parsers";
import { badgeTemplateCriteriaRegistryHref } from "../badges/badge-template-public-links";
import { LTI_RESOURCE_LINK_ISSUE_PATH } from "./constants";
import { createLtiIssuanceActionToken } from "./issuance-action-token";
import { logLtiWarning } from "./log";
import type { ResolvedLtiLaunchMessage } from "./launch-message";
import { ltiNrpsRosterFromCoreMembers, parseLtiNrpsNamesRoleServiceClaim } from "./nrps";
import { ltiRosterIssuedBadgeStatesByUserId } from "./roster-issuance-helpers";
import type {
  InstructorResourceLinkMode,
  InstructorResourceLinkViews,
  LtiBulkIssuanceView,
  LtiCourseBadgeSummaryView,
} from "./view-models";

type InstructorResourceLinkLaunchMessage = Extract<
  ResolvedLtiLaunchMessage,
  { kind: "resource-link" }
>;

export interface ResolveInstructorResourceLinkViewsInput {
  db: SqlDatabase;
  env: AppBindings;
  tenantId: string;
  launchClaims: LtiLaunchClaims;
  launchMessage: InstructorResourceLinkLaunchMessage;
  ltiLaunchSession: LTISession;
  ltiTool: LTITool;
  issuerClientId: string;
  linkedUserId: string;
  membershipRole: TenantMembershipRole;
  sha256Hex: (value: string) => Promise<string>;
  sessionHandoffTtlSeconds: number;
}

const instructorResourceLinkMode = (
  launchMessage: InstructorResourceLinkLaunchMessage,
): InstructorResourceLinkMode => {
  if (launchMessage.badgeTemplateId !== null) {
    return {
      kind: "bulk",
      badgeTemplateId: launchMessage.badgeTemplateId,
    };
  }

  return {
    kind: "course-summary",
  };
};

const ltiBulkIssuanceViewFromRoster = (input: {
  roster: ReturnType<typeof ltiNrpsRosterFromCoreMembers>;
  message: string;
  badgeTemplateId: string | null;
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
    badgeTemplateId: input.badgeTemplateId,
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
  badgeTemplateId: string | null;
  courseContextTitle: string | null;
  courseContextId: string | null;
  contextMembershipsUrl: string | null;
}): LtiBulkIssuanceView => {
  return {
    status: input.status,
    message: input.message,
    badgeTemplateId: input.badgeTemplateId,
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

const newestAssertion = (
  current: AssertionRecord | undefined,
  candidate: AssertionRecord,
): AssertionRecord => {
  if (current === undefined) {
    return candidate;
  }

  const currentIssuedAt = Date.parse(current.issuedAt);
  const candidateIssuedAt = Date.parse(candidate.issuedAt);

  if (Number.isFinite(candidateIssuedAt) && Number.isFinite(currentIssuedAt)) {
    if (candidateIssuedAt !== currentIssuedAt) {
      return candidateIssuedAt > currentIssuedAt ? candidate : current;
    }
  } else if (Number.isFinite(candidateIssuedAt)) {
    return candidate;
  } else if (Number.isFinite(currentIssuedAt)) {
    return current;
  } else if (candidate.issuedAt !== current.issuedAt) {
    return candidate.issuedAt > current.issuedAt ? candidate : current;
  }

  return candidate.id > current.id ? candidate : current;
};

const ltiCanOpenAdminDetailLinks = (membershipRole: TenantMembershipRole): boolean => {
  return membershipRole === "owner" || membershipRole === "admin";
};

const ltiCanPlaceBadgesFromLti = (membershipRole: TenantMembershipRole): boolean => {
  return membershipRole === "owner" || membershipRole === "admin" || membershipRole === "issuer";
};

const LTI_BADGE_QUALIFICATION_SUMMARY_FALLBACK =
  "Open criteria to review how learners qualify for this badge.";

interface LtiCourseBadgeTemplatePlacementGroup {
  badgeTemplateId: string;
  template: BadgeTemplateRecord;
  placements: readonly LtiResourceLinkPlacementRecord[];
}

const ltiCoursePlacementGroupsByBadgeTemplate = (input: {
  placements: readonly LtiResourceLinkPlacementRecord[];
  templatesById: ReadonlyMap<string, BadgeTemplateRecord>;
}): LtiCourseBadgeTemplatePlacementGroup[] => {
  const placementsByBadgeTemplateId = new Map<string, LtiResourceLinkPlacementRecord[]>();

  for (const placement of input.placements) {
    if (!input.templatesById.has(placement.badgeTemplateId)) {
      continue;
    }

    const placementsForTemplate = placementsByBadgeTemplateId.get(placement.badgeTemplateId) ?? [];
    placementsForTemplate.push(placement);
    placementsByBadgeTemplateId.set(placement.badgeTemplateId, placementsForTemplate);
  }

  const groups: LtiCourseBadgeTemplatePlacementGroup[] = [];

  for (const [badgeTemplateId, placementsForTemplate] of placementsByBadgeTemplateId.entries()) {
    const template = input.templatesById.get(badgeTemplateId);

    if (template === undefined) {
      continue;
    }

    groups.push({
      badgeTemplateId,
      template,
      placements: placementsForTemplate,
    });
  }

  return groups;
};

const ltiCourseBadgeOverview = (input: {
  tenantId: string;
  placementGroups: readonly LtiCourseBadgeTemplatePlacementGroup[];
}): LtiCourseBadgeSummaryView["badges"] => {
  return input.placementGroups.map((placementGroup) => {
    const summary =
      asNonEmptyString(placementGroup.template.description) ??
      LTI_BADGE_QUALIFICATION_SUMMARY_FALLBACK;

    return {
      badgeTemplateId: placementGroup.badgeTemplateId,
      title: placementGroup.template.title,
      summary,
      imageUri: placementGroup.template.imageUri,
      criteriaPath: badgeTemplateCriteriaRegistryHref(
        input.tenantId,
        placementGroup.badgeTemplateId,
      ),
    };
  });
};

const ltiCourseBadgeSummaryViewFromRoster = async (input: {
  db: SqlDatabase;
  tenantId: string;
  contextId: string;
  courseContextTitle: string | null;
  roster: ReturnType<typeof ltiNrpsRosterFromCoreMembers>;
  placements: readonly LtiResourceLinkPlacementRecord[];
  badgeTemplates: readonly BadgeTemplateRecord[];
  canPlaceBadgesFromLti: boolean;
  canOpenAdminLinks: boolean;
}): Promise<LtiCourseBadgeSummaryView> => {
  const learnerMembers = input.roster.learnerMembers;
  const templatesById = new Map(input.badgeTemplates.map((template) => [template.id, template]));
  const placementGroups = ltiCoursePlacementGroupsByBadgeTemplate({
    placements: input.placements,
    templatesById,
  });
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
    const linkedPlacement = candidate.placementGroup.placements[0] ?? null;
    const placementContextId = linkedPlacement?.contextId ?? input.contextId;

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
            resourceLinkId: linkedPlacement?.resourceLinkId ?? "",
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
  launchMessage: InstructorResourceLinkLaunchMessage;
  ltiLaunchSession: LTISession;
  ltiTool: LTITool;
  issuerClientId: string;
  linkedUserId: string;
  badgeTemplateId: string;
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
          badgeTemplateId: input.badgeTemplateId,
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
    badgeTemplateId: input.badgeTemplateId,
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
  const members = await input.ltiTool.getMembers(input.ltiLaunchSession);
  const roster = ltiNrpsRosterFromCoreMembers({
    contextId: input.summaryContextId,
    members,
  });
  const placements = await listLtiResourceLinkPlacementsForContext(input.db, {
    tenantId: input.tenantId,
    issuer: input.launchClaims.iss,
    clientId: input.issuerClientId,
    deploymentId: input.launchClaims[LTI_CLAIM_DEPLOYMENT_ID],
    contextId: input.summaryContextId,
  });
  const badgeTemplates = await listBadgeTemplatesByIds(input.db, {
    tenantId: input.tenantId,
    badgeTemplateIds: placements.map((placement) => placement.badgeTemplateId),
    includeArchived: false,
  });

  return ltiCourseBadgeSummaryViewFromRoster({
    db: input.db,
    tenantId: input.tenantId,
    contextId: input.summaryContextId,
    courseContextTitle: input.courseContextTitle,
    roster,
    placements,
    badgeTemplates,
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
  const mode = instructorResourceLinkMode(input.launchMessage);

  if (nrpsClaim === null) {
    if (mode.kind === "bulk") {
      return {
        mode,
        bulkIssuanceView: ltiEmptyBulkIssuanceView({
          status: "unavailable",
          message:
            "This LMS launch did not include a learner roster, so CredTrail cannot issue badges from this tool yet.",
          badgeTemplateId: mode.badgeTemplateId,
          courseContextTitle,
          courseContextId,
          contextMembershipsUrl: null,
        }),
        courseBadgeSummaryView: null,
      };
    }

    return {
      mode,
      bulkIssuanceView: null,
      courseBadgeSummaryView: ltiEmptyCourseBadgeSummaryView({
        status: "unavailable",
        message:
          "CredTrail could not load the learner roster from the LMS. Ask an administrator to check the LMS connection settings.",
        courseContextTitle,
      }),
    };
  }

  if (mode.kind === "bulk") {
    try {
      return {
        mode,
        bulkIssuanceView: await resolveBulkIssuanceView({
          db: input.db,
          env: input.env,
          tenantId: input.tenantId,
          launchClaims: input.launchClaims,
          launchMessage: input.launchMessage,
          ltiLaunchSession: input.ltiLaunchSession,
          ltiTool: input.ltiTool,
          issuerClientId: input.issuerClientId,
          linkedUserId: input.linkedUserId,
          badgeTemplateId: mode.badgeTemplateId,
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
        badgeTemplateId: mode.badgeTemplateId,
        detail: error instanceof Error ? error.message : "unknown error",
      });

      return {
        mode,
        bulkIssuanceView: ltiEmptyBulkIssuanceView({
          status: "error",
          message:
            "CredTrail could not load the learner roster from the LMS. Check the LMS connection settings.",
          badgeTemplateId: mode.badgeTemplateId,
          courseContextTitle,
          courseContextId,
          contextMembershipsUrl: nrpsClaim.contextMembershipsUrl,
        }),
        courseBadgeSummaryView: null,
      };
    }
  }

  const summaryContextId = courseContextId ?? input.ltiLaunchSession.context.id;

  if (summaryContextId.length === 0) {
    return {
      mode,
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
      mode,
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
      mode,
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

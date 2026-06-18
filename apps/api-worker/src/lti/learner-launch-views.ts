import {
  listAssertionLifecycleStatesByAssertionIds,
  listLearnerBadgeSummaries,
  type BadgeTemplateRecord,
  type LearnerBadgeSummaryRecord,
  type SqlDatabase,
} from "@credtrail/db";
import type { LtiLaunchClaims } from "@credtrail/lti";
import type { LTISession } from "@lti-tool/core";
import { logLtiWarning } from "./log";
import { ltiBadgeSummaryCardFromTemplate, newestByIssuedAt } from "./badge-summary-helpers";
import {
  ltiCourseContextIdFromLaunch,
  resolveOrderedCourseBadgeTemplatesForContext,
} from "./course-badge-placements";
import type {
  ValidatedCourseResourceLinkLaunch,
  ValidatedResourceLinkLaunch,
  ValidatedSelectedResourceLinkLaunch,
} from "./resource-link-launch-types";
import type {
  LtiBadgeSummaryStatus,
  LtiLearnerBadgeSummaryItem,
  LtiLearnerBadgeSummaryView,
} from "./view-models";

interface ResolveLearnerResourceLinkViewBaseInput {
  db: SqlDatabase;
  tenantId: string;
  launchClaims: LtiLaunchClaims;
  ltiLaunchSession: LTISession;
  issuerClientId: string;
  linkedUserId: string;
}

export type ResolveLearnerResourceLinkViewInput = ResolveLearnerResourceLinkViewBaseInput & {
  launch: ValidatedResourceLinkLaunch;
};

const learnerClaimActionPath = (input: { tenantId: string; assertionId: string }): string => {
  return `/tenants/${encodeURIComponent(input.tenantId)}/learner/badges/${encodeURIComponent(
    input.assertionId,
  )}/claim`;
};

const LTI_LEARNER_BADGE_ISSUED_STATUS: LtiBadgeSummaryStatus = {
  label: "Issued",
  modifier: "issued",
};

const LTI_LEARNER_BADGE_NOT_ISSUED_STATUS: LtiBadgeSummaryStatus = {
  label: "Not issued",
  modifier: "not_issued",
};

const learnerBadgeSummariesByTemplate = (
  summaries: readonly LearnerBadgeSummaryRecord[],
): ReadonlyMap<string, LearnerBadgeSummaryRecord> => {
  const summariesByBadgeTemplateId = new Map<string, LearnerBadgeSummaryRecord>();

  for (const summary of summaries) {
    summariesByBadgeTemplateId.set(
      summary.badgeTemplateId,
      newestByIssuedAt(summariesByBadgeTemplateId.get(summary.badgeTemplateId), summary, {
        issuedAt: (badgeSummary) => badgeSummary.issuedAt,
        id: (badgeSummary) => badgeSummary.assertionId,
      }),
    );
  }

  return summariesByBadgeTemplateId;
};

const learnerBadgeSummaryItems = async (input: {
  db: SqlDatabase;
  tenantId: string;
  linkedUserId: string;
  badgeTemplates: readonly BadgeTemplateRecord[];
}): Promise<LtiLearnerBadgeSummaryItem[]> => {
  if (input.badgeTemplates.length === 0) {
    return [];
  }

  const learnerBadgeSummaries = await listLearnerBadgeSummaries(input.db, {
    tenantId: input.tenantId,
    userId: input.linkedUserId,
  });
  const summariesByTemplate = learnerBadgeSummariesByTemplate(learnerBadgeSummaries);
  const matchedSummaries = input.badgeTemplates
    .map((badgeTemplate) => summariesByTemplate.get(badgeTemplate.id) ?? null)
    .filter((summary): summary is LearnerBadgeSummaryRecord => summary !== null);
  const lifecycleStates = await listAssertionLifecycleStatesByAssertionIds(input.db, {
    tenantId: input.tenantId,
    assertionIds: matchedSummaries.map((summary) => summary.assertionId),
  });
  const lifecycleStatesByAssertionId = new Map(
    lifecycleStates.map((lifecycle) => [lifecycle.assertionId, lifecycle]),
  );

  return input.badgeTemplates.map((badgeTemplate) => {
    const summary = summariesByTemplate.get(badgeTemplate.id) ?? null;
    const lifecycleState =
      summary === null
        ? null
        : (lifecycleStatesByAssertionId.get(summary.assertionId)?.state ?? "active");
    const isIssued = summary !== null && summary.revokedAt === null && lifecycleState === "active";

    return {
      badge: ltiBadgeSummaryCardFromTemplate({
        tenantId: input.tenantId,
        badgeTemplate,
      }),
      status: isIssued ? LTI_LEARNER_BADGE_ISSUED_STATUS : LTI_LEARNER_BADGE_NOT_ISSUED_STATUS,
      issuedAt: isIssued ? summary.issuedAt : null,
      claimActionPath:
        isIssued && summary !== null
          ? learnerClaimActionPath({
              tenantId: input.tenantId,
              assertionId: summary.assertionId,
            })
          : null,
    };
  });
};

const resolveSelectedLearnerBadgeSummaryView = async (
  input: ResolveLearnerResourceLinkViewBaseInput & {
    launch: ValidatedSelectedResourceLinkLaunch;
  },
): Promise<LtiLearnerBadgeSummaryView> => {
  return {
    scope: "selected",
    status: "ready",
    message: "Review the badge selected for this LMS lesson.",
    badges: await learnerBadgeSummaryItems({
      db: input.db,
      tenantId: input.tenantId,
      linkedUserId: input.linkedUserId,
      badgeTemplates: [input.launch.launchedBadgeTemplate],
    }),
  };
};

const resolveCourseLearnerBadgeSummaryView = async (
  input: ResolveLearnerResourceLinkViewBaseInput & {
    launch: ValidatedCourseResourceLinkLaunch;
  },
): Promise<LtiLearnerBadgeSummaryView> => {
  const contextId = ltiCourseContextIdFromLaunch({
    launchMessage: input.launch.launchMessage,
    ltiLaunchSession: input.ltiLaunchSession,
  });

  if (contextId.length === 0) {
    return {
      scope: "course",
      status: "unavailable",
      message:
        "CredTrail could not identify this LMS course, so badge details are not available here.",
      badges: [],
    };
  }

  const courseBadges = await resolveOrderedCourseBadgeTemplatesForContext({
    db: input.db,
    tenantId: input.tenantId,
    launchClaims: input.launchClaims,
    issuerClientId: input.issuerClientId,
    contextId,
  });

  return {
    scope: "course",
    status: "ready",
    message:
      courseBadges.orderedTemplates.length === 0
        ? "No CredTrail badges have been placed in this LMS course yet."
        : `Showing ${String(courseBadges.orderedTemplates.length)} active badge${
            courseBadges.orderedTemplates.length === 1 ? "" : "s"
          } in this course.`,
    badges: await learnerBadgeSummaryItems({
      db: input.db,
      tenantId: input.tenantId,
      linkedUserId: input.linkedUserId,
      badgeTemplates: courseBadges.orderedTemplates,
    }),
  };
};

export const resolveLearnerResourceLinkView = async (
  input: ResolveLearnerResourceLinkViewInput,
): Promise<LtiLearnerBadgeSummaryView> => {
  const launch = input.launch;

  try {
    if (launch.kind === "selected") {
      return await resolveSelectedLearnerBadgeSummaryView({
        ...input,
        launch,
      });
    }

    return await resolveCourseLearnerBadgeSummaryView({
      ...input,
      launch,
    });
  } catch (error) {
    logLtiWarning("Could not build learner badge summary view", {
      tenantId: input.tenantId,
      badgeTemplateId: launch.launchMessage.badgeTemplateId ?? "",
      detail: error instanceof Error ? error.message : "unknown error",
    });

    return {
      scope: launch.kind,
      status: "error",
      message:
        "CredTrail could not load badge details for this LMS launch. Open your dashboard to continue.",
      badges: [],
    };
  }
};

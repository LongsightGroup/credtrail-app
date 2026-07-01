import {
  listAssertionEngagementEvents,
  listAssertionLifecycleStatesByAssertionIds,
  listLearnerBadgeSummaries,
  type AssertionEngagementEventRecord,
  type AssertionLifecycleState,
  type BadgeTemplateRecord,
  type LearnerBadgeSummaryRecord,
  type SqlDatabase,
} from "@credtrail/db";
import type { LTI13JwtPayload as LtiLaunchClaims, LTISession } from "@longsightgroup/lti-tool";
import type { AppLogger } from "../app/observability";
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
  LtiLearnerBadgeClaimState,
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
  logger?: AppLogger | undefined;
}

export type ResolveLearnerResourceLinkViewInput = ResolveLearnerResourceLinkViewBaseInput & {
  launch: ValidatedResourceLinkLaunch;
};

const learnerClaimActionPath = (input: { tenantId: string; assertionId: string }): string => {
  return `/tenants/${encodeURIComponent(input.tenantId)}/learner/badges/${encodeURIComponent(
    input.assertionId,
  )}/claim`;
};

const learnerBadgeSharePath = (badge: {
  assertionId: string;
  assertionPublicId: string | null;
}): string => {
  return `/badges/${encodeURIComponent(
    badge.assertionPublicId ?? badge.assertionId,
  )}#share-this-credential`;
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

const learnerBadgeClaimStateFromEvents = (
  events: readonly AssertionEngagementEventRecord[],
): LtiLearnerBadgeClaimState => {
  if (events.some((event) => event.eventType === "wallet_accept")) {
    return "accepted";
  }

  if (events.some((event) => event.eventType === "learner_claim")) {
    return "claimed";
  }

  return "claimable";
};

const learnerBadgeSummaryIsIssued = (input: {
  summary: LearnerBadgeSummaryRecord;
  lifecycleState: AssertionLifecycleState;
}): boolean => {
  return input.summary.revokedAt === null && input.lifecycleState === "active";
};

const learnerBadgeClaimStatesByAssertionId = async (input: {
  db: SqlDatabase;
  tenantId: string;
  summaries: readonly LearnerBadgeSummaryRecord[];
  lifecycleStatesByAssertionId: ReadonlyMap<string, { state: AssertionLifecycleState }>;
}): Promise<ReadonlyMap<string, LtiLearnerBadgeClaimState>> => {
  const issuedSummaries = input.summaries.filter((summary) =>
    learnerBadgeSummaryIsIssued({
      summary,
      lifecycleState:
        input.lifecycleStatesByAssertionId.get(summary.assertionId)?.state ?? "active",
    }),
  );
  const claimStateEntries = await Promise.all(
    issuedSummaries.map(async (summary) => {
      const events = await listAssertionEngagementEvents(input.db, {
        tenantId: input.tenantId,
        assertionId: summary.assertionId,
        limit: 10,
      });

      return [summary.assertionId, learnerBadgeClaimStateFromEvents(events)] as const;
    }),
  );

  return new Map(claimStateEntries);
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
  const claimStatesByAssertionId = await learnerBadgeClaimStatesByAssertionId({
    db: input.db,
    tenantId: input.tenantId,
    summaries: matchedSummaries,
    lifecycleStatesByAssertionId,
  });

  return input.badgeTemplates.map((badgeTemplate) => {
    const summary = summariesByTemplate.get(badgeTemplate.id) ?? null;
    const lifecycleState =
      summary === null
        ? null
        : (lifecycleStatesByAssertionId.get(summary.assertionId)?.state ?? "active");
    const isIssued =
      summary !== null &&
      learnerBadgeSummaryIsIssued({
        summary,
        lifecycleState: lifecycleState ?? "active",
      });
    const claimState =
      isIssued && summary !== null
        ? (claimStatesByAssertionId.get(summary.assertionId) ?? "claimable")
        : null;

    return {
      badge: ltiBadgeSummaryCardFromTemplate({
        tenantId: input.tenantId,
        badgeTemplate,
      }),
      status: isIssued ? LTI_LEARNER_BADGE_ISSUED_STATUS : LTI_LEARNER_BADGE_NOT_ISSUED_STATUS,
      issuedAt: isIssued ? summary.issuedAt : null,
      claimState,
      claimActionPath:
        claimState === "claimable" && summary !== null
          ? learnerClaimActionPath({
              tenantId: input.tenantId,
              assertionId: summary.assertionId,
            })
          : null,
      sharePath: isIssued && summary !== null ? learnerBadgeSharePath(summary) : null,
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
    logLtiWarning(input.logger, "Could not build learner badge summary view", {
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

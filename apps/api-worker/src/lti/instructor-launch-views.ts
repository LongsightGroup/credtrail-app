import type { SqlDatabase, TenantMembershipRole } from "@credtrail/db";
import {
  LTI_CLAIM_CONTEXT,
  resolveLtiServiceCapabilities,
  type LTI13JwtPayload as LtiLaunchClaims,
  type LTISession,
  type LtiToolPort,
} from "@longsightgroup/lti-tool";
import type { AppBindings } from "../app";
import type { AppLogger } from "../app/observability";
import { asJsonObject, asNonEmptyString } from "../utils/value-parsers";
import { ltiCourseContextIdFromLaunch } from "./course-badge-placements";
import {
  emptyInstructorBulkIssuanceView,
  instructorBulkIssuanceViewDependencies,
  resolveInstructorBulkIssuanceView,
} from "./instructor-bulk-issuance-view";
import {
  emptyInstructorCourseBadgeSummaryView,
  instructorCourseSummaryViewDependencies,
  resolveInstructorCourseBadgeSummaryView,
} from "./instructor-course-summary-view";
import { loadLtiNrpsRoster, type LtiNrpsRosterLoadFailure } from "./nrps";
import type { ValidatedResourceLinkLaunch } from "./resource-link-launch-types";
import { ltiBadgeSummaryCardFromTemplate } from "./badge-summary-helpers";
import type { InstructorResourceLinkViews } from "./view-models";

interface ResolveInstructorResourceLinkViewsBaseInput {
  db: SqlDatabase;
  env: AppBindings;
  tenantId: string;
  launchClaims: LtiLaunchClaims;
  ltiLaunchSession: LTISession;
  ltiTool: LtiToolPort;
  issuerClientId: string;
  linkedUserId: string;
  membershipRole: TenantMembershipRole;
  ltiLog?: AppLogger | undefined;
  sha256Hex: (value: string) => Promise<string>;
  sessionHandoffTtlSeconds: number;
}

export type ResolveInstructorResourceLinkViewsInput =
  ResolveInstructorResourceLinkViewsBaseInput & {
    launch: ValidatedResourceLinkLaunch;
  };

const logLtiNrpsRosterFailure = (input: {
  message: string;
  tenantId: string;
  failure: LtiNrpsRosterLoadFailure;
  badgeTemplateId?: string;
  summaryContextId?: string;
  ltiLog?: AppLogger | undefined;
}): void => {
  input.ltiLog?.warn(input.message, {
    tenantId: input.tenantId,
    ...(input.badgeTemplateId === undefined ? {} : { badgeTemplateId: input.badgeTemplateId }),
    ...(input.summaryContextId === undefined ? {} : { summaryContextId: input.summaryContextId }),
    ...input.failure.logDetail,
  });
};

export const resolveInstructorResourceLinkViews = async (
  input: ResolveInstructorResourceLinkViewsInput,
): Promise<InstructorResourceLinkViews> => {
  const serviceCapabilities = resolveLtiServiceCapabilities(input.ltiLaunchSession);
  const contextMembershipsUrl = serviceCapabilities.nrps.membershipUrl ?? null;
  const contextClaim = asJsonObject(input.launchClaims[LTI_CLAIM_CONTEXT]);
  const courseContextTitle =
    asNonEmptyString(contextClaim?.title) ?? asNonEmptyString(contextClaim?.label) ?? null;
  const courseContextId = asNonEmptyString(contextClaim?.id);

  if (input.launch.kind === "selected") {
    const selectedBadge = ltiBadgeSummaryCardFromTemplate({
      tenantId: input.tenantId,
      badgeTemplate: input.launch.launchedBadgeTemplate,
    });

    const rosterResult = await loadLtiNrpsRoster({
      ltiTool: input.ltiTool,
      ltiSession: input.ltiLaunchSession,
      contextId: courseContextId ?? input.ltiLaunchSession.context.id ?? null,
    });

    if (!rosterResult.success) {
      if (rosterResult.failure.status === "error") {
        logLtiNrpsRosterFailure({
          message: "Could not load LMS roster for bulk issuance view",
          tenantId: input.tenantId,
          badgeTemplateId: selectedBadge.badgeTemplateId,
          failure: rosterResult.failure,
          ltiLog: input.ltiLog,
        });
      }

      return {
        kind: "bulk",
        bulkIssuanceView: emptyInstructorBulkIssuanceView({
          status: rosterResult.failure.status,
          message:
            rosterResult.failure.status === "unavailable"
              ? "This LMS launch did not include a learner roster, so CredTrail cannot issue badges from this tool yet."
              : "CredTrail could not load the learner roster from the LMS. Check the LMS connection settings.",
          selectedBadge,
          courseContextTitle,
          courseContextId,
          contextMembershipsUrl,
        }),
        courseBadgeSummaryView: null,
      };
    }

    try {
      return {
        kind: "bulk",
        bulkIssuanceView: await resolveInstructorBulkIssuanceView(
          instructorBulkIssuanceViewDependencies,
          {
            db: input.db,
            env: input.env,
            tenantId: input.tenantId,
            launchClaims: input.launchClaims,
            launchMessage: input.launch.launchMessage,
            ltiLaunchSession: input.ltiLaunchSession,
            roster: rosterResult.roster,
            issuerClientId: input.issuerClientId,
            linkedUserId: input.linkedUserId,
            selectedBadge,
            courseContextTitle,
            courseContextId,
            contextMembershipsUrl: contextMembershipsUrl ?? "",
            sha256Hex: input.sha256Hex,
            sessionHandoffTtlSeconds: input.sessionHandoffTtlSeconds,
            nowIso: new Date().toISOString(),
            ltiLog: input.ltiLog,
          },
        ),
        courseBadgeSummaryView: null,
      };
    } catch (error) {
      input.ltiLog?.warn("Could not build bulk issuance view from LMS roster", {
        tenantId: input.tenantId,
        badgeTemplateId: selectedBadge.badgeTemplateId,
        detail: error instanceof Error ? error.message : "unknown error",
      });

      return {
        kind: "bulk",
        bulkIssuanceView: emptyInstructorBulkIssuanceView({
          status: "error",
          message:
            "CredTrail could not load the learner roster from the LMS. Check the LMS connection settings.",
          selectedBadge,
          courseContextTitle,
          courseContextId,
          contextMembershipsUrl,
        }),
        courseBadgeSummaryView: null,
      };
    }
  }

  const summaryContextId = ltiCourseContextIdFromLaunch({
    launchMessage: input.launch.launchMessage,
    ltiLaunchSession: input.ltiLaunchSession,
  });

  if (summaryContextId.length === 0) {
    return {
      kind: "course-summary",
      bulkIssuanceView: null,
      courseBadgeSummaryView: emptyInstructorCourseBadgeSummaryView({
        status: "unavailable",
        message:
          "CredTrail could not identify this LMS course. Ask an administrator to check the LMS tool setup.",
        courseContextTitle,
      }),
    };
  }

  const rosterResult = await loadLtiNrpsRoster({
    ltiTool: input.ltiTool,
    ltiSession: input.ltiLaunchSession,
    contextId: summaryContextId,
  });

  if (!rosterResult.success) {
    if (rosterResult.failure.status === "error") {
      logLtiNrpsRosterFailure({
        message: "Could not load LMS roster for course badge summary view",
        tenantId: input.tenantId,
        summaryContextId,
        failure: rosterResult.failure,
        ltiLog: input.ltiLog,
      });
    }

    return {
      kind: "course-summary",
      bulkIssuanceView: null,
      courseBadgeSummaryView: emptyInstructorCourseBadgeSummaryView({
        status: rosterResult.failure.status,
        message:
          "CredTrail could not load the learner roster from the LMS. Ask an administrator to check the LMS connection settings.",
        courseContextTitle,
      }),
    };
  }

  try {
    return {
      kind: "course-summary",
      bulkIssuanceView: null,
      courseBadgeSummaryView: await resolveInstructorCourseBadgeSummaryView(
        instructorCourseSummaryViewDependencies,
        {
          db: input.db,
          tenantId: input.tenantId,
          launchClaims: input.launchClaims,
          issuerClientId: input.issuerClientId,
          membershipRole: input.membershipRole,
          courseContextTitle,
          summaryContextId,
          roster: rosterResult.roster,
        },
      ),
    };
  } catch (error) {
    input.ltiLog?.warn("Could not build course badge summary view", {
      tenantId: input.tenantId,
      summaryContextId,
      detail: error instanceof Error ? error.message : "unknown error",
    });

    return {
      kind: "course-summary",
      bulkIssuanceView: null,
      courseBadgeSummaryView: emptyInstructorCourseBadgeSummaryView({
        status: "error",
        message:
          "CredTrail could not load badge progress for this course. Ask an administrator to check the LMS connection settings.",
        courseContextTitle,
      }),
    };
  }
};

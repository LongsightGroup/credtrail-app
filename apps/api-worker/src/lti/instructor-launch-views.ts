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
  resolveInstructorBulkIssuanceView,
} from "./instructor-bulk-issuance-view";
import {
  emptyInstructorCourseBadgeSummaryView,
  resolveInstructorCourseBadgeSummaryView,
} from "./instructor-course-summary-view";
import { loadLtiNrpsRoster, type LtiNrpsRoster, type LtiNrpsRosterLoadFailure } from "./nrps";
import { ltiErrorDetail } from "./redaction";
import type {
  ValidatedCourseResourceLinkLaunch,
  ValidatedResourceLinkLaunch,
  ValidatedSelectedResourceLinkLaunch,
} from "./resource-link-launch-types";
import { ltiBadgeSummaryCardFromTemplate } from "./badge-summary-helpers";
import type { InstructorResourceLinkViews } from "./view-models";

type InstructorBulkResourceLinkViews = Extract<InstructorResourceLinkViews, { kind: "bulk" }>;
type InstructorCourseSummaryResourceLinkViews = Extract<
  InstructorResourceLinkViews,
  { kind: "course-summary" }
>;

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

type ResolveSelectedInstructorResourceLinkViewsInput =
  ResolveInstructorResourceLinkViewsBaseInput & {
    launch: ValidatedSelectedResourceLinkLaunch;
  };

type ResolveCourseInstructorResourceLinkViewsInput = ResolveInstructorResourceLinkViewsBaseInput & {
  launch: ValidatedCourseResourceLinkLaunch;
};

interface InstructorLaunchViewContext {
  readonly contextMembershipsUrl: string | null;
  readonly courseContextTitle: string | null;
  readonly courseContextId: string | null;
}

interface InstructorNrpsLogContext {
  readonly badgeTemplateId?: string;
  readonly summaryContextId?: string;
}

const logLtiNrpsRosterFailure = (input: {
  message: string;
  tenantId: string;
  failure: LtiNrpsRosterLoadFailure;
  context: InstructorNrpsLogContext;
  ltiLog?: AppLogger | undefined;
}): void => {
  input.ltiLog?.warn(input.message, {
    tenantId: input.tenantId,
    ...(input.context.badgeTemplateId === undefined
      ? {}
      : { badgeTemplateId: input.context.badgeTemplateId }),
    ...(input.context.summaryContextId === undefined
      ? {}
      : { summaryContextId: input.context.summaryContextId }),
    ...input.failure.logDetail,
  });
};

const logInstructorNrpsViewBuildFailure = (input: {
  message: string;
  tenantId: string;
  context: InstructorNrpsLogContext;
  error: unknown;
  ltiLog?: AppLogger | undefined;
}): void => {
  const detail = ltiErrorDetail(input.error);

  input.ltiLog?.warn(input.message, {
    tenantId: input.tenantId,
    ...(input.context.badgeTemplateId === undefined
      ? {}
      : { badgeTemplateId: input.context.badgeTemplateId }),
    ...(input.context.summaryContextId === undefined
      ? {}
      : { summaryContextId: input.context.summaryContextId }),
    ...(detail === undefined ? {} : { detail }),
  });
};

const withInstructorNrpsRoster = async <View extends InstructorResourceLinkViews>(input: {
  tenantId: string;
  ltiTool: LtiToolPort;
  ltiLaunchSession: LTISession;
  rosterContextId: string | null;
  nrpsFailureLogMessage: string;
  buildFailureLogMessage: string;
  logContext: InstructorNrpsLogContext;
  ltiLog?: AppLogger | undefined;
  onFailure: (failure: LtiNrpsRosterLoadFailure) => View;
  onBuildError: () => View;
  onSuccess: (roster: LtiNrpsRoster) => Promise<View>;
}): Promise<View> => {
  const rosterResult = await loadLtiNrpsRoster({
    ltiTool: input.ltiTool,
    ltiSession: input.ltiLaunchSession,
    contextId: input.rosterContextId,
  });

  if (!rosterResult.success) {
    if (rosterResult.failure.status === "error") {
      logLtiNrpsRosterFailure({
        message: input.nrpsFailureLogMessage,
        tenantId: input.tenantId,
        context: input.logContext,
        failure: rosterResult.failure,
        ltiLog: input.ltiLog,
      });
    }

    return input.onFailure(rosterResult.failure);
  }

  try {
    return await input.onSuccess(rosterResult.roster);
  } catch (error: unknown) {
    logInstructorNrpsViewBuildFailure({
      message: input.buildFailureLogMessage,
      tenantId: input.tenantId,
      context: input.logContext,
      error,
      ltiLog: input.ltiLog,
    });

    return input.onBuildError();
  }
};

const resolveSelectedInstructorResourceLinkViews = async (
  input: ResolveSelectedInstructorResourceLinkViewsInput,
  launchContext: InstructorLaunchViewContext,
): Promise<InstructorBulkResourceLinkViews> => {
  const selectedBadge = ltiBadgeSummaryCardFromTemplate({
    tenantId: input.tenantId,
    badgeTemplate: input.launch.launchedBadgeTemplate,
  });

  return withInstructorNrpsRoster<InstructorBulkResourceLinkViews>({
    tenantId: input.tenantId,
    ltiTool: input.ltiTool,
    ltiLaunchSession: input.ltiLaunchSession,
    rosterContextId: launchContext.courseContextId ?? input.ltiLaunchSession.context.id ?? null,
    nrpsFailureLogMessage: "Could not load LMS roster for bulk issuance view",
    buildFailureLogMessage: "Could not build bulk issuance view from LMS roster",
    logContext: { badgeTemplateId: selectedBadge.badgeTemplateId },
    ltiLog: input.ltiLog,
    onFailure: (failure) => ({
      kind: "bulk",
      bulkIssuanceView: emptyInstructorBulkIssuanceView({
        status: failure.status,
        message:
          failure.status === "unavailable"
            ? "This LMS launch did not include a learner roster, so CredTrail cannot issue badges from this tool yet."
            : "CredTrail could not load the learner roster from the LMS. Check the LMS connection settings.",
        selectedBadge,
        courseContextTitle: launchContext.courseContextTitle,
        courseContextId: launchContext.courseContextId,
        contextMembershipsUrl: launchContext.contextMembershipsUrl,
      }),
      courseBadgeSummaryView: null,
    }),
    onBuildError: () => ({
      kind: "bulk",
      bulkIssuanceView: emptyInstructorBulkIssuanceView({
        status: "error",
        message:
          "CredTrail could not load the learner roster from the LMS. Check the LMS connection settings.",
        selectedBadge,
        courseContextTitle: launchContext.courseContextTitle,
        courseContextId: launchContext.courseContextId,
        contextMembershipsUrl: launchContext.contextMembershipsUrl,
      }),
      courseBadgeSummaryView: null,
    }),
    onSuccess: async (roster) => ({
      kind: "bulk",
      bulkIssuanceView: await resolveInstructorBulkIssuanceView({
        db: input.db,
        env: input.env,
        tenantId: input.tenantId,
        launchClaims: input.launchClaims,
        launchMessage: input.launch.launchMessage,
        ltiLaunchSession: input.ltiLaunchSession,
        roster,
        issuerClientId: input.issuerClientId,
        linkedUserId: input.linkedUserId,
        selectedBadge,
        courseContextTitle: launchContext.courseContextTitle,
        courseContextId: launchContext.courseContextId,
        contextMembershipsUrl: launchContext.contextMembershipsUrl ?? "",
        sha256Hex: input.sha256Hex,
        sessionHandoffTtlSeconds: input.sessionHandoffTtlSeconds,
        nowIso: new Date().toISOString(),
        ltiLog: input.ltiLog,
      }),
      courseBadgeSummaryView: null,
    }),
  });
};

const resolveCourseInstructorResourceLinkViews = async (
  input: ResolveCourseInstructorResourceLinkViewsInput,
  launchContext: InstructorLaunchViewContext,
): Promise<InstructorCourseSummaryResourceLinkViews> => {
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
        courseContextTitle: launchContext.courseContextTitle,
      }),
    };
  }

  return withInstructorNrpsRoster<InstructorCourseSummaryResourceLinkViews>({
    tenantId: input.tenantId,
    ltiTool: input.ltiTool,
    ltiLaunchSession: input.ltiLaunchSession,
    rosterContextId: summaryContextId,
    nrpsFailureLogMessage: "Could not load LMS roster for course badge summary view",
    buildFailureLogMessage: "Could not build course badge summary view",
    logContext: { summaryContextId },
    ltiLog: input.ltiLog,
    onFailure: (failure) => ({
      kind: "course-summary",
      bulkIssuanceView: null,
      courseBadgeSummaryView: emptyInstructorCourseBadgeSummaryView({
        status: failure.status,
        message:
          "CredTrail could not load the learner roster from the LMS. Ask an administrator to check the LMS connection settings.",
        courseContextTitle: launchContext.courseContextTitle,
      }),
    }),
    onBuildError: () => ({
      kind: "course-summary",
      bulkIssuanceView: null,
      courseBadgeSummaryView: emptyInstructorCourseBadgeSummaryView({
        status: "error",
        message:
          "CredTrail could not load badge progress for this course. Ask an administrator to check the LMS connection settings.",
        courseContextTitle: launchContext.courseContextTitle,
      }),
    }),
    onSuccess: async (roster) => ({
      kind: "course-summary",
      bulkIssuanceView: null,
      courseBadgeSummaryView: await resolveInstructorCourseBadgeSummaryView({
        db: input.db,
        tenantId: input.tenantId,
        launchClaims: input.launchClaims,
        issuerClientId: input.issuerClientId,
        membershipRole: input.membershipRole,
        courseContextTitle: launchContext.courseContextTitle,
        summaryContextId,
        roster,
      }),
    }),
  });
};

export const resolveInstructorResourceLinkViews = async (
  input: ResolveInstructorResourceLinkViewsInput,
): Promise<InstructorResourceLinkViews> => {
  const serviceCapabilities = resolveLtiServiceCapabilities(input.ltiLaunchSession);
  const contextClaim = asJsonObject(input.launchClaims[LTI_CLAIM_CONTEXT]);
  const launchContext: InstructorLaunchViewContext = {
    contextMembershipsUrl: serviceCapabilities.nrps.membershipUrl ?? null,
    courseContextTitle:
      asNonEmptyString(contextClaim?.title) ?? asNonEmptyString(contextClaim?.label) ?? null,
    courseContextId: asNonEmptyString(contextClaim?.id),
  };

  const launch = input.launch;

  if (launch.kind === "selected") {
    return resolveSelectedInstructorResourceLinkViews({ ...input, launch }, launchContext);
  }

  return resolveCourseInstructorResourceLinkViews({ ...input, launch }, launchContext);
};

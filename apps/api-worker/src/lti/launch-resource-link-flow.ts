import { findBadgeTemplateById, type SqlDatabase } from "@credtrail/db";
import { LTI_CLAIM_DEPLOYMENT_ID } from "@longsightgroup/lti-tool";
import type { AppContext } from "../app";
import { renderAppPage } from "../ui/render-page";
import { LTI_SESSION_HANDOFF_TTL_SECONDS } from "./constants";
import { createCourseBadgePlacementRule } from "./course-badge-setup";
import { resolveLtiCourseBadgeAuthority } from "./course-badge-governance";
import {
  verifyLtiCourseBadgeSetupToken,
  type LtiCourseBadgeSetupPayload,
} from "./course-badge-setup-token";
import type { LinkedLtiLaunchAccount } from "./launch-account-linking";
import {
  type EstablishedLtiLaunchSession,
  type PreparedResourceLinkLaunch,
  type PrepareLaunchedResourceLinkPlacementInput,
  type ProductFlowResult,
  productFlowFailure,
  productFlowSuccess,
} from "./launch-product-types";
import type { ResolvedLtiLaunch } from "./launch-verification";
import { logLtiWarning } from "./log";
import { ltiDisplayNameFromClaims, ltiLearnerDashboardPath } from "./lti-helpers";
import {
  upsertLtiLaunchResourceLinkPlacement,
  type UpsertLtiLaunchResourceLinkPlacementResult,
} from "./resource-link-placement";
import { resolveLtiResourceLinkLaunchViews } from "./resource-link-launch-views";
import type {
  CourseResourceLinkLaunchMessage,
  ResourceLinkLaunchMessage,
  SelectedResourceLinkLaunchMessage,
  ValidatedResourceLinkLaunch,
} from "./resource-link-launch-types";
import { createLtiSessionHandoffToken } from "./session-handoff";
import { ltiLaunchResultPage } from "./pages";

/**
 * Validates product-owned Resource Link launch data after protocol verification.
 */
export const validateLaunchedResourceLinkBadgeTemplate = async (input: {
  db: SqlDatabase;
  tenantId: string;
  launchMessage: ResourceLinkLaunchMessage;
}): Promise<ProductFlowResult<ValidatedResourceLinkLaunch>> => {
  if (input.launchMessage.badgeTemplateId === null) {
    return productFlowSuccess({
      kind: "course",
      launchMessage: {
        ...input.launchMessage,
        badgeTemplateId: null,
      } satisfies CourseResourceLinkLaunchMessage,
    });
  }

  const launchMessage = {
    ...input.launchMessage,
    badgeTemplateId: input.launchMessage.badgeTemplateId,
  } satisfies SelectedResourceLinkLaunchMessage;
  const launchedBadgeTemplate = await findBadgeTemplateById(
    input.db,
    input.tenantId,
    launchMessage.badgeTemplateId,
  );

  if (launchedBadgeTemplate === null || launchedBadgeTemplate.isArchived) {
    return productFlowFailure({
      status: 400,
      body: {
        error: "LTI resource-link badge template is not available for this tenant",
      },
    });
  }

  return productFlowSuccess({
    kind: "selected",
    launchMessage,
    launchedBadgeTemplate,
  });
};

const recordLaunchedResourceLinkPlacement = async (input: {
  db: SqlDatabase;
  tenantId: string;
  issuerEntryClientId: string;
  launchClaims: ResolvedLtiLaunch["launchClaims"];
  launch: ValidatedResourceLinkLaunch;
  linkedUserId: string;
}): Promise<UpsertLtiLaunchResourceLinkPlacementResult | null> => {
  if (input.launch.kind === "course") {
    return null;
  }

  return upsertLtiLaunchResourceLinkPlacement({
    db: input.db,
    tenantId: input.tenantId,
    issuer: input.launchClaims.iss,
    clientId: input.issuerEntryClientId,
    deploymentId: input.launchClaims[LTI_CLAIM_DEPLOYMENT_ID],
    contextId: input.launch.launchMessage.resourceContextId,
    resourceLinkId: input.launch.launchMessage.resourceLinkId,
    badgeTemplateId: input.launch.launchMessage.badgeTemplateId,
    ruleId: input.launch.launchMessage.ruleId,
    createdByUserId: input.linkedUserId,
  });
};

const ltiCourseBadgeSetupMatchesLaunch = (input: {
  setup: LtiCourseBadgeSetupPayload;
  tenantId: string;
  issuerEntryClientId: string;
  launchClaims: ResolvedLtiLaunch["launchClaims"];
  launch: ValidatedResourceLinkLaunch;
}): boolean => {
  if (input.launch.kind !== "selected") {
    return false;
  }

  return (
    input.setup.tenantId === input.tenantId &&
    input.setup.issuer === input.launchClaims.iss &&
    input.setup.clientId === input.issuerEntryClientId &&
    input.setup.deploymentId === input.launchClaims[LTI_CLAIM_DEPLOYMENT_ID] &&
    input.setup.contextId === input.launch.launchMessage.resourceContextId &&
    input.setup.badgeTemplateId === input.launch.launchMessage.badgeTemplateId
  );
};

/**
 * Records or creates the CredTrail placement state implied by a Resource Link launch.
 */
export const prepareLaunchedResourceLinkPlacement = async (
  input: PrepareLaunchedResourceLinkPlacementInput,
): Promise<ProductFlowResult<PreparedResourceLinkLaunch>> => {
  if (input.launch.kind !== "selected" || input.launch.launchMessage.setupToken === null) {
    return productFlowSuccess({
      launch: input.launch,
      placementResult: await recordLaunchedResourceLinkPlacement({
        db: input.db,
        tenantId: input.tenantId,
        issuerEntryClientId: input.issuerEntryClientId,
        launchClaims: input.launchClaims,
        launch: input.launch,
        linkedUserId: input.linkedUserId,
      }),
    });
  }

  const setup = await verifyLtiCourseBadgeSetupToken(
    input.c.env,
    input.launch.launchMessage.setupToken,
  );

  if (input.launch.launchMessage.roleKind !== "instructor") {
    return productFlowFailure({
      status: 403,
      body: {
        error: "LTI course badge setup requires an instructor resource-link launch",
      },
    });
  }

  if (
    setup === null ||
    !ltiCourseBadgeSetupMatchesLaunch({
      setup,
      tenantId: input.tenantId,
      issuerEntryClientId: input.issuerEntryClientId,
      launchClaims: input.launchClaims,
      launch: input.launch,
    })
  ) {
    return productFlowFailure({
      status: 400,
      body: {
        error: "LTI course badge setup token does not match this resource-link launch",
      },
    });
  }

  const authority = await resolveLtiCourseBadgeAuthority(input.db, {
    tenantId: input.tenantId,
    userId: input.linkedUserId,
    badgeTemplate: input.launch.launchedBadgeTemplate,
  });

  if (!authority.ok) {
    return productFlowFailure({
      status: 403,
      body: {
        error: authority.message,
        reason: authority.reason,
      },
    });
  }

  const setupResult = await createCourseBadgePlacementRule({
    db: input.db,
    tenantId: input.tenantId,
    issuer: input.launchClaims.iss,
    clientId: input.issuerEntryClientId,
    deploymentId: input.launchClaims[LTI_CLAIM_DEPLOYMENT_ID],
    ltiSession: input.resolvedLaunch.ltiLaunchSession,
    badgeTemplate: input.launch.launchedBadgeTemplate,
    contextId: input.launch.launchMessage.resourceContextId,
    resourceLinkId: input.launch.launchMessage.resourceLinkId,
    createdByUserId: input.linkedUserId,
    createdByRole: input.linkedMembershipRole,
    delegatedGrantId: authority.grant.id,
    setupRequest: setup.setupRequest,
  });

  if (!setupResult.ok) {
    return productFlowFailure({
      status: 400,
      body: {
        error: setupResult.message,
        reason: setupResult.reason,
      },
    });
  }

  return productFlowSuccess({
    launch: {
      ...input.launch,
      launchMessage: {
        ...input.launch.launchMessage,
        ruleId: setupResult.rule.id,
      },
    },
    placementResult: {
      ok: true,
    },
  });
};

const buildLtiLaunchDashboardPath = async (input: {
  c: AppContext;
  tenantId: string;
  createdSession: EstablishedLtiLaunchSession["createdSession"];
}): Promise<string> => {
  const basePath = ltiLearnerDashboardPath(input.tenantId);

  if (input.createdSession.browserSessionToken === undefined) {
    return basePath;
  }

  const dashboardUrl = new URL(basePath, input.c.req.url);
  dashboardUrl.searchParams.set(
    "lti_session_handoff",
    await createLtiSessionHandoffToken(input.c.env, {
      tenantId: input.tenantId,
      sessionToken: input.createdSession.browserSessionToken,
      ttlSeconds: LTI_SESSION_HANDOFF_TTL_SECONDS,
    }),
  );

  return `${dashboardUrl.pathname}${dashboardUrl.search}`;
};

const resourceLinkViewsForLaunch = async (input: {
  c: AppContext;
  db: SqlDatabase;
  tenantId: string;
  launchClaims: ResolvedLtiLaunch["launchClaims"];
  resolvedLaunch: ResolvedLtiLaunch;
  validatedResourceLinkLaunch: ValidatedResourceLinkLaunch;
  linkedAccount: LinkedLtiLaunchAccount;
  sha256Hex: (value: string) => Promise<string>;
}): ReturnType<typeof resolveLtiResourceLinkLaunchViews> => {
  const roleKind = input.validatedResourceLinkLaunch.launchMessage.roleKind;

  if (roleKind === "instructor") {
    return resolveLtiResourceLinkLaunchViews({
      kind: "instructor",
      input: {
        db: input.db,
        env: input.c.env,
        tenantId: input.tenantId,
        launchClaims: input.launchClaims,
        launch: input.validatedResourceLinkLaunch,
        ltiLaunchSession: input.resolvedLaunch.ltiLaunchSession,
        ltiTool: input.resolvedLaunch.ltiTool,
        issuerClientId: input.resolvedLaunch.issuerEntry.clientId,
        linkedUserId: input.linkedAccount.userId,
        membershipRole: input.linkedAccount.membershipRole,
        sha256Hex: input.sha256Hex,
        sessionHandoffTtlSeconds: LTI_SESSION_HANDOFF_TTL_SECONDS,
      },
    });
  }

  if (roleKind === "learner") {
    return resolveLtiResourceLinkLaunchViews({
      kind: "learner",
      input: {
        db: input.db,
        tenantId: input.tenantId,
        launchClaims: input.launchClaims,
        launch: input.validatedResourceLinkLaunch,
        ltiLaunchSession: input.resolvedLaunch.ltiLaunchSession,
        issuerClientId: input.resolvedLaunch.issuerEntry.clientId,
        linkedUserId: input.linkedAccount.userId,
      },
    });
  }

  return resolveLtiResourceLinkLaunchViews({
    kind: "unknown",
  });
};

/**
 * Renders CredTrail's product UI for a verified LTI Resource Link launch.
 */
export const renderLtiResourceLinkLaunchResponse = async (input: {
  c: AppContext;
  db: SqlDatabase;
  tenantId: string;
  launchClaims: ResolvedLtiLaunch["launchClaims"];
  launchMessage: ResourceLinkLaunchMessage;
  linkedAccount: LinkedLtiLaunchAccount;
  establishedSession: EstablishedLtiLaunchSession;
  resolvedLaunch: ResolvedLtiLaunch;
  validatedResourceLinkLaunch: ValidatedResourceLinkLaunch;
  sha256Hex: (value: string) => Promise<string>;
}): Promise<Response> => {
  const [dashboardPath, resourceLinkViews] = await Promise.all([
    buildLtiLaunchDashboardPath({
      c: input.c,
      tenantId: input.tenantId,
      createdSession: input.establishedSession.createdSession,
    }),
    resourceLinkViewsForLaunch({
      c: input.c,
      db: input.db,
      tenantId: input.tenantId,
      launchClaims: input.launchClaims,
      resolvedLaunch: input.resolvedLaunch,
      validatedResourceLinkLaunch: input.validatedResourceLinkLaunch,
      linkedAccount: input.linkedAccount,
      sha256Hex: input.sha256Hex,
    }),
  ]);

  return renderAppPage(
    input.c,
    ltiLaunchResultPage({
      roleKind: input.launchMessage.roleKind,
      tenantId: input.tenantId,
      userId: input.linkedAccount.userId,
      membershipRole: input.linkedAccount.membershipRole,
      learnerProfileId: input.linkedAccount.learnerProfileId,
      issuer: input.launchClaims.iss,
      deploymentId: input.launchClaims[LTI_CLAIM_DEPLOYMENT_ID],
      subjectId: input.launchClaims.sub,
      targetLinkUri: input.launchMessage.resolvedTargetLinkUri,
      messageType: input.launchMessage.messageType,
      launchDisplayName: ltiDisplayNameFromClaims(input.launchClaims) ?? null,
      dashboardPath,
      instructorViews: resourceLinkViews.instructorViews,
      learnerView: resourceLinkViews.learnerView,
    }),
  );
};

/**
 * Logs non-fatal Resource Link placement write failures after launch rendering can continue.
 */
export const logResourceLinkPlacementFailure = (input: {
  tenantId: string;
  launch: ValidatedResourceLinkLaunch;
  placementResult: UpsertLtiLaunchResourceLinkPlacementResult;
}): void => {
  if (input.placementResult.ok) {
    return;
  }

  logLtiWarning("LTI launch continuing without recording resource-link placement", {
    tenantId: input.tenantId,
    resourceLinkId: input.launch.launchMessage.resourceLinkId,
    badgeTemplateId: input.launch.launchMessage.badgeTemplateId ?? "",
    reason: input.placementResult.reason,
    ...(input.placementResult.detail === undefined ? {} : { detail: input.placementResult.detail }),
  });
};

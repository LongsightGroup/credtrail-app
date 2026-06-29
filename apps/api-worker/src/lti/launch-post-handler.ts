import {
  attachLtiLaunchSessionPrincipal,
  findBadgeTemplateById,
  listBadgeTemplates,
  type SqlDatabase,
  type TenantMembershipRole,
} from "@credtrail/db";
import { LTI_CLAIM_DEPLOYMENT_ID } from "@lti-tool/core";
import type { AppBindings, AppContext } from "../app";
import { renderAppPage } from "../ui/render-page";
import type { LtiAuthenticatedPrincipal, LtiSessionInput } from "../auth/auth-provider";
import { LTI_SESSION_HANDOFF_TTL_SECONDS } from "./constants";
import { createCourseBadgePlacementRule } from "./course-badge-setup";
import {
  resolveLtiCourseBadgeAuthority,
  listLtiInstructorPlaceableBadgeTemplates,
} from "./course-badge-governance";
import {
  verifyLtiCourseBadgeSetupToken,
  type LtiCourseBadgeSetupPayload,
} from "./course-badge-setup-token";
import { ltiDeepLinkSelectionInput } from "./deep-linking-helpers";
import { linkLtiLaunchAccount, type LinkedLtiLaunchAccount } from "./launch-account-linking";
import {
  LtiLaunchMessageError,
  resolveLtiLaunchMessage,
  type ResolvedLtiLaunchMessage,
} from "./launch-message";
import {
  LtiLaunchVerificationError,
  resolveLtiLaunch,
  type ResolvedLtiLaunch,
} from "./launch-verification";
import {
  upsertLtiLaunchResourceLinkPlacement,
  type UpsertLtiLaunchResourceLinkPlacementResult,
} from "./resource-link-placement";
import {
  resolveLtiResourceLinkLaunchViews,
  type LtiResourceLinkLaunchViews,
} from "./resource-link-launch-views";
import type {
  CourseResourceLinkLaunchMessage,
  ResourceLinkLaunchMessage,
  SelectedResourceLinkLaunchMessage,
  ValidatedResourceLinkLaunch,
} from "./resource-link-launch-types";
import { createLtiSessionHandoffToken } from "./session-handoff";
import { logLtiWarning } from "./log";
import {
  ltiDisplayNameFromClaims,
  ltiEmailFromClaims,
  ltiLaunchFormInputFromRequest,
  ltiLearnerDashboardPath,
  ltiSourcedIdFromClaims,
  type LtiIssuerRegistry,
} from "./lti-helpers";
import { ltiDeepLinkSelectionPage, ltiLaunchResultPage } from "./pages";

export interface HandleLtiLaunchPostInput {
  c: AppContext;
  resolveLtiIssuerRegistry: (context: AppContext) => Promise<LtiIssuerRegistry>;
  resolveDatabase: (bindings: AppBindings) => SqlDatabase;
  sha256Hex: (value: string) => Promise<string>;
  createLtiSession: (
    context: AppContext,
    input: LtiSessionInput,
  ) => Promise<LtiAuthenticatedPrincipal>;
}

interface ValidatedLtiLaunchPostForm {
  idToken: string;
  state: string;
}

interface EstablishedLtiLaunchSession {
  linkedAccount: LinkedLtiLaunchAccount;
  createdSession: LtiAuthenticatedPrincipal;
}

type DeepLinkingLaunchMessage = Extract<ResolvedLtiLaunchMessage, { kind: "deep-linking" }>;

interface ValidatedDeepLinkingLaunch {
  launchMessage: DeepLinkingLaunchMessage;
}

type ValidatedLtiLaunchMessage = ValidatedDeepLinkingLaunch | ValidatedResourceLinkLaunch;

interface PreparedResourceLinkLaunch {
  launch: ValidatedResourceLinkLaunch;
  placementResult: UpsertLtiLaunchResourceLinkPlacementResult | null;
}

const isValidatedDeepLinkingLaunch = (
  launch: ValidatedLtiLaunchMessage,
): launch is ValidatedDeepLinkingLaunch => {
  return launch.launchMessage.kind === "deep-linking";
};

const ltiLaunchVerificationErrorResponse = (
  c: AppContext,
  error: LtiLaunchVerificationError,
): Response => {
  return c.json(
    {
      error: error.message,
      ...(error.detail === undefined ? {} : { detail: error.detail }),
    },
    error.status,
  );
};

const validateLtiLaunchPostForm = (
  c: AppContext,
  formInput: {
    idToken: string | null;
    state: string | null;
  },
): Response | ValidatedLtiLaunchPostForm => {
  if (formInput.idToken === null || formInput.idToken.trim().length === 0) {
    return c.json(
      {
        error: "id_token is required",
      },
      400,
    );
  }

  if (formInput.state === null || formInput.state.trim().length === 0) {
    return c.json(
      {
        error: "state is required",
      },
      400,
    );
  }

  return {
    idToken: formInput.idToken,
    state: formInput.state,
  };
};

const loadLtiLaunchRegistry = async (
  c: AppContext,
  resolveLtiIssuerRegistry: HandleLtiLaunchPostInput["resolveLtiIssuerRegistry"],
): Promise<LtiIssuerRegistry> => {
  try {
    return await resolveLtiIssuerRegistry(c);
  } catch {
    throw new Error("LTI issuer registry configuration is invalid");
  }
};

const verifyLtiLaunchPost = async (input: {
  c: AppContext;
  form: ValidatedLtiLaunchPostForm;
  registry: LtiIssuerRegistry;
  db: SqlDatabase;
}): Promise<ResolvedLtiLaunch> => {
  return resolveLtiLaunch({
    idToken: input.form.idToken,
    state: input.form.state,
    registry: input.registry,
    db: input.db,
    env: input.c.env,
  });
};

const resolveLtiLaunchPostMessage = (input: {
  resolvedLaunch: ResolvedLtiLaunch;
}): ResolvedLtiLaunchMessage => {
  return resolveLtiLaunchMessage(input.resolvedLaunch.launchClaims);
};

const validateLaunchedResourceLinkBadgeTemplate = async (input: {
  c: AppContext;
  db: SqlDatabase;
  tenantId: string;
  launchMessage: ResourceLinkLaunchMessage;
}): Promise<ValidatedResourceLinkLaunch | Response> => {
  if (input.launchMessage.badgeTemplateId === null) {
    return {
      kind: "course",
      launchMessage: {
        ...input.launchMessage,
        badgeTemplateId: null,
      } satisfies CourseResourceLinkLaunchMessage,
    };
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
    return input.c.json(
      {
        error: "LTI resource-link badge template is not available for this tenant",
      },
      400,
    );
  }

  return {
    kind: "selected",
    launchMessage,
    launchedBadgeTemplate,
  };
};

const validateResolvedLtiLaunchMessage = async (input: {
  c: AppContext;
  db: SqlDatabase;
  tenantId: string;
  launchMessage: ResolvedLtiLaunchMessage;
}): Promise<ValidatedLtiLaunchMessage | Response> => {
  if (input.launchMessage.kind === "deep-linking") {
    return {
      launchMessage: input.launchMessage,
    };
  }

  return validateLaunchedResourceLinkBadgeTemplate({
    c: input.c,
    db: input.db,
    tenantId: input.tenantId,
    launchMessage: input.launchMessage,
  });
};

const establishLtiLaunchSession = async (input: {
  c: AppContext;
  db: SqlDatabase;
  tenantId: string;
  launchClaims: ResolvedLtiLaunch["launchClaims"];
  launchMessage: ResolvedLtiLaunchMessage;
  ltiLaunchSession: ResolvedLtiLaunch["ltiLaunchSession"];
  sha256Hex: (value: string) => Promise<string>;
  createLtiSession: HandleLtiLaunchPostInput["createLtiSession"];
}): Promise<EstablishedLtiLaunchSession> => {
  let linkedAccount: LinkedLtiLaunchAccount;

  try {
    linkedAccount = await linkLtiLaunchAccount({
      db: input.db,
      tenantId: input.tenantId,
      launchClaims: input.launchClaims,
      sha256Hex: input.sha256Hex,
    });
  } catch (error) {
    logLtiWarning("Unable to link LTI launch to local account", {
      tenantId: input.tenantId,
      roleKind: input.launchMessage.roleKind,
      issuer: input.launchClaims.iss,
      hasEmailClaim: ltiEmailFromClaims(input.launchClaims) !== null,
      hasSourcedIdClaim: ltiSourcedIdFromClaims(input.launchClaims) !== null,
      detail: error instanceof Error ? error.message : "unknown error",
    });
    throw error;
  }

  const createdSession = await input.createLtiSession(input.c, {
    tenantId: input.tenantId,
    userId: linkedAccount.userId,
  });
  await attachLtiLaunchSessionPrincipal(input.db, {
    id: input.ltiLaunchSession.id,
    tenantId: input.tenantId,
    userId: linkedAccount.userId,
  });

  return {
    linkedAccount,
    createdSession,
  };
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

const prepareLaunchedResourceLinkPlacement = async (input: {
  c: AppContext;
  db: SqlDatabase;
  tenantId: string;
  issuerEntryClientId: string;
  launchClaims: ResolvedLtiLaunch["launchClaims"];
  resolvedLaunch: ResolvedLtiLaunch;
  launch: ValidatedResourceLinkLaunch;
  linkedUserId: string;
  linkedMembershipRole: TenantMembershipRole;
}): Promise<PreparedResourceLinkLaunch | Response> => {
  if (input.launch.kind !== "selected" || input.launch.launchMessage.setupToken === null) {
    return {
      launch: input.launch,
      placementResult: await recordLaunchedResourceLinkPlacement({
        db: input.db,
        tenantId: input.tenantId,
        issuerEntryClientId: input.issuerEntryClientId,
        launchClaims: input.launchClaims,
        launch: input.launch,
        linkedUserId: input.linkedUserId,
      }),
    };
  }

  const setup = await verifyLtiCourseBadgeSetupToken(
    input.c.env,
    input.launch.launchMessage.setupToken,
  );

  if (input.launch.launchMessage.roleKind !== "instructor") {
    return input.c.json(
      {
        error: "LTI course badge setup requires an instructor resource-link launch",
      },
      403,
    );
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
    return input.c.json(
      {
        error: "LTI course badge setup token does not match this resource-link launch",
      },
      400,
    );
  }

  const authority = await resolveLtiCourseBadgeAuthority(input.db, {
    tenantId: input.tenantId,
    userId: input.linkedUserId,
    badgeTemplate: input.launch.launchedBadgeTemplate,
  });

  if (!authority.ok) {
    return input.c.json(
      {
        error: authority.message,
        reason: authority.reason,
      },
      403,
    );
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
    return input.c.json(
      {
        error: setupResult.message,
        reason: setupResult.reason,
      },
      400,
    );
  }

  return {
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
  };
};

const buildLtiLaunchDashboardPath = async (input: {
  c: AppContext;
  tenantId: string;
  createdSession: LtiAuthenticatedPrincipal;
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

const renderLtiDeepLinkingLaunchResponse = async (input: {
  c: AppContext;
  db: SqlDatabase;
  tenantId: string;
  launchClaims: ResolvedLtiLaunch["launchClaims"];
  launchMessage: DeepLinkingLaunchMessage;
  resolvedLaunch: ResolvedLtiLaunch;
  linkedAccount: LinkedLtiLaunchAccount;
}): Promise<Response> => {
  const badgeTemplates = await listBadgeTemplates(input.db, {
    tenantId: input.tenantId,
    includeArchived: false,
  });
  const placeableBadgeTemplates = await listLtiInstructorPlaceableBadgeTemplates(input.db, {
    tenantId: input.tenantId,
    userId: input.linkedAccount.userId,
    badgeTemplates,
  });

  return renderAppPage(
    input.c,
    ltiDeepLinkSelectionPage(
      ltiDeepLinkSelectionInput({
        requestUrl: input.c.req.url,
        tenantId: input.tenantId,
        userId: input.linkedAccount.userId,
        membershipRole: input.linkedAccount.membershipRole,
        issuer: input.launchClaims.iss,
        deploymentId: input.launchClaims[LTI_CLAIM_DEPLOYMENT_ID],
        deepLinkReturnUrl: input.launchMessage.deepLinkingSettings.deepLinkReturnUrl,
        targetLinkUri: input.launchMessage.resolvedTargetLinkUri,
        ltiLaunchSession: input.resolvedLaunch.ltiLaunchSession,
        badgeTemplates: placeableBadgeTemplates,
      }),
    ),
  );
};

const renderLtiLaunchPostResponse = async (input: {
  c: AppContext;
  tenantId: string;
  launchClaims: ResolvedLtiLaunch["launchClaims"];
  launchMessage: ResourceLinkLaunchMessage;
  linkedAccount: LinkedLtiLaunchAccount;
  dashboardPath: string;
  resourceLinkViews: LtiResourceLinkLaunchViews;
}): Promise<Response> => {
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
      dashboardPath: input.dashboardPath,
      instructorViews: input.resourceLinkViews.instructorViews,
      learnerView: input.resourceLinkViews.learnerView,
    }),
  );
};

export const handleLtiLaunchPost = async (input: HandleLtiLaunchPostInput): Promise<Response> => {
  const formValidation = validateLtiLaunchPostForm(
    input.c,
    await ltiLaunchFormInputFromRequest(input.c),
  );

  if (formValidation instanceof Response) {
    return formValidation;
  }

  let registry: LtiIssuerRegistry;

  try {
    registry = await loadLtiLaunchRegistry(input.c, input.resolveLtiIssuerRegistry);
  } catch {
    return input.c.json(
      {
        error: "LTI issuer registry configuration is invalid",
      },
      500,
    );
  }

  const db = input.resolveDatabase(input.c.env);

  let resolvedLaunch: ResolvedLtiLaunch;

  try {
    resolvedLaunch = await verifyLtiLaunchPost({
      c: input.c,
      form: formValidation,
      registry,
      db,
    });
  } catch (error) {
    if (error instanceof LtiLaunchVerificationError) {
      return ltiLaunchVerificationErrorResponse(input.c, error);
    }

    throw error;
  }

  let launchMessage: ResolvedLtiLaunchMessage;

  try {
    launchMessage = resolveLtiLaunchPostMessage({ resolvedLaunch });
  } catch (error) {
    if (error instanceof LtiLaunchMessageError) {
      return input.c.json({ error: error.message }, error.status);
    }

    throw error;
  }

  const tenantId = resolvedLaunch.issuerEntry.tenantId;
  const validatedLaunchMessage = await validateResolvedLtiLaunchMessage({
    c: input.c,
    db,
    tenantId,
    launchMessage,
  });

  if (validatedLaunchMessage instanceof Response) {
    return validatedLaunchMessage;
  }

  let establishedSession: EstablishedLtiLaunchSession;

  try {
    establishedSession = await establishLtiLaunchSession({
      c: input.c,
      db,
      tenantId,
      launchClaims: resolvedLaunch.launchClaims,
      launchMessage: validatedLaunchMessage.launchMessage,
      ltiLaunchSession: resolvedLaunch.ltiLaunchSession,
      sha256Hex: input.sha256Hex,
      createLtiSession: input.createLtiSession,
    });
  } catch (error) {
    const detail = error instanceof Error ? error.message : "unknown error";
    const body =
      input.c.env.APP_ENV === "production"
        ? {
            error: "Unable to link LTI launch to local account",
          }
        : {
            error: "Unable to link LTI launch to local account",
            detail,
          };

    return input.c.json(body, 500);
  }

  input.c.header("Cache-Control", "no-store");

  if (isValidatedDeepLinkingLaunch(validatedLaunchMessage)) {
    return renderLtiDeepLinkingLaunchResponse({
      c: input.c,
      db,
      tenantId,
      launchClaims: resolvedLaunch.launchClaims,
      launchMessage: validatedLaunchMessage.launchMessage,
      resolvedLaunch,
      linkedAccount: establishedSession.linkedAccount,
    });
  }

  const preparedResourceLinkLaunch = await prepareLaunchedResourceLinkPlacement({
    c: input.c,
    db,
    tenantId,
    issuerEntryClientId: resolvedLaunch.issuerEntry.clientId,
    launchClaims: resolvedLaunch.launchClaims,
    resolvedLaunch,
    launch: validatedLaunchMessage,
    linkedUserId: establishedSession.linkedAccount.userId,
    linkedMembershipRole: establishedSession.linkedAccount.membershipRole,
  });

  if (preparedResourceLinkLaunch instanceof Response) {
    return preparedResourceLinkLaunch;
  }

  const validatedResourceLinkLaunch = preparedResourceLinkLaunch.launch;
  const placementResult = preparedResourceLinkLaunch.placementResult;

  if (placementResult !== null && !placementResult.ok) {
    logLtiWarning("LTI launch continuing without recording resource-link placement", {
      tenantId,
      resourceLinkId: validatedResourceLinkLaunch.launchMessage.resourceLinkId,
      badgeTemplateId: validatedResourceLinkLaunch.launchMessage.badgeTemplateId ?? "",
      reason: placementResult.reason,
      ...(placementResult.detail === undefined ? {} : { detail: placementResult.detail }),
    });
  }

  const dashboardPath = await buildLtiLaunchDashboardPath({
    c: input.c,
    tenantId,
    createdSession: establishedSession.createdSession,
  });

  let resourceLinkViews: LtiResourceLinkLaunchViews;

  if (validatedResourceLinkLaunch.launchMessage.roleKind === "instructor") {
    resourceLinkViews = await resolveLtiResourceLinkLaunchViews({
      kind: "instructor",
      input: {
        db,
        env: input.c.env,
        tenantId,
        launchClaims: resolvedLaunch.launchClaims,
        launch: validatedResourceLinkLaunch,
        ltiLaunchSession: resolvedLaunch.ltiLaunchSession,
        ltiTool: resolvedLaunch.ltiTool,
        issuerClientId: resolvedLaunch.issuerEntry.clientId,
        linkedUserId: establishedSession.linkedAccount.userId,
        membershipRole: establishedSession.linkedAccount.membershipRole,
        sha256Hex: input.sha256Hex,
        sessionHandoffTtlSeconds: LTI_SESSION_HANDOFF_TTL_SECONDS,
      },
    });
  } else if (validatedResourceLinkLaunch.launchMessage.roleKind === "learner") {
    resourceLinkViews = await resolveLtiResourceLinkLaunchViews({
      kind: "learner",
      input: {
        db,
        tenantId,
        launchClaims: resolvedLaunch.launchClaims,
        launch: validatedResourceLinkLaunch,
        ltiLaunchSession: resolvedLaunch.ltiLaunchSession,
        issuerClientId: resolvedLaunch.issuerEntry.clientId,
        linkedUserId: establishedSession.linkedAccount.userId,
      },
    });
  } else {
    resourceLinkViews = await resolveLtiResourceLinkLaunchViews({
      kind: "unknown",
    });
  }

  return renderLtiLaunchPostResponse({
    c: input.c,
    tenantId,
    launchClaims: resolvedLaunch.launchClaims,
    launchMessage: validatedResourceLinkLaunch.launchMessage,
    linkedAccount: establishedSession.linkedAccount,
    dashboardPath,
    resourceLinkViews,
  });
};

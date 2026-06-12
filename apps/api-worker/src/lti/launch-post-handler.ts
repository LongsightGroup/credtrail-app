import {
  findBadgeTemplateById,
  listBadgeTemplates,
  type SqlDatabase,
  type TenantMembershipRole,
} from "@credtrail/db";
import { LTI_CLAIM_DEPLOYMENT_ID } from "@credtrail/lti";
import type { AppBindings, AppContext } from "../app";
import { renderAppPage } from "../ui/render-page";
import type { LtiAuthenticatedPrincipal, LtiSessionInput } from "../auth/auth-provider";
import { LTI_SESSION_HANDOFF_TTL_SECONDS } from "./constants";
import { ltiDeepLinkSelectionInput } from "./deep-linking-helpers";
import { resolveInstructorResourceLinkViews } from "./instructor-launch-views";
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
import { createLtiSessionHandoffToken } from "./session-handoff";
import { logLtiWarning } from "./log";
import {
  ltiDisplayNameFromClaims,
  ltiLaunchFormInputFromRequest,
  ltiLearnerDashboardPath,
  type LtiIssuerRegistry,
} from "./lti-helpers";
import { ltiDeepLinkSelectionPage, ltiLaunchResultPage } from "./pages";
import type { InstructorResourceLinkViews } from "./view-models";

export interface HandleLtiLaunchPostInput {
  c: AppContext;
  resolveLtiIssuerRegistry: (context: AppContext) => Promise<LtiIssuerRegistry>;
  resolveDatabase: (bindings: AppBindings) => SqlDatabase;
  upsertTenantMembershipRole: (
    db: SqlDatabase,
    input: {
      tenantId: string;
      userId: string;
      role: TenantMembershipRole;
    },
  ) => Promise<{
    membership: {
      role: TenantMembershipRole;
    };
  }>;
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

type ResourceLinkLaunchMessage = Extract<ResolvedLtiLaunchMessage, { kind: "resource-link" }>;

type DeepLinkingLaunchMessage = Extract<ResolvedLtiLaunchMessage, { kind: "deep-linking" }>;

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
    nowIso: new Date().toISOString(),
  });
};

const resolveLtiLaunchPostMessage = (input: {
  resolvedLaunch: ResolvedLtiLaunch;
}): ResolvedLtiLaunchMessage => {
  return resolveLtiLaunchMessage({
    launchClaims: input.resolvedLaunch.launchClaims,
    launchState: input.resolvedLaunch.launchState,
  });
};

const validateLaunchedResourceLinkBadgeTemplate = async (input: {
  c: AppContext;
  db: SqlDatabase;
  tenantId: string;
  launchMessage: ResolvedLtiLaunchMessage;
}): Promise<Response | null> => {
  if (
    input.launchMessage.kind !== "resource-link" ||
    input.launchMessage.badgeTemplateId === null
  ) {
    return null;
  }

  const launchedBadgeTemplate = await findBadgeTemplateById(
    input.db,
    input.tenantId,
    input.launchMessage.badgeTemplateId,
  );

  if (launchedBadgeTemplate === null || launchedBadgeTemplate.isArchived) {
    return input.c.json(
      {
        error: "LTI resource-link badge template is not available for this tenant",
      },
      400,
    );
  }

  return null;
};

const establishLtiLaunchSession = async (input: {
  c: AppContext;
  db: SqlDatabase;
  tenantId: string;
  launchClaims: ResolvedLtiLaunch["launchClaims"];
  launchMessage: ResolvedLtiLaunchMessage;
  sha256Hex: (value: string) => Promise<string>;
  upsertTenantMembershipRole: HandleLtiLaunchPostInput["upsertTenantMembershipRole"];
  createLtiSession: HandleLtiLaunchPostInput["createLtiSession"];
}): Promise<EstablishedLtiLaunchSession> => {
  let linkedAccount: LinkedLtiLaunchAccount;

  try {
    linkedAccount = await linkLtiLaunchAccount({
      db: input.db,
      tenantId: input.tenantId,
      launchClaims: input.launchClaims,
      roleKind: input.launchMessage.roleKind,
      sha256Hex: input.sha256Hex,
      upsertTenantMembershipRole: input.upsertTenantMembershipRole,
    });
  } catch {
    throw new Error("Unable to link LTI launch to local account");
  }

  const createdSession = await input.createLtiSession(input.c, {
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
  launchMessage: ResourceLinkLaunchMessage;
  linkedUserId: string;
}): Promise<UpsertLtiLaunchResourceLinkPlacementResult | null> => {
  if (input.launchMessage.badgeTemplateId === null) {
    return null;
  }

  return upsertLtiLaunchResourceLinkPlacement({
    db: input.db,
    tenantId: input.tenantId,
    issuer: input.launchClaims.iss,
    clientId: input.issuerEntryClientId,
    deploymentId: input.launchClaims[LTI_CLAIM_DEPLOYMENT_ID],
    contextId: input.launchMessage.resourceContextId,
    resourceLinkId: input.launchMessage.resourceLinkId,
    badgeTemplateId: input.launchMessage.badgeTemplateId,
    createdByUserId: input.linkedUserId,
  });
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

const resolveLtiLaunchInstructorViews = async (input: {
  c: AppContext;
  db: SqlDatabase;
  tenantId: string;
  launchClaims: ResolvedLtiLaunch["launchClaims"];
  launchMessage: ResourceLinkLaunchMessage;
  resolvedLaunch: ResolvedLtiLaunch;
  issuerEntryClientId: string;
  linkedUserId: string;
  membershipRole: TenantMembershipRole;
  sha256Hex: (value: string) => Promise<string>;
}): Promise<InstructorResourceLinkViews | null> => {
  if (input.launchMessage.roleKind !== "instructor") {
    return null;
  }

  return resolveInstructorResourceLinkViews({
    db: input.db,
    env: input.c.env,
    tenantId: input.tenantId,
    launchClaims: input.launchClaims,
    launchMessage: input.launchMessage,
    ltiLaunchSession: input.resolvedLaunch.ltiLaunchSession,
    ltiTool: input.resolvedLaunch.ltiTool,
    issuerClientId: input.issuerEntryClientId,
    linkedUserId: input.linkedUserId,
    membershipRole: input.membershipRole,
    sha256Hex: input.sha256Hex,
    sessionHandoffTtlSeconds: LTI_SESSION_HANDOFF_TTL_SECONDS,
  });
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
        badgeTemplates,
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
  instructorViews: InstructorResourceLinkViews | null;
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
      instructorViews: input.instructorViews,
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
  const invalidBadgeTemplateResponse = await validateLaunchedResourceLinkBadgeTemplate({
    c: input.c,
    db,
    tenantId,
    launchMessage,
  });

  if (invalidBadgeTemplateResponse !== null) {
    return invalidBadgeTemplateResponse;
  }

  let establishedSession: EstablishedLtiLaunchSession;

  try {
    establishedSession = await establishLtiLaunchSession({
      c: input.c,
      db,
      tenantId,
      launchClaims: resolvedLaunch.launchClaims,
      launchMessage,
      sha256Hex: input.sha256Hex,
      upsertTenantMembershipRole: input.upsertTenantMembershipRole,
      createLtiSession: input.createLtiSession,
    });
  } catch {
    return input.c.json(
      {
        error: "Unable to link LTI launch to local account",
      },
      500,
    );
  }

  input.c.header("Cache-Control", "no-store");

  if (launchMessage.kind === "deep-linking") {
    return renderLtiDeepLinkingLaunchResponse({
      c: input.c,
      db,
      tenantId,
      launchClaims: resolvedLaunch.launchClaims,
      launchMessage,
      resolvedLaunch,
      linkedAccount: establishedSession.linkedAccount,
    });
  }

  const placementResult = await recordLaunchedResourceLinkPlacement({
    db,
    tenantId,
    issuerEntryClientId: resolvedLaunch.issuerEntry.clientId,
    launchClaims: resolvedLaunch.launchClaims,
    launchMessage,
    linkedUserId: establishedSession.linkedAccount.userId,
  });

  if (placementResult !== null && !placementResult.ok) {
    logLtiWarning("LTI launch continuing without recording resource-link placement", {
      tenantId,
      resourceLinkId: launchMessage.resourceLinkId,
      badgeTemplateId: launchMessage.badgeTemplateId ?? "",
      reason: placementResult.reason,
      ...(placementResult.detail === undefined ? {} : { detail: placementResult.detail }),
    });
  }

  const dashboardPath = await buildLtiLaunchDashboardPath({
    c: input.c,
    tenantId,
    createdSession: establishedSession.createdSession,
  });

  const instructorViews = await resolveLtiLaunchInstructorViews({
    c: input.c,
    db,
    tenantId,
    launchClaims: resolvedLaunch.launchClaims,
    launchMessage,
    resolvedLaunch,
    issuerEntryClientId: resolvedLaunch.issuerEntry.clientId,
    linkedUserId: establishedSession.linkedAccount.userId,
    membershipRole: establishedSession.linkedAccount.membershipRole,
    sha256Hex: input.sha256Hex,
  });

  return renderLtiLaunchPostResponse({
    c: input.c,
    tenantId,
    launchClaims: resolvedLaunch.launchClaims,
    launchMessage,
    linkedAccount: establishedSession.linkedAccount,
    dashboardPath,
    instructorViews,
  });
};

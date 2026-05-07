import { captureSentryException } from "@credtrail/core-domain";
import {
  findBadgeTemplateById,
  listBadgeTemplates,
  upsertLtiDeployment,
  upsertLtiResourceLinkPlacement,
  type SqlDatabase,
  type TenantMembershipRole,
} from "@credtrail/db";
import type { DeepLinkingContentItem, LTISession } from "@lti-tool/core";
import {
  LTI_CLAIM_CONTEXT,
  LTI_CLAIM_DEPLOYMENT_ID,
  parseLtiOidcLoginInitiationRequest,
} from "@credtrail/lti";
import type { Hono } from "hono";
import type { AppBindings, AppContext, AppEnv } from "../app";
import type { LtiAuthenticatedPrincipal, LtiSessionInput } from "../auth/auth-provider";
import { LTI_LAUNCH_PATH, LTI_OIDC_LOGIN_PATH } from "../lti/constants";
import {
  ltiLaunchFormInputFromRequest,
  ltiLearnerDashboardPath,
  ltiLoginInputFromRequest,
  normalizeLtiIssuer,
  type LtiIssuerRegistryEntry,
  type LtiIssuerRegistry,
} from "../lti/lti-helpers";
import { createCredTrailLtiTool } from "../lti/credtrail-lti-tool";
import { linkLtiLaunchAccount } from "../lti/launch-account-linking";
import {
  badgeTemplateIdFromTargetLinkUri,
  LtiLaunchMessageError,
  resolveLtiLaunchMessage,
} from "../lti/launch-message";
import {
  LtiLaunchVerificationError,
  ltiIssuerHasSignedLaunchConfig,
  resolveLtiLaunch,
} from "../lti/launch-verification";
import { createLtiSessionHandoffToken } from "../lti/session-handoff";
import {
  type LtiNrpsRoster,
  ltiNrpsRosterFromCoreMembers,
  parseLtiNrpsNamesRoleServiceClaim,
} from "../lti/nrps";
import {
  ltiDeepLinkSelectionPage,
  ltiLaunchResultPage,
  ltiPostMessageStorageRedirectPage,
  type LtiBulkIssuanceView,
  type LtiDeepLinkSelectionPageInput,
} from "../lti/pages";
import { asJsonObject, asNonEmptyString } from "../utils/value-parsers";

interface RegisterLtiRoutesInput {
  app: Hono<AppEnv>;
  resolveLtiIssuerRegistry: (context: AppContext) => Promise<LtiIssuerRegistry>;
  observabilityContext: (bindings: AppBindings) => { service: string; environment: string };
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

const LTI_DEEP_LINKING_SELECT_PATH = "/v1/lti/deep-linking/select";
const LTI_SESSION_HANDOFF_TTL_SECONDS = 60;

const ltiPostMessageStorageRedirectInput = (input: {
  authorizationRedirectUrl: string;
  storageTarget: string | undefined;
}): {
  authorizationRedirectUrl: string;
  platformOrigin: string;
  storageTarget: string;
  state: string;
  nonce: string;
} | null => {
  if (input.storageTarget === undefined || input.storageTarget.trim().length === 0) {
    return null;
  }

  const redirectUrl = new URL(input.authorizationRedirectUrl);
  const state = redirectUrl.searchParams.get("state");
  const nonce = redirectUrl.searchParams.get("nonce");

  if (state === null || nonce === null) {
    return null;
  }

  return {
    authorizationRedirectUrl: redirectUrl.toString(),
    platformOrigin: redirectUrl.origin,
    storageTarget: input.storageTarget,
    state,
    nonce,
  };
};

const ltiBulkIssuanceViewFromRoster = (input: {
  roster: LtiNrpsRoster;
  message: string;
  badgeTemplateId: string | null;
  courseContextTitle: string | null;
  courseContextId: string | null;
  contextMembershipsUrl: string;
}): LtiBulkIssuanceView => {
  const learnerMembers = input.roster.learnerMembers.map((member) => {
    return {
      userId: member.userId,
      sourcedId: member.sourcedId,
      displayName: member.displayName,
      email: member.email,
      roleSummary: member.roleSummary,
      status: member.status,
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
    members: [],
  };
};

const findLtiIssuerRegistryEntry = (
  registry: LtiIssuerRegistry,
  issuer: string,
  clientId: string,
): { issuer: string; entry: LtiIssuerRegistryEntry } | null => {
  const normalizedIssuer = normalizeLtiIssuer(issuer);

  for (const [candidateIssuer, entry] of Object.entries(registry)) {
    if (normalizeLtiIssuer(candidateIssuer) === normalizedIssuer && entry.clientId === clientId) {
      return {
        issuer: normalizeLtiIssuer(candidateIssuer),
        entry,
      };
    }
  }

  return null;
};

const badgeTemplateDeepLinkContentItem = (input: {
  title: string;
  description: string | null;
  launchUrl: string;
  badgeTemplateId: string;
}): DeepLinkingContentItem => {
  return {
    type: "ltiResourceLink",
    title: input.title,
    text: input.description ?? `CredTrail badge template ${input.title} (${input.badgeTemplateId})`,
    url: input.launchUrl,
    custom: {
      badgeTemplateId: input.badgeTemplateId,
    },
  };
};

const ltiDeepLinkSelectionInput = (input: {
  requestUrl: string;
  tenantId: string;
  userId: string;
  membershipRole: TenantMembershipRole;
  issuer: string;
  deploymentId: string;
  deepLinkReturnUrl: string;
  targetLinkUri: string;
  ltiLaunchSession: LTISession;
  badgeTemplates: readonly {
    id: string;
    title: string;
    description: string | null;
  }[];
}): LtiDeepLinkSelectionPageInput => {
  const options = input.badgeTemplates.map((badgeTemplate) => {
    const launchUrl = new URL(input.targetLinkUri);
    launchUrl.searchParams.set("badgeTemplateId", badgeTemplate.id);

    return {
      badgeTemplateId: badgeTemplate.id,
      title: badgeTemplate.title,
      description: badgeTemplate.description,
      launchUrl: launchUrl.toString(),
    };
  });
  const common = {
    tenantId: input.tenantId,
    userId: input.userId,
    membershipRole: input.membershipRole,
    issuer: input.issuer,
    deploymentId: input.deploymentId,
    deepLinkReturnUrl: input.deepLinkReturnUrl,
    targetLinkUri: input.targetLinkUri,
  };

  return {
    ...common,
    mode: "signed",
    signedSelectionActionUrl: new URL(LTI_DEEP_LINKING_SELECT_PATH, input.requestUrl).toString(),
    ltiSessionId: input.ltiLaunchSession.id,
    options,
  };
};

export const registerLtiRoutes = (input: RegisterLtiRoutesInput): void => {
  const {
    app,
    resolveLtiIssuerRegistry,
    observabilityContext,
    resolveDatabase,
    upsertTenantMembershipRole: upsertTenantMembershipRoleWithInput,
    sha256Hex,
    createLtiSession,
  } = input;

  const ltiOidcLoginHandler = async (c: AppContext): Promise<Response> => {
    let registry: LtiIssuerRegistry;

    try {
      registry = await resolveLtiIssuerRegistry(c);
    } catch (error) {
      await captureSentryException({
        context: observabilityContext(c.env),
        dsn: c.env.SENTRY_DSN,
        error,
        message: "LTI issuer registry configuration is invalid",
        tags: {
          path: LTI_OIDC_LOGIN_PATH,
          method: c.req.method,
        },
      });
      return c.json(
        {
          error: "LTI issuer registry configuration is invalid",
        },
        500,
      );
    }

    let loginRequest;

    try {
      loginRequest = parseLtiOidcLoginInitiationRequest(await ltiLoginInputFromRequest(c));
    } catch {
      return c.json(
        {
          error: "Invalid LTI OIDC login initiation request",
        },
        400,
      );
    }

    const issuerEntry = registry[normalizeLtiIssuer(loginRequest.iss)];

    if (issuerEntry === undefined) {
      return c.json(
        {
          error: "Unknown LTI issuer",
        },
        400,
      );
    }

    const clientId = loginRequest.client_id ?? issuerEntry.clientId;

    if (loginRequest.client_id !== undefined && loginRequest.client_id !== issuerEntry.clientId) {
      return c.json(
        {
          error: "client_id does not match configured issuer registration",
        },
        400,
      );
    }

    if (!ltiIssuerHasSignedLaunchConfig(issuerEntry)) {
      return c.json(
        {
          error:
            "LTI issuer requires platform JWKS and token endpoint configuration for signed launches",
        },
        501,
      );
    }

    const db = resolveDatabase(c.env);
    const deploymentId = loginRequest.lti_deployment_id ?? "default";
    await upsertLtiDeployment(db, {
      issuer: loginRequest.iss,
      clientId,
      deploymentId,
    });
    const ltiTool = await createCredTrailLtiTool({
      db,
      env: c.env,
      defaultTenantId: issuerEntry.tenantId,
    });
    const authRedirectUrl = await ltiTool.handleLogin({
      iss: normalizeLtiIssuer(loginRequest.iss),
      client_id: clientId,
      launchUrl: new URL(LTI_LAUNCH_PATH, c.req.url),
      login_hint: loginRequest.login_hint,
      target_link_uri: loginRequest.target_link_uri,
      lti_deployment_id: deploymentId,
      ...(loginRequest.lti_message_hint === undefined
        ? {}
        : { lti_message_hint: loginRequest.lti_message_hint }),
    });
    const postMessageStorageInput = ltiPostMessageStorageRedirectInput({
      authorizationRedirectUrl: authRedirectUrl,
      storageTarget: loginRequest.lti_storage_target,
    });

    if (postMessageStorageInput !== null) {
      c.header("Cache-Control", "no-store");
      return c.html(ltiPostMessageStorageRedirectPage(postMessageStorageInput));
    }

    return c.redirect(authRedirectUrl, 302);
  };

  app.get(LTI_OIDC_LOGIN_PATH, ltiOidcLoginHandler);
  app.post(LTI_OIDC_LOGIN_PATH, ltiOidcLoginHandler);

  app.get("/v1/lti/jwks", async (c): Promise<Response> => {
    const ltiTool = await createCredTrailLtiTool({
      db: resolveDatabase(c.env),
      env: c.env,
    });
    return c.json(await ltiTool.getJWKS());
  });

  app.post(LTI_DEEP_LINKING_SELECT_PATH, async (c): Promise<Response> => {
    const form = await c.req.formData();
    const ltiSessionId = asNonEmptyString(form.get("lti_session_id"));
    const badgeTemplateId = asNonEmptyString(form.get("badge_template_id"));

    if (ltiSessionId === null || badgeTemplateId === null) {
      return c.json(
        {
          error: "lti_session_id and badge_template_id are required",
        },
        400,
      );
    }

    const db = resolveDatabase(c.env);
    const ltiTool = await createCredTrailLtiTool({
      db,
      env: c.env,
    });
    const ltiSession = await ltiTool.getSession(ltiSessionId);

    if (ltiSession === undefined || ltiSession.services?.deepLinking === undefined) {
      return c.json(
        {
          error: "LTI Deep Linking session was not found or is no longer active",
        },
        404,
      );
    }

    const issuerRegistry = await resolveLtiIssuerRegistry(c);
    const issuerMatch = findLtiIssuerRegistryEntry(
      issuerRegistry,
      ltiSession.platform.issuer,
      ltiSession.platform.clientId,
    );

    if (issuerMatch === null) {
      return c.json(
        {
          error: "LTI issuer registration was not found for this Deep Linking session",
        },
        404,
      );
    }

    const badgeTemplates = await listBadgeTemplates(db, {
      tenantId: issuerMatch.entry.tenantId,
      includeArchived: false,
    });
    const badgeTemplate = badgeTemplates.find((template) => template.id === badgeTemplateId);

    if (badgeTemplate === undefined) {
      return c.json(
        {
          error: "Badge template is not available for this LTI tenant",
        },
        404,
      );
    }

    const launchUrl = new URL(ltiSession.launch.target);
    launchUrl.searchParams.set("badgeTemplateId", badgeTemplate.id);
    const responseHtml = await ltiTool.createDeepLinkingResponse(ltiSession, [
      badgeTemplateDeepLinkContentItem({
        badgeTemplateId: badgeTemplate.id,
        title: badgeTemplate.title,
        description: badgeTemplate.description,
        launchUrl: launchUrl.toString(),
      }),
    ]);

    c.header("Cache-Control", "no-store");
    return c.html(responseHtml);
  });

  app.post(LTI_LAUNCH_PATH, async (c): Promise<Response> => {
    const formInput = await ltiLaunchFormInputFromRequest(c);

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

    let registry: LtiIssuerRegistry;

    try {
      registry = await resolveLtiIssuerRegistry(c);
    } catch (error) {
      await captureSentryException({
        context: observabilityContext(c.env),
        dsn: c.env.SENTRY_DSN,
        error,
        message: "LTI issuer registry configuration is invalid",
        tags: {
          path: LTI_LAUNCH_PATH,
          method: c.req.method,
        },
      });
      return c.json(
        {
          error: "LTI issuer registry configuration is invalid",
        },
        500,
      );
    }

    const nowIso = new Date().toISOString();
    const db = resolveDatabase(c.env);
    const resolvedLaunch = await resolveLtiLaunch({
      idToken: formInput.idToken,
      state: formInput.state,
      registry,
      db,
      env: c.env,
      nowIso,
    }).catch(async (error: unknown) => {
      if (!(error instanceof LtiLaunchVerificationError)) {
        throw error;
      }

      if (error.status === 401) {
        await captureSentryException({
          context: observabilityContext(c.env),
          dsn: c.env.SENTRY_DSN,
          error,
          message: "Signed LTI launch verification failed",
          tags: {
            path: LTI_LAUNCH_PATH,
            method: c.req.method,
          },
          extra: {
            detail: error.detail,
          },
        });
      }

      return c.json(
        {
          error: error.message,
          ...(error.detail === undefined ? {} : { detail: error.detail }),
        },
        error.status,
      );
    });

    if (resolvedLaunch instanceof Response) {
      return resolvedLaunch;
    }

    const { issuerEntry, launchClaims, ltiLaunchSession, ltiTool } = resolvedLaunch;
    const launchMessage = (() => {
      try {
        return resolveLtiLaunchMessage({
          launchClaims,
          launchState: resolvedLaunch.launchState,
        });
      } catch (error) {
        if (error instanceof LtiLaunchMessageError) {
          return c.json({ error: error.message }, error.status);
        }
        throw error;
      }
    })();

    if (launchMessage instanceof Response) {
      return launchMessage;
    }
    const tenantId = issuerEntry.tenantId;

    if (launchMessage.kind === "resource-link" && launchMessage.badgeTemplateId !== null) {
      const launchedBadgeTemplate = await findBadgeTemplateById(
        db,
        tenantId,
        launchMessage.badgeTemplateId,
      );

      if (launchedBadgeTemplate === null || launchedBadgeTemplate.isArchived) {
        return c.json(
          {
            error: "LTI resource-link badge template is not available for this tenant",
          },
          400,
        );
      }
    }

    let linkedAccount;

    try {
      linkedAccount = await linkLtiLaunchAccount({
        db,
        tenantId,
        launchClaims,
        roleKind: launchMessage.roleKind,
        sha256Hex,
        upsertTenantMembershipRole: upsertTenantMembershipRoleWithInput,
      });
    } catch (error) {
      await captureSentryException({
        context: observabilityContext(c.env),
        dsn: c.env.SENTRY_DSN,
        error,
        message: "LTI launch could not be linked to a local user/session",
        tags: {
          path: LTI_LAUNCH_PATH,
          method: c.req.method,
        },
        extra: {
          issuer: launchClaims.iss,
          deploymentId: launchClaims[LTI_CLAIM_DEPLOYMENT_ID],
          subjectId: launchClaims.sub,
        },
      });
      return c.json(
        {
          error: "Unable to link LTI launch to local account",
        },
        500,
      );
    }

    const createdSession = await createLtiSession(c, {
      tenantId,
      userId: linkedAccount.userId,
    });

    if (launchMessage.kind === "resource-link" && launchMessage.badgeTemplateId !== null) {
      try {
        await upsertLtiResourceLinkPlacement(db, {
          tenantId,
          issuer: launchClaims.iss,
          clientId: issuerEntry.clientId,
          deploymentId: launchClaims[LTI_CLAIM_DEPLOYMENT_ID],
          contextId: launchMessage.resourceContextId,
          resourceLinkId: launchMessage.resourceLinkId,
          badgeTemplateId: launchMessage.badgeTemplateId,
          createdByUserId: linkedAccount.userId,
        });
      } catch (error) {
        await captureSentryException({
          context: observabilityContext(c.env),
          dsn: c.env.SENTRY_DSN,
          error,
          message: "LTI resource-link placement persistence failed",
          tags: {
            path: LTI_LAUNCH_PATH,
            method: c.req.method,
          },
          extra: {
            issuer: launchClaims.iss,
            tenantId,
            deploymentId: launchClaims[LTI_CLAIM_DEPLOYMENT_ID],
            resourceLinkId: launchMessage.resourceLinkId,
            badgeTemplateId: launchMessage.badgeTemplateId,
          },
        });
      }
    }

    const dashboardPath = await (async (): Promise<string> => {
      const basePath = ltiLearnerDashboardPath(tenantId);

      if (createdSession.browserSessionToken === undefined) {
        return basePath;
      }

      const dashboardUrl = new URL(basePath, c.req.url);
      dashboardUrl.searchParams.set(
        "lti_session_handoff",
        await createLtiSessionHandoffToken(c.env, {
          tenantId,
          sessionToken: createdSession.browserSessionToken,
          ttlSeconds: LTI_SESSION_HANDOFF_TTL_SECONDS,
        }),
      );
      return `${dashboardUrl.pathname}${dashboardUrl.search}`;
    })();
    c.header("Cache-Control", "no-store");
    let bulkIssuanceView: LtiBulkIssuanceView | null = null;

    if (launchMessage.kind === "resource-link" && launchMessage.roleKind === "instructor") {
      const nrpsClaim = parseLtiNrpsNamesRoleServiceClaim(launchClaims);
      const contextClaim = asJsonObject(launchClaims[LTI_CLAIM_CONTEXT]);
      const courseContextTitle =
        asNonEmptyString(contextClaim?.title) ?? asNonEmptyString(contextClaim?.label) ?? null;
      const courseContextId = asNonEmptyString(contextClaim?.id);
      const badgeTemplateId = badgeTemplateIdFromTargetLinkUri(launchMessage.resolvedTargetLinkUri);

      if (nrpsClaim === null) {
        bulkIssuanceView = ltiEmptyBulkIssuanceView({
          status: "unavailable",
          message: "LMS launch did not include NRPS names/roles service claim details.",
          badgeTemplateId,
          courseContextTitle,
          courseContextId,
          contextMembershipsUrl: null,
        });
      } else {
        try {
          const members = await ltiTool.getMembers(ltiLaunchSession);
          const roster = ltiNrpsRosterFromCoreMembers({
            contextId: courseContextId ?? ltiLaunchSession.context.id ?? null,
            members,
          });
          bulkIssuanceView = ltiBulkIssuanceViewFromRoster({
            roster,
            message: `Loaded ${String(roster.learnerMembers.length)} learner members from LMS NRPS roster.`,
            badgeTemplateId,
            courseContextTitle,
            courseContextId,
            contextMembershipsUrl: nrpsClaim.contextMembershipsUrl,
          });
        } catch (error) {
          await captureSentryException({
            context: observabilityContext(c.env),
            dsn: c.env.SENTRY_DSN,
            error,
            message: "NRPS roster pull failed for signed LTI launch",
            tags: {
              path: LTI_LAUNCH_PATH,
              method: c.req.method,
            },
            extra: {
              issuer: launchClaims.iss,
              tenantId,
              deploymentId: launchClaims[LTI_CLAIM_DEPLOYMENT_ID],
              contextMembershipsUrl: nrpsClaim.contextMembershipsUrl,
            },
          });
          bulkIssuanceView = ltiEmptyBulkIssuanceView({
            status: "error",
            message: "NRPS roster request failed for this launch. Check issuer token settings.",
            badgeTemplateId,
            courseContextTitle,
            courseContextId,
            contextMembershipsUrl: nrpsClaim.contextMembershipsUrl,
          });
        }
      }
    }

    if (launchMessage.kind === "deep-linking") {
      const badgeTemplates = await listBadgeTemplates(db, {
        tenantId,
        includeArchived: false,
      });

      return c.html(
        ltiDeepLinkSelectionPage(
          ltiDeepLinkSelectionInput({
            requestUrl: c.req.url,
            tenantId,
            userId: linkedAccount.userId,
            membershipRole: linkedAccount.membershipRole,
            issuer: launchClaims.iss,
            deploymentId: launchClaims[LTI_CLAIM_DEPLOYMENT_ID],
            deepLinkReturnUrl: launchMessage.deepLinkingSettings.deepLinkReturnUrl,
            targetLinkUri: launchMessage.resolvedTargetLinkUri,
            ltiLaunchSession,
            badgeTemplates,
          }),
        ),
      );
    }

    return c.html(
      ltiLaunchResultPage({
        roleKind: launchMessage.roleKind,
        tenantId,
        userId: linkedAccount.userId,
        membershipRole: linkedAccount.membershipRole,
        learnerProfileId: linkedAccount.learnerProfileId,
        issuer: launchClaims.iss,
        deploymentId: launchClaims[LTI_CLAIM_DEPLOYMENT_ID],
        subjectId: launchClaims.sub,
        targetLinkUri: launchMessage.resolvedTargetLinkUri,
        messageType: launchMessage.messageType,
        dashboardPath,
        bulkIssuanceView,
      }),
    );
  });
};

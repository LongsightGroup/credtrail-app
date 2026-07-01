import {
  findBadgeTemplateById,
  findLtiLaunchSessionById,
  listBadgeTemplates,
  upsertLtiDeployment,
  type SqlDatabase,
} from "@credtrail/db";
import {
  createLtiPostMessageStorageRedirect,
  formatLtiServiceError,
  parseLtiLoginInitiation,
  resolveLtiServiceCapabilities,
} from "@longsightgroup/lti-tool";
import type { Hono } from "hono";
import type { AppBindings, AppContext, AppEnv } from "../app";
import { renderAppPage } from "../ui/render-page";
import type { LtiAuthenticatedPrincipal, LtiSessionInput } from "../auth/auth-provider";
import type { DirectIssueBadgeRequest } from "../badges/recipient-identifiers";
import type { DirectIssueBadgeResult } from "../badges/direct-issue";
import {
  LTI_DEEP_LINKING_SELECT_PATH,
  LTI_LAUNCH_PATH,
  LTI_OIDC_LOGIN_PATH,
  LTI_RESOURCE_LINK_ISSUE_PATH,
} from "../lti/constants";
import {
  badgeTemplateDeepLinkContentItem,
  findLtiIssuerRegistryEntry,
} from "../lti/deep-linking-helpers";
import { createCredTrailLtiTool } from "../lti/credtrail-lti-tool";
import {
  ltiCourseBadgeSetupRuleDefinition,
  parseLtiCourseBadgeSetupPreset,
} from "../lti/course-badge-setup";
import { resolveLtiCourseBadgeAuthority } from "../lti/course-badge-governance";
import { createLtiCourseBadgeSetupToken } from "../lti/course-badge-setup-token";
import { registerLtiDynamicRegistrationRoutes } from "../lti/dynamic-registration-routes";
import { registerLtiGradebookLookupRoutes } from "../lti/gradebook-lookup-routes";
import { registerLtiJwksRoute } from "../lti/jwks-routes";
import { handleLtiLaunchPost } from "../lti/launch-post-handler";
import { executeLtiRosterIssuance, LtiRosterIssuanceError } from "../lti/roster-issuance";
import { verifyLtiIssuanceActionToken } from "../lti/issuance-action-token";
import {
  ltiLoginInputFromRequest,
  normalizeLtiIssuer,
  type LtiIssuerRegistry,
} from "../lti/lti-helpers";
import { ltiIssuerHasSignedLaunchConfig } from "../lti/launch-verification";
import { ltiRosterIssuanceResultPage, ltiPostMessageStorageRedirectPage } from "../lti/pages";
import {
  ltiSessionMatchesIssuanceAction,
  selectedLearnerUserIdsFromForm,
} from "../lti/roster-issuance-helpers";
import { asNonEmptyString, normalizeUniqueStringList } from "../utils/value-parsers";

const LTI_COURSE_BADGE_SETUP_TOKEN_TTL_SECONDS = 60 * 60;

const optionalNumberFromForm = (value: FormDataEntryValue | null): number | undefined => {
  const normalized = asNonEmptyString(value);

  if (normalized === null) {
    return undefined;
  }

  const parsed = Number(normalized);
  return Number.isFinite(parsed) ? parsed : undefined;
};

interface RegisterLtiRoutesInput {
  app: Hono<AppEnv>;
  resolveLtiIssuerRegistry: (context: AppContext) => Promise<LtiIssuerRegistry>;
  resolveDatabase: (bindings: AppBindings) => SqlDatabase;
  sha256Hex: (value: string) => Promise<string>;
  createLtiSession: (
    context: AppContext,
    input: LtiSessionInput,
  ) => Promise<LtiAuthenticatedPrincipal>;
  issueBadgeForTenant: (
    c: AppContext,
    tenantId: string,
    request: DirectIssueBadgeRequest,
    issuedByUserId?: string,
    options?: {
      recipientDisplayName?: string;
      issuerName?: string;
      issuerUrl?: string;
    },
  ) => Promise<DirectIssueBadgeResult>;
}

export const registerLtiRoutes = (input: RegisterLtiRoutesInput): void => {
  const {
    app,
    resolveLtiIssuerRegistry,
    resolveDatabase,
    sha256Hex,
    createLtiSession,
    issueBadgeForTenant,
  } = input;

  // Kept local instead of lti-tool/hono loginRouteHandler because CredTrail's
  // login path does not colocate launch at /v1/lti/oidc/launch and this handler
  // owns issuer/deployment policy before protocol redirect.
  const ltiOidcLoginHandler = async (c: AppContext): Promise<Response> => {
    let registry: LtiIssuerRegistry;

    try {
      registry = await resolveLtiIssuerRegistry(c);
    } catch {
      return c.json(
        {
          error: "LTI issuer registry configuration is invalid",
        },
        500,
      );
    }

    let loginRequest;

    try {
      loginRequest = parseLtiLoginInitiation(await ltiLoginInputFromRequest(c));
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
    const postMessageStorageInput = createLtiPostMessageStorageRedirect({
      authorizationRedirectUrl: authRedirectUrl,
      ...(loginRequest.lti_storage_target === undefined
        ? {}
        : { storageTarget: loginRequest.lti_storage_target }),
    });

    if (postMessageStorageInput !== null) {
      c.header("Cache-Control", "no-store");
      return renderAppPage(c, ltiPostMessageStorageRedirectPage(postMessageStorageInput));
    }

    return c.redirect(authRedirectUrl, 302);
  };

  app.get(LTI_OIDC_LOGIN_PATH, ltiOidcLoginHandler);
  app.post(LTI_OIDC_LOGIN_PATH, ltiOidcLoginHandler);

  registerLtiJwksRoute({
    app,
    resolveDatabase,
  });

  registerLtiDynamicRegistrationRoutes({
    app,
    resolveDatabase,
  });

  registerLtiGradebookLookupRoutes({
    app,
    resolveDatabase,
    resolveLtiIssuerRegistry,
  });

  app.post(LTI_DEEP_LINKING_SELECT_PATH, async (c): Promise<Response> => {
    const form = await c.req.formData();
    const ltiSessionId = asNonEmptyString(form.get("lti_session_id"));
    const badgeTemplateId = asNonEmptyString(form.get("badge_template_id"));
    const criteriaPreset = parseLtiCourseBadgeSetupPreset(
      asNonEmptyString(form.get("criteria_preset")),
    );

    if (ltiSessionId === null || badgeTemplateId === null || criteriaPreset === null) {
      return c.json(
        {
          error: "lti_session_id, badge_template_id, and criteria_preset are required",
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
    const ltiCapabilities =
      ltiSession === undefined ? null : resolveLtiServiceCapabilities(ltiSession);

    if (ltiSession === undefined || ltiCapabilities?.deepLinking.available !== true) {
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

    const contextId = ltiSession.context.id.trim();

    if (contextId.length === 0) {
      return c.json(
        {
          error: "LTI course context is required for course badge setup",
        },
        400,
      );
    }

    const setupRequest = {
      preset: criteriaPreset,
      scoreThreshold: optionalNumberFromForm(form.get("score_threshold")),
      gradebookItemId: asNonEmptyString(form.get("gradebook_item_id")) ?? undefined,
      completionPercent: optionalNumberFromForm(form.get("completion_percent")),
      workflowStates: normalizeUniqueStringList(form.getAll("workflow_states")),
    };
    const ruleDefinition = ltiCourseBadgeSetupRuleDefinition(contextId, setupRequest);

    if (ruleDefinition === null) {
      return c.json(
        {
          error: "Choose a criterion and provide the required threshold or gradebook item.",
        },
        400,
      );
    }

    const persistedSession = await findLtiLaunchSessionById(db, ltiSession.id);

    if (persistedSession?.userId === null || persistedSession?.userId === undefined) {
      return c.json(
        {
          error: "LTI launch session is missing linked user context",
        },
        400,
      );
    }

    if (!ltiSession.isInstructor) {
      return c.json(
        {
          error: "LTI course badge setup requires an instructor Deep Linking session",
        },
        403,
      );
    }

    const authority = await resolveLtiCourseBadgeAuthority(db, {
      tenantId: issuerMatch.entry.tenantId,
      userId: persistedSession.userId,
      badgeTemplate,
    });

    if (!authority.ok) {
      return c.json(
        {
          error: authority.message,
          reason: authority.reason,
        },
        403,
      );
    }

    const setupToken = await createLtiCourseBadgeSetupToken(c.env, {
      tenantId: issuerMatch.entry.tenantId,
      issuer: ltiSession.platform.issuer,
      clientId: ltiSession.platform.clientId,
      deploymentId: ltiSession.platform.deploymentId,
      contextId,
      badgeTemplateId: badgeTemplate.id,
      setupRequest: {
        ...setupRequest,
      },
      ttlSeconds: LTI_COURSE_BADGE_SETUP_TOKEN_TTL_SECONDS,
    });

    const launchUrl = new URL(ltiSession.launch.target);
    launchUrl.searchParams.set("badgeTemplateId", badgeTemplate.id);
    launchUrl.searchParams.set("setupToken", setupToken);
    const deepLinkingResult = await ltiTool.createAdvantage(ltiSession).createDeepLinkingResponse([
      badgeTemplateDeepLinkContentItem({
        badgeTemplateId: badgeTemplate.id,
        setupToken,
        title: badgeTemplate.title,
        description: badgeTemplate.description,
        launchUrl: launchUrl.toString(),
      }),
    ]);

    if (!deepLinkingResult.success) {
      return c.json(
        {
          error: formatLtiServiceError(deepLinkingResult.error),
        },
        502,
      );
    }

    c.header("Cache-Control", "no-store");
    return c.body(deepLinkingResult.data, 200, {
      "Content-Type": "text/html; charset=UTF-8",
    });
  });

  app.post(LTI_RESOURCE_LINK_ISSUE_PATH, async (c): Promise<Response> => {
    const form = await c.req.formData();
    const actionToken = asNonEmptyString(form.get("issuance_action_token"));
    const selectedLearnerUserIds = selectedLearnerUserIdsFromForm(form);

    if (actionToken === null) {
      return c.json(
        {
          error: "issuance_action_token is required",
        },
        400,
      );
    }

    const issuanceAction = await verifyLtiIssuanceActionToken(c.env, actionToken);

    if (issuanceAction === null) {
      return c.json(
        {
          error: "LTI issuance action token is invalid or expired",
        },
        403,
      );
    }

    const db = resolveDatabase(c.env);
    const ltiTool = await createCredTrailLtiTool({
      db,
      env: c.env,
    });
    const ltiSession = await ltiTool.getSession(issuanceAction.ltiSessionId);

    if (ltiSession === undefined) {
      return c.json(
        {
          error: "LTI launch session was not found or is no longer active",
        },
        404,
      );
    }

    if (!ltiSessionMatchesIssuanceAction(ltiSession, issuanceAction)) {
      return c.json(
        {
          error: "LTI launch session does not match issuance action",
        },
        403,
      );
    }

    if (!ltiSession.isInstructor) {
      return c.json(
        {
          error: "LTI roster badge issuance requires an instructor launch",
        },
        403,
      );
    }

    const badgeTemplate = await findBadgeTemplateById(
      db,
      issuanceAction.tenantId,
      issuanceAction.badgeTemplateId,
    );

    if (badgeTemplate === null || badgeTemplate.isArchived) {
      return c.json(
        {
          error: "LTI resource-link badge template is not available for this tenant",
        },
        404,
      );
    }

    let issuanceResult;

    try {
      issuanceResult = await executeLtiRosterIssuance({
        c,
        db,
        ltiTool,
        ltiSession,
        issuanceAction,
        selectedLearnerUserIds,
        sha256Hex,
        issueBadgeForTenant,
      });
    } catch (error) {
      if (error instanceof LtiRosterIssuanceError) {
        return c.json(
          {
            error: error.message,
          },
          error.status,
        );
      }

      throw error;
    }

    c.header("Cache-Control", "no-store");
    return renderAppPage(
      c,
      ltiRosterIssuanceResultPage({
        tenantId: issuanceResult.tenantId,
        badgeTemplateId: issuanceResult.badgeTemplateId,
        courseContextTitle: issuanceResult.courseContextTitle,
        selectedCount: issuanceResult.selectedCount,
        results: issuanceResult.results,
      }),
    );
  });

  app.post(LTI_LAUNCH_PATH, async (c): Promise<Response> => {
    return handleLtiLaunchPost({
      c,
      resolveLtiIssuerRegistry,
      resolveDatabase,
      sha256Hex,
      createLtiSession,
    });
  });
};

import { upsertLtiDeployment, type SqlDatabase } from "@credtrail/db";
import {
  createLtiPostMessageStorageRedirect,
  parseLtiLoginInitiation,
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
import { createCredTrailLtiTool } from "../lti/credtrail-lti-tool";
import { handleLtiDeepLinkingSelect } from "../lti/deep-linking-select-handler";
import { registerLtiDynamicRegistrationRoutes } from "../lti/dynamic-registration-routes";
import { registerLtiGradebookLookupRoutes } from "../lti/gradebook-lookup-routes";
import { registerLtiJwksRoute } from "../lti/jwks-routes";
import { handleLtiLaunchPost } from "../lti/launch-post-handler";
import {
  ltiLoginInputFromRequest,
  resolveLtiLoginIssuer,
  type LtiIssuerRegistry,
} from "../lti/lti-helpers";
import { ltiIssuerHasSignedLaunchConfig } from "../lti/launch-verification";
import { ltiPostMessageStorageRedirectPage } from "../lti/pages";
import { handleLtiResourceLinkIssue } from "../lti/resource-link-issue-handler";

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

    const loginIssuer = resolveLtiLoginIssuer(registry, loginRequest);

    if (loginIssuer.status === "unknown_issuer") {
      return c.json(
        {
          error: "Unknown LTI issuer",
        },
        400,
      );
    }

    if (loginIssuer.status === "client_id_mismatch") {
      return c.json(
        {
          error: "client_id does not match configured issuer registration",
        },
        400,
      );
    }

    const issuerEntry = loginIssuer.entry;
    const clientId = loginIssuer.clientId;

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
      issuer: loginIssuer.issuer,
      clientId,
      deploymentId,
    });
    const ltiTool = await createCredTrailLtiTool({
      db,
      env: c.env,
      defaultTenantId: issuerEntry.tenantId,
    });
    const authRedirectUrl = await ltiTool.handleLogin({
      iss: loginIssuer.issuer,
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
    return handleLtiDeepLinkingSelect({
      c,
      resolveLtiIssuerRegistry,
      resolveDatabase,
    });
  });

  app.post(LTI_RESOURCE_LINK_ISSUE_PATH, async (c): Promise<Response> => {
    return handleLtiResourceLinkIssue({
      c,
      resolveDatabase,
      sha256Hex,
      issueBadgeForTenant,
    });
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

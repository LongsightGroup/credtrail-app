import { upsertLtiDeployment } from "@credtrail/db";
import {
  createLtiPostMessageStorageRedirect,
  parseLtiLoginInitiation,
} from "@longsightgroup/lti-tool";
import type { Hono } from "hono";
import type { AppContext, AppEnv } from "../app/types";
import type { ResolveDatabase } from "../app/route-deps";
import { canonicalAppUrl } from "../http/canonical-app-url";
import { renderAppPage } from "../ui/render-page";
import { LTI_LAUNCH_PATH, LTI_OIDC_LOGIN_PATH } from "./constants";
import { createCredTrailLtiTool } from "./credtrail-lti-tool";
import { ltiIssuerHasSignedLaunchConfig } from "./launch-verification";
import { resolveLtiLoginIssuer, type LtiIssuerRegistry } from "./lti-issuer-registry";
import { ltiLoginInputFromRequest } from "./lti-oidc-login-request";
import { ltiPostMessageStorageRedirectPage } from "./pages";

export interface HandleLtiOidcLoginInput {
  readonly c: AppContext;
  readonly resolveLtiIssuerRegistry: (context: AppContext) => Promise<LtiIssuerRegistry>;
  resolveDatabase: ResolveDatabase;
}

export interface RegisterLtiOidcLoginRoutesInput {
  readonly app: Hono<AppEnv>;
  readonly resolveLtiIssuerRegistry: (context: AppContext) => Promise<LtiIssuerRegistry>;
  resolveDatabase: ResolveDatabase;
}

/**
 * Handles CredTrail's LTI OIDC login initiation before redirecting to the platform.
 */
export const handleLtiOidcLogin = async (input: HandleLtiOidcLoginInput): Promise<Response> => {
  const { c, resolveLtiIssuerRegistry, resolveDatabase } = input;

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

  let loginRequest: ReturnType<typeof parseLtiLoginInitiation>;

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
    tenantId: issuerEntry.tenantId,
    issuer: loginIssuer.issuer,
    clientId,
    deploymentId,
  });
  const ltiTool = await createCredTrailLtiTool({
    db,
    env: c.env,
    tenantId: issuerEntry.tenantId,
  });
  const authRedirectUrl = await ltiTool.handleLogin({
    iss: loginIssuer.issuer,
    client_id: clientId,
    launchUrl: new URL(canonicalAppUrl(c.env.PUBLIC_APP_ORIGIN, LTI_LAUNCH_PATH)),
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

/**
 * Registers CredTrail's LTI OIDC login initiation routes.
 */
export const registerLtiOidcLoginRoutes = (input: RegisterLtiOidcLoginRoutesInput): void => {
  const { app, resolveLtiIssuerRegistry, resolveDatabase } = input;

  const handler = async (c: AppContext): Promise<Response> => {
    return handleLtiOidcLogin({
      c,
      resolveLtiIssuerRegistry,
      resolveDatabase,
    });
  };

  app.get(LTI_OIDC_LOGIN_PATH, handler);
  app.post(LTI_OIDC_LOGIN_PATH, handler);
};

import type { SqlDatabase } from "@credtrail/db";
import type { Hono } from "hono";
import type { AppBindings, AppContext, AppEnv } from "../app";
import type { LtiAuthenticatedPrincipal, LtiSessionInput } from "../auth/auth-provider";
import type { DirectIssueBadgeRequest } from "../badges/recipient-identifiers";
import type { DirectIssueBadgeResult } from "../badges/direct-issue";
import {
  LTI_DEEP_LINKING_SELECT_PATH,
  LTI_LAUNCH_PATH,
  LTI_RESOURCE_LINK_ISSUE_PATH,
} from "../lti/constants";
import { handleLtiDeepLinkingSelect } from "../lti/deep-linking-select-handler";
import { registerLtiDynamicRegistrationRoutes } from "../lti/dynamic-registration-routes";
import { registerLtiGradebookLookupRoutes } from "../lti/gradebook-lookup-routes";
import { registerLtiJwksRoute } from "../lti/jwks-routes";
import { handleLtiLaunchPost } from "../lti/launch-post-handler";
import type { LtiIssuerRegistry } from "../lti/lti-helpers";
import { registerLtiOidcLoginRoutes } from "../lti/lti-oidc-login-handler";
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

  registerLtiOidcLoginRoutes({
    app,
    resolveLtiIssuerRegistry,
    resolveDatabase,
  });

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

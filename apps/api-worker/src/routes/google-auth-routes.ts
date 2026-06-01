import type { SocialProviders } from "better-auth/social-providers";
import type { Hono } from "hono";
import { BETTER_AUTH_BASE_PATH, tenantIdFromNextPath } from "../auth/better-auth-runtime";
import { applyBetterAuthResponseHeaders } from "../auth/better-auth-bridge";
import type { EnterpriseSsoAdapter } from "../auth/enterprise-sso-adapter";
import { isSafeRedirectPath, normalizeSafeRedirectPath } from "../auth/redirect-paths";
import type { AppBindings, AppContext, AppEnv } from "../app";

interface RegisterGoogleAuthRoutesInput {
  app: Hono<AppEnv>;
  createBetterAuthRequest: (context: AppContext, path: string, init?: RequestInit) => Request;
  createBetterAuthRuntime: (context: AppContext) => {
    auth: {
      handler: (request: Request) => Promise<Response>;
    };
  };
  createConfiguredSocialProviders: (bindings: AppBindings) => SocialProviders | undefined;
  enterpriseSso: EnterpriseSsoAdapter<AppContext, AppBindings>;
  rememberRequestedTenant: (context: AppContext, tenantId: string) => unknown;
}

const normalizeHostedLoginNextPath = (nextPath: string): string => {
  return normalizeSafeRedirectPath(nextPath, "/auth/resolve");
};

const googleLoginRedirectPath = (input: {
  tenantId: string;
  nextPath: string;
  reason: "google_unavailable" | "google_failed";
}): string => {
  const url = new URL("/login", "https://credtrail.local");

  if (input.tenantId.length > 0) {
    url.searchParams.set("tenantId", input.tenantId);
  }

  if (input.nextPath.length > 0) {
    url.searchParams.set("next", input.nextPath);
  }

  url.searchParams.set("reason", input.reason);
  return `${url.pathname}${url.search}`;
};

const authResolveCallbackPath = (nextPath: string): string => {
  const url = new URL("/auth/resolve", "https://credtrail.local");

  if (isSafeRedirectPath(nextPath) && nextPath !== "/auth/resolve") {
    url.searchParams.set("next", nextPath);
  }

  return `${url.pathname}${url.search}`;
};

export const registerGoogleAuthRoutes = (input: RegisterGoogleAuthRoutesInput): void => {
  input.app.get("/auth/google/start", async (c) => {
    if (input.createConfiguredSocialProviders(c.env)?.google === undefined) {
      return c.redirect(
        googleLoginRedirectPath({
          tenantId: (c.req.query("tenantId") ?? "").trim(),
          nextPath: normalizeHostedLoginNextPath((c.req.query("next") ?? "").trim()),
          reason: "google_unavailable",
        }),
        302,
      );
    }

    const tenantIdQuery = (c.req.query("tenantId") ?? "").trim();
    const nextPathQuery = (c.req.query("next") ?? "").trim();
    const requestedTenantId =
      tenantIdQuery.length > 0
        ? tenantIdQuery
        : (tenantIdFromNextPath(nextPathQuery)?.trim() ?? "");
    const nextPath = normalizeHostedLoginNextPath((c.req.query("next") ?? "").trim());

    if (requestedTenantId.length > 0) {
      const localLoginBlocked = await input.enterpriseSso.enforceLocalMagicLinkRequest(c, {
        tenantId: requestedTenantId,
        nextPath,
      });

      if (localLoginBlocked !== null && localLoginBlocked !== undefined) {
        return localLoginBlocked;
      }
    }

    if (requestedTenantId.length > 0) {
      input.rememberRequestedTenant(c, requestedTenantId);
    }

    const { auth } = input.createBetterAuthRuntime(c);
    const loginPath = googleLoginRedirectPath({
      tenantId: requestedTenantId,
      nextPath,
      reason: "google_failed",
    });
    const response = await auth.handler(
      input.createBetterAuthRequest(c, "/sign-in/social", {
        method: "POST",
        headers: {
          "content-type": "application/json",
        },
        body: JSON.stringify({
          provider: "google",
          callbackURL: authResolveCallbackPath(nextPath),
          errorCallbackURL: loginPath,
          disableRedirect: true,
        }),
      }),
    );

    if (!response.ok) {
      return c.redirect(loginPath, 302);
    }

    applyBetterAuthResponseHeaders(c, response);

    const payload = await response.json<{
      url?: string | undefined;
    }>();
    const authorizationUrl = payload.url?.trim();

    if (authorizationUrl === undefined || authorizationUrl.length === 0) {
      return c.redirect(loginPath, 302);
    }

    return c.redirect(authorizationUrl, 302);
  });

  input.app.get(`${BETTER_AUTH_BASE_PATH}/callback/google`, async (c) => {
    if (input.createConfiguredSocialProviders(c.env)?.google === undefined) {
      return c.redirect("/login?reason=google_unavailable", 302);
    }

    const requestUrl = new URL(c.req.url);
    const { auth } = input.createBetterAuthRuntime(c);
    return auth.handler(
      input.createBetterAuthRequest(c, `/callback/google${requestUrl.search}`, {
        method: "GET",
      }),
    );
  });
};

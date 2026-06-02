import { findTenantAuthPolicy, findTenantById, upsertUserByEmail } from "@credtrail/db";
import type { SocialProviders } from "better-auth/social-providers";
import { deleteCookie, getCookie, setCookie } from "hono/cookie";
import type { AuthenticatedPrincipal, RequestedTenantContext } from "../auth/auth-context";
import { createBetterAuthProvider } from "../auth/better-auth-adapter";
import { applyBetterAuthResponseHeaders } from "../auth/better-auth-bridge";
import { createBetterAuthRuntimeConfig } from "../auth/better-auth-config";
import {
  BREAK_GLASS_PENDING_MFA_COOKIE_NAME,
  createBreakGlassPolicyAdapter,
} from "../auth/break-glass-policy";
import {
  BETTER_AUTH_BASE_PATH,
  REQUESTED_TENANT_COOKIE_NAME,
  buildHostedMagicLinkToken,
  buildHostedMagicLinkUrl,
  createBetterAuthSessionForCredtrailUser,
  createCredtrailBetterAuth,
  findBetterAuthSessionByToken,
  parseHostedMagicLinkToken,
} from "../auth/better-auth-runtime";
import { createEnterpriseSsoAdapter } from "../auth/enterprise-sso-adapter";
import { normalizeSafeRedirectPath } from "../auth/redirect-paths";
import { sendMagicLinkEmailNotification } from "../notifications/send-magic-link-email";
import { sendMemberInviteEmailNotification } from "../notifications/send-member-invite-email";
import { sendPasswordResetEmailNotification } from "../notifications/send-password-reset-email";
import { addSecondsToIso, sessionCookieSecure } from "../utils/crypto";
import { resolveDatabase } from "./database";
import type { AppBindings, AppContext, AppEnv } from "./types";

const MAGIC_LINK_TTL_SECONDS = 10 * 60;
const SESSION_TTL_SECONDS = 7 * 24 * 60 * 60;

const requestedTenantFromCookie = (context: AppContext): RequestedTenantContext | null => {
  const tenantId = getCookie(context, REQUESTED_TENANT_COOKIE_NAME)?.trim();

  if (tenantId === undefined || tenantId.length === 0) {
    return null;
  }

  return {
    tenantId,
    source: "route",
    authoritative: true,
  };
};

export const rememberRequestedTenant = (
  context: AppContext,
  tenantId: string,
): RequestedTenantContext => {
  const requestedTenant: RequestedTenantContext = {
    tenantId,
    source: "route",
    authoritative: true,
  };

  setCookie(context, REQUESTED_TENANT_COOKIE_NAME, tenantId, {
    httpOnly: true,
    secure: sessionCookieSecure(context.env.APP_ENV),
    sameSite: "Lax",
    path: "/",
    maxAge: SESSION_TTL_SECONDS,
  });
  context.set("requestedTenantContext", requestedTenant);
  return requestedTenant;
};

export const createLocalDevelopmentSessionForCredtrailUser = async (
  context: AppContext,
  input: {
    tenantId: string;
    userId: string;
  },
): Promise<AuthenticatedPrincipal> => {
  if (context.env.APP_ENV !== "development") {
    throw new Error("Local development session creation is only available in development");
  }

  rememberRequestedTenant(context, input.tenantId);

  const db = resolveDatabase(context.env);
  const runtimeConfig = createBetterAuthRuntimeConfig(context.env);
  const { session, sessionToken } = await createBetterAuthSessionForCredtrailUser({
    db,
    runtimeConfig,
    credtrailUserId: input.userId,
    userAgent: context.req.header("user-agent") ?? null,
  });

  setCookie(context, runtimeConfig.session.cookieName, sessionToken, {
    httpOnly: true,
    sameSite: "Lax",
    secure: sessionCookieSecure(context.env.APP_ENV),
    path: "/",
    maxAge: runtimeConfig.session.expiresInSeconds,
  });

  const principal: AuthenticatedPrincipal = {
    userId: input.userId,
    authSessionId: session.sessionId,
    authMethod: "better_auth",
    expiresAt: session.expiresAt,
  };

  context.set("authenticatedPrincipal", principal);
  return principal;
};

const rememberRequestedTenantForEmbeddedLaunch = (
  context: AppContext,
  tenantId: string,
): RequestedTenantContext => {
  const requestedTenant: RequestedTenantContext = {
    tenantId,
    source: "route",
    authoritative: true,
  };

  setCookie(context, REQUESTED_TENANT_COOKIE_NAME, tenantId, {
    httpOnly: true,
    secure: true,
    sameSite: "None",
    path: "/",
    maxAge: SESSION_TTL_SECONDS,
  });
  context.set("requestedTenantContext", requestedTenant);
  return requestedTenant;
};

const clearRequestedTenant = (context: AppContext): void => {
  deleteCookie(context, REQUESTED_TENANT_COOKIE_NAME, {
    path: "/",
  });
  context.set("requestedTenantContext", null);
};

export const pendingBreakGlassTenantFromCookie = (context: AppContext): string | null => {
  const tenantId = getCookie(context, BREAK_GLASS_PENDING_MFA_COOKIE_NAME)?.trim();
  return tenantId === undefined || tenantId.length === 0 ? null : tenantId;
};

export const createBetterAuthRequest = (
  context: AppContext,
  path: string,
  init?: RequestInit,
): Request => {
  const runtimeConfig = createBetterAuthRuntimeConfig(context.env);
  const url = new URL(`${BETTER_AUTH_BASE_PATH}${path}`, runtimeConfig.baseURL);
  const headers = new Headers(context.req.raw.headers);

  if (init?.headers !== undefined) {
    const overrideHeaders = new Headers(init.headers);

    for (const [key, value] of overrideHeaders.entries()) {
      headers.set(key, value);
    }
  }

  const requestInit: RequestInit = {
    headers,
    ...(init?.method === undefined ? {} : { method: init.method }),
    ...(init?.body === undefined ? {} : { body: init.body }),
    ...(init?.redirect === undefined ? {} : { redirect: init.redirect }),
  };

  return new Request(url.toString(), requestInit);
};

export const createConfiguredSocialProviders = (
  bindings: AppBindings,
): SocialProviders | undefined => {
  const googleClientId = bindings.GOOGLE_OAUTH_CLIENT_ID?.trim();
  const googleClientSecret = bindings.GOOGLE_OAUTH_CLIENT_SECRET?.trim();

  if (
    googleClientId === undefined ||
    googleClientId.length === 0 ||
    googleClientSecret === undefined ||
    googleClientSecret.length === 0
  ) {
    return undefined;
  }

  return {
    google: {
      clientId: googleClientId,
      clientSecret: googleClientSecret,
    },
  };
};

export const createBetterAuthRuntime = (
  context: AppContext,
  options?: {
    generateMagicLinkToken?: (() => string) | undefined;
    oauthProviders?:
      | readonly import("better-auth/plugins/generic-oauth").GenericOAuthConfig[]
      | undefined;
    socialProviders?: SocialProviders | undefined;
    sendMagicLink?:
      | ((data: { email: string; token: string; url: string }) => Promise<void>)
      | undefined;
    sendResetPassword?:
      | ((data: { email: string; url: string; token: string }) => Promise<void>)
      | undefined;
  },
): {
  runtimeConfig: ReturnType<typeof createBetterAuthRuntimeConfig>;
  auth: ReturnType<typeof createCredtrailBetterAuth>;
} => {
  const runtimeConfig = createBetterAuthRuntimeConfig(context.env);

  return {
    runtimeConfig,
    auth: createCredtrailBetterAuth({
      db: resolveDatabase(context.env),
      runtimeConfig,
      magicLinkTtlSeconds: MAGIC_LINK_TTL_SECONDS,
      generateMagicLinkToken: options?.generateMagicLinkToken,
      oauthProviders: options?.oauthProviders,
      socialProviders: options?.socialProviders ?? createConfiguredSocialProviders(context.env),
      sendMagicLink:
        options?.sendMagicLink ??
        (async () => {
          return Promise.resolve();
        }),
      sendResetPassword:
        options?.sendResetPassword ??
        (async () => {
          return Promise.resolve();
        }),
    }),
  };
};

interface DevelopmentMagicLinkVerificationRow {
  value: string;
  expiresAt: string | Date;
}

const emailFromMagicLinkVerificationValue = (value: string): string | null => {
  try {
    const parsed = JSON.parse(value) as {
      email?: unknown;
    };
    const email = typeof parsed.email === "string" ? parsed.email.trim() : "";
    return email.length === 0 ? null : email;
  } catch {
    return null;
  }
};

const createDevelopmentMagicLinkSession = async (
  context: AppContext,
  token: string,
): Promise<import("../auth/better-auth-adapter").BetterAuthResolvedSession | null> => {
  if (context.env.APP_ENV !== "development") {
    return null;
  }

  const db = resolveDatabase(context.env);
  const verification = await db
    .prepare(
      `
      SELECT
        value,
        expires_at AS expiresAt
      FROM auth.verification
      WHERE identifier = ?
      LIMIT 1
    `,
    )
    .bind(token)
    .first<DevelopmentMagicLinkVerificationRow>();

  if (verification === null) {
    return null;
  }

  if (new Date(verification.expiresAt).getTime() <= Date.now()) {
    await db.prepare("DELETE FROM auth.verification WHERE identifier = ?").bind(token).run();
    return null;
  }

  const email = emailFromMagicLinkVerificationValue(verification.value);

  if (email === null) {
    return null;
  }

  const user = await upsertUserByEmail(db, email);
  const runtimeConfig = createBetterAuthRuntimeConfig(context.env);
  const { session, sessionToken } = await createBetterAuthSessionForCredtrailUser({
    db,
    runtimeConfig,
    credtrailUserId: user.id,
    userAgent: context.req.header("user-agent") ?? null,
  });

  await db.prepare("DELETE FROM auth.verification WHERE identifier = ?").bind(token).run();

  setCookie(context, runtimeConfig.session.cookieName, sessionToken, {
    httpOnly: true,
    sameSite: "Lax",
    secure: sessionCookieSecure(context.env.APP_ENV),
    path: "/",
    maxAge: runtimeConfig.session.expiresInSeconds,
  });

  return {
    sessionToken,
    sessionId: session.sessionId,
    accountId: null,
    expiresAt: session.expiresAt,
    user: {
      id: session.userId,
      email: session.userEmail,
      emailVerified: session.userEmailVerified,
    },
  };
};

const resolveCurrentBetterAuthSession = async (
  context: AppContext,
): Promise<import("../auth/better-auth-adapter").BetterAuthResolvedSession | null> => {
  const resolveDevelopmentSession = async (): Promise<
    import("../auth/better-auth-adapter").BetterAuthResolvedSession | null
  > => {
    if (context.env.APP_ENV !== "development") {
      return null;
    }

    const runtimeConfig = createBetterAuthRuntimeConfig(context.env);
    const sessionToken = getCookie(context, runtimeConfig.session.cookieName)?.trim();

    if (sessionToken === undefined || sessionToken.length === 0) {
      return null;
    }

    const session = await findBetterAuthSessionByToken(resolveDatabase(context.env), sessionToken);

    if (session === null || new Date(session.expiresAt).getTime() <= Date.now()) {
      return null;
    }

    return {
      sessionToken,
      sessionId: session.sessionId,
      accountId: null,
      expiresAt: session.expiresAt,
      user: {
        id: session.userId,
        email: session.userEmail,
        emailVerified: session.userEmailVerified,
      },
    };
  };
  const { auth } = createBetterAuthRuntime(context);
  const response = await auth.handler(
    createBetterAuthRequest(context, "/get-session", {
      method: "GET",
    }),
  );

  if (!response.ok) {
    return resolveDevelopmentSession();
  }

  applyBetterAuthResponseHeaders(context, response);

  const payload = await response.json<{
    session: {
      id: string;
      expiresAt: string;
    };
    user: {
      id: string;
      email: string | null;
      emailVerified: boolean;
    };
  } | null>();

  if (payload === null) {
    return resolveDevelopmentSession();
  }

  return {
    sessionId: payload.session.id,
    accountId: null,
    expiresAt: payload.session.expiresAt,
    user: {
      id: payload.user.id,
      email: payload.user.email,
      emailVerified: payload.user.emailVerified,
    },
  };
};

export const betterAuthProvider = createBetterAuthProvider<AppContext, AppBindings>({
  resolveDatabase,
  requestMagicLink: async (context, input) => {
    const defaultNextPath = "/auth/resolve";
    const nextPath = normalizeSafeRedirectPath(input.nextPath, defaultNextPath);
    const expiresAt = addSecondsToIso(new Date().toISOString(), MAGIC_LINK_TTL_SECONDS);
    let deliveryStatus: "sent" | "skipped" | "failed" = "skipped";
    let debugMagicLinkToken: string | undefined;
    let debugMagicLinkUrl: string | undefined;
    const { auth, runtimeConfig } = createBetterAuthRuntime(context, {
      generateMagicLinkToken: () => buildHostedMagicLinkToken(input.tenantId),
      sendMagicLink: async ({ email, token }) => {
        debugMagicLinkToken = token;
        debugMagicLinkUrl = buildHostedMagicLinkUrl({
          baseURL: runtimeConfig.baseURL,
          token,
          nextPath,
        });

        if (context.env.APP_ENV === "development") {
          return;
        }

        try {
          await sendMagicLinkEmailNotification({
            emailBinding: context.env.EMAIL,
            fromEmail: context.env.TRANSACTIONAL_EMAIL_FROM_ADDRESS,
            fromName: context.env.TRANSACTIONAL_EMAIL_FROM_NAME,
            recipientEmail: email,
            tenantId: input.tenantId,
            magicLinkUrl: debugMagicLinkUrl,
            expiresAtIso: expiresAt,
            preferredLocale: input.preferredLocale,
            preferredTimeZone: input.preferredTimeZone,
          });
          deliveryStatus = "sent";
        } catch {
          deliveryStatus = "failed";
        }
      },
      sendResetPassword: async ({ email, url }) => {
        await sendPasswordResetEmailNotification({
          emailBinding: context.env.EMAIL,
          fromEmail: context.env.TRANSACTIONAL_EMAIL_FROM_ADDRESS,
          fromName: context.env.TRANSACTIONAL_EMAIL_FROM_NAME,
          recipientEmail: email,
          tenantId: input.tenantId,
          resetUrl: url,
        });
      },
    });
    const response = await auth.handler(
      createBetterAuthRequest(context, "/sign-in/magic-link", {
        method: "POST",
        headers: {
          "content-type": "application/json",
        },
        body: JSON.stringify({
          email: input.email,
          callbackURL: nextPath,
        }),
      }),
    );

    await response.arrayBuffer();

    if (!response.ok) {
      throw new Error("Better Auth magic-link request failed");
    }

    return {
      tenantId: input.tenantId,
      email: input.email,
      deliveryStatus,
      expiresAt,
      debugMagicLinkToken,
      debugMagicLinkUrl,
    };
  },
  createMagicLinkSession: async (context, token) => {
    const tokenTenant = parseHostedMagicLinkToken(token);

    if (tokenTenant !== null) {
      rememberRequestedTenant(context, tokenTenant.tenantId);
    }

    const developmentSession = await createDevelopmentMagicLinkSession(context, token);

    if (developmentSession !== null) {
      return developmentSession;
    }

    const { auth } = createBetterAuthRuntime(context);
    const response = await auth.handler(
      createBetterAuthRequest(context, `/magic-link/verify?token=${encodeURIComponent(token)}`, {
        method: "GET",
      }),
    );

    if (!response.ok) {
      return null;
    }

    applyBetterAuthResponseHeaders(context, response);

    const payload = await response.json<{
      token?: string | undefined;
      user?:
        | {
            id: string;
            email: string | null;
            emailVerified: boolean;
          }
        | undefined;
    }>();
    const sessionToken = payload.token?.trim();

    if (sessionToken === undefined || sessionToken.length === 0) {
      return null;
    }

    const session = await findBetterAuthSessionByToken(resolveDatabase(context.env), sessionToken);

    if (session === null) {
      return null;
    }

    return {
      sessionToken,
      sessionId: session.sessionId,
      accountId: null,
      expiresAt: session.expiresAt,
      user: {
        id: payload.user?.id ?? session.userId,
        email: payload.user?.email ?? session.userEmail,
        emailVerified: payload.user?.emailVerified ?? session.userEmailVerified,
      },
    };
  },
  createLtiSession: async (context, input) => {
    const runtimeConfig = createBetterAuthRuntimeConfig(context.env);
    const { session, sessionToken } = await createBetterAuthSessionForCredtrailUser({
      db: resolveDatabase(context.env),
      runtimeConfig,
      credtrailUserId: input.userId,
      userAgent: context.req.header("user-agent") ?? null,
    });

    setCookie(context, runtimeConfig.session.cookieName, sessionToken, {
      httpOnly: true,
      sameSite: "None",
      secure: true,
      path: "/",
      maxAge: runtimeConfig.session.expiresInSeconds,
    });
    rememberRequestedTenantForEmbeddedLaunch(context, input.tenantId);

    return {
      sessionToken,
      sessionId: session.sessionId,
      accountId: null,
      expiresAt: session.expiresAt,
      user: {
        id: session.userId,
        email: session.userEmail,
        emailVerified: session.userEmailVerified,
      },
    };
  },
  resolveSession: resolveCurrentBetterAuthSession,
  revokeSession: async (context) => {
    const { auth } = createBetterAuthRuntime(context);
    const response = await auth.handler(
      createBetterAuthRequest(context, "/sign-out", {
        method: "POST",
      }),
    );

    applyBetterAuthResponseHeaders(context, response);
    clearRequestedTenant(context);
    deleteCookie(context, BREAK_GLASS_PENDING_MFA_COOKIE_NAME, {
      path: "/",
    });
  },
  resolveRequestedTenantContext: (context) => {
    return Promise.resolve(
      context.get("requestedTenantContext") ?? requestedTenantFromCookie(context),
    );
  },
  cacheAuthenticatedPrincipal: (
    context: AppContext,
    principal: AppEnv["Variables"]["authenticatedPrincipal"],
  ): void => {
    context.set("authenticatedPrincipal", principal);
  },
  cacheRequestedTenantContext: (
    context: AppContext,
    requestedTenant: AppEnv["Variables"]["requestedTenantContext"],
  ): void => {
    context.set("requestedTenantContext", requestedTenant);
  },
});

const tenantMemberInviteLoginUrl = (context: AppContext, tenantId: string): string => {
  const loginUrl = new URL("/login", context.req.url);
  loginUrl.searchParams.set("tenantId", tenantId);
  loginUrl.searchParams.set("next", "/auth/resolve");
  loginUrl.searchParams.set("reason", "sso_required");
  return loginUrl.toString();
};

export const requestTenantMemberInvite = async (
  context: AppContext,
  input: {
    tenantId: string;
    email: string;
    role: "owner" | "admin" | "issuer" | "viewer";
  },
): Promise<{
  deliveryStatus: "sent" | "skipped" | "failed";
  inviteKind: "magic_link" | "sso_notice";
}> => {
  const db = resolveDatabase(context.env);
  const [tenant, policy] = await Promise.all([
    findTenantById(db, input.tenantId),
    findTenantAuthPolicy(db, input.tenantId),
  ]);

  if (tenant?.planTier === "enterprise" && policy?.loginMode === "sso_required") {
    try {
      await sendMemberInviteEmailNotification({
        emailBinding: context.env.EMAIL,
        fromEmail: context.env.TRANSACTIONAL_EMAIL_FROM_ADDRESS,
        fromName: context.env.TRANSACTIONAL_EMAIL_FROM_NAME,
        recipientEmail: input.email,
        tenantId: input.tenantId,
        tenantDisplayName: tenant.displayName,
        role: input.role,
        signInUrl: tenantMemberInviteLoginUrl(context, input.tenantId),
      });

      return {
        deliveryStatus: "sent",
        inviteKind: "sso_notice",
      };
    } catch {
      return {
        deliveryStatus: "failed",
        inviteKind: "sso_notice",
      };
    }
  }

  const result = await betterAuthProvider.requestMagicLink(context, {
    tenantId: input.tenantId,
    email: input.email,
    nextPath: "/auth/resolve",
  });

  return {
    deliveryStatus: result.deliveryStatus,
    inviteKind: "magic_link",
  };
};

export const resolveAuthenticatedPrincipal = async (
  c: AppContext,
): Promise<AuthenticatedPrincipal | null> => {
  const cachedPrincipal = c.get("authenticatedPrincipal");

  if (cachedPrincipal !== undefined) {
    return cachedPrincipal ?? null;
  }

  const principal = await betterAuthProvider.resolveAuthenticatedPrincipal(c);
  c.set("authenticatedPrincipal", principal);
  return principal;
};

export const resolveRequestedTenantContext = async (
  c: AppContext,
): Promise<RequestedTenantContext | null> => {
  const cachedRequestedTenant = c.get("requestedTenantContext");

  if (cachedRequestedTenant !== undefined) {
    return cachedRequestedTenant ?? null;
  }

  const requestedTenant = await betterAuthProvider.resolveRequestedTenantContext(c);
  c.set("requestedTenantContext", requestedTenant);
  return requestedTenant;
};

export const breakGlassPolicyAdapter = createBreakGlassPolicyAdapter<AppContext, AppBindings>({
  resolveDatabase,
  createBetterAuthRuntime,
  createBetterAuthRequest,
  resolveCurrentSession: resolveCurrentBetterAuthSession,
  rememberRequestedTenant: (context, tenantId) => {
    rememberRequestedTenant(context, tenantId);
  },
});

export const enterpriseSsoAdapter = createEnterpriseSsoAdapter<AppContext, AppBindings>({
  resolveDatabase,
  createBetterAuthRuntime,
  createBetterAuthRequest,
  resolveAuthenticatedPrincipal,
  resolveRequestedTenantContext,
  rememberRequestedTenant,
});

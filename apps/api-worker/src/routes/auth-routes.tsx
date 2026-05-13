import {
  countAuthMagicLinkRateLimitAttempts,
  listAccessibleTenantContextsForUser,
  findTenantMembership,
  findUserByEmail,
  pruneAuthMagicLinkRateLimitAttempts,
  recordAuthMagicLinkRateLimitAttempt,
  type AuthMagicLinkRateLimitDimension,
  type SqlDatabase,
} from "@credtrail/db";
import { appPage, renderAppPage } from "../ui/render-page";
import type { Hono } from "hono";
import { deleteCookie, setCookie } from "hono/cookie";
import { parseMagicLinkRequest, parseMagicLinkVerifyRequest } from "@credtrail/validation";
import type { AppBindings, AppContext, AppEnv } from "../app";
import type { AuthenticatedPrincipal, RequestedTenantContext } from "../auth/auth-context";
import { tenantIdFromNextPath } from "../auth/better-auth-runtime";
import {
  BREAK_GLASS_PENDING_MFA_COOKIE_NAME,
  buildLocalLoginPath,
  buildLocalTwoFactorPath,
  type BreakGlassPolicyAdapter,
} from "../auth/break-glass-policy";
import type { EnterpriseSsoAdapter } from "../auth/enterprise-sso-adapter";
import type { RequestMagicLinkInput, RequestMagicLinkResult } from "../auth/auth-provider";
import { turnstileConfigured, verifyTurnstileToken } from "../auth/turnstile";
import {
  localBreakGlassLoginPage,
  localResetPasswordPage,
  localTwoFactorPage,
  magicLinkLoginPage,
  organizationChooserPage,
} from "../auth/pages";
import {
  resolveChosenTenantLocation,
  resolveTenantContextSelection,
  toAccessibleTenantContextViews,
} from "../auth/tenant-context-selection";
import { sessionCookieSecure, sha256Hex } from "../utils/crypto";

const MAGIC_LINK_RATE_LIMIT_WINDOW_MS = 10 * 60 * 1000;
const MAGIC_LINK_RATE_LIMIT_PRUNE_MS = 24 * 60 * 60 * 1000;

const MAGIC_LINK_RATE_LIMITS: Record<
  AuthMagicLinkRateLimitDimension,
  { challengeAt: number; blockAt: number }
> = {
  ip: { challengeAt: 3, blockAt: 20 },
  tenant: { challengeAt: 12, blockAt: 60 },
  email: { challengeAt: 3, blockAt: 10 },
  tenant_email: { challengeAt: 3, blockAt: 10 },
};

const googleOAuthConfigured = (env: AppBindings): boolean => {
  return (
    (env.GOOGLE_OAUTH_CLIENT_ID?.trim().length ?? 0) > 0 &&
    (env.GOOGLE_OAUTH_CLIENT_SECRET?.trim().length ?? 0) > 0
  );
};

const googleSignInStartPath = (input: { tenantId: string; nextPath: string }): string => {
  const params = new URLSearchParams();

  if (input.tenantId.length > 0) {
    params.set("tenantId", input.tenantId);
  }

  if (input.nextPath.length > 0) {
    params.set("next", input.nextPath);
  }

  const query = params.toString();
  return query.length === 0 ? "/auth/google/start" : `/auth/google/start?${query}`;
};

const hostedSocialProvidersForLogin = (
  env: AppBindings,
  input: { tenantId: string; nextPath: string },
):
  | readonly [
      {
        id: "google";
        label: string;
        startPath: string;
      },
    ]
  | readonly [] => {
  if (!googleOAuthConfigured(env)) {
    return [];
  }

  return [
    {
      id: "google",
      label: "Google",
      startPath: googleSignInStartPath(input),
    },
  ];
};

interface RegisterAuthRoutesInput {
  app: Hono<AppEnv>;
  resolveDatabase: (bindings: AppBindings) => SqlDatabase;
  requestMagicLink: (
    c: AppContext,
    input: RequestMagicLinkInput,
  ) => Promise<RequestMagicLinkResult>;
  createMagicLinkSession: (c: AppContext, token: string) => Promise<AuthenticatedPrincipal | null>;
  resolveAuthenticatedPrincipal: (c: AppContext) => Promise<AuthenticatedPrincipal | null>;
  resolveRequestedTenantContext: (c: AppContext) => Promise<RequestedTenantContext | null>;
  rememberRequestedTenant: (c: AppContext, tenantId: string) => RequestedTenantContext;
  revokeCurrentSession: (c: AppContext) => Promise<void>;
  enterpriseSso?: EnterpriseSsoAdapter<AppContext, AppBindings> | undefined;
  breakGlassPolicy?: BreakGlassPolicyAdapter<AppContext, AppBindings> | undefined;
}

const getFormValue = (formData: FormData, name: string): string => {
  const raw = formData.get(name);
  return typeof raw === "string" ? raw.trim() : "";
};

const clientIpFromRequest = (c: AppContext): string => {
  const cloudflareIp = c.req.header("cf-connecting-ip")?.trim();

  if (cloudflareIp !== undefined && cloudflareIp.length > 0) {
    return cloudflareIp;
  }

  const forwardedFor = c.req.header("x-forwarded-for")?.split(",")[0]?.trim();

  if (forwardedFor !== undefined && forwardedFor.length > 0) {
    return forwardedFor;
  }

  return "unknown";
};

const magicLinkRateLimitDimensions = async (input: {
  tenantId: string;
  email: string;
  clientIp: string;
}): Promise<
  readonly {
    dimensionType: AuthMagicLinkRateLimitDimension;
    dimensionHash: string;
  }[]
> => {
  const normalizedEmail = input.email.trim().toLowerCase();
  return [
    {
      dimensionType: "ip",
      dimensionHash: await sha256Hex(`magic-link:ip:${input.clientIp}`),
    },
    {
      dimensionType: "tenant",
      dimensionHash: await sha256Hex(`magic-link:tenant:${input.tenantId}`),
    },
    {
      dimensionType: "email",
      dimensionHash: await sha256Hex(`magic-link:email:${normalizedEmail}`),
    },
    {
      dimensionType: "tenant_email",
      dimensionHash: await sha256Hex(
        `magic-link:tenant-email:${input.tenantId}:${normalizedEmail}`,
      ),
    },
  ];
};

const recordMagicLinkAttempts = async (
  db: SqlDatabase,
  dimensions: Awaited<ReturnType<typeof magicLinkRateLimitDimensions>>,
  nowIso: string,
): Promise<void> => {
  await Promise.all(
    dimensions.map((dimension) =>
      recordAuthMagicLinkRateLimitAttempt(db, {
        ...dimension,
        occurredAt: nowIso,
      }),
    ),
  );
};

const buildMagicLinkAcceptedPayload = (input: {
  email: string;
  tenantId?: string | undefined;
  deliveryStatus?: "sent" | "skipped" | "failed" | undefined;
  expiresAt?: string | undefined;
  magicLinkToken?: string | undefined;
  magicLinkUrl?: string | undefined;
}) => {
  return {
    status: "sent" as const,
    deliveryStatus: input.deliveryStatus ?? "sent",
    email: input.email,
    ...(input.tenantId === undefined ? {} : { tenantId: input.tenantId }),
    ...(input.expiresAt === undefined ? {} : { expiresAt: input.expiresAt }),
    ...(input.magicLinkToken === undefined ? {} : { magicLinkToken: input.magicLinkToken }),
    ...(input.magicLinkUrl === undefined ? {} : { magicLinkUrl: input.magicLinkUrl }),
  };
};

const tenantChoiceRoleLabel = (role: string): string => {
  switch (role) {
    case "owner":
      return "Owner";
    case "admin":
      return "Admin";
    case "issuer":
      return "Issuer";
    case "viewer":
      return "Viewer";
    default:
      return role;
  }
};

export const registerAuthRoutes = (input: RegisterAuthRoutesInput): void => {
  const {
    app,
    resolveDatabase,
    requestMagicLink,
    createMagicLinkSession,
    resolveAuthenticatedPrincipal,
    resolveRequestedTenantContext,
    rememberRequestedTenant,
    revokeCurrentSession,
    enterpriseSso,
    breakGlassPolicy,
  } = input;

  const renderNoAccessibleOrganizationsPage = (
    c: AppContext,
    title: string,
    message: string,
    status: 403,
  ): Response | Promise<Response> => {
    return renderAppPage(
      c,
      appPage({
        title,
        body: (
          <>
            <h1>{title}</h1>
            <p>{message}</p>
          </>
        ),
      }),
      status,
    );
  };

  const loadAccessibleTenantContextViews = async (c: AppContext, userId: string) => {
    const contexts = await listAccessibleTenantContextsForUser(resolveDatabase(c.env), userId);
    return toAccessibleTenantContextViews(contexts);
  };

  app.get("/", (c) => {
    return c.redirect("/login", 302);
  });

  app.get("/login", async (c) => {
    const tenantIdQuery = (c.req.query("tenantId") ?? "").trim();
    const nextPath = (c.req.query("next") ?? "").trim();
    const reason = (c.req.query("reason") ?? "").trim();
    const tenantId =
      tenantIdQuery.length > 0 ? tenantIdQuery : (tenantIdFromNextPath(nextPath)?.trim() ?? "");

    if (enterpriseSso !== undefined && tenantId.length > 0) {
      const loginExperience = await enterpriseSso.resolveLoginExperience(c, {
        tenantId,
        nextPath,
      });

      if (loginExperience.autoStartPath !== null) {
        return c.redirect(loginExperience.autoStartPath, 302);
      }

      return renderAppPage(
        c,
        magicLinkLoginPage({
          tenantId,
          nextPath,
          turnstileSiteKey: c.env.TURNSTILE_SITE_KEY,
          ...(reason.length === 0 ? {} : { reason }),
          localLoginAllowed: loginExperience.localLoginAllowed,
          explicitLocalLoginPath: loginExperience.explicitLocalLoginPath,
          enterpriseProviders: loginExperience.enterpriseProviders,
          hostedSocialProviders: loginExperience.localLoginAllowed
            ? hostedSocialProvidersForLogin(c.env, {
                tenantId,
                nextPath,
              })
            : [],
          ...(loginExperience.notice === undefined ? {} : { notice: loginExperience.notice }),
        }),
      );
    }

    return renderAppPage(
      c,
      magicLinkLoginPage({
        tenantId,
        nextPath,
        turnstileSiteKey: c.env.TURNSTILE_SITE_KEY,
        hostedSocialProviders: hostedSocialProvidersForLogin(c.env, {
          tenantId,
          nextPath,
        }),
        ...(reason.length === 0 ? {} : { reason }),
      }),
    );
  });

  app.get("/login/local", async (c) => {
    const tenantId = (c.req.query("tenantId") ?? "").trim();
    const nextPath = (c.req.query("next") ?? "").trim();
    const reason = (c.req.query("reason") ?? "").trim();

    if (breakGlassPolicy === undefined || tenantId.length === 0) {
      const loginUrl = new URL("/login", c.req.url);
      if (tenantId.length > 0) {
        loginUrl.searchParams.set("tenantId", tenantId);
      }
      if (nextPath.length > 0) {
        loginUrl.searchParams.set("next", nextPath);
      }
      loginUrl.searchParams.set("reason", "break_glass_unavailable");
      return c.redirect(`${loginUrl.pathname}${loginUrl.search}`, 302);
    }

    return renderAppPage(
      c,
      localBreakGlassLoginPage({
        tenantId,
        nextPath,
        ...(reason.length === 0 ? {} : { reason }),
      }),
    );
  });

  app.post("/auth/local/reset-password/request", async (c) => {
    if (breakGlassPolicy === undefined) {
      return c.redirect("/login?reason=break_glass_unavailable", 302);
    }

    const formData = await c.req.formData();
    const tenantId = getFormValue(formData, "tenantId");
    const nextPath = getFormValue(formData, "next");
    const email = getFormValue(formData, "email");
    const status = await breakGlassPolicy.requestPasswordReset(c, {
      tenantId,
      email,
      nextPath,
    });

    return c.redirect(
      buildLocalLoginPath({
        tenantId,
        nextPath,
        reason: status === "sent" ? "reset_sent" : "break_glass_unavailable",
      }),
      302,
    );
  });

  app.post("/auth/local/sign-in", async (c) => {
    if (breakGlassPolicy === undefined) {
      return c.redirect("/login?reason=break_glass_unavailable", 302);
    }

    const formData = await c.req.formData();
    const tenantId = getFormValue(formData, "tenantId");
    const nextPath = getFormValue(formData, "next");
    const email = getFormValue(formData, "email");
    const password = getFormValue(formData, "password");
    const result = await breakGlassPolicy.signIn(c, {
      tenantId,
      email,
      password,
      nextPath,
    });

    if (result.status === "authenticated") {
      return c.redirect(nextPath.startsWith("/") ? nextPath : "/auth/resolve", 302);
    }

    if (result.status === "two_factor_required") {
      return c.redirect(
        buildLocalTwoFactorPath({
          tenantId,
          nextPath,
        }),
        302,
      );
    }

    if (result.status === "setup_required") {
      setCookie(c, BREAK_GLASS_PENDING_MFA_COOKIE_NAME, tenantId, {
        httpOnly: true,
        secure: sessionCookieSecure(c.env.APP_ENV),
        sameSite: "Lax",
        path: "/",
      });

      return c.redirect(
        buildLocalTwoFactorPath({
          tenantId,
          nextPath,
          setup: true,
        }),
        302,
      );
    }

    return c.redirect(
      buildLocalLoginPath({
        tenantId,
        nextPath,
        reason: result.reason,
      }),
      302,
    );
  });

  app.get("/auth/local/reset-password", async (c) => {
    const tenantId = (c.req.query("tenantId") ?? "").trim();
    const nextPath = (c.req.query("next") ?? "").trim();
    const token = (c.req.query("token") ?? "").trim();
    const reason = (c.req.query("reason") ?? "").trim();

    if (tenantId.length === 0 || token.length === 0) {
      return renderAppPage(
        c,
        appPage({
          title: "Invalid Reset Link",
          body: (
            <>
              <h1>Invalid reset link</h1>
              <p>Request a new local setup link from the break-glass sign-in page.</p>
            </>
          ),
        }),
        400,
      );
    }

    return renderAppPage(
      c,
      localResetPasswordPage({
        tenantId,
        nextPath,
        token,
        ...(reason.length === 0 ? {} : { reason }),
      }),
    );
  });

  app.post("/auth/local/reset-password", async (c) => {
    if (breakGlassPolicy === undefined) {
      return c.redirect("/login?reason=break_glass_unavailable", 302);
    }

    const formData = await c.req.formData();
    const tenantId = getFormValue(formData, "tenantId");
    const nextPath = getFormValue(formData, "next");
    const token = getFormValue(formData, "token");
    const newPassword = getFormValue(formData, "newPassword");
    const status = await breakGlassPolicy.resetPassword(c, {
      tenantId,
      token,
      newPassword,
    });

    return c.redirect(
      buildLocalLoginPath({
        tenantId,
        nextPath,
        reason: status === "complete" ? "password_reset_complete" : "break_glass_unavailable",
      }),
      302,
    );
  });

  app.get("/auth/local/two-factor", async (c) => {
    const tenantId = (c.req.query("tenantId") ?? "").trim();
    const nextPath = (c.req.query("next") ?? "").trim();
    const reason = (c.req.query("reason") ?? "").trim();

    return renderAppPage(
      c,
      localTwoFactorPage({
        tenantId,
        nextPath,
        ...(reason.length === 0 ? {} : { reason }),
      }),
    );
  });

  app.get("/auth/local/two-factor/setup", async (c) => {
    const tenantId = (c.req.query("tenantId") ?? "").trim();
    const nextPath = (c.req.query("next") ?? "").trim();
    const reason = (c.req.query("reason") ?? "").trim();

    return renderAppPage(
      c,
      localTwoFactorPage({
        tenantId,
        nextPath,
        ...(reason.length === 0 ? {} : { reason }),
      }),
    );
  });

  app.post("/auth/local/two-factor/setup", async (c) => {
    if (breakGlassPolicy === undefined) {
      return c.redirect("/login?reason=break_glass_unavailable", 302);
    }

    const formData = await c.req.formData();
    const tenantId = getFormValue(formData, "tenantId");
    const nextPath = getFormValue(formData, "next");
    const password = getFormValue(formData, "password");
    const result = await breakGlassPolicy.enrollTwoFactor(c, {
      tenantId,
      password,
    });

    if (result.status === "rejected") {
      return c.redirect(
        buildLocalTwoFactorPath({
          tenantId,
          nextPath,
          setup: true,
          reason: result.reason,
        }),
        302,
      );
    }

    return renderAppPage(
      c,
      localTwoFactorPage({
        tenantId,
        nextPath,
        setup: {
          totpUri: result.totpUri,
          backupCodes: result.backupCodes,
        },
      }),
    );
  });

  app.post("/auth/local/two-factor/verify", async (c) => {
    if (breakGlassPolicy === undefined) {
      return c.redirect("/login?reason=break_glass_unavailable", 302);
    }

    const formData = await c.req.formData();
    const tenantId = getFormValue(formData, "tenantId");
    const nextPath = getFormValue(formData, "next");
    const code = getFormValue(formData, "code");
    const result = await breakGlassPolicy.verifyTwoFactor(c, {
      tenantId,
      code,
    });

    if (result.status === "rejected") {
      return c.redirect(
        buildLocalTwoFactorPath({
          tenantId,
          nextPath,
          reason: result.reason,
        }),
        302,
      );
    }

    deleteCookie(c, BREAK_GLASS_PENDING_MFA_COOKIE_NAME, {
      path: "/",
    });
    const fallbackPath = "/auth/resolve";
    return c.redirect(nextPath.startsWith("/") ? nextPath : fallbackPath, 302);
  });

  app.post("/v1/auth/magic-link/request", async (c) => {
    const payload = await c.req.json<unknown>();
    const request = parseMagicLinkRequest(payload);
    const db = resolveDatabase(c.env);
    const now = new Date();
    const nowIso = now.toISOString();
    const windowStartIso = new Date(now.getTime() - MAGIC_LINK_RATE_LIMIT_WINDOW_MS).toISOString();
    const pruneBeforeIso = new Date(now.getTime() - MAGIC_LINK_RATE_LIMIT_PRUNE_MS).toISOString();
    const clientIp = clientIpFromRequest(c);
    const requestedTenantId =
      request.tenantId?.trim() ?? tenantIdFromNextPath(request.nextPath ?? "") ?? "";
    const dimensions = await magicLinkRateLimitDimensions({
      tenantId: requestedTenantId.length === 0 ? "unscoped" : requestedTenantId,
      email: request.email,
      clientIp,
    });

    if (requestedTenantId.length > 0) {
      const localLoginBlocked = await enterpriseSso?.enforceLocalMagicLinkRequest(c, {
        tenantId: requestedTenantId,
        nextPath: request.nextPath,
      });

      if (localLoginBlocked !== null && localLoginBlocked !== undefined) {
        return localLoginBlocked;
      }
    }

    await pruneAuthMagicLinkRateLimitAttempts(db, pruneBeforeIso);

    const counts = await Promise.all(
      dimensions.map(async (dimension) => {
        return {
          ...dimension,
          count: await countAuthMagicLinkRateLimitAttempts(db, {
            ...dimension,
            sinceIso: windowStartIso,
          }),
        };
      }),
    );
    const hardLimitExceeded = counts.some((entry) => {
      return entry.count >= MAGIC_LINK_RATE_LIMITS[entry.dimensionType].blockAt;
    });

    if (hardLimitExceeded) {
      return c.json(
        {
          error: "Too many sign-in link requests. Try again later.",
        },
        429,
      );
    }

    const turnstileRequired = counts.some((entry) => {
      return entry.count >= MAGIC_LINK_RATE_LIMITS[entry.dimensionType].challengeAt;
    });

    if (turnstileRequired) {
      const turnstileAccepted = await verifyTurnstileToken({
        secretKey: c.env.TURNSTILE_SECRET_KEY,
        token: request.turnstileToken,
        remoteIp: clientIp === "unknown" ? undefined : clientIp,
        idempotencyKey: crypto.randomUUID(),
      });

      if (!turnstileAccepted) {
        await recordMagicLinkAttempts(db, dimensions, nowIso);
        return c.json(
          {
            error: "Human verification is required before requesting another sign-in link.",
            turnstileRequired: true,
            turnstileSiteKey: c.env.TURNSTILE_SITE_KEY,
            turnstileConfigured: turnstileConfigured(c.env.TURNSTILE_SECRET_KEY),
          },
          428,
        );
      }
    }

    await recordMagicLinkAttempts(db, dimensions, nowIso);

    const user = await findUserByEmail(db, request.email);

    if (user === null) {
      return c.json(
        buildMagicLinkAcceptedPayload({
          email: request.email,
          ...(requestedTenantId.length === 0 ? {} : { tenantId: requestedTenantId }),
        }),
        202,
      );
    }

    let tenantId = requestedTenantId;

    if (tenantId.length > 0) {
      const membership = await findTenantMembership(db, tenantId, user.id);

      if (membership === null) {
        return c.json(
          buildMagicLinkAcceptedPayload({
            email: request.email,
            tenantId,
          }),
          202,
        );
      }
    } else {
      const contexts = await loadAccessibleTenantContextViews(c, user.id);

      if (contexts.length === 0) {
        return c.json(
          buildMagicLinkAcceptedPayload({
            email: request.email,
          }),
          202,
        );
      }

      if (contexts.length > 1) {
        return c.json(
          {
            status: "tenant_selection_required" as const,
            email: request.email,
            organizations: contexts.map((context) => ({
              tenantId: context.tenantId,
              label: context.tenantDisplayName,
              roleLabel: tenantChoiceRoleLabel(context.membershipRole),
            })),
          },
          200,
        );
      }

      const [context] = contexts;

      if (context === undefined) {
        return c.json(
          buildMagicLinkAcceptedPayload({
            email: request.email,
          }),
          202,
        );
      }

      tenantId = context.tenantId;

      const localLoginBlocked = await enterpriseSso?.enforceLocalMagicLinkRequest(c, {
        tenantId,
        nextPath: request.nextPath,
      });

      if (localLoginBlocked !== null && localLoginBlocked !== undefined) {
        return localLoginBlocked;
      }
    }

    const magicLinkResult = await requestMagicLink(c, {
      tenantId,
      email: request.email,
      nextPath: request.nextPath,
      preferredLocale: request.preferredLocale,
      preferredTimeZone: request.preferredTimeZone,
    });

    if (c.env.APP_ENV === "development") {
      return c.json(
        buildMagicLinkAcceptedPayload({
          deliveryStatus: magicLinkResult.deliveryStatus,
          tenantId: magicLinkResult.tenantId,
          email: magicLinkResult.email,
          expiresAt: magicLinkResult.expiresAt,
          magicLinkToken: magicLinkResult.debugMagicLinkToken,
          magicLinkUrl: magicLinkResult.debugMagicLinkUrl,
        }),
        202,
      );
    }

    return c.json(
      buildMagicLinkAcceptedPayload({
        deliveryStatus: magicLinkResult.deliveryStatus,
        tenantId: magicLinkResult.tenantId,
        email: magicLinkResult.email,
        expiresAt: magicLinkResult.expiresAt,
      }),
      202,
    );
  });

  app.post("/v1/auth/magic-link/verify", async (c) => {
    const payload = await c.req.json<unknown>();
    const request = parseMagicLinkVerifyRequest(payload);
    const principal = await createMagicLinkSession(c, request.token);

    if (principal === null) {
      return c.json(
        {
          error: "Invalid or expired magic link token",
        },
        400,
      );
    }

    const requestedTenant = await resolveRequestedTenantContext(c);

    if (requestedTenant === null) {
      return c.json(
        {
          error: "Unable to resolve tenant context for authenticated session",
        },
        500,
      );
    }

    return c.json({
      status: "authenticated",
      tenantId: requestedTenant.tenantId,
      userId: principal.userId,
      expiresAt: principal.expiresAt,
    });
  });

  app.get("/auth/magic-link/verify", async (c) => {
    const tokenRaw = c.req.query("token");

    if (tokenRaw === undefined || tokenRaw.trim().length === 0) {
      return renderAppPage(
        c,
        appPage({
          title: "Invalid Magic Link",
          body: (
            <>
              <h1>Invalid magic link</h1>
              <p>Missing token. Request a new sign-in link.</p>
            </>
          ),
        }),
        400,
      );
    }

    const principal = await createMagicLinkSession(c, tokenRaw.trim());

    if (principal === null) {
      return renderAppPage(
        c,
        appPage({
          title: "Expired Magic Link",
          body: (
            <>
              <h1>Magic link expired</h1>
              <p>The link is invalid or expired. Request a new sign-in link.</p>
            </>
          ),
        }),
        400,
      );
    }

    const requestedTenant = await resolveRequestedTenantContext(c);

    if (requestedTenant === null) {
      return renderAppPage(
        c,
        appPage({
          title: "Sign-in Error",
          body: (
            <>
              <h1>Unable to complete sign-in</h1>
              <p>Please request a new sign-in link.</p>
            </>
          ),
        }),
        500,
      );
    }

    const nextPathRaw = c.req.query("next");
    const fallbackPath = "/auth/resolve";
    const nextPath = nextPathRaw?.startsWith("/") === true ? nextPathRaw : fallbackPath;

    return c.redirect(nextPath, 302);
  });

  app.get("/auth/resolve", async (c) => {
    const principal = await resolveAuthenticatedPrincipal(c);

    if (principal === null) {
      return c.redirect("/login?reason=auth_required", 302);
    }

    const contexts = await loadAccessibleTenantContextViews(c, principal.userId);
    const requestedTenant = await resolveRequestedTenantContext(c);
    const nextPath = (c.req.query("next") ?? "").trim();
    const selection = resolveTenantContextSelection({
      contexts,
      requestedTenant,
      nextPath,
    });

    if (selection.kind === "redirect") {
      rememberRequestedTenant(c, selection.tenantId);
      return c.redirect(selection.location, 302);
    }

    if (selection.kind === "chooser") {
      return c.redirect(selection.location, 302);
    }

    const message =
      selection.reason === "requested_tenant_forbidden"
        ? "Your account does not have access to the requested tenant route."
        : "No active CredTrail organizations are currently available for this account.";

    return renderNoAccessibleOrganizationsPage(c, "Organization Access Required", message, 403);
  });

  app.get("/account/organizations", async (c) => {
    const principal = await resolveAuthenticatedPrincipal(c);

    if (principal === null) {
      return c.redirect("/login?reason=auth_required", 302);
    }

    const contexts = await loadAccessibleTenantContextViews(c, principal.userId);

    if (contexts.length === 0) {
      return renderNoAccessibleOrganizationsPage(
        c,
        "Organization Access Required",
        "No active CredTrail organizations are currently available for this account.",
        403,
      );
    }

    if (contexts.length === 1) {
      const [context] = contexts;

      if (context === undefined) {
        return renderNoAccessibleOrganizationsPage(
          c,
          "Organization Access Required",
          "No active CredTrail organizations are currently available for this account.",
          403,
        );
      }

      rememberRequestedTenant(c, context.tenantId);
      return c.redirect(context.preferredPath, 302);
    }

    const requestedTenant = await resolveRequestedTenantContext(c);
    const nextPath = (c.req.query("next") ?? "").trim();

    return renderAppPage(
      c,
      organizationChooserPage({
        organizations: contexts,
        nextPath,
        currentTenantId: requestedTenant?.tenantId ?? null,
      }),
    );
  });

  app.post("/account/organizations/select", async (c) => {
    const principal = await resolveAuthenticatedPrincipal(c);

    if (principal === null) {
      return c.redirect("/login?reason=auth_required", 302);
    }

    const formData = await c.req.formData();
    const tenantId = getFormValue(formData, "tenantId");
    const nextPath = getFormValue(formData, "next");
    const contexts = await loadAccessibleTenantContextViews(c, principal.userId);
    const location = resolveChosenTenantLocation({
      contexts,
      tenantId,
      nextPath,
    });

    if (location === null) {
      return renderNoAccessibleOrganizationsPage(
        c,
        "Organization Access Required",
        "Your account does not have access to the selected tenant.",
        403,
      );
    }

    rememberRequestedTenant(c, tenantId);
    return c.redirect(location, 302);
  });

  app.get("/v1/auth/sso/:providerId/start", async (c) => {
    if (enterpriseSso === undefined) {
      return c.json(
        {
          error: "Enterprise SSO is not configured",
        },
        404,
      );
    }

    const providerId = (c.req.param("providerId") ?? "").trim();
    const tenantId = (c.req.query("tenantId") ?? "").trim();
    const nextPath = (c.req.query("next") ?? "").trim();

    if (providerId.length === 0 || tenantId.length === 0) {
      return c.json(
        {
          error: "Provider ID and tenant ID are required",
        },
        400,
      );
    }

    return enterpriseSso.start(c, {
      tenantId,
      providerId,
      nextPath,
    });
  });

  app.get("/auth/sso/callback/:providerId", async (c) => {
    if (enterpriseSso === undefined) {
      return c.json(
        {
          error: "Enterprise SSO is not configured",
        },
        404,
      );
    }

    const providerId = (c.req.param("providerId") ?? "").trim();

    if (providerId.length === 0) {
      return c.json(
        {
          error: "Provider ID is required",
        },
        400,
      );
    }

    return enterpriseSso.proxyCallback(c, {
      providerId,
    });
  });

  app.get("/auth/sso/finalize", async (c) => {
    if (enterpriseSso === undefined) {
      return c.redirect("/login?reason=sso_failed", 302);
    }

    const tenantId = (c.req.query("tenantId") ?? "").trim();
    const providerIdRaw = (c.req.query("providerId") ?? "").trim();
    const nextPath = (c.req.query("next") ?? "").trim();
    const status = (c.req.query("status") ?? "").trim();
    const error = (c.req.query("error") ?? "").trim();

    if (tenantId.length === 0) {
      return c.redirect("/login?reason=sso_failed", 302);
    }

    return enterpriseSso.finalize(c, {
      tenantId,
      providerId: providerIdRaw.length > 0 ? providerIdRaw : null,
      nextPath,
      status: status.length > 0 ? status : null,
      error: error.length > 0 ? error : null,
    });
  });

  app.get("/v1/auth/session", async (c) => {
    const principal = await resolveAuthenticatedPrincipal(c);

    if (principal === null) {
      return c.json(
        {
          error: "Not authenticated",
        },
        401,
      );
    }

    const requestedTenant = await resolveRequestedTenantContext(c);

    if (requestedTenant === null) {
      return c.json(
        {
          error: "Not authenticated",
        },
        401,
      );
    }

    return c.json({
      status: "authenticated",
      tenantId: requestedTenant.tenantId,
      userId: principal.userId,
      expiresAt: principal.expiresAt,
    });
  });

  app.post("/v1/auth/logout", async (c) => {
    await revokeCurrentSession(c);

    return c.json({
      status: "signed_out",
    });
  });
};

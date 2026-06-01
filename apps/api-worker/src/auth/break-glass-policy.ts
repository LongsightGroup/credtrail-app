import {
  findActiveTenantBreakGlassAccountByEmail,
  findTenantById,
  markTenantBreakGlassAccountUsed,
  markTenantBreakGlassEnrollmentEmailSent,
  resolveTenantAuthPolicy,
  type SqlDatabase,
} from "@credtrail/db";
import { applyBetterAuthResponseHeaders } from "./better-auth-bridge";
import type { BetterAuthRuntimeConfig } from "./better-auth-config";
import {
  resolveAuthenticatedPrincipalFromSession,
  type BetterAuthResolvedSession,
} from "./better-auth-adapter";
import { findBetterAuthSessionByToken } from "./better-auth-runtime";
import { normalizeSafeRedirectPath } from "./redirect-paths";
import type { AuthenticatedPrincipal } from "./auth-context";

export const BREAK_GLASS_PENDING_MFA_COOKIE_NAME = "credtrail_break_glass_pending_mfa";

interface BetterAuthRuntime {
  auth: {
    handler: (request: Request) => Promise<Response>;
  };
  runtimeConfig: BetterAuthRuntimeConfig;
}

export interface BreakGlassPolicyContext<BindingsType> {
  env: BindingsType;
  req: {
    url: string;
  };
  header: (name: string, value?: string, options?: { append?: boolean }) => void;
}

export interface BreakGlassPolicyAdapterInput<
  ContextType extends BreakGlassPolicyContext<BindingsType>,
  BindingsType,
> {
  resolveDatabase: (bindings: BindingsType) => SqlDatabase;
  createBetterAuthRuntime: (context: ContextType) => BetterAuthRuntime;
  createBetterAuthRequest: (context: ContextType, path: string, init?: RequestInit) => Request;
  resolveCurrentSession: (context: ContextType) => Promise<BetterAuthResolvedSession | null>;
  rememberRequestedTenant: (context: ContextType, tenantId: string) => void;
  authSystem?: string | undefined;
}

export interface BreakGlassPolicyAdapter<
  ContextType extends BreakGlassPolicyContext<BindingsType>,
  BindingsType,
> {
  requestPasswordReset: (
    context: ContextType,
    input: {
      tenantId: string;
      email: string;
      nextPath: string;
    },
  ) => Promise<"sent" | "unavailable">;
  signIn: (
    context: ContextType,
    input: {
      tenantId: string;
      email: string;
      password: string;
      nextPath: string;
    },
  ) => Promise<
    | {
        status: "authenticated";
        principal: AuthenticatedPrincipal;
      }
    | {
        status: "two_factor_required";
      }
    | {
        status: "setup_required";
      }
    | {
        status: "rejected";
        reason: string;
      }
  >;
  enrollTwoFactor: (
    context: ContextType,
    input: {
      tenantId: string;
      password: string;
    },
  ) => Promise<
    | {
        status: "enrollment_ready";
        totpUri: string;
        backupCodes: readonly string[];
      }
    | {
        status: "rejected";
        reason: string;
      }
  >;
  verifyTwoFactor: (
    context: ContextType,
    input: {
      tenantId: string;
      code: string;
      trustDevice?: boolean | undefined;
    },
  ) => Promise<
    | {
        status: "authenticated";
        principal: AuthenticatedPrincipal;
      }
    | {
        status: "rejected";
        reason: string;
      }
  >;
  resetPassword: (
    context: ContextType,
    input: {
      tenantId: string;
      token: string;
      newPassword: string;
    },
  ) => Promise<"complete" | "rejected">;
}

const normalizeNextPath = (tenantId: string, nextPath: string | undefined): string => {
  return normalizeSafeRedirectPath(nextPath, `/tenants/${encodeURIComponent(tenantId)}/admin`);
};

export const buildLocalLoginPath = (input: {
  tenantId: string;
  nextPath?: string | undefined;
  reason?: string | undefined;
}): string => {
  const url = new URL("/login/local", "https://credtrail.local");
  url.searchParams.set("tenantId", input.tenantId);
  url.searchParams.set("next", normalizeNextPath(input.tenantId, input.nextPath));

  if (input.reason !== undefined && input.reason.trim().length > 0) {
    url.searchParams.set("reason", input.reason);
  }

  return `${url.pathname}${url.search}`;
};

export const buildLocalResetPasswordPath = (input: {
  tenantId: string;
  nextPath?: string | undefined;
  token?: string | undefined;
  reason?: string | undefined;
}): string => {
  const url = new URL("/auth/local/reset-password", "https://credtrail.local");
  url.searchParams.set("tenantId", input.tenantId);
  url.searchParams.set("next", normalizeNextPath(input.tenantId, input.nextPath));

  if (input.token !== undefined && input.token.trim().length > 0) {
    url.searchParams.set("token", input.token);
  }

  if (input.reason !== undefined && input.reason.trim().length > 0) {
    url.searchParams.set("reason", input.reason);
  }

  return `${url.pathname}${url.search}`;
};

export const buildLocalTwoFactorPath = (input: {
  tenantId: string;
  nextPath?: string | undefined;
  setup?: boolean | undefined;
  reason?: string | undefined;
}): string => {
  const url = new URL(
    input.setup === true ? "/auth/local/two-factor/setup" : "/auth/local/two-factor",
    "https://credtrail.local",
  );
  url.searchParams.set("tenantId", input.tenantId);
  url.searchParams.set("next", normalizeNextPath(input.tenantId, input.nextPath));

  if (input.reason !== undefined && input.reason.trim().length > 0) {
    url.searchParams.set("reason", input.reason);
  }

  return `${url.pathname}${url.search}`;
};

const parseErrorCode = async (response: Response): Promise<string | null> => {
  try {
    const payload = (await response.json()) as {
      code?: unknown;
      error?: unknown;
    };

    if (typeof payload.code === "string" && payload.code.trim().length > 0) {
      return payload.code;
    }

    if (typeof payload.error === "string" && payload.error.trim().length > 0) {
      return payload.error;
    }

    return null;
  } catch {
    return null;
  }
};

const resolveBreakGlassState = async (
  db: SqlDatabase,
  tenantId: string,
): Promise<"available" | "unavailable"> => {
  const tenant = await findTenantById(db, tenantId);

  if (tenant === null || tenant.planTier !== "enterprise") {
    return "unavailable";
  }

  const policy = await resolveTenantAuthPolicy(db, tenantId);

  if (!policy.breakGlassEnabled || policy.localMfaRequired !== true) {
    return "unavailable";
  }

  return "available";
};

const resolveAuthenticatedPrincipalFromToken = async (
  db: SqlDatabase,
  token: string,
  authSystem?: string,
): Promise<AuthenticatedPrincipal | null> => {
  const session = await findBetterAuthSessionByToken(db, token);

  if (session === null) {
    return null;
  }

  return resolveAuthenticatedPrincipalFromSession({
    db,
    session: {
      sessionId: session.sessionId,
      accountId: null,
      expiresAt: session.expiresAt,
      user: {
        id: session.userId,
        email: session.userEmail,
        emailVerified: session.userEmailVerified,
      },
    },
    authSystem,
  });
};

const signOutSession = async <
  ContextType extends BreakGlassPolicyContext<BindingsType>,
  BindingsType,
>(
  context: ContextType,
  input: BreakGlassPolicyAdapterInput<ContextType, BindingsType>,
): Promise<void> => {
  const { auth } = input.createBetterAuthRuntime(context);
  const response = await auth.handler(
    input.createBetterAuthRequest(context, "/sign-out", {
      method: "POST",
    }),
  );

  applyBetterAuthResponseHeaders(context, response);
};

export const createBreakGlassPolicyAdapter = <
  ContextType extends BreakGlassPolicyContext<BindingsType>,
  BindingsType,
>(
  input: BreakGlassPolicyAdapterInput<ContextType, BindingsType>,
): BreakGlassPolicyAdapter<ContextType, BindingsType> => {
  const requestPasswordReset: BreakGlassPolicyAdapter<
    ContextType,
    BindingsType
  >["requestPasswordReset"] = async (context, request) => {
    const db = input.resolveDatabase(context.env);

    if ((await resolveBreakGlassState(db, request.tenantId)) !== "available") {
      return "unavailable";
    }

    const allowlistedAccount = await findActiveTenantBreakGlassAccountByEmail(
      db,
      request.tenantId,
      request.email,
    );

    if (allowlistedAccount === null) {
      return "sent";
    }

    const { auth, runtimeConfig } = input.createBetterAuthRuntime(context);
    const redirectTo = new URL(
      buildLocalResetPasswordPath({
        tenantId: request.tenantId,
        nextPath: request.nextPath,
      }),
      runtimeConfig.baseURL,
    );
    const response = await auth.handler(
      input.createBetterAuthRequest(context, "/request-password-reset", {
        method: "POST",
        headers: {
          "content-type": "application/json",
        },
        body: JSON.stringify({
          email: request.email,
          redirectTo: redirectTo.toString(),
        }),
      }),
    );

    applyBetterAuthResponseHeaders(context, response);

    if (!response.ok) {
      return "sent";
    }

    await markTenantBreakGlassEnrollmentEmailSent(db, {
      tenantId: request.tenantId,
      userId: allowlistedAccount.userId,
      sentAt: new Date().toISOString(),
    });

    return "sent";
  };

  const signIn: BreakGlassPolicyAdapter<ContextType, BindingsType>["signIn"] = async (
    context,
    request,
  ) => {
    const db = input.resolveDatabase(context.env);

    if ((await resolveBreakGlassState(db, request.tenantId)) !== "available") {
      return {
        status: "rejected",
        reason: "break_glass_unavailable",
      };
    }

    const allowlistedAccount = await findActiveTenantBreakGlassAccountByEmail(
      db,
      request.tenantId,
      request.email,
    );

    if (allowlistedAccount === null) {
      return {
        status: "rejected",
        reason: "break_glass_invalid_credentials",
      };
    }

    input.rememberRequestedTenant(context, request.tenantId);

    const { auth } = input.createBetterAuthRuntime(context);
    const response = await auth.handler(
      input.createBetterAuthRequest(context, "/sign-in/email", {
        method: "POST",
        headers: {
          "content-type": "application/json",
        },
        body: JSON.stringify({
          email: request.email,
          password: request.password,
          rememberMe: true,
        }),
      }),
    );

    applyBetterAuthResponseHeaders(context, response);

    if (!response.ok) {
      return {
        status: "rejected",
        reason: "break_glass_invalid_credentials",
      };
    }

    const payload = (await response.json()) as {
      twoFactorRedirect?: boolean | undefined;
      token?: string | undefined;
      user?: {
        email?: string | null | undefined;
        twoFactorEnabled?: boolean | undefined;
      } | null;
    };

    if (payload.twoFactorRedirect === true) {
      return {
        status: "two_factor_required",
      };
    }

    if (payload.user?.twoFactorEnabled !== true) {
      return {
        status: "setup_required",
      };
    }

    const token = payload.token?.trim();

    if (token === undefined || token.length === 0) {
      return {
        status: "rejected",
        reason: "break_glass_invalid_credentials",
      };
    }

    const principal = await resolveAuthenticatedPrincipalFromToken(db, token, input.authSystem);

    if (principal === null) {
      return {
        status: "rejected",
        reason: "break_glass_invalid_credentials",
      };
    }

    await markTenantBreakGlassAccountUsed(db, {
      tenantId: request.tenantId,
      userId: allowlistedAccount.userId,
      usedAt: new Date().toISOString(),
    });

    return {
      status: "authenticated",
      principal,
    };
  };

  const enrollTwoFactor: BreakGlassPolicyAdapter<
    ContextType,
    BindingsType
  >["enrollTwoFactor"] = async (context, request) => {
    const db = input.resolveDatabase(context.env);

    if ((await resolveBreakGlassState(db, request.tenantId)) !== "available") {
      return {
        status: "rejected",
        reason: "break_glass_unavailable",
      };
    }

    const session = await input.resolveCurrentSession(context);
    const email = session?.user?.email?.trim() ?? "";

    if (email.length === 0) {
      return {
        status: "rejected",
        reason: "break_glass_not_authenticated",
      };
    }

    const allowlistedAccount = await findActiveTenantBreakGlassAccountByEmail(
      db,
      request.tenantId,
      email,
    );

    if (allowlistedAccount === null) {
      return {
        status: "rejected",
        reason: "break_glass_not_allowlisted",
      };
    }

    input.rememberRequestedTenant(context, request.tenantId);

    const { auth } = input.createBetterAuthRuntime(context);
    const response = await auth.handler(
      input.createBetterAuthRequest(context, "/two-factor/enable", {
        method: "POST",
        headers: {
          "content-type": "application/json",
        },
        body: JSON.stringify({
          password: request.password,
          issuer: `CredTrail (${request.tenantId})`,
        }),
      }),
    );

    applyBetterAuthResponseHeaders(context, response);

    if (!response.ok) {
      const code = await parseErrorCode(response);

      return {
        status: "rejected",
        reason:
          code === "INVALID_PASSWORD"
            ? "break_glass_invalid_password"
            : "break_glass_enrollment_failed",
      };
    }

    const payload = (await response.json()) as {
      totpURI?: string | undefined;
      backupCodes?: unknown;
    };
    const backupCodes = Array.isArray(payload.backupCodes)
      ? payload.backupCodes.filter((entry): entry is string => typeof entry === "string")
      : [];

    if (typeof payload.totpURI !== "string" || payload.totpURI.trim().length === 0) {
      return {
        status: "rejected",
        reason: "break_glass_enrollment_failed",
      };
    }

    return {
      status: "enrollment_ready",
      totpUri: payload.totpURI,
      backupCodes,
    };
  };

  const verifyTwoFactor: BreakGlassPolicyAdapter<
    ContextType,
    BindingsType
  >["verifyTwoFactor"] = async (context, request) => {
    const db = input.resolveDatabase(context.env);

    if ((await resolveBreakGlassState(db, request.tenantId)) !== "available") {
      return {
        status: "rejected",
        reason: "break_glass_unavailable",
      };
    }

    input.rememberRequestedTenant(context, request.tenantId);

    const { auth } = input.createBetterAuthRuntime(context);
    const response = await auth.handler(
      input.createBetterAuthRequest(context, "/two-factor/verify-totp", {
        method: "POST",
        headers: {
          "content-type": "application/json",
        },
        body: JSON.stringify({
          code: request.code,
          trustDevice: request.trustDevice ?? false,
        }),
      }),
    );

    applyBetterAuthResponseHeaders(context, response);

    if (!response.ok) {
      return {
        status: "rejected",
        reason: "break_glass_invalid_code",
      };
    }

    const payload = (await response.json()) as {
      token?: string | undefined;
      user?: {
        email?: string | null | undefined;
      } | null;
    };
    const email = payload.user?.email?.trim() ?? "";

    if (email.length === 0) {
      return {
        status: "rejected",
        reason: "break_glass_invalid_code",
      };
    }

    const allowlistedAccount = await findActiveTenantBreakGlassAccountByEmail(
      db,
      request.tenantId,
      email,
    );

    if (allowlistedAccount === null) {
      await signOutSession(context, input);

      return {
        status: "rejected",
        reason: "break_glass_not_allowlisted",
      };
    }

    const token = payload.token?.trim();

    if (token === undefined || token.length === 0) {
      return {
        status: "rejected",
        reason: "break_glass_invalid_code",
      };
    }

    const principal = await resolveAuthenticatedPrincipalFromToken(db, token, input.authSystem);

    if (principal === null) {
      return {
        status: "rejected",
        reason: "break_glass_invalid_code",
      };
    }

    await markTenantBreakGlassAccountUsed(db, {
      tenantId: request.tenantId,
      userId: allowlistedAccount.userId,
      usedAt: new Date().toISOString(),
    });

    return {
      status: "authenticated",
      principal,
    };
  };

  const resetPassword: BreakGlassPolicyAdapter<ContextType, BindingsType>["resetPassword"] = async (
    context,
    request,
  ) => {
    const db = input.resolveDatabase(context.env);

    if ((await resolveBreakGlassState(db, request.tenantId)) !== "available") {
      return "rejected";
    }

    const { auth } = input.createBetterAuthRuntime(context);
    const response = await auth.handler(
      input.createBetterAuthRequest(context, "/reset-password", {
        method: "POST",
        headers: {
          "content-type": "application/json",
        },
        body: JSON.stringify({
          token: request.token,
          newPassword: request.newPassword,
        }),
      }),
    );

    applyBetterAuthResponseHeaders(context, response);

    if (!response.ok) {
      return "rejected";
    }

    return "complete";
  };

  return {
    requestPasswordReset,
    signIn,
    enrollTwoFactor,
    verifyTwoFactor,
    resetPassword,
  };
};

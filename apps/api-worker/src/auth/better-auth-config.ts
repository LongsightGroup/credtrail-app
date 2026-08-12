import { canonicalAppOrigin } from "../http/canonical-app-url";

export const BETTER_AUTH_AUTH_SYSTEM = "better_auth";
export const BETTER_AUTH_SESSION_TTL_SECONDS = 7 * 24 * 60 * 60;
export const BETTER_AUTH_SESSION_COOKIE_NAME = "better-auth.session_token";
const BETTER_AUTH_SCHEMA = "auth";

export interface BetterAuthRuntimeBindings {
  APP_ENV: string;
  PLATFORM_DOMAIN: string;
  PUBLIC_APP_ORIGIN: string;
  BETTER_AUTH_SECRET?: string | undefined;
  BETTER_AUTH_TRUSTED_ORIGINS?: string | undefined;
  GOOGLE_OAUTH_CLIENT_ID?: string | undefined;
  GOOGLE_OAUTH_CLIENT_SECRET?: string | undefined;
}

export interface BetterAuthRuntimeConfig {
  authSystem: typeof BETTER_AUTH_AUTH_SYSTEM;
  baseURL: string;
  trustedOrigins: string[];
  secret: string | null;
  session: {
    cookieName: typeof BETTER_AUTH_SESSION_COOKIE_NAME;
    expiresInSeconds: number;
    disableRefresh: boolean;
  };
  database: {
    schema: typeof BETTER_AUTH_SCHEMA;
    searchPath: string;
  };
}

const normalizeOrigin = (origin: string): string | null => {
  const trimmed = origin.trim();

  if (trimmed.length === 0) {
    return null;
  }

  try {
    const parsed = new URL(trimmed);
    return parsed.origin;
  } catch {
    return null;
  }
};

export const createBetterAuthRuntimeConfig = (
  bindings: BetterAuthRuntimeBindings,
): BetterAuthRuntimeConfig => {
  const baseURL = canonicalAppOrigin(bindings.PUBLIC_APP_ORIGIN);
  const trustedOrigins = new Set<string>();

  trustedOrigins.add(baseURL);

  for (const origin of (bindings.BETTER_AUTH_TRUSTED_ORIGINS ?? "").split(",")) {
    const normalizedOrigin = normalizeOrigin(origin);

    if (normalizedOrigin !== null) {
      trustedOrigins.add(normalizedOrigin);
    }
  }

  const trimmedSecret = bindings.BETTER_AUTH_SECRET?.trim();

  return {
    authSystem: BETTER_AUTH_AUTH_SYSTEM,
    baseURL,
    trustedOrigins: [...trustedOrigins],
    secret: trimmedSecret === undefined || trimmedSecret.length === 0 ? null : trimmedSecret,
    session: {
      cookieName: BETTER_AUTH_SESSION_COOKIE_NAME,
      expiresInSeconds: BETTER_AUTH_SESSION_TTL_SECONDS,
      disableRefresh: true,
    },
    database: {
      schema: BETTER_AUTH_SCHEMA,
      searchPath: `${BETTER_AUTH_SCHEMA},public`,
    },
  };
};

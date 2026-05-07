import {
  logWarn,
  type ImmutableCredentialStore,
  type JsonObject,
  type ObservabilityContext,
} from "@credtrail/core-domain";
import {
  findTenantSigningRegistrationByDid,
  listLtiIssuerRegistrations,
  upsertTenantMembershipRole,
  type SqlDatabase,
} from "@credtrail/db";
import { createPostgresDatabase } from "@credtrail/db/postgres";
import { Hono, type Context } from "hono";
import { deleteCookie, getCookie, setCookie } from "hono/cookie";
import {
  credentialDownloadFilename,
  credentialPdfDownloadFilename,
  renderBadgePdfDocument,
} from "./badges/pdf";
import {
  achievementDetailsFromCredential,
  badgeHeroImageMarkup,
  githubAvatarUrlForUsername,
  githubUsernameFromUrl,
  imsOb3ValidatorUrl,
  evidenceDetailsFromCredential,
  recipientAvatarUrlFromAssertion,
  recipientDisplayNameFromAssertion,
} from "./badges/public-badge-helpers";
import {
  badgeNameFromCredential,
  isWebUrl,
  issuerIdentifierFromCredential,
  issuerNameFromCredential,
  issuerUrlFromCredential,
  recipientFromCredential,
} from "./badges/credential-display";
import {
  buildRevocationStatusListCredential,
  credentialStatusForAssertion,
  decodedRevocationStatusBit,
  parseStatusListIndex,
  revocationStatusListUrlForTenant,
} from "./badges/revocation-status";
import { createPublicBadgePageRenderers } from "./badges/public-badge-pages";
import { createIssueBadgeForTenant } from "./badges/direct-issue";
import {
  assertionBelongsToTenant,
  loadCredentialForAssertion,
  loadPublicBadgeViewModel,
  loadVerificationViewModel,
  parseTenantScopedCredentialId,
  publicBadgePathForAssertion,
  type VerificationViewModel,
} from "./badges/public-badge-model";
import {
  VC_DATA_MODEL_CONTEXT_URL,
  createCredentialVerificationChecks,
} from "./credentials/verification-checks";
import { createCredentialProofVerificationHelpers } from "./credentials/proof-verification";
import { registerCommonMiddleware } from "./http/common-middleware";
import { createLoadJsonObjectFromUrl } from "./http/json-object-loader";
import { registerPageAssetRoutes } from "./ui/page-assets";
import { createSignCredentialForDid } from "./signing/credential-signer";
import {
  didDocumentForSigningEntry,
  didForTenantPathRequest,
  didForWellKnownRequest,
  jwksDocumentForSigningEntry,
} from "./signing/did-documents";
import { createSigningRegistryResolvers } from "./signing/registry";
import {
  ADMIN_ROLES,
  ISSUER_ROLES,
  TENANT_MEMBER_ROLES,
  createTenantAccessHelpers,
  defaultInstitutionOrgUnitId,
  isUniqueConstraintError,
} from "./auth/tenant-access";
import type {
  AuthContextVariables,
  AuthenticatedPrincipal,
  RequestedTenantContext,
} from "./auth/auth-context";
import { createBetterAuthProvider } from "./auth/better-auth-adapter";
import { applyBetterAuthResponseHeaders } from "./auth/better-auth-bridge";
import { createBetterAuthRuntimeConfig } from "./auth/better-auth-config";
import {
  BREAK_GLASS_PENDING_MFA_COOKIE_NAME,
  createBreakGlassPolicyAdapter,
} from "./auth/break-glass-policy";
import {
  BETTER_AUTH_BASE_PATH,
  REQUESTED_TENANT_COOKIE_NAME,
  buildHostedMagicLinkToken,
  buildHostedMagicLinkUrl,
  createBetterAuthSessionForCredtrailUser,
  createCredtrailBetterAuth,
  findBetterAuthSessionByToken,
  parseHostedMagicLinkToken,
} from "./auth/better-auth-runtime";
import { createEnterpriseSsoAdapter } from "./auth/enterprise-sso-adapter";
import { createOAuthTokenHelpers } from "./ob3/oauth-token-helpers";
import { createOb3ErrorResponses } from "./ob3/error-responses";
import { createOb3AccessTokenAuthenticator } from "./ob3/access-token-auth";
import { ob3ServiceDescriptionDocument as ob3ServiceDescriptionDocumentFromRequest } from "./ob3/service-description";
import {
  ltiIssuerRegistryFromStoredRows,
  parseLtiIssuerRegistryFromEnv,
  type LtiIssuerRegistry,
} from "./lti/lti-helpers";
import { createLearnerDashboardPage, learnerDidSettingsNoticeFromQuery } from "./learner/pages";
import { createLearnerRecordPage } from "./learner/learner-record-page";
import {
  sendIssuanceEmailNotification,
  type SendIssuanceEmailNotificationInput,
} from "./notifications/send-issuance-email";
import { sendMagicLinkEmailNotification } from "./notifications/send-magic-link-email";
import { sendPasswordResetEmailNotification } from "./notifications/send-password-reset-email";
import { registerAdminRoutes } from "./routes/admin-routes";
import { registerAssertionRoutes } from "./routes/assertion-routes";
import { registerAuthRoutes } from "./routes/auth-routes";
import { registerBadgeTemplateRoutes } from "./routes/badge-template-routes";
import { registerBadgeRuleRoutes } from "./routes/badge-rule-routes";
import { registerCredentialRoutes } from "./routes/credential-routes";
import { registerDidRoutes } from "./routes/did-routes";
import { registerLearnerRoutes } from "./routes/learner-routes";
import { registerLearnerRecordExportRoutes } from "./routes/learner-record-export-routes";
import { registerLearnerRecordRoutes } from "./routes/learner-record-routes";
import { registerLtiRoutes } from "./routes/lti-routes";
import { registerMigrationRoutes } from "./routes/migration-routes";
import { registerOb3Routes } from "./routes/ob3-routes";
import { registerPresentationRoutes } from "./routes/presentation-routes";
import { registerPublicBadgeRoutes } from "./routes/public-badge-routes";
import { registerQueueRoutes } from "./routes/queue-routes";
import { registerExecutiveRoutes } from "./routes/executive-routes";
import { registerReportingRoutes } from "./routes/reporting-routes";
import { registerSigningRoutes } from "./routes/signing-routes";
import { registerTenantGovernanceRoutes } from "./routes/tenant-governance-routes";
import { registerOid4vciRoutes } from "./routes/oid4vci-routes";
import {
  addSecondsToIso,
  generateOpaqueToken,
  sessionCookieSecure,
  sha256Base64Url,
  sha256Hex,
} from "./utils/crypto";
import { escapeHtml, formatIsoTimestamp, linkedInAddToProfileUrl } from "./utils/display-format";
import { asJsonObject, asNonEmptyString, asString } from "./utils/value-parsers";
import { createApiWorker } from "./worker/create-worker";
import {
  issueBadgeQueueJobFromRequest,
  revokeBadgeQueueJobFromRequest,
} from "./queue/job-builders";
import {
  createProcessQueuedJobs,
  processQueueInputWithDefaults,
  readJsonBodyOrEmptyObject,
} from "./queue/processing";
import { queueProcessorRequestFromSchedule } from "./queue/scheduled-trigger";
import {
  createPresentationVerificationHelpers,
  didKeyVerificationMethod,
  ed25519PublicJwkFromDidKey,
  verifiableCredentialObjectsFromPresentation as verifiableCredentialObjectsFromPresentationHelper,
} from "./presentation/verification-helpers";

export interface AppBindings {
  APP_ENV: string;
  DATABASE_URL?: string;
  BADGE_OBJECTS: ImmutableCredentialStore;
  PLATFORM_DOMAIN: string;
  SENTRY_DSN?: string;
  TENANT_SIGNING_REGISTRY_JSON?: string;
  TENANT_SIGNING_KEY_HISTORY_JSON?: string;
  TENANT_REMOTE_SIGNER_REGISTRY_JSON?: string;
  MAILTRAP_API_TOKEN?: string;
  MAILTRAP_INBOX_ID?: string;
  MAILTRAP_API_BASE_URL?: string;
  MAILTRAP_FROM_EMAIL?: string;
  MAILTRAP_FROM_NAME?: string;
  TURNSTILE_SITE_KEY?: string;
  TURNSTILE_SECRET_KEY?: string;
  BETTER_AUTH_SECRET?: string;
  BETTER_AUTH_TRUSTED_ORIGINS?: string;
  GITHUB_TOKEN?: string;
  JOB_PROCESSOR_TOKEN?: string;
  BOOTSTRAP_ADMIN_TOKEN?: string;
  LTI_ISSUER_REGISTRY_JSON?: string;
  LTI_STATE_SIGNING_SECRET?: string;
  CANVAS_OAUTH_STATE_SIGNING_SECRET?: string;
  OB3_DISCOVERY_TITLE?: string;
  OB3_TERMS_OF_SERVICE_URL?: string;
  OB3_PRIVACY_POLICY_URL?: string;
  OB3_IMAGE_URL?: string;
  OB3_OAUTH_REGISTRATION_URL?: string;
  OB3_OAUTH_AUTHORIZATION_URL?: string;
  OB3_OAUTH_TOKEN_URL?: string;
  OB3_OAUTH_REFRESH_URL?: string;
  RULE_BUILDER_TUTORIAL_EMBED_URL?: string;
}

export interface AppEnv {
  Bindings: AppBindings;
  Variables: AuthContextVariables;
}

export type AppContext = Context<AppEnv>;

export const app = new Hono<AppEnv>();
export { sendIssuanceEmailNotification };
export type { SendIssuanceEmailNotificationInput };
const API_SERVICE_NAME = "api-worker";
const MAGIC_LINK_TTL_SECONDS = 10 * 60;
const SESSION_TTL_SECONDS = 7 * 24 * 60 * 60;
const LEARNER_IDENTITY_LINK_TTL_SECONDS = 10 * 60;
const OID4VCI_PRE_AUTH_CODE_TTL_SECONDS = 10 * 60;
const OID4VCI_ACCESS_TOKEN_TTL_SECONDS = 10 * 60;
const SAKAI_SHOWCASE_TENANT_ID = "sakai";
const SAKAI_SHOWCASE_TEMPLATE_ID = "badge_template_sakai_1000";
const databasesByUrl = new Map<string, SqlDatabase>();
const STORAGE_READINESS_PROBE_KEY = "__credtrail__/healthz/dependency-probe.jsonld";

const resolveDatabase = (bindings: AppBindings): SqlDatabase => {
  if (bindings.DATABASE_URL === undefined) {
    throw new Error("DATABASE_URL is required");
  }
  const databaseUrl = bindings.DATABASE_URL.trim();

  if (databaseUrl.length === 0) {
    throw new Error("DATABASE_URL is required");
  }

  const existingDatabase = databasesByUrl.get(databaseUrl);

  if (existingDatabase !== undefined) {
    return existingDatabase;
  }

  const database = createPostgresDatabase({
    databaseUrl,
  });
  databasesByUrl.set(databaseUrl, database);
  return database;
};

const observabilityContext = (bindings: AppBindings): ObservabilityContext => {
  return {
    service: API_SERVICE_NAME,
    environment: bindings.APP_ENV,
  };
};

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

const rememberRequestedTenant = (context: AppContext, tenantId: string): RequestedTenantContext => {
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

const pendingBreakGlassTenantFromCookie = (context: AppContext): string | null => {
  const tenantId = getCookie(context, BREAK_GLASS_PENDING_MFA_COOKIE_NAME)?.trim();
  return tenantId === undefined || tenantId.length === 0 ? null : tenantId;
};

const createBetterAuthRequest = (
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

const createBetterAuthRuntime = (
  context: AppContext,
  options?: {
    generateMagicLinkToken?: (() => string) | undefined;
    oauthProviders?:
      | readonly import("better-auth/plugins/generic-oauth").GenericOAuthConfig[]
      | undefined;
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

const resolveCurrentBetterAuthSession = async (
  context: AppContext,
): Promise<import("./auth/better-auth-adapter").BetterAuthResolvedSession | null> => {
  const { auth } = createBetterAuthRuntime(context);
  const response = await auth.handler(
    createBetterAuthRequest(context, "/get-session", {
      method: "GET",
    }),
  );

  if (!response.ok) {
    return null;
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
    return null;
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

const betterAuthProvider = createBetterAuthProvider<AppContext, AppBindings>({
  resolveDatabase,
  requestMagicLink: async (context, input) => {
    const defaultNextPath = "/auth/resolve";
    const nextPath = input.nextPath?.startsWith("/") === true ? input.nextPath : defaultNextPath;
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

        try {
          await sendMagicLinkEmailNotification({
            mailtrapApiToken: context.env.MAILTRAP_API_TOKEN,
            mailtrapInboxId: context.env.MAILTRAP_INBOX_ID,
            mailtrapApiBaseUrl: context.env.MAILTRAP_API_BASE_URL,
            mailtrapFromEmail: context.env.MAILTRAP_FROM_EMAIL,
            mailtrapFromName: context.env.MAILTRAP_FROM_NAME,
            recipientEmail: email,
            tenantId: input.tenantId,
            magicLinkUrl: debugMagicLinkUrl,
            expiresAtIso: expiresAt,
          });
          deliveryStatus = "sent";
        } catch {
          deliveryStatus = "failed";
        }
      },
      sendResetPassword: async ({ email, url }) => {
        await sendPasswordResetEmailNotification({
          mailtrapApiToken: context.env.MAILTRAP_API_TOKEN,
          mailtrapInboxId: context.env.MAILTRAP_INBOX_ID,
          mailtrapApiBaseUrl: context.env.MAILTRAP_API_BASE_URL,
          mailtrapFromEmail: context.env.MAILTRAP_FROM_EMAIL,
          mailtrapFromName: context.env.MAILTRAP_FROM_NAME,
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

const resolveAuthenticatedPrincipal = async (
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

const resolveRequestedTenantContext = async (
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

const breakGlassPolicyAdapter = createBreakGlassPolicyAdapter<AppContext, AppBindings>({
  resolveDatabase,
  createBetterAuthRuntime,
  createBetterAuthRequest,
  resolveCurrentSession: resolveCurrentBetterAuthSession,
  rememberRequestedTenant: (context, tenantId) => {
    rememberRequestedTenant(context, tenantId);
  },
});

const enterpriseSsoAdapter = createEnterpriseSsoAdapter<AppContext, AppBindings>({
  resolveDatabase,
  createBetterAuthRuntime,
  createBetterAuthRequest,
  resolveAuthenticatedPrincipal,
  resolveRequestedTenantContext,
  rememberRequestedTenant,
});

const resolveLtiIssuerRegistry = async (c: AppContext): Promise<LtiIssuerRegistry> => {
  const envRegistry = parseLtiIssuerRegistryFromEnv(c.env.LTI_ISSUER_REGISTRY_JSON);
  const dbRows = await listLtiIssuerRegistrations(resolveDatabase(c.env));
  const dbRegistry = ltiIssuerRegistryFromStoredRows(dbRows);
  return {
    ...envRegistry,
    ...dbRegistry,
  };
};

const {
  resolveSigningEntryForDid,
  resolveHistoricalSigningKeysForDid,
  resolveRemoteSignerRegistryEntryForDid,
} = createSigningRegistryResolvers<AppContext, AppBindings>({
  resolveDatabase,
  findTenantSigningRegistrationByDid,
});

const {
  requireBootstrapAdmin,
  requireBootstrapAdminUiToken,
  requireTenantRole,
  requireScopedOrgUnitPermission,
  requireDelegatedIssuingAuthorityPermission,
} = createTenantAccessHelpers<AppContext, AppBindings>({
  resolveAuthenticatedPrincipal,
  resolvePendingBreakGlassTenantId: pendingBreakGlassTenantFromCookie,
  resolveDatabase,
});

const ob3ServiceDescriptionDocument = (c: AppContext): JsonObject => {
  return ob3ServiceDescriptionDocumentFromRequest({
    requestUrl: c.req.url,
    discoveryTitle: c.env.OB3_DISCOVERY_TITLE,
    termsOfServiceUrl: c.env.OB3_TERMS_OF_SERVICE_URL,
    privacyPolicyUrl: c.env.OB3_PRIVACY_POLICY_URL,
    imageUrl: c.env.OB3_IMAGE_URL,
    oauthRegistrationUrl: c.env.OB3_OAUTH_REGISTRATION_URL,
    oauthAuthorizationUrl: c.env.OB3_OAUTH_AUTHORIZATION_URL,
    oauthTokenUrl: c.env.OB3_OAUTH_TOKEN_URL,
    oauthRefreshUrl: c.env.OB3_OAUTH_REFRESH_URL,
  });
};

const { oauthErrorJson, oauthTokenErrorJson, oauthTokenSuccessJson, ob3ErrorJson } =
  createOb3ErrorResponses<AppContext>();

const authenticateOb3AccessToken = createOb3AccessTokenAuthenticator<AppContext, AppBindings>({
  resolveDatabase,
  sha256Hex,
  ob3ErrorJson,
});

const { authenticateOAuthClient, issueOAuthAccessAndRefreshTokens } =
  createOAuthTokenHelpers<AppContext>({
    oauthTokenErrorJson,
    sha256Hex,
    generateOpaqueToken,
    addSecondsToIso,
  });

const loadJsonObjectFromUrl = createLoadJsonObjectFromUrl<AppBindings>({
  appRequest: async (pathWithQuery, init, bindings) => {
    return app.request(pathWithQuery, init, bindings);
  },
  asJsonObject,
});

const {
  collectContextUrls,
  normalizedStringValues,
  summarizeCredentialLifecycleVerification,
  summarizeCredentialVerificationChecks,
} = createCredentialVerificationChecks<AppContext>({
  asJsonObject,
  asNonEmptyString,
  loadJsonObjectFromUrl,
  parseStatusListIndex,
  decodedRevocationStatusBit,
});

const { selectCredentialProofObject, verifyCredentialProofSummary } =
  createCredentialProofVerificationHelpers<AppContext>({
    resolveSigningEntryForDid,
    resolveHistoricalSigningKeysForDid,
  });

const signCredentialForDid = createSignCredentialForDid<AppContext>({
  resolveSigningEntryForDid,
  resolveRemoteSignerRegistryEntryForDid,
  asJsonObject,
  asNonEmptyString,
  selectCredentialProofObject,
});

const verifiableCredentialObjectsFromPresentation = (
  presentation: JsonObject,
): JsonObject[] | null => {
  return verifiableCredentialObjectsFromPresentationHelper(presentation, asJsonObject);
};

const { verifyPresentationHolderProofSummary, verifyCredentialInPresentation } =
  createPresentationVerificationHelpers<AppContext>({
    asJsonObject,
    asNonEmptyString,
    asString,
    selectCredentialProofObject,
    verifyCredentialProofSummary,
    summarizeCredentialVerificationChecks,
    summarizeCredentialLifecycleVerification,
  });

class HttpErrorResponse extends Error {
  public readonly statusCode: 400 | 404 | 409 | 422 | 500 | 502;

  public readonly payload: {
    error: string;
    did?: string | undefined;
  };

  public constructor(
    statusCode: 400 | 404 | 409 | 422 | 500 | 502,
    payload: {
      error: string;
      did?: string | undefined;
    },
  ) {
    super(payload.error);
    this.statusCode = statusCode;
    this.payload = payload;
  }
}

const {
  publicBadgeNotFoundPage,
  publicBadgePage,
  tenantBadgeWallPage,
  tenantBadgeCriteriaRegistryPage,
} = createPublicBadgePageRenderers({
  asString,
  achievementDetailsFromCredential,
  badgeHeroImageMarkup,
  badgeNameFromCredential,
  evidenceDetailsFromCredential,
  escapeHtml,
  formatIsoTimestamp,
  githubAvatarUrlForUsername,
  githubUsernameFromUrl,
  imsOb3ValidatorUrl,
  isWebUrl,
  issuerIdentifierFromCredential,
  issuerNameFromCredential,
  issuerUrlFromCredential,
  linkedInAddToProfileUrl,
  publicBadgePathForAssertion,
  recipientAvatarUrlFromAssertion,
  recipientDisplayNameFromAssertion,
  recipientFromCredential,
});

const learnerDashboardPage = createLearnerDashboardPage({
  escapeHtml,
  formatIsoTimestamp,
});

const learnerRecordPage = createLearnerRecordPage({
  escapeHtml,
  formatIsoTimestamp,
});

const walletCredentialOfferPayload = (
  requestUrl: string,
  model: VerificationViewModel,
  options?: {
    preAuthorizedCode?: string | undefined;
    offerExpiresAt?: string | undefined;
    tokenEndpointPath?: string | undefined;
    credentialEndpointPath?: string | undefined;
  },
): Record<string, unknown> => {
  const assertion = model.assertion;
  const requestBaseUrl = new URL(requestUrl);
  const publicBadgePath = `/badges/${encodeURIComponent(assertion.publicId ?? assertion.id)}`;
  const verificationPath = `${publicBadgePath}/verification`;
  const credentialJsonldPath = `${publicBadgePath}/jsonld`;
  const credentialDownloadPath = `${publicBadgePath}/download`;
  const preAuthorizedCode =
    options?.preAuthorizedCode ?? `public-badge:${assertion.publicId ?? assertion.id}`;
  const tokenEndpointPath = options?.tokenEndpointPath ?? "/credentials/v1/token";
  const credentialEndpointPath = options?.credentialEndpointPath ?? "/credentials/v1/credentials";

  return {
    credential_issuer: requestBaseUrl.origin,
    credential_endpoint: new URL(credentialEndpointPath, requestBaseUrl).toString(),
    credential_configuration_ids: ["OpenBadgeCredential"],
    grants: {
      "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
        "pre-authorized_code": preAuthorizedCode,
        tx_code_required: false,
      },
    },
    credentials: [
      {
        format: "ldp_vc",
        types: ["VerifiableCredential", "OpenBadgeCredential"],
      },
    ],
    x_credtrail: {
      token_endpoint: new URL(tokenEndpointPath, requestBaseUrl).toString(),
      credential_endpoint: new URL(credentialEndpointPath, requestBaseUrl).toString(),
      public_badge_url: new URL(publicBadgePath, requestBaseUrl).toString(),
      verification_url: new URL(verificationPath, requestBaseUrl).toString(),
      credential_jsonld_url: new URL(credentialJsonldPath, requestBaseUrl).toString(),
      credential_download_url: new URL(credentialDownloadPath, requestBaseUrl).toString(),
      ...(options?.offerExpiresAt === undefined
        ? {}
        : {
            offer_expires_at: options.offerExpiresAt,
          }),
    },
  };
};

const publicBadgeSummaryPayload = (
  requestUrl: string,
  model: VerificationViewModel,
): Record<string, unknown> => {
  const requestBaseUrl = new URL(requestUrl);
  const assertion = model.assertion;
  const achievementDetails = achievementDetailsFromCredential(model.credential);
  const badgeName = badgeNameFromCredential(model.credential);
  const recipientDisplayName =
    model.recipientDisplayName ?? recipientDisplayNameFromAssertion(assertion);
  const recipientAvatarUrl = recipientAvatarUrlFromAssertion(assertion);
  const issuerName = issuerNameFromCredential(model.credential);
  const issuerId = issuerIdentifierFromCredential(model.credential);
  const issuerUrl = issuerUrlFromCredential(model.credential);
  const recipientId = recipientFromCredential(model.credential);
  const publicBadgePath = `/badges/${encodeURIComponent(assertion.publicId ?? assertion.id)}`;
  const summaryPath = `${publicBadgePath}/summary`;
  const verificationPath = `${publicBadgePath}/verification`;
  const ob3JsonPath = `${publicBadgePath}/jsonld`;
  const credentialDownloadPath = `${publicBadgePath}/download`;
  const credentialPdfDownloadPath = `${publicBadgePath}/download.pdf`;
  const walletOfferPath = `/credentials/v1/offers/${encodeURIComponent(assertion.publicId ?? assertion.id)}`;
  const showcasePath = `/showcase/${encodeURIComponent(assertion.tenantId)}?badgeTemplateId=${encodeURIComponent(assertion.badgeTemplateId)}`;
  const criteriaRegistryPath = `/showcase/${encodeURIComponent(
    assertion.tenantId,
  )}/criteria?badgeTemplateId=${encodeURIComponent(assertion.badgeTemplateId)}`;
  const verificationLabel = model.lifecycle.state === "active" ? "verified" : model.lifecycle.state;

  return {
    badge: {
      assertionId: assertion.id,
      publicBadgeId: assertion.publicId ?? assertion.id,
      tenantId: assertion.tenantId,
      badgeTemplateId: assertion.badgeTemplateId,
      name: badgeName,
      description: achievementDetails.description,
      badgeClassId: achievementDetails.badgeClassUri,
      criteriaUri: achievementDetails.criteriaUri,
      imageUri: achievementDetails.imageUri,
      issuedAt: assertion.issuedAt,
      issuedAtLabel: `${formatIsoTimestamp(assertion.issuedAt)} UTC`,
    },
    recipient: {
      identity: assertion.recipientIdentity,
      identityType: assertion.recipientIdentityType,
      id: recipientId,
      displayName: recipientDisplayName,
      avatarUrl: recipientAvatarUrl,
    },
    issuer: {
      name: issuerName,
      id: issuerId,
      url: issuerUrl,
    },
    lifecycle: {
      state: model.lifecycle.state,
      source: model.lifecycle.source,
      reasonCode: model.lifecycle.reasonCode,
      reason: model.lifecycle.reason,
      transitionedAt: model.lifecycle.transitionedAt,
      revokedAt: model.lifecycle.revokedAt,
    },
    verification: {
      label: verificationLabel,
      isValid: model.lifecycle.state === "active",
    },
    links: {
      badgePagePath: publicBadgePath,
      badgePageUrl: new URL(publicBadgePath, requestBaseUrl).toString(),
      summaryPath,
      summaryUrl: new URL(summaryPath, requestBaseUrl).toString(),
      verificationPath,
      verificationUrl: new URL(verificationPath, requestBaseUrl).toString(),
      ob3JsonPath,
      ob3JsonUrl: new URL(ob3JsonPath, requestBaseUrl).toString(),
      credentialDownloadPath,
      credentialDownloadUrl: new URL(credentialDownloadPath, requestBaseUrl).toString(),
      credentialPdfDownloadPath,
      credentialPdfDownloadUrl: new URL(credentialPdfDownloadPath, requestBaseUrl).toString(),
      walletOfferPath,
      walletOfferUrl: new URL(walletOfferPath, requestBaseUrl).toString(),
      showcasePath,
      showcaseUrl: new URL(showcasePath, requestBaseUrl).toString(),
      criteriaRegistryPath,
      criteriaRegistryUrl: new URL(criteriaRegistryPath, requestBaseUrl).toString(),
    },
  };
};

registerCommonMiddleware({
  app,
  observabilityContext,
});

registerPageAssetRoutes({
  app,
});

app.get("/healthz/dependencies", async (c) => {
  try {
    await resolveDatabase(c.env).prepare("SELECT 1 AS ready").first<{ ready: number }>();
    await c.env.BADGE_OBJECTS.head(STORAGE_READINESS_PROBE_KEY);
  } catch (error: unknown) {
    const detail = error instanceof Error ? error.message : "Unknown dependency check failure";

    logWarn(observabilityContext(c.env), "dependency_healthcheck_failed", {
      detail,
    });

    return c.json(
      {
        service: API_SERVICE_NAME,
        status: "degraded",
        detail,
      },
      503,
    );
  }

  return c.json({
    service: API_SERVICE_NAME,
    status: "ok",
  });
});

registerAdminRoutes({
  app,
  requireBootstrapAdmin,
  requireBootstrapAdminUiToken,
  resolveDatabase,
  isUniqueConstraintError,
});

registerOb3Routes({
  app,
  resolveDatabase,
  resolveAuthenticatedPrincipal,
  resolveRequestedTenantContext,
  observabilityContext,
  ob3ServiceDescriptionDocument,
  oauthErrorJson,
  oauthTokenErrorJson,
  oauthTokenSuccessJson,
  ob3ErrorJson,
  generateOpaqueToken,
  sha256Hex,
  sha256Base64Url,
  addSecondsToIso,
  issueOAuthAccessAndRefreshTokens,
  authenticateOAuthClient,
  authenticateOb3AccessToken,
});

registerDidRoutes({
  app,
  didForWellKnownRequest,
  didForTenantPathRequest,
  resolveSigningEntryForDid,
  didDocumentForSigningEntry,
  jwksDocumentForSigningEntry,
  resolveHistoricalSigningKeysForDid,
});

registerCredentialRoutes({
  app,
  resolveDatabase,
  loadVerificationViewModel,
  loadPublicBadgeViewModel,
  credentialStatusForAssertion,
  revocationStatusListUrlForTenant,
  summarizeCredentialVerificationChecks,
  summarizeCredentialLifecycleVerification,
  verifyCredentialProofSummary,
  credentialDownloadFilename,
  publicBadgePathForAssertion,
  asString,
  achievementDetailsFromCredential,
  recipientDisplayNameFromAssertion,
  recipientFromCredential,
  badgeNameFromCredential,
  issuerNameFromCredential,
  formatIsoTimestamp,
  renderBadgePdfDocument,
  credentialPdfDownloadFilename,
  resolveSigningEntryForDid,
  resolveRemoteSignerRegistryEntryForDid,
  buildRevocationStatusListCredential,
  signCredentialForDid,
});

registerOid4vciRoutes({
  app,
  resolveDatabase,
  loadPublicBadgeViewModel,
  loadVerificationViewModel,
  walletCredentialOfferPayload,
  asNonEmptyString,
  generateOpaqueToken,
  sha256Hex,
  addSecondsToIso,
  preAuthorizedCodeTtlSeconds: OID4VCI_PRE_AUTH_CODE_TTL_SECONDS,
  accessTokenTtlSeconds: OID4VCI_ACCESS_TOKEN_TTL_SECONDS,
});

registerPresentationRoutes({
  app,
  resolveDatabase,
  resolveAuthenticatedPrincipal,
  resolveRequestedTenantContext,
  parseTenantScopedCredentialId,
  loadCredentialForAssertion,
  ed25519PublicJwkFromDidKey,
  didKeyVerificationMethod,
  asJsonObject,
  asNonEmptyString,
  normalizedStringValues,
  collectContextUrls,
  verifiableCredentialObjectsFromPresentation,
  verifyPresentationHolderProofSummary,
  verifyCredentialInPresentation,
  VC_DATA_MODEL_CONTEXT_URL,
});

registerPublicBadgeRoutes({
  app,
  resolveDatabase,
  loadPublicBadgeViewModel,
  publicBadgeNotFoundPage,
  publicBadgePage,
  publicBadgeSummaryPayload,
  tenantBadgeWallPage,
  tenantBadgeCriteriaRegistryPage,
  asNonEmptyString,
  SAKAI_SHOWCASE_TENANT_ID,
  SAKAI_SHOWCASE_TEMPLATE_ID,
});

registerLearnerRoutes({
  app,
  resolveDatabase,
  requireTenantRole,
  TENANT_MEMBER_ROLES,
  addSecondsToIso,
  generateOpaqueToken,
  sha256Hex,
  LEARNER_IDENTITY_LINK_TTL_SECONDS,
  learnerDidSettingsNoticeFromQuery,
  learnerDashboardPage,
  learnerRecordPage,
});

registerLearnerRecordRoutes({
  app,
  resolveDatabase,
  requireTenantRole,
  ADMIN_ROLES,
  ISSUER_ROLES,
});

registerLearnerRecordExportRoutes({
  app,
  resolveDatabase,
  requireTenantRole,
  ADMIN_ROLES,
});

registerLtiRoutes({
  app,
  resolveLtiIssuerRegistry,
  observabilityContext,
  resolveDatabase,
  upsertTenantMembershipRole,
  sha256Hex,
  createLtiSession: (context, input) => {
    return betterAuthProvider.createLtiSession(context, input);
  },
});

registerMigrationRoutes({
  app,
  resolveDatabase,
  requireTenantRole,
  ISSUER_ROLES,
});

registerAuthRoutes({
  app,
  resolveDatabase,
  requestMagicLink: (context, input) => {
    return betterAuthProvider.requestMagicLink(context, input);
  },
  createMagicLinkSession: (context, token) => {
    return betterAuthProvider.createMagicLinkSession(context, token);
  },
  resolveAuthenticatedPrincipal: (context) => {
    return betterAuthProvider.resolveAuthenticatedPrincipal(context);
  },
  resolveRequestedTenantContext: (context) => {
    return betterAuthProvider.resolveRequestedTenantContext(context);
  },
  rememberRequestedTenant,
  revokeCurrentSession: (context) => {
    return betterAuthProvider.revokeCurrentSession(context);
  },
  enterpriseSso: enterpriseSsoAdapter,
  breakGlassPolicy: breakGlassPolicyAdapter,
});

registerReportingRoutes({
  app,
  resolveDatabase,
  requireTenantRole,
  ADMIN_ROLES,
});

registerExecutiveRoutes({
  app,
  resolveDatabase,
  requireTenantRole,
  TENANT_MEMBER_ROLES,
});

registerTenantGovernanceRoutes({
  app,
  resolveDatabase,
  requestBreakGlassPasswordReset: (context, request) => {
    return breakGlassPolicyAdapter.requestPasswordReset(context, {
      tenantId: request.tenantId,
      email: request.email,
      nextPath: `/tenants/${encodeURIComponent(request.tenantId)}/admin`,
    });
  },
  generateOpaqueToken,
  sha256Hex,
  requireTenantRole,
  ADMIN_ROLES,
  ISSUER_ROLES,
});

registerBadgeTemplateRoutes({
  app,
  resolveDatabase,
  requireTenantRole,
  requireScopedOrgUnitPermission,
  defaultInstitutionOrgUnitId,
  ADMIN_ROLES,
  ISSUER_ROLES,
  TENANT_MEMBER_ROLES,
});

const issueBadgeForTenant = createIssueBadgeForTenant<AppContext, AppBindings>({
  resolveDatabase,
  signCredentialForDid,
  sendIssuanceEmailNotification,
  observabilityContext,
  publicBadgePathForAssertion,
  HttpErrorResponseClass: HttpErrorResponse,
});

registerBadgeRuleRoutes({
  app,
  resolveDatabase,
  requireTenantRole,
  issueBadgeForTenant: (c, tenantId, request, issuedByUserId) => {
    return issueBadgeForTenant(c, tenantId, request, issuedByUserId);
  },
  ISSUER_ROLES,
  ADMIN_ROLES,
  TENANT_MEMBER_ROLES,
});

registerAssertionRoutes({
  app,
  resolveDatabase,
  requireTenantRole,
  requireDelegatedIssuingAuthorityPermission,
  assertionBelongsToTenant,
  issueBadgeForTenant,
  ADMIN_ROLES,
  ISSUER_ROLES,
  TENANT_MEMBER_ROLES,
  HttpErrorResponseClass: HttpErrorResponse,
});

registerSigningRoutes({
  app,
  signCredentialForDid,
});

const processQueuedJobs = createProcessQueuedJobs({
  resolveDatabase,
  observabilityContext,
  issueBadgeForTenant,
});

registerQueueRoutes({
  app,
  resolveDatabase,
  sha256Hex,
  readJsonBodyOrEmptyObject,
  processQueuedJobs,
  processQueueInputWithDefaults,
  issueBadgeQueueJobFromRequest,
  revokeBadgeQueueJobFromRequest,
});

const worker = createApiWorker({
  app,
  queueProcessorRequestFromSchedule,
  observabilityContext,
});

export default worker;

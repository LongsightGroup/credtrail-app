import {
  type JsonObject,
  type ObservabilityContext,
} from '@credtrail/core-domain';
import {
  createSession,
  findTenantSigningRegistrationByDid,
  findActiveSessionByHash,
  listLtiIssuerRegistrations,
  touchSession,
  upsertTenantMembershipRole,
  type SessionRecord,
  type SqlDatabase,
} from '@credtrail/db';
import { createPostgresDatabase } from '@credtrail/db/postgres';
import { Hono, type Context } from 'hono';
import { deleteCookie, getCookie } from 'hono/cookie';
import {
  credentialDownloadFilename,
  credentialPdfDownloadFilename,
  renderBadgePdfDocument,
} from './badges/pdf';
import {
  achievementDetailsFromCredential,
  badgeHeroImageMarkup,
  githubAvatarUrlForUsername,
  githubUsernameFromUrl,
  imsOb2ValidatorUrl,
  evidenceDetailsFromCredential,
  recipientAvatarUrlFromAssertion,
  recipientDisplayNameFromAssertion,
} from './badges/public-badge-helpers';
import {
  badgeNameFromCredential,
  isWebUrl,
  issuerIdentifierFromCredential,
  issuerNameFromCredential,
  issuerUrlFromCredential,
  recipientFromCredential,
} from './badges/credential-display';
import {
  buildRevocationStatusListCredential,
  credentialStatusForAssertion,
  decodedRevocationStatusBit,
  parseStatusListIndex,
  revocationStatusListUrlForTenant,
} from './badges/revocation-status';
import { createPublicBadgePageRenderers } from './badges/public-badge-pages';
import { createIssueBadgeForTenant } from './badges/direct-issue';
import {
  assertionBelongsToTenant,
  loadCredentialForAssertion,
  loadPublicBadgeViewModel,
  loadVerificationViewModel,
  parseTenantScopedCredentialId,
  publicBadgePathForAssertion,
} from './badges/public-badge-model';
import {
  VC_DATA_MODEL_CONTEXT_URL,
  createCredentialVerificationChecks,
} from './credentials/verification-checks';
import { createCredentialProofVerificationHelpers } from './credentials/proof-verification';
import { registerCommonMiddleware } from './http/common-middleware';
import { createLoadJsonObjectFromUrl } from './http/json-object-loader';
import {
  createSignCredentialForDid,
} from './signing/credential-signer';
import {
  didDocumentForSigningEntry,
  didForTenantPathRequest,
  didForWellKnownRequest,
  jwksDocumentForSigningEntry,
} from './signing/did-documents';
import {
  createSigningRegistryResolvers,
} from './signing/registry';
import {
  ADMIN_ROLES,
  ISSUER_ROLES,
  TENANT_MEMBER_ROLES,
  createTenantAccessHelpers,
  defaultInstitutionOrgUnitId,
  isUniqueConstraintError,
} from './auth/tenant-access';
import { createOAuthTokenHelpers } from './ob3/oauth-token-helpers';
import { createOb3ErrorResponses } from './ob3/error-responses';
import { createOb3AccessTokenAuthenticator } from './ob3/access-token-auth';
import { ob3ServiceDescriptionDocument as ob3ServiceDescriptionDocumentFromRequest } from './ob3/service-description';
import {
  ltiIssuerRegistryFromStoredRows,
  parseLtiIssuerRegistryFromEnv,
  signLtiStatePayload as signLtiStatePayloadHelper,
  validateLtiStateToken as validateLtiStateTokenHelper,
  type LtiIssuerRegistry,
} from './lti/lti-helpers';
import {
  createLearnerDashboardPage,
  learnerDidSettingsNoticeFromQuery,
} from './learner/pages';
import {
  sendIssuanceEmailNotification,
  type SendIssuanceEmailNotificationInput,
} from './notifications/send-issuance-email';
import { registerAdminRoutes } from './routes/admin-routes';
import { registerAssertionRoutes } from './routes/assertion-routes';
import { registerAuthRoutes } from './routes/auth-routes';
import { registerBadgeTemplateRoutes } from './routes/badge-template-routes';
import { registerCredentialRoutes } from './routes/credential-routes';
import { registerDidRoutes } from './routes/did-routes';
import { registerLearnerRoutes } from './routes/learner-routes';
import { registerLtiRoutes } from './routes/lti-routes';
import { registerOb3Routes } from './routes/ob3-routes';
import { registerPresentationRoutes } from './routes/presentation-routes';
import { registerPublicBadgeRoutes } from './routes/public-badge-routes';
import { registerQueueRoutes } from './routes/queue-routes';
import { registerSigningRoutes } from './routes/signing-routes';
import { registerTenantGovernanceRoutes } from './routes/tenant-governance-routes';
import {
  addSecondsToIso,
  generateOpaqueToken,
  sessionCookieSecure,
  sha256Base64Url,
  sha256Hex,
} from './utils/crypto';
import { escapeHtml, formatIsoTimestamp, linkedInAddToProfileUrl } from './utils/display-format';
import { asJsonObject, asNonEmptyString, asString } from './utils/value-parsers';
import { createApiWorker } from './worker/create-worker';
import {
  issueBadgeQueueJobFromRequest,
  revokeBadgeQueueJobFromRequest,
} from './queue/job-builders';
import {
  createProcessQueuedJobs,
  processQueueInputWithDefaults,
  readJsonBodyOrEmptyObject,
} from './queue/processing';
import { queueProcessorRequestFromSchedule } from './queue/scheduled-trigger';
import {
  createPresentationVerificationHelpers,
  didKeyVerificationMethod,
  ed25519PublicJwkFromDidKey,
  verifiableCredentialObjectsFromPresentation as verifiableCredentialObjectsFromPresentationHelper,
} from './presentation/verification-helpers';

export interface AppBindings {
  APP_ENV: string;
  DATABASE_URL?: string;
  BADGE_OBJECTS: R2Bucket;
  PLATFORM_DOMAIN: string;
  MARKETING_SITE_ORIGIN?: string;
  SENTRY_DSN?: string;
  TENANT_SIGNING_REGISTRY_JSON?: string;
  TENANT_SIGNING_KEY_HISTORY_JSON?: string;
  TENANT_REMOTE_SIGNER_REGISTRY_JSON?: string;
  MAILTRAP_API_TOKEN?: string;
  MAILTRAP_INBOX_ID?: string;
  MAILTRAP_API_BASE_URL?: string;
  MAILTRAP_FROM_EMAIL?: string;
  MAILTRAP_FROM_NAME?: string;
  GITHUB_TOKEN?: string;
  JOB_PROCESSOR_TOKEN?: string;
  BOOTSTRAP_ADMIN_TOKEN?: string;
  LTI_ISSUER_REGISTRY_JSON?: string;
  LTI_STATE_SIGNING_SECRET?: string;
  OB3_DISCOVERY_TITLE?: string;
  OB3_TERMS_OF_SERVICE_URL?: string;
  OB3_PRIVACY_POLICY_URL?: string;
  OB3_IMAGE_URL?: string;
  OB3_OAUTH_REGISTRATION_URL?: string;
  OB3_OAUTH_AUTHORIZATION_URL?: string;
  OB3_OAUTH_TOKEN_URL?: string;
  OB3_OAUTH_REFRESH_URL?: string;
}

export interface AppEnv {
  Bindings: AppBindings;
}

export type AppContext = Context<AppEnv>;

export const app = new Hono<AppEnv>();
export { sendIssuanceEmailNotification };
export type { SendIssuanceEmailNotificationInput };
const API_SERVICE_NAME = 'api-worker';
const MAGIC_LINK_TTL_SECONDS = 10 * 60;
const SESSION_TTL_SECONDS = 7 * 24 * 60 * 60;
const LEARNER_IDENTITY_LINK_TTL_SECONDS = 10 * 60;
const SESSION_COOKIE_NAME = 'credtrail_session';
const LANDING_ASSET_PATH_PREFIX = '/_astro/';
const LANDING_STATIC_PATHS = new Set(['/credtrail-logo.png', '/favicon.svg']);
const SAKAI_SHOWCASE_TENANT_ID = 'sakai';
const SAKAI_SHOWCASE_TEMPLATE_ID = 'badge_template_sakai_1000';
const databasesByUrl = new Map<string, SqlDatabase>();

const resolveDatabase = (bindings: AppBindings): SqlDatabase => {
  if (bindings.DATABASE_URL === undefined) {
    throw new Error('DATABASE_URL is required');
  }
  const databaseUrl = bindings.DATABASE_URL.trim();

  if (databaseUrl.length === 0) {
    throw new Error('DATABASE_URL is required');
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

const resolveSessionFromCookie = async (c: AppContext): Promise<SessionRecord | null> => {
  const db = resolveDatabase(c.env);
  const sessionToken = getCookie(c, SESSION_COOKIE_NAME);

  if (sessionToken === undefined) {
    return null;
  }

  const sessionTokenHash = await sha256Hex(sessionToken);
  const nowIso = new Date().toISOString();
  const session = await findActiveSessionByHash(db, sessionTokenHash, nowIso);

  if (session === null) {
    deleteCookie(c, SESSION_COOKIE_NAME, {
      path: '/',
    });
    return null;
  }

  await touchSession(db, session.id, nowIso);
  return session;
};

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
  resolveSessionFromCookie,
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

const { publicBadgeNotFoundPage, publicBadgePage, tenantBadgeWallPage } =
  createPublicBadgePageRenderers({
    asString,
    achievementDetailsFromCredential,
    badgeHeroImageMarkup,
    badgeNameFromCredential,
    evidenceDetailsFromCredential,
    escapeHtml,
    formatIsoTimestamp,
    githubAvatarUrlForUsername,
    githubUsernameFromUrl,
    imsOb2ValidatorUrl,
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


registerCommonMiddleware({
  app,
  landingAssetPathPrefix: LANDING_ASSET_PATH_PREFIX,
  landingStaticPaths: LANDING_STATIC_PATHS,
  observabilityContext,
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
  resolveSessionFromCookie,
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

registerPresentationRoutes({
  app,
  resolveDatabase,
  resolveSessionFromCookie,
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
  tenantBadgeWallPage,
  asNonEmptyString,
  SAKAI_SHOWCASE_TENANT_ID,
  SAKAI_SHOWCASE_TEMPLATE_ID,
});

registerLearnerRoutes({
  app,
  resolveDatabase,
  resolveSessionFromCookie,
  addSecondsToIso,
  generateOpaqueToken,
  sha256Hex,
  LEARNER_IDENTITY_LINK_TTL_SECONDS,
  learnerDidSettingsNoticeFromQuery,
  learnerDashboardPage,
});

registerLtiRoutes({
  app,
  resolveLtiIssuerRegistry,
  observabilityContext,
  generateOpaqueToken,
  signLtiStatePayload: (payload, secret) => {
    return signLtiStatePayloadHelper(payload, secret, sha256Base64Url);
  },
  addSecondsToIso,
  validateLtiStateToken: (stateToken, secret, nowIso) => {
    return validateLtiStateTokenHelper(stateToken, secret, nowIso, sha256Base64Url);
  },
  resolveDatabase,
  upsertTenantMembershipRole,
  sha256Hex,
  createSession,
  sessionCookieSecure,
  SESSION_TTL_SECONDS,
  SESSION_COOKIE_NAME,
});

registerAuthRoutes({
  app,
  resolveDatabase,
  resolveSessionFromCookie,
  addSecondsToIso,
  generateOpaqueToken,
  sha256Hex,
  sessionCookieSecure,
  MAGIC_LINK_TTL_SECONDS,
  SESSION_TTL_SECONDS,
  SESSION_COOKIE_NAME,
});

registerTenantGovernanceRoutes({
  app,
  resolveDatabase,
  requireTenantRole,
  ADMIN_ROLES,
  ISSUER_ROLES,
});

registerBadgeTemplateRoutes({
  app,
  resolveDatabase,
  resolveSessionFromCookie,
  requireTenantRole,
  requireScopedOrgUnitPermission,
  defaultInstitutionOrgUnitId,
  ADMIN_ROLES,
  ISSUER_ROLES,
});

const issueBadgeForTenant = createIssueBadgeForTenant<AppContext, AppBindings>({
  resolveDatabase,
  signCredentialForDid,
  sendIssuanceEmailNotification,
  observabilityContext,
  publicBadgePathForAssertion,
  HttpErrorResponseClass: HttpErrorResponse,
});

registerAssertionRoutes({
  app,
  resolveDatabase,
  requireTenantRole,
  requireDelegatedIssuingAuthorityPermission,
  assertionBelongsToTenant,
  issueBadgeForTenant,
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

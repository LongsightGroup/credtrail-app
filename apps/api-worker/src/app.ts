import type { JsonObject } from "@credtrail/core-domain";
import {
  findTenantSigningRegistrationByDid,
  listLtiIssuerRegistrations,
  upsertTenantMembershipRole,
} from "@credtrail/db";
import { Hono } from "hono";
import {
  credentialDownloadFilename,
  credentialPdfDownloadFilename,
  renderBadgePdfDocument,
} from "./badges/pdf";
import {
  achievementDetailsFromCredential,
  githubAvatarUrlForUsername,
  githubUsernameFromUrl,
  imsOb3ValidatorUrl,
  evidenceDetailsFromCredential,
  recipientAvatarUrlFromAssertion,
  recipientDisplayNameFromAssertion,
  trustEdCredentialDetailsFromCredential,
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
import { publicBadgeSummaryPayload as buildPublicBadgeSummaryPayload } from "./badges/public-badge-summary-payload";
import { createIssueBadgeForTenant } from "./badges/direct-issue";
import { processBadgeTemplateImageGenerationJob } from "./badges/badge-template-image-generation";
import {
  assertionBelongsToTenant,
  loadCredentialForAssertion,
  loadPublicBadgeViewModel,
  loadVerificationViewModel,
  parseTenantScopedCredentialId,
  publicBadgePathForAssertion,
} from "./badges/public-badge-model";
import {
  VC_DATA_MODEL_CONTEXT_URL,
  createCredentialVerificationChecks,
} from "./credentials/verification-checks";
import { createCredentialProofVerificationHelpers } from "./credentials/proof-verification";
import { registerCommonMiddleware } from "./http/common-middleware";
import { createLoadJsonObjectFromUrl } from "./http/json-object-loader";
import { registerAppPageRenderer } from "./ui/render-page";
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
} from "./auth/tenant-access";
import { createOAuthTokenHelpers } from "./ob3/oauth-token-helpers";
import { createOb3ErrorResponses } from "./ob3/error-responses";
import { createOb3AccessTokenAuthenticator } from "./ob3/access-token-auth";
import { ob3ServiceDescriptionDocument } from "./ob3/service-description-runtime";
import { createResolveLtiIssuerRegistry } from "./lti/lti-issuer-registry";
import { createLearnerDashboardPage, learnerDidSettingsNoticeFromQuery } from "./learner/pages";
import { createLearnerRecordPage } from "./learner/learner-record-page";
import {
  sendIssuanceEmailNotification,
  type SendIssuanceEmailNotificationInput,
} from "./notifications/send-issuance-email";
import { registerAssertionRoutes } from "./routes/assertion-routes";
import { registerAuthRoutes } from "./routes/auth-routes";
import { registerBootstrapAdminRoutes } from "./routes/bootstrap-admin-routes";
import { registerBadgeTemplateImageRoutes } from "./routes/badge-template-image-routes";
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
import { registerGoogleAuthRoutes } from "./routes/google-auth-routes";
import { registerHealthRoutes } from "./routes/health-routes";
import { registerExecutiveRoutes } from "./routes/executive-routes";
import { registerReportingRoutes } from "./routes/reporting-routes";
import { registerSigningRoutes } from "./routes/signing-routes";
import { registerTenantGovernanceRoutes } from "./routes/tenant-governance-routes";
import { registerTenantLmsConnectionRoutes } from "./routes/tenant-lms-connection-routes";
import { registerOid4vciRoutes } from "./routes/oid4vci-routes";
import { addSecondsToIso, generateOpaqueToken, sha256Base64Url, sha256Hex } from "./utils/crypto";
import { formatIsoTimestamp, linkedInAddToProfileUrl } from "./utils/display-format";
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
  type ProcessQueueRunResult,
} from "./queue/processing";
import {
  createPresentationVerificationHelpers,
  didKeyVerificationMethod,
  ed25519PublicJwkFromDidKey,
  verifiableCredentialObjectsFromPresentation as verifiableCredentialObjectsFromPresentationHelper,
} from "./presentation/verification-helpers";
import { resolveDatabase } from "./app/database";
import { API_SERVICE_NAME, observabilityContext } from "./app/observability";
import {
  betterAuthProvider,
  breakGlassPolicyAdapter,
  createLocalDevelopmentSessionForCredtrailUser,
  createBetterAuthRequest,
  createBetterAuthRuntime,
  createConfiguredSocialProviders,
  enterpriseSsoAdapter,
  pendingBreakGlassTenantFromCookie,
  rememberRequestedTenant,
  requestTenantMemberInvite,
  resolveAuthenticatedPrincipal,
  resolveRequestedTenantContext,
} from "./app/auth-runtime";
import type { AppBindings, AppContext, AppEnv } from "./app/types";
import { HttpErrorResponse } from "./http/http-error-response";
import { walletCredentialOfferPayload } from "./oid4vci/wallet-credential-offer-payload";

export type { AppBindings, AppContext, AppEnv } from "./app/types";

export const app = new Hono<AppEnv>();
export { sendIssuanceEmailNotification };
export type { SendIssuanceEmailNotificationInput };
const LEARNER_IDENTITY_LINK_TTL_SECONDS = 10 * 60;
const OID4VCI_PRE_AUTH_CODE_TTL_SECONDS = 10 * 60;
const OID4VCI_ACCESS_TOKEN_TTL_SECONDS = 10 * 60;
const SAKAI_SHOWCASE_TENANT_ID = "sakai";
const SAKAI_SHOWCASE_TEMPLATE_ID = "badge_template_sakai_1000";
const STORAGE_READINESS_PROBE_KEY = "__credtrail__/healthz/dependency-probe.jsonld";

const resolveLtiIssuerRegistry = createResolveLtiIssuerRegistry({
  resolveDatabase,
  listLtiIssuerRegistrations,
});

const {
  resolveSigningEntryForDid,
  resolveHistoricalSigningKeysForDid,
  resolveRemoteSignerRegistryEntryForDid,
} = createSigningRegistryResolvers<AppContext, AppBindings>({
  resolveDatabase,
  findTenantSigningRegistrationByDid,
});

const {
  requireTenantRole,
  requireScopedOrgUnitPermission,
  requireDelegatedIssuingAuthorityPermission,
} = createTenantAccessHelpers<AppContext, AppBindings>({
  resolveAuthenticatedPrincipal,
  resolvePendingBreakGlassTenantId: pendingBreakGlassTenantFromCookie,
  resolveDatabase,
});

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

const {
  publicBadgeNotFoundPage,
  publicBadgePage,
  tenantBadgeWallPage,
  tenantBadgeCriteriaRegistryPage,
} = createPublicBadgePageRenderers({
  asString,
  achievementDetailsFromCredential,
  badgeNameFromCredential,
  evidenceDetailsFromCredential,
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
  trustEdCredentialDetailsFromCredential,
});

const learnerDashboardPage = createLearnerDashboardPage({
  formatIsoTimestamp,
});

const learnerRecordPage = createLearnerRecordPage({
  formatIsoTimestamp,
});

registerCommonMiddleware({
  app,
  observabilityContext,
});

registerAppPageRenderer(app);

registerGoogleAuthRoutes({
  app,
  createBetterAuthRequest,
  createBetterAuthRuntime,
  createConfiguredSocialProviders,
  enterpriseSso: enterpriseSsoAdapter,
  rememberRequestedTenant,
});

registerHealthRoutes({
  app,
  observabilityContext,
  resolveDatabase,
  serviceName: API_SERVICE_NAME,
  storageReadinessProbeKey: STORAGE_READINESS_PROBE_KEY,
});

registerBootstrapAdminRoutes({
  app,
  resolveDatabase,
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
  publicBadgeSummaryPayload: (requestUrl, model) => {
    return buildPublicBadgeSummaryPayload({
      requestUrl,
      model,
      formatIsoTimestamp,
    });
  },
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

const issueBadgeForTenant = createIssueBadgeForTenant<AppContext, AppBindings>({
  resolveDatabase,
  signCredentialForDid,
  sendIssuanceEmailNotification,
  observabilityContext,
  publicBadgePathForAssertion,
  HttpErrorResponseClass: HttpErrorResponse,
});

registerLtiRoutes({
  app,
  resolveLtiIssuerRegistry,
  resolveDatabase,
  upsertTenantMembershipRole,
  sha256Hex,
  createLtiSession: (context, input) => {
    return betterAuthProvider.createLtiSession(context, input);
  },
  issueBadgeForTenant,
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
  createLocalDevelopmentSession: createLocalDevelopmentSessionForCredtrailUser,
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
  defaultInstitutionOrgUnitId,
  requestTenantMemberInvite,
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
  requireScopedOrgUnitPermission,
  requireDelegatedIssuingAuthorityPermission,
  assertionBelongsToTenant,
  issueBadgeForTenant,
  ADMIN_ROLES,
  ISSUER_ROLES,
});

registerBadgeTemplateImageRoutes({
  app,
  resolveDatabase,
  requireTenantRole,
  requireScopedOrgUnitPermission,
  ADMIN_ROLES,
});

registerTenantLmsConnectionRoutes({
  app,
  resolveDatabase,
  requireTenantRole,
  ISSUER_ROLES,
  ADMIN_ROLES,
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
  processBadgeTemplateImageGenerationJob: (c, tenantId, payload) => {
    return processBadgeTemplateImageGenerationJob({
      db: resolveDatabase(c.env),
      store: c.env.BADGE_OBJECTS,
      env: c.env,
      tenantId,
      payload,
    });
  },
});

export const processScheduledQueue = (env: AppBindings): Promise<ProcessQueueRunResult> => {
  return processQueuedJobs({ env } as AppContext, processQueueInputWithDefaults({}));
};

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
  processScheduledQueue,
  observabilityContext,
});

export default worker;

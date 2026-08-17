import type { JsonObject } from "@credtrail/core-domain";
import { findTenantSigningRegistrationByDid, listAllLtiIssuerRegistrations } from "@credtrail/db";
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
import { processBadgeRuleLifecycleForTenant } from "./badges/badge-rule-lifecycle-processor";
import { processBadgeRuleApprovalNotificationJob } from "./badges/badge-rule-approval-notification-queue";
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
import { createLoadJsonObjectFromUrl } from "./http/json-object-loader";
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
  APPROVAL_WORKSPACE_ROLES,
  ISSUER_ROLES,
  TENANT_MEMBER_ROLES,
  createTenantAccessHelpers,
  defaultInstitutionOrgUnitId,
} from "./auth/tenant-access";
import { createOAuthTokenHelpers } from "./ob3/oauth-token-helpers";
import { createOb3ErrorResponses } from "./ob3/error-responses";
import { createOb3AccessTokenAuthenticator } from "./ob3/access-token-auth";
import { ob3ServiceDescriptionDocument } from "./ob3/service-description-runtime";
import { runScheduledBadgeRuleLifecycleEnqueue } from "./queue/badge-rule-lifecycle-schedule";
import { createResolveLtiIssuerRegistry } from "./lti/lti-issuer-registry-resolver";
import { processAutomatedBadgeRuleQueueJob } from "./badges/automated-badge-rule-job";
import { createLearnerDashboardPage, learnerDidSettingsNoticeFromQuery } from "./learner/pages";
import { createLearnerRecordPage } from "./learner/learner-record-page";
import { sendIssuanceEmailNotification } from "./notifications/send-issuance-email";
import { addSecondsToIso, generateOpaqueToken, sha256Base64Url, sha256Hex } from "./utils/crypto";
import { formatIsoTimestamp, linkedInAddToProfileUrl } from "./utils/display-format";
import { asJsonObject, asNonEmptyString, asString } from "./utils/value-parsers";
import { createApiWorker } from "./worker/create-worker";
import { createPostgresQueueIngressStore } from "./queue/ingress-store";
import { createLmsCourseAuthoringService } from "./lms/lms-course-authoring-service";
import { DEFAULT_GRADEBOOK_REQUEST_TIMEOUT_MS } from "./lms/gradebook-request-options";
import { createProductionBadgeRuleVersionReferenceLabelService } from "./lms/badge-rule-version-reference-label-service";
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
import { registerRoutes } from "./app/register-routes";
import type { AppDeps } from "./app/app-deps";
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
import { canonicalAppUrl } from "./http/canonical-app-url";
import { walletCredentialOfferPayload } from "./oid4vci/wallet-credential-offer-payload";

export const app = new Hono<AppEnv>();
const LEARNER_IDENTITY_LINK_TTL_SECONDS = 10 * 60;
const OID4VCI_PRE_AUTH_CODE_TTL_SECONDS = 10 * 60;
const OID4VCI_ACCESS_TOKEN_TTL_SECONDS = 10 * 60;
const SAKAI_SHOWCASE_TENANT_ID = "sakai";
const SAKAI_SHOWCASE_TEMPLATE_ID = "badge_template_sakai_1000";
const STORAGE_READINESS_PROBE_KEY = "__credtrail__/healthz/dependency-probe.jsonld";

const resolveLtiIssuerRegistry = createResolveLtiIssuerRegistry({
  resolveDatabase,
  listAllLtiIssuerRegistrations,
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
  publicAppOrigin: (bindings) => bindings.PUBLIC_APP_ORIGIN,
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

const issueBadgeForTenant = createIssueBadgeForTenant<AppContext, AppBindings>({
  resolveDatabase,
  signCredentialForDid,
  sendIssuanceEmailNotification,
  observabilityContext,
  publicBadgePathForAssertion,
  HttpErrorResponseClass: HttpErrorResponse,
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
  processBadgeRuleLifecycleJob: (c, tenantId, payload) => {
    return processBadgeRuleLifecycleForTenant({
      db: resolveDatabase(c.env),
      tenantId,
      nowIso: payload.scheduledFor,
      observability: observabilityContext(c.env),
      env: c.env,
      adminUrlForTenant: (adminTenantId) =>
        canonicalAppUrl(
          c.env.PUBLIC_APP_ORIGIN,
          `/tenants/${encodeURIComponent(adminTenantId)}/admin/rules`,
        ),
    }).then(() => undefined);
  },
  processAutomatedBadgeRuleJob: (c, tenantId, payload) => {
    return processAutomatedBadgeRuleQueueJob({
      db: resolveDatabase(c.env),
      tenantId,
      payload,
      sha256Hex,
      observability: observabilityContext(c.env),
    });
  },
  processBadgeRuleApprovalNotificationJob: (c, tenantId, payload) => {
    return processBadgeRuleApprovalNotificationJob({
      db: resolveDatabase(c.env),
      env: c.env,
      tenantId,
      payload,
    });
  },
});

export const processScheduledQueue = async (env: AppBindings): Promise<ProcessQueueRunResult> => {
  await runScheduledBadgeRuleLifecycleEnqueue(env);

  return processQueuedJobs({ env } as AppContext, processQueueInputWithDefaults({}));
};

const lmsCourseAuthoring = createLmsCourseAuthoringService({
  currentTimestamp: () => new Date().toISOString(),
  requestTimeoutMs: DEFAULT_GRADEBOOK_REQUEST_TIMEOUT_MS,
});
const loadBadgeRuleVersionReferenceLabels =
  createProductionBadgeRuleVersionReferenceLabelService(lmsCourseAuthoring);

const appDeps: AppDeps = {
  observabilityContext,
  resolveDatabase,
  lmsCourseAuthoring,
  loadBadgeRuleVersionReferenceLabels,
  serviceName: API_SERVICE_NAME,
  storageReadinessProbeKey: STORAGE_READINESS_PROBE_KEY,
  createBetterAuthRequest,
  createBetterAuthRuntime,
  createConfiguredSocialProviders,
  enterpriseSso: enterpriseSsoAdapter,
  rememberRequestedTenant,
  resolveAuthenticatedPrincipal,
  resolveRequestedTenantContext,
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
  didForWellKnownRequest,
  didForTenantPathRequest,
  resolveSigningEntryForDid,
  didDocumentForSigningEntry,
  jwksDocumentForSigningEntry,
  resolveHistoricalSigningKeysForDid,
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
  resolveRemoteSignerRegistryEntryForDid,
  buildRevocationStatusListCredential,
  signCredentialForDid,
  walletCredentialOfferPayload,
  asNonEmptyString,
  preAuthorizedCodeTtlSeconds: OID4VCI_PRE_AUTH_CODE_TTL_SECONDS,
  accessTokenTtlSeconds: OID4VCI_ACCESS_TOKEN_TTL_SECONDS,
  parseTenantScopedCredentialId,
  loadCredentialForAssertion,
  ed25519PublicJwkFromDidKey,
  didKeyVerificationMethod,
  asJsonObject,
  normalizedStringValues,
  collectContextUrls,
  verifiableCredentialObjectsFromPresentation,
  verifyPresentationHolderProofSummary,
  verifyCredentialInPresentation,
  VC_DATA_MODEL_CONTEXT_URL,
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
  SAKAI_SHOWCASE_TENANT_ID,
  SAKAI_SHOWCASE_TEMPLATE_ID,
  requireTenantRole,
  TENANT_MEMBER_ROLES,
  LEARNER_IDENTITY_LINK_TTL_SECONDS,
  learnerDidSettingsNoticeFromQuery,
  learnerDashboardPage,
  learnerRecordPage,
  ADMIN_ROLES,
  APPROVAL_WORKSPACE_ROLES,
  ISSUER_ROLES,
  resolveLtiIssuerRegistry,
  createLtiSession: (context, input) => {
    return betterAuthProvider.createLtiSession(context, input);
  },
  issueBadgeForTenant,
  requestMagicLink: (context, input) => {
    return betterAuthProvider.requestMagicLink(context, input);
  },
  createLocalDevelopmentSession: createLocalDevelopmentSessionForCredtrailUser,
  createMagicLinkSession: (context, token) => {
    return betterAuthProvider.createMagicLinkSession(context, token);
  },
  revokeCurrentSession: (context) => {
    return betterAuthProvider.revokeCurrentSession(context);
  },
  breakGlassPolicy: breakGlassPolicyAdapter,
  defaultInstitutionOrgUnitId,
  requestTenantMemberInvite,
  requestBreakGlassPasswordReset: (context, request) => {
    return breakGlassPolicyAdapter.requestPasswordReset(context, {
      tenantId: request.tenantId,
      email: request.email,
      nextPath: `/tenants/${encodeURIComponent(request.tenantId)}/admin`,
    });
  },
  requireScopedOrgUnitPermission,
  requireDelegatedIssuingAuthorityPermission,
  assertionBelongsToTenant,
  HttpErrorResponseClass: HttpErrorResponse,
  readJsonBodyOrEmptyObject,
  processQueuedJobs,
  processQueueInputWithDefaults,
  resolveQueueIngressStore: (bindings) =>
    createPostgresQueueIngressStore(resolveDatabase(bindings)),
};

registerRoutes({
  app,
  deps: appDeps,
});

const worker = createApiWorker({
  app,
  processScheduledQueue,
  observabilityContext,
});

export default worker;

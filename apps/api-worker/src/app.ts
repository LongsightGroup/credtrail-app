import type { JsonObject, ObservabilityContext } from "@credtrail/core-domain";
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
import { processBadgeTemplateImageGenerationJob } from "./badges/badge-template-image-generation";
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
import { registerAssertionRoutes } from "./routes/assertion-routes";
import { registerAuthRoutes } from "./routes/auth-routes";
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
import {
  betterAuthProvider,
  breakGlassPolicyAdapter,
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

export type { AppBindings, AppContext, AppEnv } from "./app/types";

export const app = new Hono<AppEnv>();
export { sendIssuanceEmailNotification };
export type { SendIssuanceEmailNotificationInput };
const API_SERVICE_NAME = "api-worker";
const LEARNER_IDENTITY_LINK_TTL_SECONDS = 10 * 60;
const OID4VCI_PRE_AUTH_CODE_TTL_SECONDS = 10 * 60;
const OID4VCI_ACCESS_TOKEN_TTL_SECONDS = 10 * 60;
const SAKAI_SHOWCASE_TENANT_ID = "sakai";
const SAKAI_SHOWCASE_TEMPLATE_ID = "badge_template_sakai_1000";
const STORAGE_READINESS_PROBE_KEY = "__credtrail__/healthz/dependency-probe.jsonld";

const observabilityContext = (bindings: AppBindings): ObservabilityContext => {
  return {
    service: API_SERVICE_NAME,
    environment: bindings.APP_ENV,
  };
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
});

const learnerDashboardPage = createLearnerDashboardPage({
  formatIsoTimestamp,
});

const learnerRecordPage = createLearnerRecordPage({
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

registerAppPageRenderer(app);

registerPageAssetRoutes({
  app,
});

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

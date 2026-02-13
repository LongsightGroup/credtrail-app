import {
  captureSentryException,
  createDidDocument,
  createDidWeb,
  createTenantScopedId,
  splitTenantScopedId,
  decodeJwkPublicKeyMultibase,
  type DataIntegrityCryptosuite,
  type Ed25519PrivateJwk,
  type Ed25519PublicJwk,
  type P256PrivateJwk,
  type P256PublicJwk,
  type JsonObject,
  generateTenantDidSigningMaterial,
  getImmutableCredentialObject,
  logError,
  logInfo,
  logWarn,
  signCredentialWithDataIntegrityProof,
  signCredentialWithEd25519Signature2020,
  verifyCredentialProofWithDataIntegrity,
  verifyCredentialProofWithEd25519Signature2020,
  storeImmutableCredentialObject,
  type ObservabilityContext,
} from '@credtrail/core-domain';
import {
  addLearnerIdentityAlias,
  completeJobQueueMessage,
  createAuditLog,
  createDelegatedIssuingAuthorityGrant,
  createAssertion,
  createBadgeTemplate,
  createTenantOrgUnit,
  createLearnerIdentityLinkProof,
  createMagicLinkToken,
  createOAuthAccessToken,
  createOAuthAuthorizationCode,
  createOAuthClient,
  createOAuthRefreshToken,
  createSession,
  consumeOAuthRefreshToken,
  consumeOAuthAuthorizationCode,
  enqueueJobQueueMessage,
  ensureTenantMembership,
  failJobQueueMessage,
  findLearnerIdentityLinkProofByHash,
  findLearnerProfileById,
  findLearnerProfileByIdentity,
  deleteLtiIssuerRegistrationByIssuer,
  findTenantMembership,
  findUserById,
  findAssertionById,
  findAssertionByPublicId,
  findAssertionByIdempotencyKey,
  findBadgeTemplateById,
  findDelegatedIssuingAuthorityGrantById,
  findActiveDelegatedIssuingAuthorityGrantForAction,
  findTenantSigningRegistrationByDid,
  findActiveSessionByHash,
  isLearnerIdentityLinkProofValid,
  listAssertionStatusListEntries,
  listAssertionLifecycleEvents,
  resolveAssertionLifecycleState,
  recordAssertionLifecycleTransition,
  listLtiIssuerRegistrations,
  listDelegatedIssuingAuthorityGrantEvents,
  listDelegatedIssuingAuthorityGrants,
  listLearnerBadgeSummaries,
  listLearnerIdentitiesByProfile,
  removeLearnerIdentityAliasesByType,
  leaseJobQueueMessages,
  findMagicLinkTokenByHash,
  findOb3SubjectProfile,
  findActiveOAuthAccessTokenByHash,
  findOAuthClientById,
  hasTenantMembershipOrgUnitAccess,
  hasTenantMembershipOrgUnitScopeAssignments,
  isMagicLinkTokenValid,
  listBadgeTemplates,
  listBadgeTemplateOwnershipEvents,
  listTenantMembershipOrgUnitScopes,
  listTenantOrgUnits,
  listOb3SubjectCredentials,
  listPublicBadgeWallEntries,
  markLearnerIdentityLinkProofUsed,
  markMagicLinkTokenUsed,
  nextAssertionStatusListIndex,
  resolveLearnerProfileForIdentity,
  recordAssertionRevocation,
  revokeDelegatedIssuingAuthorityGrant,
  removeTenantMembershipOrgUnitScope,
  revokeSessionByHash,
  revokeOAuthAccessTokenByHash,
  revokeOAuthRefreshTokenByHash,
  setBadgeTemplateArchivedState,
  touchSession,
  upsertBadgeTemplateById,
  upsertTenantMembershipOrgUnitScope,
  upsertTenantMembershipRole,
  upsertTenant,
  upsertTenantSigningRegistration,
  upsertOb3SubjectCredential,
  upsertOb3SubjectProfile,
  transferBadgeTemplateOwnership,
  updateBadgeTemplate,
  type AssertionRecord,
  type DelegatedIssuingAuthorityAction,
  type LtiIssuerRegistrationRecord,
  type LearnerBadgeSummaryRecord,
  type RecipientIdentifierInput,
  type RecipientIdentifierType,
  type PublicBadgeWallEntryRecord,
  type SessionRecord,
  type SqlDatabase,
  type TenantMembershipOrgUnitScopeRole,
  type TenantMembershipRole,
  upsertLtiIssuerRegistration,
  upsertUserByEmail,
} from '@credtrail/db';
import { createPostgresDatabase } from '@credtrail/db/postgres';
import { renderPageShell } from '@credtrail/ui-components';
import {
  LTI_CLAIM_DEPLOYMENT_ID,
  LTI_CLAIM_LIS,
  LTI_CLAIM_MESSAGE_TYPE,
  LTI_CLAIM_RESOURCE_LINK,
  LTI_CLAIM_TARGET_LINK_URI,
  LTI_MESSAGE_TYPE_RESOURCE_LINK_REQUEST,
  parseLtiLaunchClaims,
  parseLtiOidcLoginInitiationRequest,
  resolveLtiRoleKind,
  type LtiLaunchClaims,
  type LtiOidcLoginInitiationRequest,
  type LtiRoleKind,
} from '@credtrail/lti';
import {
  parseBadgeTemplateListQuery,
  parseTenantOrgUnitListQuery,
  parseDelegatedIssuingAuthorityGrantListQuery,
  parseBadgeTemplatePathParams,
  parseAssertionPathParams,
  parseAssertionLifecycleTransitionRequest,
  parseProcessQueueRequest,
  parseQueueJob,
  parseCredentialPathParams,
  parseCreateBadgeTemplateRequest,
  parseCreateTenantOrgUnitRequest,
  parseAdminUpsertBadgeTemplateByIdRequest,
  parseAdminUpsertTenantMembershipRoleRequest,
  parseAdminDeleteLtiIssuerRegistrationRequest,
  parseAdminUpsertLtiIssuerRegistrationRequest,
  parseAdminUpsertTenantRequest,
  parseAdminUpsertTenantSigningRegistrationRequest,
  type IssueBadgeQueueJob,
  type IssueBadgeRequest,
  type ProcessQueueRequest,
  type QueueJob,
  parseIssueBadgeRequest,
  parseKeyGenerationRequest,
  parseLearnerIdentityLinkRequest,
  parseLearnerIdentityLinkVerifyRequest,
  parseLearnerDidSettingsRequest,
  parsePresentationCreateRequest,
  parsePresentationVerifyRequest,
  parseManualIssueBadgeRequest,
  parseIssueSakaiCommitBadgeRequest,
  parseMagicLinkRequest,
  parseMagicLinkVerifyRequest,
  parseTenantPathParams,
  parseTenantUserOrgUnitPathParams,
  parseTenantUserDelegatedGrantPathParams,
  parseTenantUserPathParams,
  type RevokeBadgeQueueJob,
  type RevokeBadgeRequest,
  type ManualIssueBadgeRequest,
  parseRevokeBadgeRequest,
  parseSignCredentialRequest,
  parseTenantSigningRegistry,
  parseTenantSigningRegistryEntry,
  parseTransferBadgeTemplateOwnershipRequest,
  parseCreateDelegatedIssuingAuthorityGrantRequest,
  parseRevokeDelegatedIssuingAuthorityGrantRequest,
  parseUpsertTenantMembershipOrgUnitScopeRequest,
  parseUpdateBadgeTemplateRequest,
  type TenantSigningRegistryEntry,
  type TenantSigningRegistry,
} from '@credtrail/validation';
import { Hono, type Context } from 'hono';
import { deleteCookie, getCookie, setCookie } from 'hono/cookie';
import { PDFDocument, StandardFonts, rgb, type PDFImage, type PDFPage } from 'pdf-lib';

interface AppBindings {
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

interface AppEnv {
  Bindings: AppBindings;
}

type AppContext = Context<AppEnv>;

export const app = new Hono<AppEnv>();
const API_SERVICE_NAME = 'api-worker';
const MAGIC_LINK_TTL_SECONDS = 10 * 60;
const SESSION_TTL_SECONDS = 7 * 24 * 60 * 60;
const LEARNER_IDENTITY_LINK_TTL_SECONDS = 10 * 60;
const OAUTH_AUTHORIZATION_CODE_TTL_SECONDS = 5 * 60;
const OAUTH_ACCESS_TOKEN_TTL_SECONDS = 60 * 60;
const OAUTH_REFRESH_TOKEN_TTL_SECONDS = 30 * 24 * 60 * 60;
const SESSION_COOKIE_NAME = 'credtrail_session';
const LANDING_ASSET_PATH_PREFIX = '/_astro/';
const LANDING_STATIC_PATHS = new Set(['/credtrail-logo.png', '/favicon.svg']);
const SAKAI_REPO_OWNER = 'sakaiproject';
const SAKAI_REPO_NAME = 'sakai';
const SAKAI_MIN_COMMIT_COUNT = 1000;
const SAKAI_ISSUER_NAME = 'Sakai Project';
const SAKAI_ISSUER_URL = 'https://www.sakaiproject.org/';
const SAKAI_SHOWCASE_TENANT_ID = 'sakai';
const SAKAI_SHOWCASE_TEMPLATE_ID = 'badge_template_sakai_1000';
const DEFAULT_JOB_PROCESS_LIMIT = 10;
const DEFAULT_JOB_PROCESS_LEASE_SECONDS = 30;
const DEFAULT_JOB_PROCESS_RETRY_DELAY_SECONDS = 30;
const IMS_GLOBAL_OB2_VALIDATOR_BASE_URL = 'https://openbadgesvalidator.imsglobal.org/';
const LTI_OIDC_LOGIN_PATH = '/v1/lti/oidc/login';
const LTI_LAUNCH_PATH = '/v1/lti/launch';
const LTI_OIDC_SCOPE = 'openid';
const LTI_OIDC_RESPONSE_TYPE = 'id_token';
const LTI_OIDC_RESPONSE_MODE = 'form_post';
const LTI_OIDC_PROMPT = 'none';
const LTI_STATE_TTL_SECONDS = 10 * 60;
const OB3_BASE_PATH = '/ims/ob/v3p0';
const OB3_DISCOVERY_PATH = `${OB3_BASE_PATH}/discovery`;
const OB3_OAUTH_SCOPE_CREDENTIAL_READONLY =
  'https://purl.imsglobal.org/spec/ob/v3p0/scope/credential.readonly';
const OB3_OAUTH_SCOPE_CREDENTIAL_UPSERT =
  'https://purl.imsglobal.org/spec/ob/v3p0/scope/credential.upsert';
const OB3_OAUTH_SCOPE_PROFILE_READONLY =
  'https://purl.imsglobal.org/spec/ob/v3p0/scope/profile.readonly';
const OB3_OAUTH_SCOPE_PROFILE_UPDATE =
  'https://purl.imsglobal.org/spec/ob/v3p0/scope/profile.update';
const OB3_OAUTH_SUPPORTED_SCOPE_URIS = [
  OB3_OAUTH_SCOPE_CREDENTIAL_READONLY,
  OB3_OAUTH_SCOPE_CREDENTIAL_UPSERT,
  OB3_OAUTH_SCOPE_PROFILE_READONLY,
  OB3_OAUTH_SCOPE_PROFILE_UPDATE,
] as const;
const OB3_OAUTH_SUPPORTED_SCOPE_SET = new Set<string>(OB3_OAUTH_SUPPORTED_SCOPE_URIS);
const OAUTH_GRANT_TYPE_AUTHORIZATION_CODE = 'authorization_code';
const OAUTH_GRANT_TYPE_REFRESH_TOKEN = 'refresh_token';
const OAUTH_RESPONSE_TYPE_CODE = 'code';
const OAUTH_TOKEN_ENDPOINT_AUTH_METHOD_CLIENT_SECRET_BASIC = 'client_secret_basic';
const OAUTH_TOKEN_TYPE_HINT_ACCESS_TOKEN = 'access_token';
const OAUTH_TOKEN_TYPE_HINT_REFRESH_TOKEN = 'refresh_token';
const OAUTH_PKCE_CODE_CHALLENGE_METHOD_S256 = 'S256';
const OAUTH_PKCE_CODE_CHALLENGE_PATTERN = /^[A-Za-z0-9_-]{43}$/;
const OAUTH_PKCE_CODE_VERIFIER_PATTERN = /^[A-Za-z0-9._~-]{43,128}$/;
const OB3_OAUTH_SCOPE_DESCRIPTIONS: Record<string, string> = {
  [OB3_OAUTH_SCOPE_CREDENTIAL_READONLY]:
    'Permission to read AchievementCredentials for the authenticated entity.',
  [OB3_OAUTH_SCOPE_CREDENTIAL_UPSERT]:
    'Permission to create or update AchievementCredentials for the authenticated entity.',
  [OB3_OAUTH_SCOPE_PROFILE_READONLY]:
    'Permission to read the profile for the authenticated entity.',
  [OB3_OAUTH_SCOPE_PROFILE_UPDATE]:
    'Permission to update the profile for the authenticated entity.',
};
const OB3_DISCOVERY_CACHE_CONTROL = 'public, max-age=300';
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

const addSecondsToIso = (fromIso: string, seconds: number): string => {
  const fromMs = Date.parse(fromIso);

  if (!Number.isFinite(fromMs)) {
    throw new Error('Invalid ISO timestamp');
  }

  return new Date(fromMs + seconds * 1000).toISOString();
};

const bytesToBase64Url = (bytes: Uint8Array): string => {
  let raw = '';

  for (const byte of bytes) {
    raw += String.fromCharCode(byte);
  }

  return btoa(raw).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
};

const generateOpaqueToken = (): string => {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return bytesToBase64Url(bytes);
};

const sha256Hex = async (value: string): Promise<string> => {
  const encoded = new TextEncoder().encode(value);
  const digest = await crypto.subtle.digest('SHA-256', encoded);
  const digestBytes = new Uint8Array(digest);
  const hex: string[] = [];

  for (const byte of digestBytes) {
    hex.push(byte.toString(16).padStart(2, '0'));
  }

  return hex.join('');
};

const sha256Base64Url = async (value: string): Promise<string> => {
  const encoded = new TextEncoder().encode(value);
  const digest = await crypto.subtle.digest('SHA-256', encoded);
  return bytesToBase64Url(new Uint8Array(digest));
};

const isPkceCodeChallenge = (value: string): boolean => {
  return OAUTH_PKCE_CODE_CHALLENGE_PATTERN.test(value);
};

const isPkceCodeVerifier = (value: string): boolean => {
  return OAUTH_PKCE_CODE_VERIFIER_PATTERN.test(value);
};

const sessionCookieSecure = (environment: string): boolean => {
  return environment !== 'development';
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

interface LtiIssuerRegistryEntry {
  authorizationEndpoint: string;
  clientId: string;
  tenantId: string;
  allowUnsignedIdToken: boolean;
}

type LtiIssuerRegistry = Record<string, LtiIssuerRegistryEntry>;

interface LtiStatePayload {
  iss: string;
  clientId: string;
  nonce: string;
  loginHint: string;
  targetLinkUri: string;
  ltiMessageHint?: string;
  ltiDeploymentId?: string;
  issuedAt: string;
  expiresAt: string;
}

const isIsoTimestamp = (value: string): boolean => {
  return Number.isFinite(Date.parse(value));
};

const parseLtiStatePayload = (input: unknown): LtiStatePayload | null => {
  const payload = asJsonObject(input);

  if (payload === null) {
    return null;
  }

  const iss = asNonEmptyString(payload.iss);
  const clientId = asNonEmptyString(payload.clientId);
  const nonce = asNonEmptyString(payload.nonce);
  const loginHint = asNonEmptyString(payload.loginHint);
  const targetLinkUri = asNonEmptyString(payload.targetLinkUri);
  const issuedAt = asNonEmptyString(payload.issuedAt);
  const expiresAt = asNonEmptyString(payload.expiresAt);
  let ltiMessageHint: string | undefined;
  let ltiDeploymentId: string | undefined;

  if (
    iss === null ||
    clientId === null ||
    nonce === null ||
    loginHint === null ||
    targetLinkUri === null ||
    issuedAt === null ||
    expiresAt === null
  ) {
    return null;
  }

  if (!isAbsoluteHttpUrl(iss) || !isAbsoluteHttpUrl(targetLinkUri)) {
    return null;
  }

  if (!isIsoTimestamp(issuedAt) || !isIsoTimestamp(expiresAt)) {
    return null;
  }

  if (payload.ltiMessageHint !== undefined) {
    const parsedLtiMessageHint = asNonEmptyString(payload.ltiMessageHint);

    if (parsedLtiMessageHint === null) {
      return null;
    }

    ltiMessageHint = parsedLtiMessageHint;
  }

  if (payload.ltiDeploymentId !== undefined) {
    const parsedLtiDeploymentId = asNonEmptyString(payload.ltiDeploymentId);

    if (parsedLtiDeploymentId === null) {
      return null;
    }

    ltiDeploymentId = parsedLtiDeploymentId;
  }

  return {
    iss,
    clientId,
    nonce,
    loginHint,
    targetLinkUri,
    issuedAt,
    expiresAt,
    ...(ltiMessageHint === undefined ? {} : { ltiMessageHint }),
    ...(ltiDeploymentId === undefined ? {} : { ltiDeploymentId }),
  };
};

const normalizeLtiIssuer = (issuer: string): string => {
  return issuer.trim().replace(/\/+$/g, '');
};

const isAbsoluteHttpUrl = (value: string): boolean => {
  try {
    const parsed = new URL(value);
    return parsed.protocol === 'http:' || parsed.protocol === 'https:';
  } catch {
    return false;
  }
};

const normalizeAbsoluteUrlForComparison = (value: string): string | null => {
  try {
    const parsed = new URL(value);

    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
      return null;
    }

    parsed.hash = '';
    return parsed.toString();
  } catch {
    return null;
  }
};

const parseLtiIssuerRegistryFromEnv = (rawRegistry: string | undefined): LtiIssuerRegistry => {
  if (rawRegistry === undefined || rawRegistry.trim().length === 0) {
    return {};
  }

  let parsedRegistry: unknown;

  try {
    parsedRegistry = JSON.parse(rawRegistry);
  } catch {
    throw new Error('LTI_ISSUER_REGISTRY_JSON is not valid JSON');
  }

  const registryObject = asJsonObject(parsedRegistry);

  if (registryObject === null) {
    throw new Error('LTI_ISSUER_REGISTRY_JSON must be a JSON object keyed by issuer URL');
  }

  const registry: LtiIssuerRegistry = {};

  for (const [issuer, candidate] of Object.entries(registryObject)) {
    const entryObject = asJsonObject(candidate);

    if (entryObject === null) {
      throw new Error(`LTI_ISSUER_REGISTRY_JSON["${issuer}"] must be an object`);
    }

    const authorizationEndpoint = asNonEmptyString(entryObject.authorizationEndpoint);
    const clientId = asNonEmptyString(entryObject.clientId);
    const tenantId = asNonEmptyString(entryObject.tenantId);
    const allowUnsignedIdToken = entryObject.allowUnsignedIdToken;

    if (authorizationEndpoint === null || !isAbsoluteHttpUrl(authorizationEndpoint)) {
      throw new Error(
        `LTI_ISSUER_REGISTRY_JSON["${issuer}"].authorizationEndpoint must be an absolute http(s) URL`,
      );
    }

    if (clientId === null) {
      throw new Error(`LTI_ISSUER_REGISTRY_JSON["${issuer}"].clientId must be a non-empty string`);
    }

    if (tenantId === null) {
      throw new Error(`LTI_ISSUER_REGISTRY_JSON["${issuer}"].tenantId must be a non-empty string`);
    }

    if (allowUnsignedIdToken !== undefined && typeof allowUnsignedIdToken !== 'boolean') {
      throw new Error(
        `LTI_ISSUER_REGISTRY_JSON["${issuer}"].allowUnsignedIdToken must be a boolean when provided`,
      );
    }

    registry[normalizeLtiIssuer(issuer)] = {
      authorizationEndpoint,
      clientId,
      tenantId,
      allowUnsignedIdToken: allowUnsignedIdToken ?? false,
    };
  }

  return registry;
};

const ltiIssuerRegistryFromStoredRows = (
  rows: readonly LtiIssuerRegistrationRecord[],
): LtiIssuerRegistry => {
  const registry: LtiIssuerRegistry = {};

  for (const row of rows) {
    const issuer = normalizeLtiIssuer(row.issuer);

    if (!isAbsoluteHttpUrl(issuer)) {
      throw new Error(`Stored LTI issuer "${row.issuer}" is not a valid absolute http(s) URL`);
    }

    if (!isAbsoluteHttpUrl(row.authorizationEndpoint)) {
      throw new Error(`Stored LTI issuer "${row.issuer}" has invalid authorization endpoint URL`);
    }

    const clientId = row.clientId.trim();
    const tenantId = row.tenantId.trim();

    if (clientId.length === 0) {
      throw new Error(`Stored LTI issuer "${row.issuer}" has empty clientId`);
    }

    if (tenantId.length === 0) {
      throw new Error(`Stored LTI issuer "${row.issuer}" has empty tenantId`);
    }

    registry[issuer] = {
      authorizationEndpoint: row.authorizationEndpoint,
      clientId,
      tenantId,
      allowUnsignedIdToken: row.allowUnsignedIdToken,
    };
  }

  return registry;
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

const ltiStateSigningSecret = (env: AppBindings): string => {
  const configuredSecret = env.LTI_STATE_SIGNING_SECRET?.trim();
  return configuredSecret === undefined || configuredSecret.length === 0
    ? `${env.PLATFORM_DOMAIN}:lti-state-secret`
    : configuredSecret;
};

const textToBase64Url = (value: string): string => {
  return bytesToBase64Url(new TextEncoder().encode(value));
};

const base64UrlToText = (value: string): string | null => {
  const normalizedBase64 = value.replace(/-/g, '+').replace(/_/g, '/');
  const paddedBase64 = `${normalizedBase64}${'='.repeat((4 - (normalizedBase64.length % 4)) % 4)}`;

  try {
    return atob(paddedBase64);
  } catch {
    return null;
  }
};

const signLtiStatePayload = async (payload: LtiStatePayload, secret: string): Promise<string> => {
  const encodedPayload = textToBase64Url(JSON.stringify(payload));
  const signature = await sha256Base64Url(`${encodedPayload}.${secret}`);
  return `${encodedPayload}.${signature}`;
};

type LtiStateValidationResult =
  | {
      status: 'ok';
      payload: LtiStatePayload;
    }
  | {
      status: 'invalid';
      reason: string;
    };

const validateLtiStateToken = async (
  stateToken: string,
  secret: string,
  nowIso: string,
): Promise<LtiStateValidationResult> => {
  const [encodedPayload, providedSignature] = stateToken.split('.', 2);

  if (
    encodedPayload === undefined ||
    providedSignature === undefined ||
    encodedPayload.length === 0 ||
    providedSignature.length === 0
  ) {
    return {
      status: 'invalid',
      reason: 'state token is malformed',
    };
  }

  const expectedSignature = await sha256Base64Url(`${encodedPayload}.${secret}`);

  if (providedSignature !== expectedSignature) {
    return {
      status: 'invalid',
      reason: 'state token signature is invalid',
    };
  }

  const payloadJson = base64UrlToText(encodedPayload);

  if (payloadJson === null) {
    return {
      status: 'invalid',
      reason: 'state token payload is not valid base64url data',
    };
  }

  let parsedPayload: unknown;

  try {
    parsedPayload = JSON.parse(payloadJson);
  } catch {
    return {
      status: 'invalid',
      reason: 'state token payload is not valid JSON',
    };
  }

  const payload = parseLtiStatePayload(parsedPayload);

  if (payload === null) {
    return {
      status: 'invalid',
      reason: 'state token payload failed validation',
    };
  }

  const nowMs = Date.parse(nowIso);
  const expiresAtMs = Date.parse(payload.expiresAt);

  if (!Number.isFinite(nowMs) || !Number.isFinite(expiresAtMs) || nowMs >= expiresAtMs) {
    return {
      status: 'invalid',
      reason: 'state token is expired',
    };
  }

  return {
    status: 'ok',
    payload,
  };
};

const ltiAudienceIncludesClientId = (
  audienceClaim: LtiLaunchClaims['aud'],
  clientId: string,
): boolean => {
  if (typeof audienceClaim === 'string') {
    return audienceClaim === clientId;
  }

  return audienceClaim.includes(clientId);
};

const ltiRoleLabel = (roleKind: LtiRoleKind): string => {
  if (roleKind === 'instructor') {
    return 'Instructor';
  }

  if (roleKind === 'learner') {
    return 'Learner';
  }

  return 'Unknown role';
};

const ltiMembershipRoleFromRoleKind = (roleKind: LtiRoleKind): TenantMembershipRole => {
  return roleKind === 'instructor' ? 'issuer' : 'viewer';
};

const ltiFederatedSubjectIdentity = (issuer: string, subjectId: string): string => {
  return `${normalizeLtiIssuer(issuer)}::${subjectId}`;
};

const ltiDisplayNameFromClaims = (claims: LtiLaunchClaims): string | undefined => {
  const fullName = asNonEmptyString(claims.name);

  if (fullName !== null) {
    return fullName;
  }

  const givenName = asNonEmptyString(claims.given_name);
  const familyName = asNonEmptyString(claims.family_name);

  if (givenName !== null && familyName !== null) {
    return `${givenName} ${familyName}`;
  }

  return givenName ?? familyName ?? undefined;
};

const isLikelyEmailAddress = (value: string): boolean => {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);
};

const ltiEmailFromClaims = (claims: LtiLaunchClaims): string | null => {
  const emailClaim = asNonEmptyString(claims.email);

  if (emailClaim === null || !isLikelyEmailAddress(emailClaim)) {
    return null;
  }

  return emailClaim;
};
const ltiSourcedIdFromClaims = (claims: LtiLaunchClaims): string | null => {
  const lisClaim = asJsonObject(claims[LTI_CLAIM_LIS]);
  return asNonEmptyString(lisClaim?.person_sourcedid);
};

const ltiSyntheticEmail = async (tenantId: string, federatedSubject: string): Promise<string> => {
  const digest = await sha256Hex(`${tenantId}:${federatedSubject}`);
  return `lti-${digest.slice(0, 24)}@credtrail-lti.local`;
};

const ltiLearnerDashboardPath = (tenantId: string): string => {
  return `/tenants/${encodeURIComponent(tenantId)}/learner/dashboard`;
};

const ltiLaunchResultPage = (input: {
  roleKind: LtiRoleKind;
  tenantId: string;
  userId: string;
  membershipRole: TenantMembershipRole;
  learnerProfileId: string;
  issuer: string;
  deploymentId: string;
  subjectId: string;
  targetLinkUri: string;
  messageType: string;
  dashboardPath: string;
}): string => {
  return renderPageShell(
    'LTI Launch Complete | CredTrail',
    `<section style="display:grid;gap:1rem;max-width:52rem;">
      <h1 style="margin:0;">LTI 1.3 launch complete</h1>
      <p style="margin:0;color:#334155;">
        Launch accepted for <strong>${escapeHtml(ltiRoleLabel(input.roleKind))}</strong>.
      </p>
      <dl style="margin:0;display:grid;grid-template-columns:minmax(12rem,max-content) 1fr;gap:0.45rem 0.8rem;">
        <dt style="font-weight:600;">Issuer</dt>
        <dd style="margin:0;overflow-wrap:anywhere;">${escapeHtml(input.issuer)}</dd>
        <dt style="font-weight:600;">Deployment ID</dt>
        <dd style="margin:0;overflow-wrap:anywhere;">${escapeHtml(input.deploymentId)}</dd>
        <dt style="font-weight:600;">Tenant</dt>
        <dd style="margin:0;overflow-wrap:anywhere;">${escapeHtml(input.tenantId)}</dd>
        <dt style="font-weight:600;">User ID</dt>
        <dd style="margin:0;overflow-wrap:anywhere;">${escapeHtml(input.userId)}</dd>
        <dt style="font-weight:600;">Membership role</dt>
        <dd style="margin:0;overflow-wrap:anywhere;">${escapeHtml(input.membershipRole)}</dd>
        <dt style="font-weight:600;">Learner profile</dt>
        <dd style="margin:0;overflow-wrap:anywhere;">${escapeHtml(input.learnerProfileId)}</dd>
        <dt style="font-weight:600;">LTI subject</dt>
        <dd style="margin:0;overflow-wrap:anywhere;">${escapeHtml(input.subjectId)}</dd>
        <dt style="font-weight:600;">Message type</dt>
        <dd style="margin:0;overflow-wrap:anywhere;">${escapeHtml(input.messageType)}</dd>
        <dt style="font-weight:600;">Target link URI</dt>
        <dd style="margin:0;overflow-wrap:anywhere;">${escapeHtml(input.targetLinkUri)}</dd>
      </dl>
      <p style="margin:0;color:#475569;">
        LTI identity is linked and this browser is now signed into CredTrail.
      </p>
      <p style="margin:0;">
        <a href="${escapeHtml(input.dashboardPath)}">Open learner dashboard</a>
      </p>
    </section>`,
  );
};

interface LtiIssuerRegistrationFormState {
  issuer?: string;
  tenantId?: string;
  authorizationEndpoint?: string;
  clientId?: string;
  allowUnsignedIdToken?: boolean;
}

const ltiIssuerRegistrationAdminPage = (input: {
  token: string;
  registrations: readonly LtiIssuerRegistrationRecord[];
  submissionError?: string;
  formState?: LtiIssuerRegistrationFormState;
}): string => {
  const registrationRows =
    input.registrations.length === 0
      ? '<tr><td colspan="6" style="padding:0.75rem;">No LTI issuer registrations configured.</td></tr>'
      : input.registrations
          .map((registration) => {
            return `<tr>
      <td style="padding:0.5rem;vertical-align:top;word-break:break-word;">${escapeHtml(registration.issuer)}</td>
      <td style="padding:0.5rem;vertical-align:top;">${escapeHtml(registration.tenantId)}</td>
      <td style="padding:0.5rem;vertical-align:top;word-break:break-word;">${escapeHtml(registration.clientId)}</td>
      <td style="padding:0.5rem;vertical-align:top;word-break:break-word;">${escapeHtml(registration.authorizationEndpoint)}</td>
      <td style="padding:0.5rem;vertical-align:top;">${registration.allowUnsignedIdToken ? 'true' : 'false'}</td>
      <td style="padding:0.5rem;vertical-align:top;">
        <form method="post" action="/admin/lti/issuer-registrations/delete">
          <input type="hidden" name="token" value="${escapeHtml(input.token)}" />
          <input type="hidden" name="issuer" value="${escapeHtml(registration.issuer)}" />
          <button type="submit">Delete</button>
        </form>
      </td>
    </tr>`;
          })
          .join('\n');

  return renderPageShell(
    'LTI Issuer Registrations | CredTrail',
    `<section style="display:grid;gap:1rem;max-width:64rem;">
      <h1 style="margin:0;">Manual LTI issuer registration configuration</h1>
      <p style="margin:0;color:#334155;">
        Configure issuer mappings used by LTI 1.3 OIDC login and launch. Stored registrations override env-based defaults.
      </p>
      ${
        input.submissionError === undefined
          ? ''
          : `<p style="margin:0;padding:0.75rem;border:1px solid #fecaca;background:#fef2f2;color:#991b1b;">
              ${escapeHtml(input.submissionError)}
            </p>`
      }
      <form method="post" action="/admin/lti/issuer-registrations" style="display:grid;gap:0.75rem;padding:1rem;border:1px solid #cbd5e1;border-radius:0.5rem;">
        <input type="hidden" name="token" value="${escapeHtml(input.token)}" />
        <label style="display:grid;gap:0.35rem;">
          <span>Issuer URL</span>
          <input name="issuer" type="url" required value="${escapeHtml(input.formState?.issuer ?? '')}" />
        </label>
        <label style="display:grid;gap:0.35rem;">
          <span>Tenant ID</span>
          <input name="tenantId" type="text" required value="${escapeHtml(input.formState?.tenantId ?? '')}" />
        </label>
        <label style="display:grid;gap:0.35rem;">
          <span>Client ID</span>
          <input name="clientId" type="text" required value="${escapeHtml(input.formState?.clientId ?? '')}" />
        </label>
        <label style="display:grid;gap:0.35rem;">
          <span>Authorization endpoint</span>
          <input name="authorizationEndpoint" type="url" required value="${escapeHtml(input.formState?.authorizationEndpoint ?? '')}" />
        </label>
        <label style="display:flex;gap:0.5rem;align-items:center;">
          <input name="allowUnsignedIdToken" type="checkbox" ${
            input.formState?.allowUnsignedIdToken === true ? 'checked' : ''
          } />
          <span>Allow unsigned id_token (test-mode only)</span>
        </label>
        <div>
          <button type="submit">Save registration</button>
        </div>
      </form>
      <div style="overflow:auto;">
        <table style="width:100%;border-collapse:collapse;">
          <thead>
            <tr>
              <th style="text-align:left;padding:0.5rem;border-bottom:1px solid #cbd5e1;">Issuer</th>
              <th style="text-align:left;padding:0.5rem;border-bottom:1px solid #cbd5e1;">Tenant</th>
              <th style="text-align:left;padding:0.5rem;border-bottom:1px solid #cbd5e1;">Client ID</th>
              <th style="text-align:left;padding:0.5rem;border-bottom:1px solid #cbd5e1;">Authorization endpoint</th>
              <th style="text-align:left;padding:0.5rem;border-bottom:1px solid #cbd5e1;">Unsigned test mode</th>
              <th style="text-align:left;padding:0.5rem;border-bottom:1px solid #cbd5e1;">Actions</th>
            </tr>
          </thead>
          <tbody>
            ${registrationRows}
          </tbody>
        </table>
      </div>
    </section>`,
  );
};

const ltiIssuerRegistrationAdminPageResponse = async (
  c: AppContext,
  input: {
    token: string;
    submissionError?: string;
    formState?: LtiIssuerRegistrationFormState;
    status?: 200 | 400;
  },
): Promise<Response> => {
  const registrations = await listLtiIssuerRegistrations(resolveDatabase(c.env));
  const pageHtml = ltiIssuerRegistrationAdminPage({
    token: input.token,
    registrations,
    ...(input.submissionError === undefined ? {} : { submissionError: input.submissionError }),
    ...(input.formState === undefined ? {} : { formState: input.formState }),
  });
  return c.html(pageHtml, input.status ?? 200);
};

const ltiLoginInputFromRequest = async (c: AppContext): Promise<Record<string, string>> => {
  if (c.req.method === 'GET') {
    return {
      iss: c.req.query('iss') ?? '',
      login_hint: c.req.query('login_hint') ?? '',
      target_link_uri: c.req.query('target_link_uri') ?? '',
      ...(c.req.query('client_id') === undefined
        ? {}
        : { client_id: c.req.query('client_id') ?? '' }),
      ...(c.req.query('lti_message_hint') === undefined
        ? {}
        : {
            lti_message_hint: c.req.query('lti_message_hint') ?? '',
          }),
      ...(c.req.query('lti_deployment_id') === undefined
        ? {}
        : {
            lti_deployment_id: c.req.query('lti_deployment_id') ?? '',
          }),
    };
  }

  const contentType = c.req.header('content-type') ?? '';

  if (!contentType.toLowerCase().includes('application/x-www-form-urlencoded')) {
    return {};
  }

  const rawBody = await c.req.text();
  const formData = new URLSearchParams(rawBody);

  return {
    iss: formData.get('iss') ?? '',
    login_hint: formData.get('login_hint') ?? '',
    target_link_uri: formData.get('target_link_uri') ?? '',
    ...(formData.get('client_id') === null ? {} : { client_id: formData.get('client_id') ?? '' }),
    ...(formData.get('lti_message_hint') === null
      ? {}
      : {
          lti_message_hint: formData.get('lti_message_hint') ?? '',
        }),
    ...(formData.get('lti_deployment_id') === null
      ? {}
      : {
          lti_deployment_id: formData.get('lti_deployment_id') ?? '',
        }),
  };
};

const ltiLaunchFormInputFromRequest = async (
  c: AppContext,
): Promise<{ idToken: string | null; state: string | null }> => {
  const contentType = c.req.header('content-type') ?? '';

  if (!contentType.toLowerCase().includes('application/x-www-form-urlencoded')) {
    return {
      idToken: null,
      state: null,
    };
  }

  const rawBody = await c.req.text();
  const formData = new URLSearchParams(rawBody);

  return {
    idToken: formData.get('id_token'),
    state: formData.get('state'),
  };
};

type Ed25519SigningPublicJwk = Extract<
  TenantSigningRegistryEntry['publicJwk'],
  { kty: 'OKP'; crv: 'Ed25519' }
>;
type P256SigningPublicJwk = Extract<
  TenantSigningRegistryEntry['publicJwk'],
  { kty: 'EC'; crv: 'P-256' }
>;
type Ed25519SigningPrivateJwk = NonNullable<
  Extract<TenantSigningRegistryEntry['privateJwk'], { kty: 'OKP'; crv: 'Ed25519' }>
>;
type P256SigningPrivateJwk = NonNullable<
  Extract<TenantSigningRegistryEntry['privateJwk'], { kty: 'EC'; crv: 'P-256' }>
>;

const isEd25519SigningPublicJwk = (
  jwk: TenantSigningRegistryEntry['publicJwk'],
): jwk is Ed25519SigningPublicJwk => {
  return jwk.kty === 'OKP';
};

const isP256SigningPublicJwk = (
  jwk: TenantSigningRegistryEntry['publicJwk'],
): jwk is P256SigningPublicJwk => {
  return jwk.kty === 'EC';
};

const isEd25519SigningPrivateJwk = (
  jwk: TenantSigningRegistryEntry['privateJwk'],
): jwk is Ed25519SigningPrivateJwk => {
  return jwk?.kty === 'OKP';
};

const isP256SigningPrivateJwk = (
  jwk: TenantSigningRegistryEntry['privateJwk'],
): jwk is P256SigningPrivateJwk => {
  return jwk?.kty === 'EC';
};

const toEd25519PublicJwk = (jwk: Ed25519SigningPublicJwk): Ed25519PublicJwk => {
  if (jwk.kid === undefined) {
    return {
      kty: jwk.kty,
      crv: jwk.crv,
      x: jwk.x,
    };
  }

  return {
    kty: jwk.kty,
    crv: jwk.crv,
    x: jwk.x,
    kid: jwk.kid,
  };
};

const toP256PublicJwk = (jwk: P256SigningPublicJwk): P256PublicJwk => {
  if (jwk.kid === undefined) {
    return {
      kty: jwk.kty,
      crv: jwk.crv,
      x: jwk.x,
      y: jwk.y,
    };
  }

  return {
    kty: jwk.kty,
    crv: jwk.crv,
    x: jwk.x,
    y: jwk.y,
    kid: jwk.kid,
  };
};

const toEd25519PrivateJwk = (jwk: Ed25519SigningPrivateJwk): Ed25519PrivateJwk => {
  if (jwk.kid === undefined) {
    return {
      kty: jwk.kty,
      crv: jwk.crv,
      x: jwk.x,
      d: jwk.d,
    };
  }

  return {
    kty: jwk.kty,
    crv: jwk.crv,
    x: jwk.x,
    d: jwk.d,
    kid: jwk.kid,
  };
};

const toP256PrivateJwk = (jwk: P256SigningPrivateJwk): P256PrivateJwk => {
  if (jwk.kid === undefined) {
    return {
      kty: jwk.kty,
      crv: jwk.crv,
      x: jwk.x,
      y: jwk.y,
      d: jwk.d,
    };
  }

  return {
    kty: jwk.kty,
    crv: jwk.crv,
    x: jwk.x,
    y: jwk.y,
    d: jwk.d,
    kid: jwk.kid,
  };
};

type SigningPublicJwk = TenantSigningRegistryEntry['publicJwk'];

interface HistoricalSigningKeyEntry {
  keyId: string;
  publicJwk: SigningPublicJwk;
}

type SigningKeyHistoryRegistry = Record<string, HistoricalSigningKeyEntry[]>;

interface RemoteSignerRegistryEntry {
  url: string;
  authorizationHeader: string | null;
  timeoutMs: number;
}

type RemoteSignerRegistry = Record<string, RemoteSignerRegistryEntry>;

const DEFAULT_REMOTE_SIGNER_TIMEOUT_MS = 10_000;
const MAX_REMOTE_SIGNER_TIMEOUT_MS = 60_000;

const parseSigningRegistryFromEnv = (rawRegistry: string | undefined): TenantSigningRegistry => {
  if (rawRegistry === undefined || rawRegistry.trim().length === 0) {
    return {};
  }

  let parsedRegistry: unknown;

  try {
    parsedRegistry = JSON.parse(rawRegistry) as unknown;
  } catch {
    throw new Error('TENANT_SIGNING_REGISTRY_JSON is not valid JSON');
  }

  return parseTenantSigningRegistry(parsedRegistry);
};

const parseSigningKeyHistoryRegistryFromEnv = (
  rawRegistry: string | undefined,
): SigningKeyHistoryRegistry => {
  if (rawRegistry === undefined || rawRegistry.trim().length === 0) {
    return {};
  }

  let parsedRegistry: unknown;

  try {
    parsedRegistry = JSON.parse(rawRegistry) as unknown;
  } catch {
    throw new Error('TENANT_SIGNING_KEY_HISTORY_JSON is not valid JSON');
  }

  if (
    parsedRegistry === null ||
    typeof parsedRegistry !== 'object' ||
    Array.isArray(parsedRegistry)
  ) {
    throw new Error('TENANT_SIGNING_KEY_HISTORY_JSON must be an object keyed by DID');
  }

  const output: SigningKeyHistoryRegistry = {};

  for (const [did, registryValue] of Object.entries(parsedRegistry as Record<string, unknown>)) {
    if (!Array.isArray(registryValue)) {
      throw new Error(`TENANT_SIGNING_KEY_HISTORY_JSON["${did}"] must be an array`);
    }

    const parsedEntries: HistoricalSigningKeyEntry[] = [];

    for (const [index, entry] of registryValue.entries()) {
      if (entry === null || typeof entry !== 'object' || Array.isArray(entry)) {
        throw new Error(
          `TENANT_SIGNING_KEY_HISTORY_JSON["${did}"][${String(index)}] must be an object`,
        );
      }

      const keyId = (entry as Record<string, unknown>).keyId;
      const publicJwk = (entry as Record<string, unknown>).publicJwk;

      if (typeof keyId !== 'string' || keyId.trim().length === 0) {
        throw new Error(
          `TENANT_SIGNING_KEY_HISTORY_JSON["${did}"][${String(index)}].keyId must be a non-empty string`,
        );
      }

      const parsedSigningEntry = parseTenantSigningRegistryEntry({
        tenantId: did,
        keyId,
        publicJwk,
      });

      parsedEntries.push({
        keyId: parsedSigningEntry.keyId,
        publicJwk: parsedSigningEntry.publicJwk,
      });
    }

    output[did] = parsedEntries;
  }

  return output;
};

const parseRemoteSignerRegistryFromEnv = (
  rawRegistry: string | undefined,
): RemoteSignerRegistry => {
  if (rawRegistry === undefined || rawRegistry.trim().length === 0) {
    return {};
  }

  let parsedRegistry: unknown;

  try {
    parsedRegistry = JSON.parse(rawRegistry) as unknown;
  } catch {
    throw new Error('TENANT_REMOTE_SIGNER_REGISTRY_JSON is not valid JSON');
  }

  if (
    parsedRegistry === null ||
    typeof parsedRegistry !== 'object' ||
    Array.isArray(parsedRegistry)
  ) {
    throw new Error('TENANT_REMOTE_SIGNER_REGISTRY_JSON must be an object keyed by DID');
  }

  const output: RemoteSignerRegistry = {};

  for (const [did, entry] of Object.entries(parsedRegistry as Record<string, unknown>)) {
    if (entry === null || typeof entry !== 'object' || Array.isArray(entry)) {
      throw new Error(`TENANT_REMOTE_SIGNER_REGISTRY_JSON["${did}"] must be an object`);
    }

    const entryObject = entry as Record<string, unknown>;
    const url = entryObject.url;
    const authorizationHeader = entryObject.authorizationHeader;
    const timeoutMs = entryObject.timeoutMs;

    if (typeof url !== 'string' || url.trim().length === 0) {
      throw new Error(
        `TENANT_REMOTE_SIGNER_REGISTRY_JSON["${did}"].url must be a non-empty string`,
      );
    }

    let normalizedAuthorizationHeader: string | null = null;

    if (authorizationHeader !== undefined) {
      if (typeof authorizationHeader !== 'string' || authorizationHeader.trim().length === 0) {
        throw new Error(
          `TENANT_REMOTE_SIGNER_REGISTRY_JSON["${did}"].authorizationHeader must be a non-empty string`,
        );
      }

      normalizedAuthorizationHeader = authorizationHeader.trim();
    }

    let normalizedTimeoutMs = DEFAULT_REMOTE_SIGNER_TIMEOUT_MS;

    if (timeoutMs !== undefined) {
      if (
        typeof timeoutMs !== 'number' ||
        !Number.isInteger(timeoutMs) ||
        timeoutMs <= 0 ||
        timeoutMs > MAX_REMOTE_SIGNER_TIMEOUT_MS
      ) {
        throw new Error(
          `TENANT_REMOTE_SIGNER_REGISTRY_JSON["${did}"].timeoutMs must be an integer between 1 and ${String(MAX_REMOTE_SIGNER_TIMEOUT_MS)}`,
        );
      }

      normalizedTimeoutMs = timeoutMs;
    }

    output[did] = {
      url: url.trim(),
      authorizationHeader: normalizedAuthorizationHeader,
      timeoutMs: normalizedTimeoutMs,
    };
  }

  return output;
};

const parseSigningEntryFromStoredJson = (
  tenantId: string,
  keyId: string,
  publicJwkJson: string,
  privateJwkJson: string | null,
): TenantSigningRegistryEntry => {
  let parsedPublicJwk: unknown;
  let parsedPrivateJwk: unknown = undefined;

  try {
    parsedPublicJwk = JSON.parse(publicJwkJson) as unknown;
  } catch {
    throw new Error(`Invalid stored public JWK JSON for tenant "${tenantId}"`);
  }

  if (privateJwkJson !== null) {
    try {
      parsedPrivateJwk = JSON.parse(privateJwkJson) as unknown;
    } catch {
      throw new Error(`Invalid stored private JWK JSON for tenant "${tenantId}"`);
    }
  }

  return parseTenantSigningRegistryEntry({
    tenantId,
    keyId,
    publicJwk: parsedPublicJwk,
    ...(parsedPrivateJwk === undefined ? {} : { privateJwk: parsedPrivateJwk }),
  });
};

const resolveSigningEntryForDid = async (
  c: AppContext,
  did: string,
): Promise<TenantSigningRegistryEntry | null> => {
  const dbSigningRegistration = await findTenantSigningRegistrationByDid(
    resolveDatabase(c.env),
    did,
  );

  if (dbSigningRegistration !== null) {
    return parseSigningEntryFromStoredJson(
      dbSigningRegistration.tenantId,
      dbSigningRegistration.keyId,
      dbSigningRegistration.publicJwkJson,
      dbSigningRegistration.privateJwkJson,
    );
  }

  const envRegistry = parseSigningRegistryFromEnv(c.env.TENANT_SIGNING_REGISTRY_JSON);
  return envRegistry[did] ?? null;
};

const resolveHistoricalSigningKeysForDid = (
  c: AppContext,
  did: string,
): readonly HistoricalSigningKeyEntry[] => {
  const historyRegistry = parseSigningKeyHistoryRegistryFromEnv(
    c.env.TENANT_SIGNING_KEY_HISTORY_JSON,
  );
  return historyRegistry[did] ?? [];
};

const resolveRemoteSignerRegistryEntryForDid = (
  c: AppContext,
  did: string,
): RemoteSignerRegistryEntry | null => {
  const remoteSignerRegistry = parseRemoteSignerRegistryFromEnv(
    c.env.TENANT_REMOTE_SIGNER_REGISTRY_JSON,
  );
  return remoteSignerRegistry[did] ?? null;
};

const requireBootstrapAdmin = (c: AppContext): Response | null => {
  const configuredToken = c.env.BOOTSTRAP_ADMIN_TOKEN?.trim();

  if (configuredToken === undefined || configuredToken.length === 0) {
    return c.json(
      {
        error: 'Bootstrap admin API is not configured',
      },
      503,
    );
  }

  const authorizationHeader = c.req.header('authorization');
  const expectedAuthorization = `Bearer ${configuredToken}`;

  if (authorizationHeader !== expectedAuthorization) {
    return c.json(
      {
        error: 'Unauthorized',
      },
      401,
    );
  }

  return null;
};

const requireBootstrapAdminUiToken = (c: AppContext, token: string | null): Response | null => {
  const configuredToken = c.env.BOOTSTRAP_ADMIN_TOKEN?.trim();

  if (configuredToken === undefined || configuredToken.length === 0) {
    return c.json(
      {
        error: 'Bootstrap admin API is not configured',
      },
      503,
    );
  }

  if (token === null || token !== configuredToken) {
    return c.json(
      {
        error: 'Unauthorized',
      },
      401,
    );
  }

  return null;
};

const isUniqueConstraintError = (error: unknown): boolean => {
  return (
    error instanceof Error &&
    (error.message.includes('UNIQUE constraint failed') ||
      error.message.includes('duplicate key value violates unique constraint'))
  );
};

const ISSUER_ROLES: TenantMembershipRole[] = ['owner', 'admin', 'issuer'];
const TENANT_MEMBER_ROLES: TenantMembershipRole[] = ['owner', 'admin', 'issuer', 'viewer'];
const ADMIN_ROLES: TenantMembershipRole[] = ['owner', 'admin'];

const hasRequiredRole = (
  membershipRole: TenantMembershipRole,
  allowedRoles: readonly TenantMembershipRole[],
): boolean => {
  return allowedRoles.includes(membershipRole);
};

const requireTenantRole = async (
  c: AppContext,
  tenantId: string,
  allowedRoles: readonly TenantMembershipRole[],
): Promise<
  | {
      session: SessionRecord;
      membershipRole: TenantMembershipRole;
    }
  | Response
> => {
  const session = await resolveSessionFromCookie(c);

  if (session === null) {
    return c.json(
      {
        error: 'Not authenticated',
      },
      401,
    );
  }

  if (session.tenantId !== tenantId) {
    return c.json(
      {
        error: 'Forbidden for requested tenant',
      },
      403,
    );
  }

  const membership = await findTenantMembership(resolveDatabase(c.env), tenantId, session.userId);

  if (membership === null) {
    return c.json(
      {
        error: 'Membership not found for requested tenant',
      },
      403,
    );
  }

  if (!hasRequiredRole(membership.role, allowedRoles)) {
    return c.json(
      {
        error: 'Insufficient role for requested action',
      },
      403,
    );
  }

  return {
    session,
    membershipRole: membership.role,
  };
};

const defaultInstitutionOrgUnitId = (tenantId: string): string => {
  return `${tenantId}:org:institution`;
};

const canBypassOrgScopeChecks = (membershipRole: TenantMembershipRole): boolean => {
  return membershipRole === 'owner' || membershipRole === 'admin';
};

const hasScopedOrgUnitPermission = async (input: {
  db: SqlDatabase;
  tenantId: string;
  userId: string;
  membershipRole: TenantMembershipRole;
  orgUnitId: string;
  requiredRole: TenantMembershipOrgUnitScopeRole;
  allowWhenNoScopes: boolean;
}): Promise<boolean> => {
  if (canBypassOrgScopeChecks(input.membershipRole)) {
    return true;
  }

  if (input.membershipRole !== 'issuer') {
    return false;
  }

  const hasScopedAssignments = await hasTenantMembershipOrgUnitScopeAssignments(
    input.db,
    input.tenantId,
    input.userId,
  );

  if (!hasScopedAssignments) {
    return input.allowWhenNoScopes;
  }

  return hasTenantMembershipOrgUnitAccess(input.db, {
    tenantId: input.tenantId,
    userId: input.userId,
    orgUnitId: input.orgUnitId,
    requiredRole: input.requiredRole,
  });
};

const requireScopedOrgUnitPermission = async (
  c: AppContext,
  input: {
    db: SqlDatabase;
    tenantId: string;
    userId: string;
    membershipRole: TenantMembershipRole;
    orgUnitId: string;
    requiredRole: TenantMembershipOrgUnitScopeRole;
    allowWhenNoScopes?: boolean;
  },
): Promise<Response | null> => {
  const allowed = await hasScopedOrgUnitPermission({
    db: input.db,
    tenantId: input.tenantId,
    userId: input.userId,
    membershipRole: input.membershipRole,
    orgUnitId: input.orgUnitId,
    requiredRole: input.requiredRole,
    allowWhenNoScopes: input.allowWhenNoScopes === true,
  });

  if (allowed) {
    return null;
  }

  return c.json(
    {
      error: 'Insufficient org-unit scope for requested action',
    },
    403,
  );
};

const requireDelegatedIssuingAuthorityPermission = async (
  c: AppContext,
  input: {
    db: SqlDatabase;
    tenantId: string;
    userId: string;
    membershipRole: TenantMembershipRole;
    ownerOrgUnitId: string;
    badgeTemplateId: string;
    requiredAction: DelegatedIssuingAuthorityAction;
  },
): Promise<Response | null> => {
  if (canBypassOrgScopeChecks(input.membershipRole)) {
    return null;
  }

  const delegatedGrant = await findActiveDelegatedIssuingAuthorityGrantForAction(input.db, {
    tenantId: input.tenantId,
    userId: input.userId,
    orgUnitId: input.ownerOrgUnitId,
    badgeTemplateId: input.badgeTemplateId,
    requiredAction: input.requiredAction,
  });

  if (delegatedGrant !== null) {
    return null;
  }

  if (input.membershipRole === 'issuer') {
    return requireScopedOrgUnitPermission(c, {
      db: input.db,
      tenantId: input.tenantId,
      userId: input.userId,
      membershipRole: input.membershipRole,
      orgUnitId: input.ownerOrgUnitId,
      requiredRole: 'issuer',
      allowWhenNoScopes: true,
    });
  }

  return c.json(
    {
      error: 'Insufficient role for requested action',
    },
    403,
  );
};

const didForWellKnownRequest = (requestUrl: string): string => {
  const request = new URL(requestUrl);
  return createDidWeb({ host: request.host });
};

const didForTenantPathRequest = (requestUrl: string, tenantSlug: string): string => {
  const request = new URL(requestUrl);
  return createDidWeb({ host: request.host, pathSegments: [tenantSlug] });
};

const didDocumentForSigningEntry = (input: {
  did: string;
  signingEntry: TenantSigningRegistryEntry;
}): JsonObject | null => {
  const verificationMethodId = `${input.did}#${input.signingEntry.keyId}`;

  if (isEd25519SigningPublicJwk(input.signingEntry.publicJwk)) {
    return createDidDocument({
      did: input.did,
      keyId: input.signingEntry.keyId,
      publicJwk: toEd25519PublicJwk(input.signingEntry.publicJwk),
    }) as unknown as JsonObject;
  }

  if (isP256SigningPublicJwk(input.signingEntry.publicJwk)) {
    const didDocument: JsonObject = {
      '@context': ['https://www.w3.org/ns/did/v1', 'https://w3id.org/security/suites/jws-2020/v1'],
      id: input.did,
      verificationMethod: [
        {
          id: verificationMethodId,
          type: 'JsonWebKey2020',
          controller: input.did,
          publicKeyJwk: toP256PublicJwk(input.signingEntry.publicJwk) as unknown as JsonObject,
        },
      ],
      assertionMethod: [verificationMethodId],
    };

    return didDocument;
  }

  return null;
};

const publicJwkFromSigningPublicJwk = (publicJwk: SigningPublicJwk): JsonObject => {
  if (isEd25519SigningPublicJwk(publicJwk)) {
    return toEd25519PublicJwk(publicJwk) as unknown as JsonObject;
  }

  if (isP256SigningPublicJwk(publicJwk)) {
    return toP256PublicJwk(publicJwk) as unknown as JsonObject;
  }

  return publicJwk as unknown as JsonObject;
};

const jwksDocumentForSigningEntry = (input: {
  signingEntry: TenantSigningRegistryEntry;
  historicalKeys?: readonly HistoricalSigningKeyEntry[];
}): JsonObject => {
  const keys: JsonObject[] = [publicJwkFromSigningPublicJwk(input.signingEntry.publicJwk)];
  const activeKeyId = input.signingEntry.keyId;

  for (const historicalEntry of input.historicalKeys ?? []) {
    if (historicalEntry.keyId === activeKeyId) {
      continue;
    }

    keys.push(publicJwkFromSigningPublicJwk(historicalEntry.publicJwk));
  }

  return {
    keys,
  };
};

const resolveAbsoluteUrl = (requestUrl: string, configuredValue: string): string => {
  const trimmedValue = configuredValue.trim();

  if (trimmedValue.length === 0) {
    throw new Error('Expected non-empty URL value');
  }

  return new URL(trimmedValue, requestUrl).toString();
};

const ob3ServiceDescriptionDocument = (c: AppContext): JsonObject => {
  const requestUrl = c.req.url;
  const serverUrl = resolveAbsoluteUrl(requestUrl, OB3_BASE_PATH);
  const configuredTitle = c.env.OB3_DISCOVERY_TITLE?.trim();
  const title =
    configuredTitle === undefined || configuredTitle.length === 0
      ? 'CredTrail Open Badges API'
      : configuredTitle;
  const termsOfService = resolveAbsoluteUrl(requestUrl, c.env.OB3_TERMS_OF_SERVICE_URL ?? '/terms');
  const privacyPolicyUrl = resolveAbsoluteUrl(
    requestUrl,
    c.env.OB3_PRIVACY_POLICY_URL ?? '/privacy',
  );
  const imageUrl = resolveAbsoluteUrl(requestUrl, c.env.OB3_IMAGE_URL ?? '/credtrail-logo.png');
  const registrationUrl = resolveAbsoluteUrl(
    requestUrl,
    c.env.OB3_OAUTH_REGISTRATION_URL ?? `${OB3_BASE_PATH}/oauth/register`,
  );
  const authorizationUrl = resolveAbsoluteUrl(
    requestUrl,
    c.env.OB3_OAUTH_AUTHORIZATION_URL ?? `${OB3_BASE_PATH}/oauth/authorize`,
  );
  const tokenUrl = resolveAbsoluteUrl(
    requestUrl,
    c.env.OB3_OAUTH_TOKEN_URL ?? `${OB3_BASE_PATH}/oauth/token`,
  );
  const refreshUrl = resolveAbsoluteUrl(
    requestUrl,
    c.env.OB3_OAUTH_REFRESH_URL ?? `${OB3_BASE_PATH}/oauth/refresh`,
  );

  return {
    openapi: '3.0.1',
    info: {
      title,
      description: 'Open Badges v3.0 Service Description Document',
      version: '3.0',
      termsOfService,
      'x-imssf-privacyPolicyUrl': privacyPolicyUrl,
      'x-imssf-image': imageUrl,
    },
    servers: [
      {
        url: serverUrl,
        description: 'Open Badges v3.0 service endpoint',
      },
    ],
    tags: [
      {
        name: 'OpenBadgeCredentials',
        description: 'Exchange OpenBadgeCredentials and Profile resources.',
      },
      {
        name: 'Discovery',
        description: 'Service Description Document metadata endpoint.',
      },
    ],
    paths: {
      '/credentials': {
        get: {
          tags: ['OpenBadgeCredentials'],
          summary: 'Get credentials for the authenticated entity.',
          operationId: 'getCredentials',
          responses: {
            200: {
              description: 'Credentials returned.',
            },
            default: {
              description: 'Request was invalid or cannot be served.',
            },
          },
          security: [
            {
              OAuth2ACG: [OB3_OAUTH_SCOPE_CREDENTIAL_READONLY],
            },
          ],
        },
        post: {
          tags: ['OpenBadgeCredentials'],
          summary: 'Create or update a credential for the authenticated entity.',
          operationId: 'upsertCredential',
          responses: {
            200: {
              description: 'Credential replaced.',
            },
            201: {
              description: 'Credential created.',
            },
            default: {
              description: 'Request was invalid or cannot be served.',
            },
          },
          security: [
            {
              OAuth2ACG: [OB3_OAUTH_SCOPE_CREDENTIAL_UPSERT],
            },
          ],
        },
      },
      '/profile': {
        get: {
          tags: ['OpenBadgeCredentials'],
          summary: 'Get profile for the authenticated entity.',
          operationId: 'getProfile',
          responses: {
            200: {
              description: 'Profile returned.',
            },
            default: {
              description: 'Request was invalid or cannot be served.',
            },
          },
          security: [
            {
              OAuth2ACG: [OB3_OAUTH_SCOPE_PROFILE_READONLY],
            },
          ],
        },
        put: {
          tags: ['OpenBadgeCredentials'],
          summary: 'Update profile for the authenticated entity.',
          operationId: 'putProfile',
          responses: {
            200: {
              description: 'Profile updated.',
            },
            default: {
              description: 'Request was invalid or cannot be served.',
            },
          },
          security: [
            {
              OAuth2ACG: [OB3_OAUTH_SCOPE_PROFILE_UPDATE],
            },
          ],
        },
      },
      '/discovery': {
        get: {
          tags: ['Discovery'],
          summary: 'Get the service description document.',
          operationId: 'getServiceDescription',
          responses: {
            200: {
              description: 'Service description document returned.',
            },
            default: {
              description: 'Request was invalid or cannot be served.',
            },
          },
        },
      },
    },
    components: {
      securitySchemes: {
        OAuth2ACG: {
          type: 'oauth2',
          'x-imssf-registrationUrl': registrationUrl,
          flows: {
            authorizationCode: {
              authorizationUrl,
              tokenUrl,
              refreshUrl,
              scopes: OB3_OAUTH_SCOPE_DESCRIPTIONS,
            },
          },
        },
      },
    },
  };
};

interface OAuthErrorResponse {
  error: string;
  error_description?: string | undefined;
}

interface OAuthClientMetadata {
  clientId: string;
  clientSecretHash: string;
  redirectUris: string[];
  grantTypes: string[];
  responseTypes: string[];
  scope: string[];
  tokenEndpointAuthMethod: string;
}

const oauthErrorJson = (
  c: AppContext,
  status: 400 | 401 | 403 | 500,
  error: string,
  errorDescription?: string,
): Response => {
  return c.json(
    {
      error,
      ...(errorDescription === undefined ? {} : { error_description: errorDescription }),
    } satisfies OAuthErrorResponse,
    status,
  );
};

const oauthTokenErrorJson = (
  c: AppContext,
  status: 400 | 401 | 403 | 500,
  error: string,
  errorDescription?: string,
  includeWwwAuthenticate = false,
): Response => {
  c.header('Cache-Control', 'no-store');
  c.header('Pragma', 'no-cache');

  if (includeWwwAuthenticate) {
    c.header('WWW-Authenticate', 'Basic realm="OAuth2 Token Endpoint"');
  }

  return oauthErrorJson(c, status, error, errorDescription);
};

const oauthTokenSuccessJson = (
  c: AppContext,
  payload: {
    access_token: string;
    token_type: 'Bearer';
    expires_in: number;
    scope: string;
    refresh_token?: string | undefined;
  },
): Response => {
  c.header('Cache-Control', 'no-store');
  c.header('Pragma', 'no-cache');
  return c.json(payload);
};

const ob3ErrorJson = (
  c: AppContext,
  status: 400 | 401 | 403 | 404 | 500,
  description: string,
  options?: {
    includeWwwAuthenticate?: boolean;
  },
): Response => {
  if (options?.includeWwwAuthenticate === true) {
    c.header('WWW-Authenticate', 'Bearer realm="Open Badges API"');
  }

  return c.json(
    {
      imsx_codeMajor: 'failure',
      imsx_severity: 'error',
      imsx_description: description,
    },
    status,
  );
};

const parseBearerAuthorizationHeader = (authorizationHeader: string | undefined): string | null => {
  if (authorizationHeader === undefined) {
    return null;
  }

  const [scheme, token] = authorizationHeader.split(/\s+/, 2);

  if (scheme?.toLowerCase() !== 'bearer') {
    return null;
  }

  const normalizedToken = token?.trim();
  return normalizedToken === undefined || normalizedToken.length === 0 ? null : normalizedToken;
};

interface Ob3AccessTokenContext {
  userId: string;
  tenantId: string;
}

const authenticateOb3AccessToken = async (
  c: AppContext,
  requiredScope: string,
): Promise<Ob3AccessTokenContext | Response> => {
  const bearerToken = parseBearerAuthorizationHeader(c.req.header('authorization'));

  if (bearerToken === null) {
    return ob3ErrorJson(c, 401, 'Bearer access token is required', {
      includeWwwAuthenticate: true,
    });
  }

  const accessTokenHash = await sha256Hex(bearerToken);
  const accessToken = await findActiveOAuthAccessTokenByHash(resolveDatabase(c.env), {
    accessTokenHash,
    nowIso: new Date().toISOString(),
  });

  if (accessToken === null) {
    return ob3ErrorJson(c, 401, 'Access token is invalid or expired', {
      includeWwwAuthenticate: true,
    });
  }

  const scopes = splitSpaceDelimited(accessToken.scope);

  if (!scopes.includes(requiredScope)) {
    return ob3ErrorJson(c, 403, 'Access token does not grant the required scope');
  }

  return {
    userId: accessToken.userId,
    tenantId: accessToken.tenantId,
  };
};

const normalizeOb3ProfileType = (value: unknown): string[] => {
  if (Array.isArray(value)) {
    const normalized = value
      .map((entry) => asNonEmptyString(entry))
      .filter((entry): entry is string => entry !== null);
    const deduplicated = Array.from(new Set<string>(normalized));

    if (!deduplicated.includes('Profile')) {
      deduplicated.push('Profile');
    }

    return deduplicated.length === 0 ? ['Profile'] : deduplicated;
  }

  const singularType = asNonEmptyString(value);

  if (singularType === null) {
    return ['Profile'];
  }

  return singularType === 'Profile' ? ['Profile'] : [singularType, 'Profile'];
};

const ob3ProfileIdForAccessToken = (input: { tenantId: string; userId: string }): string => {
  return `urn:credtrail:profile:${encodeURIComponent(input.tenantId)}:${encodeURIComponent(input.userId)}`;
};

const normalizeOb3Profile = (input: {
  profile: JsonObject;
  tenantId: string;
  userId: string;
}): JsonObject => {
  const normalizedProfile: JsonObject = {
    ...input.profile,
  };
  const fallbackId = ob3ProfileIdForAccessToken({
    tenantId: input.tenantId,
    userId: input.userId,
  });
  normalizedProfile.id = asNonEmptyString(normalizedProfile.id) ?? fallbackId;
  normalizedProfile.type = normalizeOb3ProfileType(normalizedProfile.type);
  return normalizedProfile;
};

const defaultOb3Profile = (input: {
  tenantId: string;
  userId: string;
  email?: string | undefined;
}): JsonObject => {
  return {
    id: ob3ProfileIdForAccessToken({
      tenantId: input.tenantId,
      userId: input.userId,
    }),
    type: ['Profile'],
    ...(input.email === undefined ? {} : { email: input.email, name: input.email }),
  };
};

const parseCompactJwsSegmentObject = (segment: string): JsonObject | null => {
  if (segment.length === 0) {
    return null;
  }

  const normalizedBase64 = segment.replace(/-/g, '+').replace(/_/g, '/');
  const paddedBase64 = `${normalizedBase64}${'='.repeat((4 - (normalizedBase64.length % 4)) % 4)}`;

  try {
    const segmentRaw = atob(paddedBase64);
    return asJsonObject(JSON.parse(segmentRaw) as unknown);
  } catch {
    return null;
  }
};

const parseCompactJwsPayloadObject = (compactJws: string): JsonObject | null => {
  const segments = compactJws.split('.');

  if (segments.length !== 3) {
    return null;
  }

  const payloadSegment = segments[1];

  if (payloadSegment === undefined) {
    return null;
  }

  return parseCompactJwsSegmentObject(payloadSegment);
};

const parseCompactJwsHeaderObject = (compactJws: string): JsonObject | null => {
  const segments = compactJws.split('.');

  if (segments.length !== 3) {
    return null;
  }

  const headerSegment = segments[0];

  if (headerSegment === undefined) {
    return null;
  }

  return parseCompactJwsSegmentObject(headerSegment);
};

const resolveOb3CredentialIdFromCompactJws = (compactJws: string): string => {
  const header = parseCompactJwsHeaderObject(compactJws);
  const payload = parseCompactJwsPayloadObject(compactJws);

  if (header === null || payload === null) {
    throw new Error('Compact JWS must contain JSON JOSE header and payload objects');
  }

  const allowedJoseHeaders = new Set(['alg', 'kid', 'jwk', 'typ']);

  for (const headerName of Object.keys(header)) {
    if (!allowedJoseHeaders.has(headerName)) {
      throw new Error(`JOSE header property "${headerName}" is not supported`);
    }
  }

  const alg = asNonEmptyString(header.alg);
  const typ = asNonEmptyString(header.typ);
  const kid = asNonEmptyString(header.kid);
  const jwk = asJsonObject(header.jwk);

  if (alg === null) {
    throw new Error('JOSE header must include a non-empty alg value');
  }

  if (alg.toLowerCase() === 'none') {
    throw new Error('JOSE header alg must not be "none"');
  }

  if (typ !== null && typ !== 'JWT') {
    throw new Error('JOSE header typ must be "JWT" when provided');
  }

  if (kid === null && jwk === null) {
    throw new Error('JOSE header must include kid or jwk');
  }

  if (jwk !== null && asNonEmptyString(jwk.d) !== null) {
    throw new Error('JOSE header jwk must not include private key material');
  }

  const iss = asNonEmptyString(payload.iss);
  const jti = asNonEmptyString(payload.jti);
  const sub = asNonEmptyString(payload.sub);
  const nbf = payload.nbf;
  const exp = payload.exp;

  if (iss === null) {
    throw new Error('JWT payload must include a non-empty iss claim');
  }

  if (jti === null) {
    throw new Error('JWT payload must include a non-empty jti claim');
  }

  if (typeof nbf !== 'number' || !Number.isFinite(nbf)) {
    throw new Error('JWT payload must include a numeric nbf claim');
  }

  if (sub === null) {
    throw new Error('JWT payload must include a non-empty sub claim');
  }

  if (exp !== undefined && (typeof exp !== 'number' || !Number.isFinite(exp))) {
    throw new Error('JWT payload exp must be numeric when provided');
  }

  return jti;
};

const parsePositiveIntegerQueryParam = (
  value: string | undefined,
  options: {
    minimum: number;
    fallback: number;
  },
): number | null => {
  if (value === undefined) {
    return options.fallback;
  }

  const normalized = Number(value);

  if (
    !Number.isFinite(normalized) ||
    !Number.isInteger(normalized) ||
    normalized < options.minimum
  ) {
    return null;
  }

  return normalized;
};

const normalizeSinceQueryParam = (rawSince: string | undefined): string | null | undefined => {
  if (rawSince === undefined) {
    return undefined;
  }

  const parsedSince = Date.parse(rawSince);

  if (!Number.isFinite(parsedSince)) {
    return null;
  }

  return new Date(parsedSince).toISOString();
};

const ob3CredentialsPageUrl = (input: {
  requestUrl: string;
  limit: number;
  offset: number;
  since: string | undefined;
}): string => {
  const url = new URL(`${OB3_BASE_PATH}/credentials`, input.requestUrl);
  url.searchParams.set('limit', String(input.limit));
  url.searchParams.set('offset', String(input.offset));

  if (input.since !== undefined) {
    url.searchParams.set('since', input.since);
  }

  return url.toString();
};

const ob3CredentialsLinkHeader = (input: {
  requestUrl: string;
  limit: number;
  offset: number;
  totalCount: number;
  since: string | undefined;
}): string => {
  const normalizedLastOffset =
    input.totalCount <= 0
      ? 0
      : Math.floor((Math.max(1, input.totalCount) - 1) / input.limit) * input.limit;
  const links: string[] = [];

  if (input.offset + input.limit < input.totalCount) {
    links.push(
      `<${ob3CredentialsPageUrl({
        requestUrl: input.requestUrl,
        limit: input.limit,
        offset: input.offset + input.limit,
        since: input.since,
      })}>; rel="next"`,
    );
  }

  links.push(
    `<${ob3CredentialsPageUrl({
      requestUrl: input.requestUrl,
      limit: input.limit,
      offset: normalizedLastOffset,
      since: input.since,
    })}>; rel="last"`,
  );
  links.push(
    `<${ob3CredentialsPageUrl({
      requestUrl: input.requestUrl,
      limit: input.limit,
      offset: 0,
      since: input.since,
    })}>; rel="first"`,
  );

  if (input.offset > 0) {
    links.push(
      `<${ob3CredentialsPageUrl({
        requestUrl: input.requestUrl,
        limit: input.limit,
        offset: Math.max(input.offset - input.limit, 0),
        since: input.since,
      })}>; rel="prev"`,
    );
  }

  return links.join(', ');
};

const splitSpaceDelimited = (value: string): string[] => {
  const tokens = value
    .trim()
    .split(/\s+/)
    .map((token) => token.trim())
    .filter((token) => token.length > 0);
  const seen = new Set<string>();
  const uniqueTokens: string[] = [];

  for (const token of tokens) {
    if (!seen.has(token)) {
      seen.add(token);
      uniqueTokens.push(token);
    }
  }

  return uniqueTokens;
};

const allScopesSupported = (scopes: readonly string[]): boolean => {
  for (const scope of scopes) {
    if (!OB3_OAUTH_SUPPORTED_SCOPE_SET.has(scope)) {
      return false;
    }
  }

  return true;
};

const isSubset = (subset: readonly string[], superset: readonly string[]): boolean => {
  const supersetSet = new Set<string>(superset);

  for (const value of subset) {
    if (!supersetSet.has(value)) {
      return false;
    }
  }

  return true;
};

const parseStringArray = (value: unknown): string[] | null => {
  if (!Array.isArray(value)) {
    return null;
  }

  const parsed: string[] = [];

  for (const entry of value) {
    if (typeof entry !== 'string') {
      return null;
    }

    const normalized = entry.trim();

    if (normalized.length === 0) {
      return null;
    }

    parsed.push(normalized);
  }

  return parsed;
};

type RedirectUriValidationError = 'invalid_url' | 'invalid_scheme';

const validateRedirectUri = (redirectUri: string): RedirectUriValidationError | null => {
  let parsedRedirectUri: URL;

  try {
    parsedRedirectUri = new URL(redirectUri);
  } catch {
    return 'invalid_url';
  }

  if (parsedRedirectUri.protocol !== 'https:' && parsedRedirectUri.protocol !== 'http:') {
    return 'invalid_scheme';
  }

  return null;
};

const parseOAuthClientMetadata = (record: {
  clientId: string;
  clientSecretHash: string;
  redirectUrisJson: string;
  grantTypesJson: string;
  responseTypesJson: string;
  scope: string;
  tokenEndpointAuthMethod: string;
}): OAuthClientMetadata | null => {
  let redirectUrisRaw: unknown;
  let grantTypesRaw: unknown;
  let responseTypesRaw: unknown;

  try {
    redirectUrisRaw = JSON.parse(record.redirectUrisJson) as unknown;
    grantTypesRaw = JSON.parse(record.grantTypesJson) as unknown;
    responseTypesRaw = JSON.parse(record.responseTypesJson) as unknown;
  } catch {
    return null;
  }

  const redirectUris = parseStringArray(redirectUrisRaw);
  const grantTypes = parseStringArray(grantTypesRaw);
  const responseTypes = parseStringArray(responseTypesRaw);
  const scope = splitSpaceDelimited(record.scope);

  if (redirectUris === null || redirectUris.length === 0) {
    return null;
  }

  for (const redirectUri of redirectUris) {
    if (validateRedirectUri(redirectUri) !== null) {
      return null;
    }
  }

  if (grantTypes?.length !== 1 || grantTypes[0] !== OAUTH_GRANT_TYPE_AUTHORIZATION_CODE) {
    return null;
  }

  if (responseTypes?.length !== 1 || responseTypes[0] !== OAUTH_RESPONSE_TYPE_CODE) {
    return null;
  }

  if (
    record.tokenEndpointAuthMethod !== OAUTH_TOKEN_ENDPOINT_AUTH_METHOD_CLIENT_SECRET_BASIC ||
    scope.length === 0 ||
    !allScopesSupported(scope)
  ) {
    return null;
  }

  return {
    clientId: record.clientId,
    clientSecretHash: record.clientSecretHash,
    redirectUris,
    grantTypes,
    responseTypes,
    scope,
    tokenEndpointAuthMethod: record.tokenEndpointAuthMethod,
  };
};

const parseBasicAuthorizationHeader = (
  authorizationHeader: string | undefined,
): { clientId: string; clientSecret: string } | null => {
  if (authorizationHeader === undefined) {
    return null;
  }

  const [scheme, credentials] = authorizationHeader.split(/\s+/, 2);

  if (scheme?.toLowerCase() !== 'basic' || credentials === undefined) {
    return null;
  }

  let decodedCredentials: string;

  try {
    decodedCredentials = atob(credentials);
  } catch {
    return null;
  }

  const separatorIndex = decodedCredentials.indexOf(':');

  if (separatorIndex <= 0) {
    return null;
  }

  const clientId = decodedCredentials.slice(0, separatorIndex).trim();
  const clientSecret = decodedCredentials.slice(separatorIndex + 1);

  if (clientId.length === 0 || clientSecret.length === 0) {
    return null;
  }

  return {
    clientId,
    clientSecret,
  };
};

const authenticateOAuthClient = async (
  c: AppContext,
  db: SqlDatabase,
): Promise<{ clientMetadata: OAuthClientMetadata } | Response> => {
  const basicAuth = parseBasicAuthorizationHeader(c.req.header('authorization'));

  if (basicAuth === null) {
    return oauthTokenErrorJson(
      c,
      401,
      'invalid_client',
      'Client authentication with client_secret_basic is required',
      true,
    );
  }

  const registeredClient = await findOAuthClientById(db, basicAuth.clientId);

  if (registeredClient === null) {
    return oauthTokenErrorJson(c, 401, 'invalid_client', 'Unknown client_id', true);
  }

  const providedSecretHash = await sha256Hex(basicAuth.clientSecret);

  if (providedSecretHash !== registeredClient.clientSecretHash) {
    return oauthTokenErrorJson(c, 401, 'invalid_client', 'Client authentication failed', true);
  }

  const clientMetadata = parseOAuthClientMetadata(registeredClient);

  if (clientMetadata === null) {
    return oauthTokenErrorJson(c, 401, 'invalid_client', 'Invalid client registration', true);
  }

  return {
    clientMetadata,
  };
};

const issueOAuthAccessAndRefreshTokens = async (input: {
  db: SqlDatabase;
  clientMetadata: OAuthClientMetadata;
  userId: string;
  tenantId: string;
  scopeTokens: string[];
  nowIso: string;
}): Promise<{
  accessToken: string;
  refreshToken: string;
}> => {
  const accessToken = generateOpaqueToken();
  const refreshToken = generateOpaqueToken();
  const accessTokenHash = await sha256Hex(accessToken);
  const refreshTokenHash = await sha256Hex(refreshToken);

  await createOAuthAccessToken(input.db, {
    clientId: input.clientMetadata.clientId,
    userId: input.userId,
    tenantId: input.tenantId,
    accessTokenHash,
    scope: input.scopeTokens.join(' '),
    expiresAt: addSecondsToIso(input.nowIso, OAUTH_ACCESS_TOKEN_TTL_SECONDS),
  });

  await createOAuthRefreshToken(input.db, {
    clientId: input.clientMetadata.clientId,
    userId: input.userId,
    tenantId: input.tenantId,
    refreshTokenHash,
    scope: input.scopeTokens.join(' '),
    expiresAt: addSecondsToIso(input.nowIso, OAUTH_REFRESH_TOKEN_TTL_SECONDS),
  });

  return {
    accessToken,
    refreshToken,
  };
};

const oauthRedirectUriWithParams = (
  redirectUri: string,
  params: Record<string, string | undefined>,
): string => {
  const redirectTarget = new URL(redirectUri);

  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined) {
      redirectTarget.searchParams.set(key, value);
    }
  }

  return redirectTarget.toString();
};

const BITSTRING_STATUS_LIST_CONTEXT = 'https://w3id.org/vc/status-list/bsl/v1';

const revocationStatusListPathForTenant = (tenantId: string): string => {
  return `/credentials/v1/status-lists/${encodeURIComponent(tenantId)}/revocation`;
};

const revocationStatusListUrlForTenant = (requestUrl: string, tenantId: string): string => {
  return new URL(revocationStatusListPathForTenant(tenantId), requestUrl).toString();
};

const credentialStatusForAssertion = (
  statusListCredentialUrl: string,
  statusListIndex: number,
): CredentialStatusListReference => {
  const statusListIndexString = String(statusListIndex);

  return {
    id: `${statusListCredentialUrl}#${statusListIndexString}`,
    type: 'BitstringStatusListEntry',
    statusPurpose: 'revocation',
    statusListIndex: statusListIndexString,
    statusListCredential: statusListCredentialUrl,
  };
};

const gzipBytes = async (bytes: Uint8Array): Promise<Uint8Array> => {
  const normalizedBytes = Uint8Array.from(bytes);
  const sourceStream = new ReadableStream<BufferSource>({
    start(controller): void {
      controller.enqueue(normalizedBytes);
      controller.close();
    },
  });
  const compressedStream = sourceStream.pipeThrough(new CompressionStream('gzip'));
  const compressedBuffer = await new Response(compressedStream).arrayBuffer();
  return new Uint8Array(compressedBuffer);
};

const base64UrlToBytes = (value: string): Uint8Array | null => {
  if (value.trim().length === 0) {
    return null;
  }

  const normalizedBase64 = value.replace(/-/g, '+').replace(/_/g, '/');
  const paddedBase64 = `${normalizedBase64}${'='.repeat((4 - (normalizedBase64.length % 4)) % 4)}`;

  try {
    const raw = atob(paddedBase64);
    const bytes = new Uint8Array(raw.length);

    for (let index = 0; index < raw.length; index += 1) {
      bytes[index] = raw.charCodeAt(index);
    }

    return bytes;
  } catch {
    return null;
  }
};

const gunzipBytes = async (bytes: Uint8Array): Promise<Uint8Array | null> => {
  try {
    const normalizedBytes = Uint8Array.from(bytes);
    const sourceStream = new ReadableStream<BufferSource>({
      start(controller): void {
        controller.enqueue(normalizedBytes);
        controller.close();
      },
    });
    const decompressedStream = sourceStream.pipeThrough(new DecompressionStream('gzip'));
    const decompressedBuffer = await new Response(decompressedStream).arrayBuffer();
    return new Uint8Array(decompressedBuffer);
  } catch {
    return null;
  }
};

interface RevocationStatusBitEntry {
  statusListIndex: number;
  revoked: boolean;
}

const encodeRevocationBitstring = async (
  statusEntries: readonly RevocationStatusBitEntry[],
): Promise<string> => {
  let maxStatusListIndex = -1;

  for (const entry of statusEntries) {
    if (!Number.isInteger(entry.statusListIndex) || entry.statusListIndex < 0) {
      throw new Error(`Invalid status list index "${String(entry.statusListIndex)}"`);
    }

    maxStatusListIndex = Math.max(maxStatusListIndex, entry.statusListIndex);
  }

  const bitsetLength = maxStatusListIndex < 0 ? 1 : Math.floor(maxStatusListIndex / 8) + 1;
  const bitset = new Uint8Array(bitsetLength);

  for (const entry of statusEntries) {
    if (!entry.revoked) {
      continue;
    }

    const byteIndex = Math.floor(entry.statusListIndex / 8);
    const bitIndex = entry.statusListIndex % 8;
    const currentByte = bitset[byteIndex] ?? 0;
    bitset[byteIndex] = currentByte | (1 << bitIndex);
  }

  const compressed = await gzipBytes(bitset);
  return `u${bytesToBase64Url(compressed)}`;
};

interface BuildRevocationStatusListCredentialInput {
  requestUrl: string;
  tenantId: string;
  issuerDid: string;
  statusEntries: readonly RevocationStatusBitEntry[];
}

const buildRevocationStatusListCredential = async (
  input: BuildRevocationStatusListCredentialInput,
): Promise<{
  credential: JsonObject;
  issuedAt: string;
}> => {
  const statusListCredentialUrl = revocationStatusListUrlForTenant(
    input.requestUrl,
    input.tenantId,
  );
  const encodedList = await encodeRevocationBitstring(input.statusEntries);
  const issuedAt = new Date().toISOString();

  return {
    issuedAt,
    credential: {
      '@context': ['https://www.w3.org/ns/credentials/v2', BITSTRING_STATUS_LIST_CONTEXT],
      id: statusListCredentialUrl,
      type: ['VerifiableCredential', 'BitstringStatusListCredential'],
      issuer: input.issuerDid,
      validFrom: issuedAt,
      credentialSubject: {
        id: `${statusListCredentialUrl}#list`,
        type: 'BitstringStatusList',
        statusPurpose: 'revocation',
        encodedList,
      },
    },
  };
};

const issueBadgeQueueJobFromRequest = (
  request: IssueBadgeRequest,
): { assertionId: string; job: IssueBadgeQueueJob } => {
  const assertionId = createTenantScopedId(request.tenantId);
  const idempotencyKey = request.idempotencyKey ?? crypto.randomUUID();

  const job: IssueBadgeQueueJob = {
    jobType: 'issue_badge',
    tenantId: request.tenantId,
    payload: {
      assertionId,
      badgeTemplateId: request.badgeTemplateId,
      recipientIdentity: request.recipientIdentity,
      recipientIdentityType: request.recipientIdentityType,
      ...(request.recipientIdentifiers === undefined
        ? {}
        : {
            recipientIdentifiers: request.recipientIdentifiers,
          }),
      requestedAt: new Date().toISOString(),
      ...(request.requestedByUserId === undefined
        ? {}
        : {
            requestedByUserId: request.requestedByUserId,
          }),
    },
    idempotencyKey,
  };

  return {
    assertionId,
    job,
  };
};

const revokeBadgeQueueJobFromRequest = (
  request: RevokeBadgeRequest,
): { revocationId: string; job: RevokeBadgeQueueJob } => {
  const revocationId = createTenantScopedId(request.tenantId);
  const idempotencyKey = request.idempotencyKey ?? crypto.randomUUID();

  const job: RevokeBadgeQueueJob = {
    jobType: 'revoke_badge',
    tenantId: request.tenantId,
    payload: {
      revocationId,
      assertionId: request.assertionId,
      reason: request.reason,
      requestedAt: new Date().toISOString(),
      ...(request.requestedByUserId === undefined
        ? {}
        : {
            requestedByUserId: request.requestedByUserId,
          }),
    },
    idempotencyKey,
  };

  return {
    revocationId,
    job,
  };
};

interface ProcessQueueRunResult {
  leased: number;
  processed: number;
  succeeded: number;
  retried: number;
  deadLettered: number;
  failedToFinalize: number;
}

interface ProcessQueueConfig {
  limit: number;
  leaseSeconds: number;
  retryDelaySeconds: number;
}

const processQueueInputWithDefaults = (input: ProcessQueueRequest): ProcessQueueConfig => {
  return {
    limit: input.limit ?? DEFAULT_JOB_PROCESS_LIMIT,
    leaseSeconds: input.leaseSeconds ?? DEFAULT_JOB_PROCESS_LEASE_SECONDS,
    retryDelaySeconds: input.retryDelaySeconds ?? DEFAULT_JOB_PROCESS_RETRY_DELAY_SECONDS,
  };
};

const readJsonBodyOrEmptyObject = async (c: AppContext): Promise<unknown> => {
  const contentLengthHeader = c.req.header('content-length');

  if (contentLengthHeader === undefined || contentLengthHeader === '0') {
    return {};
  }

  return c.req.json<unknown>();
};

const queueJobFromMessage = (message: {
  tenantId: string;
  jobType: QueueJob['jobType'];
  payloadJson: string;
  idempotencyKey: string;
}): QueueJob => {
  let payload: unknown;

  try {
    payload = JSON.parse(message.payloadJson) as unknown;
  } catch {
    throw new Error(`Invalid queue payload JSON for message type "${message.jobType}"`);
  }

  return parseQueueJob({
    jobType: message.jobType,
    tenantId: message.tenantId,
    payload,
    idempotencyKey: message.idempotencyKey,
  });
};

const processQueuedJob = async (c: AppContext, job: QueueJob): Promise<void> => {
  switch (job.jobType) {
    case 'issue_badge':
      await issueBadgeForTenant(
        c,
        job.tenantId,
        {
          badgeTemplateId: job.payload.badgeTemplateId,
          recipientIdentity: job.payload.recipientIdentity,
          recipientIdentityType: job.payload.recipientIdentityType,
          recipientIdentifiers: job.payload.recipientIdentifiers,
          idempotencyKey: job.idempotencyKey,
        },
        job.payload.requestedByUserId,
      );
      return;
    case 'revoke_badge': {
      const revocationResult = await recordAssertionRevocation(resolveDatabase(c.env), {
        tenantId: job.tenantId,
        assertionId: job.payload.assertionId,
        revocationId: job.payload.revocationId,
        reason: job.payload.reason,
        idempotencyKey: job.idempotencyKey,
        revokedByUserId: job.payload.requestedByUserId,
        revokedAt: new Date().toISOString(),
      });
      await createAuditLog(resolveDatabase(c.env), {
        tenantId: job.tenantId,
        ...(job.payload.requestedByUserId === undefined
          ? {}
          : {
              actorUserId: job.payload.requestedByUserId,
            }),
        action: 'assertion.revoked',
        targetType: 'assertion',
        targetId: job.payload.assertionId,
        metadata: {
          revocationId: job.payload.revocationId,
          reason: job.payload.reason,
          status: revocationResult.status,
          revokedAt: revocationResult.revokedAt,
        },
      });
      return;
    }
    case 'rebuild_verification_cache':
    case 'import_migration_batch':
      logInfo(observabilityContext(c.env), 'queue_job_received', {
        jobType: job.jobType,
        tenantId: job.tenantId,
        idempotencyKey: job.idempotencyKey,
      });
      return;
  }
};

const processQueuedJobs = async (
  c: AppContext,
  requestInput: ProcessQueueConfig,
): Promise<ProcessQueueRunResult> => {
  const nowIso = new Date().toISOString();
  const leasedMessages = await leaseJobQueueMessages(resolveDatabase(c.env), {
    limit: requestInput.limit,
    leaseSeconds: requestInput.leaseSeconds,
    nowIso,
  });
  const result: ProcessQueueRunResult = {
    leased: leasedMessages.length,
    processed: 0,
    succeeded: 0,
    retried: 0,
    deadLettered: 0,
    failedToFinalize: 0,
  };

  for (const leasedMessage of leasedMessages) {
    const leaseToken = leasedMessage.leaseToken;

    if (leaseToken === null) {
      result.failedToFinalize += 1;
      continue;
    }

    try {
      const job = queueJobFromMessage(leasedMessage);
      await processQueuedJob(c, job);
      await completeJobQueueMessage(resolveDatabase(c.env), {
        id: leasedMessage.id,
        leaseToken,
        nowIso: new Date().toISOString(),
      });

      result.processed += 1;
      result.succeeded += 1;
    } catch (error: unknown) {
      const detail = error instanceof Error ? error.message : 'Unknown queue processing error';

      await captureSentryException({
        context: observabilityContext(c.env),
        dsn: c.env.SENTRY_DSN,
        error,
        message: 'DB queue job processing failed',
        extra: {
          messageId: leasedMessage.id,
          jobType: leasedMessage.jobType,
          tenantId: leasedMessage.tenantId,
        },
      });

      logError(observabilityContext(c.env), 'queue_job_failed', {
        messageId: leasedMessage.id,
        jobType: leasedMessage.jobType,
        tenantId: leasedMessage.tenantId,
        detail,
      });

      const status = await failJobQueueMessage(resolveDatabase(c.env), {
        id: leasedMessage.id,
        leaseToken,
        nowIso: new Date().toISOString(),
        error: detail,
        retryDelaySeconds: requestInput.retryDelaySeconds,
      });

      result.processed += 1;

      if (status === 'failed') {
        result.deadLettered += 1;
      } else if (status === 'pending') {
        result.retried += 1;
      } else {
        result.failedToFinalize += 1;
      }
    }
  }

  return result;
};

const queueProcessorUrl = (platformDomain: string): string => {
  return `https://${platformDomain}/v1/jobs/process`;
};

const queueProcessorRequestFromSchedule = (env: AppBindings): Request => {
  const headers = new Headers({
    'content-type': 'application/json',
  });
  const processorToken = env.JOB_PROCESSOR_TOKEN?.trim();

  if (processorToken !== undefined && processorToken.length > 0) {
    headers.set('authorization', `Bearer ${processorToken}`);
  }

  return new Request(queueProcessorUrl(env.PLATFORM_DOMAIN), {
    method: 'POST',
    headers,
    body: '{}',
  });
};

const escapeHtml = (value: string): string => {
  return value
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
};

const asJsonObject = (value: unknown): JsonObject | null => {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    return null;
  }

  return value as JsonObject;
};

const asString = (value: unknown): string | null => {
  if (typeof value !== 'string') {
    return null;
  }

  return value;
};

const formatIsoTimestamp = (timestampIso: string): string => {
  const timestampMs = Date.parse(timestampIso);

  if (!Number.isFinite(timestampMs)) {
    return timestampIso;
  }

  return new Intl.DateTimeFormat('en-US', {
    dateStyle: 'medium',
    timeStyle: 'short',
    timeZone: 'UTC',
  }).format(new Date(timestampMs));
};

const linkedInIssuedDateFromIso = (
  issuedAtIso: string,
): {
  issueYear: string;
  issueMonth: string;
} | null => {
  const timestampMs = Date.parse(issuedAtIso);

  if (!Number.isFinite(timestampMs)) {
    return null;
  }

  const issuedAtDate = new Date(timestampMs);
  return {
    issueYear: String(issuedAtDate.getUTCFullYear()),
    issueMonth: String(issuedAtDate.getUTCMonth() + 1),
  };
};

const linkedInAddToProfileUrl = (input: {
  badgeName: string;
  issuerName: string;
  issuedAtIso: string;
  credentialUrl: string;
  credentialId: string;
}): string => {
  const linkedInUrl = new URL('https://www.linkedin.com/profile/add');
  linkedInUrl.searchParams.set('startTask', 'CERTIFICATION_NAME');
  linkedInUrl.searchParams.set('name', input.badgeName);
  linkedInUrl.searchParams.set('certUrl', input.credentialUrl);

  const credentialId = input.credentialId.trim();

  if (credentialId.length > 0) {
    linkedInUrl.searchParams.set('certId', credentialId);
  }

  const issuerName = input.issuerName.trim();

  if (issuerName.length > 0 && issuerName !== 'Unknown issuer') {
    linkedInUrl.searchParams.set('organizationName', issuerName);
  }

  const issuedDate = linkedInIssuedDateFromIso(input.issuedAtIso);

  if (issuedDate !== null) {
    linkedInUrl.searchParams.set('issueYear', issuedDate.issueYear);
    linkedInUrl.searchParams.set('issueMonth', issuedDate.issueMonth);
  }

  return linkedInUrl.toString();
};

const badgeNameFromCredential = (credential: JsonObject): string => {
  const credentialSubject = asJsonObject(credential.credentialSubject);
  const achievement = asJsonObject(credentialSubject?.achievement);
  return asString(achievement?.name) ?? 'Badge credential';
};

const titleCaseWords = (value: string): string => {
  return value
    .split(/\s+/)
    .filter((token) => token.length > 0)
    .map((token) => `${token.slice(0, 1).toUpperCase()}${token.slice(1)}`)
    .join(' ');
};

const humanizedTenantToken = (token: string): string | null => {
  const trimmed = token.trim();

  if (trimmed.length === 0) {
    return null;
  }

  const withoutTenantPrefix = trimmed.replace(/^tenant[_-]?/i, '');
  const normalized = withoutTenantPrefix.replace(/[_-]+/g, ' ').trim();

  if (normalized.length < 2) {
    return null;
  }

  if (/^[a-z0-9]+$/i.test(normalized) && !/[a-z]/i.test(normalized)) {
    return null;
  }

  return titleCaseWords(normalized);
};

const issuerDisplayNameFromDidWeb = (issuerDid: string): string | null => {
  if (!issuerDid.startsWith('did:web:')) {
    return null;
  }

  const encodedSegments = issuerDid.slice('did:web:'.length).split(':');
  const decodedSegments = encodedSegments
    .map((segment) => {
      try {
        return decodeURIComponent(segment);
      } catch {
        return segment;
      }
    })
    .filter((segment) => segment.length > 0);
  const tenantSegment = decodedSegments.at(-1);
  const humanTenant = tenantSegment === undefined ? null : humanizedTenantToken(tenantSegment);

  if (humanTenant !== null) {
    return humanTenant;
  }

  const host = decodedSegments.at(0);

  if (host === undefined) {
    return null;
  }

  if (host === 'credtrail.org' || host.endsWith('.credtrail.org')) {
    return 'CredTrail';
  }

  return host.replace(/^www\./, '');
};

const issuerObjectFromCredential = (credential: JsonObject): JsonObject | null => {
  return asJsonObject(credential.issuer);
};

const issuerNameFromCredential = (credential: JsonObject): string => {
  const issuerAsString = asNonEmptyString(credential.issuer);

  if (issuerAsString !== null) {
    return issuerDisplayNameFromDidWeb(issuerAsString) ?? issuerAsString;
  }

  const issuerObject = issuerObjectFromCredential(credential);
  const issuerName = asNonEmptyString(issuerObject?.name);

  if (issuerName !== null) {
    return issuerName;
  }

  const issuerId = asNonEmptyString(issuerObject?.id);

  if (issuerId !== null) {
    return issuerDisplayNameFromDidWeb(issuerId) ?? issuerId;
  }

  return 'Unknown issuer';
};

const isWebUrl = (value: string): boolean => {
  try {
    const parsedUrl = new URL(value);
    return parsedUrl.protocol === 'http:' || parsedUrl.protocol === 'https:';
  } catch {
    return false;
  }
};

const issuerUrlFromCredential = (credential: JsonObject): string | null => {
  const issuerAsString = asNonEmptyString(credential.issuer);

  if (issuerAsString !== null && isWebUrl(issuerAsString)) {
    return issuerAsString;
  }

  const issuerObject = issuerObjectFromCredential(credential);
  const issuerUrl = linkedDataReferenceId(issuerObject?.url);

  if (issuerUrl !== null) {
    return issuerUrl;
  }

  const issuerId = asNonEmptyString(issuerObject?.id);
  return issuerId !== null && isWebUrl(issuerId) ? issuerId : null;
};

const issuerIdentifierFromCredential = (credential: JsonObject): string | null => {
  const issuerAsString = asNonEmptyString(credential.issuer);

  if (issuerAsString !== null) {
    return issuerAsString;
  }

  const issuerObject = issuerObjectFromCredential(credential);
  return asNonEmptyString(issuerObject?.id);
};

const recipientFromCredential = (credential: JsonObject): string => {
  const credentialSubject = asJsonObject(credential.credentialSubject);
  return asString(credentialSubject?.id) ?? 'Unknown recipient';
};

interface CredentialProofVerificationSummary {
  status: 'valid' | 'invalid' | 'unchecked';
  format: string | null;
  cryptosuite: string | null;
  verificationMethod: string | null;
  reason: string | null;
}

interface CredentialLifecycleVerificationSummary {
  state: 'active' | 'expired' | 'revoked';
  reason: string | null;
  checkedAt: string;
  expiresAt: string | null;
  revokedAt: string | null;
}

interface CredentialStatusListReference extends JsonObject {
  id: string;
  type: string;
  statusPurpose: 'revocation';
  statusListIndex: string;
  statusListCredential: string;
}

interface CredentialVerificationCheckSummary {
  status: 'valid' | 'invalid' | 'unchecked';
  reason: string | null;
}

interface CredentialDateVerificationCheckSummary extends CredentialVerificationCheckSummary {
  validFrom: string | null;
  validUntil: string | null;
}

interface CredentialStatusVerificationCheckSummary extends CredentialVerificationCheckSummary {
  type: string | null;
  statusPurpose: string | null;
  statusListIndex: string | null;
  statusListCredential: string | null;
  revoked: boolean | null;
}

interface CredentialVerificationChecksSummary {
  jsonLdSafeMode: CredentialVerificationCheckSummary;
  credentialSchema: CredentialVerificationCheckSummary;
  credentialSubject: CredentialVerificationCheckSummary;
  dates: CredentialDateVerificationCheckSummary;
  credentialStatus: CredentialStatusVerificationCheckSummary;
}

const parseTimestampMilliseconds = (value: string): number | null => {
  const parsed = Date.parse(value);
  return Number.isNaN(parsed) ? null : parsed;
};

const expirationTimestampFromCredential = (credential: JsonObject): string | null => {
  return asNonEmptyString(credential.validUntil) ?? asNonEmptyString(credential.expirationDate);
};

const summarizeCredentialLifecycleVerification = (
  credential: JsonObject,
  revokedAt: string | null,
  checkedAt: string,
): CredentialLifecycleVerificationSummary => {
  const expiresAt = expirationTimestampFromCredential(credential);
  const checkedAtMilliseconds = parseTimestampMilliseconds(checkedAt) ?? Date.now();

  if (revokedAt !== null) {
    return {
      state: 'revoked',
      reason: 'credential has been revoked by issuer',
      checkedAt,
      expiresAt,
      revokedAt,
    };
  }

  if (expiresAt !== null) {
    const expiresAtMilliseconds = parseTimestampMilliseconds(expiresAt);

    if (expiresAtMilliseconds !== null && expiresAtMilliseconds <= checkedAtMilliseconds) {
      return {
        state: 'expired',
        reason: 'credential validUntil/expirationDate has passed',
        checkedAt,
        expiresAt,
        revokedAt: null,
      };
    }
  }

  return {
    state: 'active',
    reason: null,
    checkedAt,
    expiresAt,
    revokedAt: null,
  };
};

const VC_DATA_MODEL_CONTEXT_URL = 'https://www.w3.org/ns/credentials/v2';

const JSON_LD_KEYWORDS = new Set([
  '@base',
  '@container',
  '@context',
  '@direction',
  '@graph',
  '@id',
  '@import',
  '@included',
  '@index',
  '@json',
  '@language',
  '@list',
  '@nest',
  '@none',
  '@prefix',
  '@propagate',
  '@protected',
  '@reverse',
  '@set',
  '@type',
  '@value',
  '@version',
  '@vocab',
]);

const OB3_SAFE_MODE_KNOWN_TERMS = new Set([
  'id',
  'type',
  'name',
  'description',
  'issuer',
  'image',
  'narrative',
  'criteria',
  'alignment',
  'achievement',
  'achievementType',
  'awardedDate',
  'validFrom',
  'validUntil',
  'issuanceDate',
  'expirationDate',
  'credentialSubject',
  'credentialStatus',
  'credentialSchema',
  'proof',
  'proofPurpose',
  'proofValue',
  'verificationMethod',
  'cryptosuite',
  'created',
  'nonce',
  'challenge',
  'domain',
  'statusPurpose',
  'statusListIndex',
  'statusListCredential',
  'encodedList',
  'identifier',
  'identifierType',
  'result',
  'resultDescription',
  'resultType',
  'evidence',
  'url',
  'endorsement',
  'endorsementJwt',
  'subject',
]);

const collectContextUrls = (value: unknown, output: string[]): void => {
  const stringValue = asNonEmptyString(value);

  if (stringValue !== null) {
    output.push(stringValue);
    return;
  }

  if (!Array.isArray(value)) {
    return;
  }

  for (const entry of value) {
    collectContextUrls(entry, output);
  }
};

const collectInlineContextTerms = (value: unknown, terms: Set<string>): void => {
  if (Array.isArray(value)) {
    for (const entry of value) {
      collectInlineContextTerms(entry, terms);
    }
    return;
  }

  const contextObject = asJsonObject(value);

  if (contextObject === null) {
    return;
  }

  for (const key of Object.keys(contextObject)) {
    if (key.startsWith('@')) {
      continue;
    }

    const normalizedKey = key.trim();

    if (normalizedKey.length > 0) {
      terms.add(normalizedKey);
    }
  }
};

const collectUnknownJsonLdTerms = (
  value: unknown,
  path: string,
  knownTerms: ReadonlySet<string>,
  unknownTermPaths: string[],
): void => {
  if (Array.isArray(value)) {
    for (const [index, entry] of value.entries()) {
      collectUnknownJsonLdTerms(entry, `${path}[${String(index)}]`, knownTerms, unknownTermPaths);
    }
    return;
  }

  const valueObject = asJsonObject(value);

  if (valueObject === null) {
    return;
  }

  for (const [key, entryValue] of Object.entries(valueObject)) {
    if (key.startsWith('@')) {
      if (!JSON_LD_KEYWORDS.has(key)) {
        unknownTermPaths.push(`${path}.${key}`);
      }
    } else if (!key.includes(':') && !knownTerms.has(key)) {
      unknownTermPaths.push(`${path}.${key}`);
    }

    collectUnknownJsonLdTerms(entryValue, `${path}.${key}`, knownTerms, unknownTermPaths);
  }
};

const verifyCredentialJsonLdSafeModeSummary = (
  credential: JsonObject,
): CredentialVerificationCheckSummary => {
  const context = credential['@context'];

  if (context === undefined) {
    return {
      status: 'invalid',
      reason: 'credential is missing @context',
    };
  }

  const contextUrls: string[] = [];
  collectContextUrls(context, contextUrls);

  if (!contextUrls.includes(VC_DATA_MODEL_CONTEXT_URL)) {
    return {
      status: 'invalid',
      reason: 'credential @context must include https://www.w3.org/ns/credentials/v2',
    };
  }

  const knownTerms = new Set<string>(OB3_SAFE_MODE_KNOWN_TERMS);
  collectInlineContextTerms(context, knownTerms);

  const unknownTermPaths: string[] = [];
  collectUnknownJsonLdTerms(credential, '$', knownTerms, unknownTermPaths);

  if (unknownTermPaths.length > 0) {
    return {
      status: 'invalid',
      reason: `credential contains terms not defined by known JSON-LD context entries (${unknownTermPaths
        .slice(0, 3)
        .join(', ')})`,
    };
  }

  return {
    status: 'valid',
    reason: null,
  };
};

const normalizedStringValues = (value: unknown): string[] => {
  const singular = asNonEmptyString(value);

  if (singular !== null) {
    return [singular];
  }

  if (!Array.isArray(value)) {
    return [];
  }

  return value
    .map((entry) => asNonEmptyString(entry))
    .filter((entry): entry is string => entry !== null);
};

const loadJsonObjectFromUrl = async (
  c: AppContext,
  resourceUrl: string,
  acceptHeader: string,
): Promise<{ status: 'ok'; value: JsonObject } | { status: 'error'; reason: string }> => {
  let parsedResourceUrl: URL;

  try {
    parsedResourceUrl = new URL(resourceUrl);
  } catch {
    return {
      status: 'error',
      reason: 'URL is invalid',
    };
  }

  let response: Response;

  try {
    const requestUrl = new URL(c.req.url);

    if (parsedResourceUrl.origin === requestUrl.origin) {
      const pathWithQuery = `${parsedResourceUrl.pathname}${parsedResourceUrl.search}`;
      response = await app.request(
        pathWithQuery,
        {
          method: 'GET',
          headers: {
            accept: acceptHeader,
          },
        },
        c.env,
      );
    } else {
      response = await fetch(resourceUrl, {
        headers: {
          accept: acceptHeader,
        },
      });
    }
  } catch {
    return {
      status: 'error',
      reason: 'request failed',
    };
  }

  if (!response.ok) {
    return {
      status: 'error',
      reason: `HTTP ${String(response.status)}`,
    };
  }

  const responseBody = await response.json<unknown>().catch(() => null);
  const responseObject = asJsonObject(responseBody);

  if (responseObject === null) {
    return {
      status: 'error',
      reason: 'response is not a JSON object',
    };
  }

  return {
    status: 'ok',
    value: responseObject,
  };
};

const schemaRequiredPropertyNames = (schemaObject: JsonObject): string[] => {
  const requiredValue = schemaObject.required;

  if (!Array.isArray(requiredValue)) {
    return [];
  }

  return requiredValue
    .map((entry) => asNonEmptyString(entry))
    .filter((entry): entry is string => entry !== null);
};

const verifyCredentialSchemaSummary = async (
  c: AppContext,
  credential: JsonObject,
): Promise<CredentialVerificationCheckSummary> => {
  const credentialSchemaValue = credential.credentialSchema;

  if (credentialSchemaValue === undefined) {
    return {
      status: 'unchecked',
      reason: null,
    };
  }

  const entries = Array.isArray(credentialSchemaValue)
    ? credentialSchemaValue
    : [credentialSchemaValue];

  if (entries.length === 0) {
    return {
      status: 'invalid',
      reason: 'credentialSchema must include at least one schema entry when present',
    };
  }

  let has1EdTechJsonSchemaValidator = false;

  for (const [index, entry] of entries.entries()) {
    const schemaEntry = asJsonObject(entry);

    if (schemaEntry === null) {
      return {
        status: 'invalid',
        reason: `credentialSchema[${String(index)}] must be a JSON object`,
      };
    }

    const schemaId = asNonEmptyString(schemaEntry.id);
    const schemaTypes = normalizedStringValues(schemaEntry.type);

    if (schemaId === null) {
      return {
        status: 'invalid',
        reason: `credentialSchema[${String(index)}] is missing a non-empty id`,
      };
    }

    if (schemaTypes.length === 0) {
      return {
        status: 'invalid',
        reason: `credentialSchema[${String(index)}] is missing a non-empty type`,
      };
    }

    if (schemaTypes.includes('1EdTechJsonSchemaValidator2019')) {
      has1EdTechJsonSchemaValidator = true;

      const loadedSchema = await loadJsonObjectFromUrl(
        c,
        schemaId,
        'application/schema+json, application/json',
      );

      if (loadedSchema.status !== 'ok') {
        return {
          status: 'invalid',
          reason: `credentialSchema[${String(index)}] schema could not be loaded (${loadedSchema.reason})`,
        };
      }

      const requiredPropertyNames = schemaRequiredPropertyNames(loadedSchema.value);
      const missingRequiredProperties = requiredPropertyNames.filter((propertyName) => {
        return !(propertyName in credential);
      });

      if (missingRequiredProperties.length > 0) {
        return {
          status: 'invalid',
          reason: `credential does not satisfy credentialSchema[${String(index)}] required properties (${missingRequiredProperties
            .slice(0, 3)
            .join(', ')})`,
        };
      }
    }
  }

  if (!has1EdTechJsonSchemaValidator) {
    return {
      status: 'invalid',
      reason: "credentialSchema must include a schema with type '1EdTechJsonSchemaValidator2019'",
    };
  }

  return {
    status: 'valid',
    reason: null,
  };
};

const hasCredentialSubjectIdentifier = (credentialSubject: JsonObject): boolean => {
  const identifierValue = credentialSubject.identifier;

  if (asNonEmptyString(identifierValue) !== null) {
    return true;
  }

  if (Array.isArray(identifierValue)) {
    return identifierValue.some((entry) => {
      const identifierEntryAsString = asNonEmptyString(entry);

      if (identifierEntryAsString !== null) {
        return true;
      }

      const identifierEntryAsObject = asJsonObject(entry);
      return asNonEmptyString(identifierEntryAsObject?.identifier) !== null;
    });
  }

  const identifierEntryAsObject = asJsonObject(identifierValue);
  return asNonEmptyString(identifierEntryAsObject?.identifier) !== null;
};

const verifyCredentialSubjectSummary = (
  credential: JsonObject,
): CredentialVerificationCheckSummary => {
  const credentialSubject = asJsonObject(credential.credentialSubject);

  if (credentialSubject === null) {
    return {
      status: 'invalid',
      reason: 'credentialSubject must be an object',
    };
  }

  const subjectId = asNonEmptyString(credentialSubject.id);
  const hasIdentifier = hasCredentialSubjectIdentifier(credentialSubject);

  if (subjectId === null && !hasIdentifier) {
    return {
      status: 'invalid',
      reason: 'credentialSubject must include id or at least one identifier',
    };
  }

  const credentialTypes = normalizedStringValues(credential.type);

  if (credentialTypes.includes('OpenBadgeCredential')) {
    const achievement = asJsonObject(credentialSubject.achievement);

    if (achievement === null) {
      return {
        status: 'invalid',
        reason: 'credentialSubject.achievement must be an object for OpenBadgeCredential',
      };
    }

    const achievementTypes = normalizedStringValues(achievement.type);

    if (!achievementTypes.includes('Achievement')) {
      return {
        status: 'invalid',
        reason:
          'credentialSubject.achievement.type must include Achievement for OpenBadgeCredential',
      };
    }
  }

  return {
    status: 'valid',
    reason: null,
  };
};

const validFromTimestampFromCredential = (credential: JsonObject): string | null => {
  return asNonEmptyString(credential.validFrom) ?? asNonEmptyString(credential.issuanceDate);
};

const verifyCredentialDatesSummary = (
  credential: JsonObject,
  checkedAt: string,
): CredentialDateVerificationCheckSummary => {
  const validFrom = validFromTimestampFromCredential(credential);
  const validUntil = expirationTimestampFromCredential(credential);

  if (validFrom === null) {
    return {
      status: 'invalid',
      reason: 'credential must include validFrom or issuanceDate',
      validFrom,
      validUntil,
    };
  }

  const validFromMilliseconds = parseTimestampMilliseconds(validFrom);

  if (validFromMilliseconds === null) {
    return {
      status: 'invalid',
      reason: 'credential validFrom/issuanceDate must be a valid ISO timestamp',
      validFrom,
      validUntil,
    };
  }

  const validUntilMilliseconds =
    validUntil === null ? null : parseTimestampMilliseconds(validUntil);

  if (validUntil !== null && validUntilMilliseconds === null) {
    return {
      status: 'invalid',
      reason: 'credential validUntil/expirationDate must be a valid ISO timestamp',
      validFrom,
      validUntil,
    };
  }

  if (validUntilMilliseconds !== null && validUntilMilliseconds < validFromMilliseconds) {
    return {
      status: 'invalid',
      reason:
        'credential validUntil/expirationDate must not be earlier than validFrom/issuanceDate',
      validFrom,
      validUntil,
    };
  }

  const checkedAtMilliseconds = parseTimestampMilliseconds(checkedAt) ?? Date.now();

  if (validFromMilliseconds > checkedAtMilliseconds) {
    return {
      status: 'invalid',
      reason: 'credential validFrom/issuanceDate is in the future',
      validFrom,
      validUntil,
    };
  }

  return {
    status: 'valid',
    reason: null,
    validFrom,
    validUntil,
  };
};

const parseStatusListIndex = (value: string): number | null => {
  if (!/^\d+$/.test(value)) {
    return null;
  }

  const parsed = Number.parseInt(value, 10);
  return Number.isInteger(parsed) && parsed >= 0 ? parsed : null;
};

const decodedRevocationStatusBit = async (
  encodedList: string,
  statusListIndex: number,
): Promise<boolean | null> => {
  if (!encodedList.startsWith('u')) {
    return null;
  }

  const compressedBytes = base64UrlToBytes(encodedList.slice(1));

  if (compressedBytes === null) {
    return null;
  }

  const bitset = await gunzipBytes(compressedBytes);

  if (bitset === null) {
    return null;
  }

  const byteIndex = Math.floor(statusListIndex / 8);
  const bitIndex = statusListIndex % 8;

  if (byteIndex >= bitset.length) {
    return null;
  }

  const byte = bitset[byteIndex] ?? 0;
  return (byte & (1 << bitIndex)) !== 0;
};

const loadStatusListCredentialForVerification = async (
  c: AppContext,
  statusListCredentialUrl: string,
): Promise<{ status: 'ok'; credential: JsonObject } | { status: 'error'; reason: string }> => {
  const loadedCredential = await loadJsonObjectFromUrl(
    c,
    statusListCredentialUrl,
    'application/ld+json, application/json',
  );

  if (loadedCredential.status !== 'ok') {
    return {
      status: 'error',
      reason: `credential status list could not be retrieved (${loadedCredential.reason})`,
    };
  }

  return {
    status: 'ok',
    credential: loadedCredential.value,
  };
};

const verifyCredentialStatusSummary = async (
  c: AppContext,
  credential: JsonObject,
  expectedStatusList: CredentialStatusListReference | null,
): Promise<CredentialStatusVerificationCheckSummary> => {
  const credentialStatus = credential.credentialStatus;

  if (credentialStatus === undefined) {
    return {
      status: expectedStatusList === null ? 'unchecked' : 'invalid',
      reason:
        expectedStatusList === null
          ? null
          : 'credentialStatus is required when revocation metadata is configured',
      type: null,
      statusPurpose: null,
      statusListIndex: null,
      statusListCredential: null,
      revoked: null,
    };
  }

  const credentialStatusObject = asJsonObject(credentialStatus);

  if (credentialStatusObject === null) {
    return {
      status: 'invalid',
      reason: 'credentialStatus must be a JSON object',
      type: null,
      statusPurpose: null,
      statusListIndex: null,
      statusListCredential: null,
      revoked: null,
    };
  }

  const statusType = asNonEmptyString(credentialStatusObject.type);
  const statusPurpose = asNonEmptyString(credentialStatusObject.statusPurpose);
  const statusListIndex = asNonEmptyString(credentialStatusObject.statusListIndex);
  const statusListCredential = asNonEmptyString(credentialStatusObject.statusListCredential);

  if (expectedStatusList === null) {
    return {
      status: 'invalid',
      reason: 'credentialStatus is present but no revocation metadata exists for this credential',
      type: statusType,
      statusPurpose,
      statusListIndex,
      statusListCredential,
      revoked: null,
    };
  }

  if (
    statusType === null ||
    statusListIndex === null ||
    statusListCredential === null ||
    (statusPurpose !== null && statusPurpose !== 'revocation')
  ) {
    return {
      status: 'invalid',
      reason: 'credentialStatus is missing required Bitstring status list fields',
      type: statusType,
      statusPurpose,
      statusListIndex,
      statusListCredential,
      revoked: null,
    };
  }

  if (statusType !== 'BitstringStatusListEntry' && statusType !== '1EdTechRevocationList') {
    return {
      status: 'invalid',
      reason: 'credentialStatus type must be BitstringStatusListEntry or 1EdTechRevocationList',
      type: statusType,
      statusPurpose,
      statusListIndex,
      statusListCredential,
      revoked: null,
    };
  }

  if (statusListIndex !== expectedStatusList.statusListIndex) {
    return {
      status: 'invalid',
      reason:
        'credentialStatus statusListIndex does not match the expected credential revocation index',
      type: statusType,
      statusPurpose,
      statusListIndex,
      statusListCredential,
      revoked: null,
    };
  }

  if (statusListCredential !== expectedStatusList.statusListCredential) {
    return {
      status: 'invalid',
      reason:
        'credentialStatus statusListCredential does not match the expected revocation list URL',
      type: statusType,
      statusPurpose,
      statusListIndex,
      statusListCredential,
      revoked: null,
    };
  }

  const normalizedStatusListIndex = parseStatusListIndex(statusListIndex);

  if (normalizedStatusListIndex === null) {
    return {
      status: 'invalid',
      reason: 'credentialStatus statusListIndex must be a non-negative integer string',
      type: statusType,
      statusPurpose,
      statusListIndex,
      statusListCredential,
      revoked: null,
    };
  }

  const statusListCredentialResult = await loadStatusListCredentialForVerification(
    c,
    statusListCredential,
  );

  if (statusListCredentialResult.status !== 'ok') {
    return {
      status: 'invalid',
      reason: statusListCredentialResult.reason,
      type: statusType,
      statusPurpose,
      statusListIndex,
      statusListCredential,
      revoked: null,
    };
  }

  const statusListCredentialSubject = asJsonObject(
    statusListCredentialResult.credential.credentialSubject,
  );
  const encodedList = asNonEmptyString(statusListCredentialSubject?.encodedList);

  if (encodedList === null) {
    return {
      status: 'invalid',
      reason: 'credential status list is missing credentialSubject.encodedList',
      type: statusType,
      statusPurpose,
      statusListIndex,
      statusListCredential,
      revoked: null,
    };
  }

  const revoked = await decodedRevocationStatusBit(encodedList, normalizedStatusListIndex);

  if (revoked === null) {
    return {
      status: 'invalid',
      reason:
        'credential status list encodedList could not be decoded for the specified statusListIndex',
      type: statusType,
      statusPurpose,
      statusListIndex,
      statusListCredential,
      revoked: null,
    };
  }

  return {
    status: 'valid',
    reason: null,
    type: statusType,
    statusPurpose: statusPurpose ?? 'revocation',
    statusListIndex,
    statusListCredential,
    revoked,
  };
};

const summarizeCredentialVerificationChecks = async (input: {
  context: AppContext;
  credential: JsonObject;
  checkedAt: string;
  expectedStatusList: CredentialStatusListReference | null;
}): Promise<CredentialVerificationChecksSummary> => {
  return {
    jsonLdSafeMode: verifyCredentialJsonLdSafeModeSummary(input.credential),
    credentialSchema: await verifyCredentialSchemaSummary(input.context, input.credential),
    credentialSubject: verifyCredentialSubjectSummary(input.credential),
    dates: verifyCredentialDatesSummary(input.credential, input.checkedAt),
    credentialStatus: await verifyCredentialStatusSummary(
      input.context,
      input.credential,
      input.expectedStatusList,
    ),
  };
};

const selectCredentialProofObject = (credential: JsonObject): JsonObject | null => {
  const credentialProofValue = credential.proof;
  const singleProof = asJsonObject(credentialProofValue);

  if (singleProof !== null) {
    return singleProof;
  }

  if (!Array.isArray(credentialProofValue)) {
    return null;
  }

  const proofEntries = credentialProofValue
    .map((entry) => asJsonObject(entry))
    .filter((entry) => entry !== null);
  const assertionMethodEntry = proofEntries.find((entry) => {
    return asNonEmptyString(entry.proofPurpose) === 'assertionMethod';
  });

  return assertionMethodEntry ?? proofEntries[0] ?? null;
};

const resolveVerificationPublicJwkForDidKeyId = (input: {
  context: AppContext;
  did: string;
  keyId: string;
  activeSigningEntry: TenantSigningRegistryEntry;
}): SigningPublicJwk | null => {
  if (input.keyId === input.activeSigningEntry.keyId) {
    return input.activeSigningEntry.publicJwk;
  }

  const historicalEntry = resolveHistoricalSigningKeysForDid(input.context, input.did).find(
    (entry) => {
      return entry.keyId === input.keyId;
    },
  );

  return historicalEntry?.publicJwk ?? null;
};

const verifyCredentialProofSummary = async (
  c: AppContext,
  credential: JsonObject,
): Promise<CredentialProofVerificationSummary> => {
  const proof = selectCredentialProofObject(credential);

  if (proof === null) {
    return {
      status: 'unchecked',
      format: null,
      cryptosuite: null,
      verificationMethod: null,
      reason: 'credential has no proof object',
    };
  }

  const proofType = asNonEmptyString(proof.type);
  const proofValue = asNonEmptyString(proof.proofValue);
  const proofPurpose = asNonEmptyString(proof.proofPurpose);
  const verificationMethod = asNonEmptyString(proof.verificationMethod);
  const verificationMethodParts =
    verificationMethod === null ? null : verificationMethod.split('#', 2);
  const verificationMethodKeyId =
    verificationMethodParts === null
      ? null
      : (() => {
          const [, keyId] = verificationMethodParts;
          return keyId === undefined || keyId.length === 0 ? null : keyId;
        })();
  const methodDid =
    verificationMethodParts === null
      ? null
      : (() => {
          const [didPart] = verificationMethodParts;
          return didPart === undefined || didPart.length === 0 ? null : didPart;
        })();
  const issuerIdentifier = issuerIdentifierFromCredential(credential);
  const issuerDidFromCredential = issuerIdentifier?.startsWith('did:') ? issuerIdentifier : null;
  const issuerDid = methodDid ?? issuerIdentifier;

  if (
    proofType === null ||
    proofValue === null ||
    proofPurpose === null ||
    verificationMethod === null
  ) {
    return {
      status: 'invalid',
      format: proofType,
      cryptosuite: asNonEmptyString(proof.cryptosuite),
      verificationMethod,
      reason: 'proof object is missing required fields',
    };
  }

  if (proofPurpose !== 'assertionMethod') {
    return {
      status: 'invalid',
      format: proofType,
      cryptosuite: asNonEmptyString(proof.cryptosuite),
      verificationMethod,
      reason: 'proofPurpose must be assertionMethod',
    };
  }

  if (verificationMethodKeyId === null) {
    return {
      status: 'invalid',
      format: proofType,
      cryptosuite: asNonEmptyString(proof.cryptosuite),
      verificationMethod,
      reason: 'verificationMethod must include a key fragment',
    };
  }

  if (
    methodDid !== null &&
    issuerDidFromCredential !== null &&
    methodDid !== issuerDidFromCredential
  ) {
    return {
      status: 'invalid',
      format: proofType,
      cryptosuite: asNonEmptyString(proof.cryptosuite),
      verificationMethod,
      reason: 'verificationMethod DID must match credential issuer DID',
    };
  }

  if (!issuerDid?.startsWith('did:')) {
    return {
      status: 'unchecked',
      format: proofType,
      cryptosuite: asNonEmptyString(proof.cryptosuite),
      verificationMethod,
      reason: 'issuer DID could not be resolved for proof verification',
    };
  }

  const signingEntry = await resolveSigningEntryForDid(c, issuerDid);

  if (signingEntry === null) {
    return {
      status: 'unchecked',
      format: proofType,
      cryptosuite: asNonEmptyString(proof.cryptosuite),
      verificationMethod,
      reason: `no signing configuration for issuer DID ${issuerDid}`,
    };
  }

  if (verificationMethodKeyId !== signingEntry.keyId) {
    const historicalPublicJwk = resolveVerificationPublicJwkForDidKeyId({
      context: c,
      did: issuerDid,
      keyId: verificationMethodKeyId,
      activeSigningEntry: signingEntry,
    });

    if (historicalPublicJwk === null) {
      return {
        status: 'invalid',
        format: proofType,
        cryptosuite: asNonEmptyString(proof.cryptosuite),
        verificationMethod,
        reason: 'verificationMethod key fragment must match an active or historical signing key id',
      };
    }

    if (proofType === 'Ed25519Signature2020') {
      if (!isEd25519SigningPublicJwk(historicalPublicJwk)) {
        return {
          status: 'invalid',
          format: proofType,
          cryptosuite: null,
          verificationMethod,
          reason: 'Ed25519Signature2020 requires an Ed25519 public key',
        };
      }

      const isValid = await verifyCredentialProofWithEd25519Signature2020({
        credential: {
          ...credential,
          proof: {
            type: 'Ed25519Signature2020',
            created: asString(proof.created) ?? '',
            proofPurpose: 'assertionMethod',
            verificationMethod,
            proofValue,
          },
        },
        publicJwk: toEd25519PublicJwk(historicalPublicJwk),
      });

      return {
        status: isValid ? 'valid' : 'invalid',
        format: proofType,
        cryptosuite: null,
        verificationMethod,
        reason: isValid ? null : 'signature verification failed',
      };
    }

    if (proofType === 'DataIntegrityProof') {
      const cryptosuite = asNonEmptyString(proof.cryptosuite);

      if (cryptosuite !== 'eddsa-rdfc-2022' && cryptosuite !== 'ecdsa-sd-2023') {
        return {
          status: 'invalid',
          format: proofType,
          cryptosuite,
          verificationMethod,
          reason: 'unsupported Data Integrity cryptosuite',
        };
      }

      let verificationPublicJwk: Ed25519PublicJwk | P256PublicJwk;

      if (cryptosuite === 'eddsa-rdfc-2022') {
        if (!isEd25519SigningPublicJwk(historicalPublicJwk)) {
          return {
            status: 'invalid',
            format: proofType,
            cryptosuite,
            verificationMethod,
            reason: 'eddsa-rdfc-2022 requires an Ed25519 public key',
          };
        }

        verificationPublicJwk = toEd25519PublicJwk(historicalPublicJwk);
      } else {
        if (!isP256SigningPublicJwk(historicalPublicJwk)) {
          return {
            status: 'invalid',
            format: proofType,
            cryptosuite,
            verificationMethod,
            reason: 'ecdsa-sd-2023 requires a P-256 public key',
          };
        }

        verificationPublicJwk = toP256PublicJwk(historicalPublicJwk);
      }

      const isValid = await verifyCredentialProofWithDataIntegrity({
        credential: {
          ...credential,
          proof: {
            type: 'DataIntegrityProof',
            cryptosuite,
            created: asString(proof.created) ?? '',
            proofPurpose: 'assertionMethod',
            verificationMethod,
            proofValue,
          },
        },
        publicJwk: verificationPublicJwk,
      });

      return {
        status: isValid ? 'valid' : 'invalid',
        format: proofType,
        cryptosuite,
        verificationMethod,
        reason: isValid ? null : 'signature verification failed',
      };
    }

    return {
      status: 'unchecked',
      format: proofType,
      cryptosuite: asNonEmptyString(proof.cryptosuite),
      verificationMethod,
      reason: 'proof format is not currently supported',
    };
  }

  if (proofType === 'Ed25519Signature2020') {
    if (!isEd25519SigningPublicJwk(signingEntry.publicJwk)) {
      return {
        status: 'invalid',
        format: proofType,
        cryptosuite: null,
        verificationMethod,
        reason: 'Ed25519Signature2020 requires an Ed25519 public key',
      };
    }

    const isValid = await verifyCredentialProofWithEd25519Signature2020({
      credential: {
        ...credential,
        proof: {
          type: 'Ed25519Signature2020',
          created: asString(proof.created) ?? '',
          proofPurpose: 'assertionMethod',
          verificationMethod,
          proofValue,
        },
      },
      publicJwk: toEd25519PublicJwk(signingEntry.publicJwk),
    });

    return {
      status: isValid ? 'valid' : 'invalid',
      format: proofType,
      cryptosuite: null,
      verificationMethod,
      reason: isValid ? null : 'signature verification failed',
    };
  }

  if (proofType === 'DataIntegrityProof') {
    const cryptosuite = asNonEmptyString(proof.cryptosuite);

    if (cryptosuite !== 'eddsa-rdfc-2022' && cryptosuite !== 'ecdsa-sd-2023') {
      return {
        status: 'invalid',
        format: proofType,
        cryptosuite,
        verificationMethod,
        reason: 'unsupported Data Integrity cryptosuite',
      };
    }

    let verificationPublicJwk: Ed25519PublicJwk | P256PublicJwk;

    if (cryptosuite === 'eddsa-rdfc-2022') {
      const signingPublicJwk = signingEntry.publicJwk;

      if (!isEd25519SigningPublicJwk(signingPublicJwk)) {
        return {
          status: 'invalid',
          format: proofType,
          cryptosuite,
          verificationMethod,
          reason: 'eddsa-rdfc-2022 requires an Ed25519 public key',
        };
      }

      verificationPublicJwk = toEd25519PublicJwk(signingPublicJwk);
    } else {
      const signingPublicJwk = signingEntry.publicJwk;

      if (!isP256SigningPublicJwk(signingPublicJwk)) {
        return {
          status: 'invalid',
          format: proofType,
          cryptosuite,
          verificationMethod,
          reason: 'ecdsa-sd-2023 requires a P-256 public key',
        };
      }

      verificationPublicJwk = toP256PublicJwk(signingPublicJwk);
    }

    const isValid = await verifyCredentialProofWithDataIntegrity({
      credential: {
        ...credential,
        proof: {
          type: 'DataIntegrityProof',
          cryptosuite,
          created: asString(proof.created) ?? '',
          proofPurpose: 'assertionMethod',
          verificationMethod,
          proofValue,
        },
      },
      publicJwk: verificationPublicJwk,
    });

    return {
      status: isValid ? 'valid' : 'invalid',
      format: proofType,
      cryptosuite,
      verificationMethod,
      reason: isValid ? null : 'signature verification failed',
    };
  }

  return {
    status: 'unchecked',
    format: proofType,
    cryptosuite: asNonEmptyString(proof.cryptosuite),
    verificationMethod,
    reason: 'proof format is not currently supported',
  };
};

type SupportedCredentialProofType = 'Ed25519Signature2020' | 'DataIntegrityProof';

interface SignCredentialForDidInput {
  context: AppContext;
  did: string;
  credential: JsonObject;
  proofType: SupportedCredentialProofType;
  cryptosuite?: DataIntegrityCryptosuite;
  createdAt?: string;
  missingPrivateKeyError?: string;
  ed25519KeyRequirementError?: string;
}

type SignCredentialErrorStatusCode = 400 | 404 | 422 | 500 | 502;

type SignCredentialForDidResult =
  | {
      status: 'ok';
      keyId: string;
      verificationMethod: string;
      credential: JsonObject;
    }
  | {
      status: 'error';
      statusCode: SignCredentialErrorStatusCode;
      error: string;
      did: string;
    };

const signCredentialWithRemoteSigner = async (input: {
  did: string;
  keyId: string;
  verificationMethod: string;
  credential: JsonObject;
  proofType: SupportedCredentialProofType;
  cryptosuite?: DataIntegrityCryptosuite;
  createdAt?: string;
  remoteSigner: RemoteSignerRegistryEntry;
}): Promise<
  | {
      status: 'ok';
      credential: JsonObject;
    }
  | {
      status: 'error';
      reason: string;
    }
> => {
  const abortController = new AbortController();
  const timeoutHandle: ReturnType<typeof setTimeout> = setTimeout(() => {
    abortController.abort('remote-signer-timeout');
  }, input.remoteSigner.timeoutMs);

  let response: Response;

  try {
    const headers: Record<string, string> = {
      'content-type': 'application/json',
      accept: 'application/json',
    };

    if (input.remoteSigner.authorizationHeader !== null) {
      headers.authorization = input.remoteSigner.authorizationHeader;
    }

    response = await fetch(input.remoteSigner.url, {
      method: 'POST',
      headers,
      body: JSON.stringify({
        did: input.did,
        keyId: input.keyId,
        verificationMethod: input.verificationMethod,
        proofType: input.proofType,
        ...(input.cryptosuite === undefined ? {} : { cryptosuite: input.cryptosuite }),
        ...(input.createdAt === undefined ? {} : { createdAt: input.createdAt }),
        credential: input.credential,
      }),
      signal: abortController.signal,
    });
  } catch {
    return {
      status: 'error',
      reason: 'request to remote signer failed',
    };
  } finally {
    clearTimeout(timeoutHandle);
  }

  if (!response.ok) {
    return {
      status: 'error',
      reason: `remote signer returned HTTP ${String(response.status)}`,
    };
  }

  const responseBody = await response.json<unknown>().catch(() => null);
  const responseObject = asJsonObject(responseBody);
  const signedCredential = asJsonObject(responseObject?.credential);

  if (signedCredential === null) {
    return {
      status: 'error',
      reason: 'remote signer response is missing a JSON credential object',
    };
  }

  const signedProof = selectCredentialProofObject(signedCredential);

  if (signedProof === null) {
    return {
      status: 'error',
      reason: 'remote signer credential is missing a proof object',
    };
  }

  const signedProofType = asNonEmptyString(signedProof.type);
  const signedVerificationMethod = asNonEmptyString(signedProof.verificationMethod);

  if (
    signedProofType !== input.proofType ||
    signedVerificationMethod !== input.verificationMethod
  ) {
    return {
      status: 'error',
      reason: 'remote signer proof metadata does not match requested proof parameters',
    };
  }

  if (input.proofType === 'DataIntegrityProof' && input.cryptosuite !== undefined) {
    const signedCryptosuite = asNonEmptyString(signedProof.cryptosuite);

    if (signedCryptosuite !== input.cryptosuite) {
      return {
        status: 'error',
        reason: 'remote signer proof cryptosuite does not match requested cryptosuite',
      };
    }
  }

  return {
    status: 'ok',
    credential: signedCredential,
  };
};

const signCredentialForDid = async (
  input: SignCredentialForDidInput,
): Promise<SignCredentialForDidResult> => {
  const signingEntry = await resolveSigningEntryForDid(input.context, input.did);

  if (signingEntry === null) {
    return {
      status: 'error',
      statusCode: 404,
      error: 'No signing configuration for requested DID',
      did: input.did,
    };
  }

  const verificationMethod = `${input.did}#${signingEntry.keyId}`;

  if (input.proofType === 'DataIntegrityProof' && input.cryptosuite === undefined) {
    return {
      status: 'error',
      statusCode: 400,
      error: 'DataIntegrityProof signing requires a cryptosuite value',
      did: input.did,
    };
  }

  if (signingEntry.privateJwk !== undefined) {
    let signedCredential: JsonObject;

    if (input.proofType === 'DataIntegrityProof') {
      const cryptosuite = input.cryptosuite;

      if (cryptosuite === undefined) {
        return {
          status: 'error',
          statusCode: 400,
          error: 'DataIntegrityProof signing requires a cryptosuite value',
          did: input.did,
        };
      }

      if (cryptosuite === 'eddsa-rdfc-2022') {
        if (!isEd25519SigningPrivateJwk(signingEntry.privateJwk)) {
          return {
            status: 'error',
            statusCode: 422,
            error: 'DataIntegrity eddsa-rdfc-2022 signing requires an Ed25519 private key',
            did: input.did,
          };
        }

        signedCredential = await signCredentialWithDataIntegrityProof({
          credential: input.credential,
          privateJwk: toEd25519PrivateJwk(signingEntry.privateJwk),
          verificationMethod,
          cryptosuite,
          ...(input.createdAt === undefined ? {} : { createdAt: input.createdAt }),
        });
      } else {
        if (!isP256SigningPrivateJwk(signingEntry.privateJwk)) {
          return {
            status: 'error',
            statusCode: 422,
            error: 'DataIntegrity ecdsa-sd-2023 signing requires a P-256 private key',
            did: input.did,
          };
        }

        signedCredential = await signCredentialWithDataIntegrityProof({
          credential: input.credential,
          privateJwk: toP256PrivateJwk(signingEntry.privateJwk),
          verificationMethod,
          cryptosuite,
          ...(input.createdAt === undefined ? {} : { createdAt: input.createdAt }),
        });
      }
    } else {
      if (!isEd25519SigningPrivateJwk(signingEntry.privateJwk)) {
        return {
          status: 'error',
          statusCode: 422,
          error:
            input.ed25519KeyRequirementError ??
            'Credential signing endpoint requires an Ed25519 private key',
          did: input.did,
        };
      }

      signedCredential = await signCredentialWithEd25519Signature2020({
        credential: input.credential,
        privateJwk: toEd25519PrivateJwk(signingEntry.privateJwk),
        verificationMethod,
        ...(input.createdAt === undefined ? {} : { createdAt: input.createdAt }),
      });
    }

    return {
      status: 'ok',
      keyId: signingEntry.keyId,
      verificationMethod,
      credential: signedCredential,
    };
  }

  const remoteSigner = resolveRemoteSignerRegistryEntryForDid(input.context, input.did);

  if (remoteSigner === null) {
    return {
      status: 'error',
      statusCode: 500,
      error:
        input.missingPrivateKeyError ??
        'DID is missing private signing key material and no remote signer is configured',
      did: input.did,
    };
  }

  const remoteSignerResult = await signCredentialWithRemoteSigner({
    did: input.did,
    keyId: signingEntry.keyId,
    verificationMethod,
    credential: input.credential,
    proofType: input.proofType,
    ...(input.cryptosuite === undefined ? {} : { cryptosuite: input.cryptosuite }),
    ...(input.createdAt === undefined ? {} : { createdAt: input.createdAt }),
    remoteSigner,
  });

  if (remoteSignerResult.status !== 'ok') {
    return {
      status: 'error',
      statusCode: 502,
      error: `Remote signer request failed: ${remoteSignerResult.reason}`,
      did: input.did,
    };
  }

  return {
    status: 'ok',
    keyId: signingEntry.keyId,
    verificationMethod,
    credential: remoteSignerResult.credential,
  };
};

interface PresentationCredentialBindingSummary {
  status: 'valid' | 'invalid';
  reason: string | null;
}

interface PresentationCredentialVerificationResult {
  credentialId: string | null;
  subjectId: string | null;
  binding: PresentationCredentialBindingSummary;
  proof: CredentialProofVerificationSummary;
  checks: CredentialVerificationChecksSummary;
  lifecycle: CredentialLifecycleVerificationSummary;
  status: 'valid' | 'invalid';
}

const didKeyMultibaseFromDid = (did: string): string | null => {
  if (!did.startsWith('did:key:')) {
    return null;
  }

  const multibase = did.slice('did:key:'.length).trim();
  return multibase.length === 0 ? null : multibase;
};

const didKeyVerificationMethod = (did: string): string | null => {
  const multibase = didKeyMultibaseFromDid(did);
  return multibase === null ? null : did + '#' + multibase;
};

const ed25519PublicJwkFromDidKey = (did: string): Ed25519PublicJwk | null => {
  const multibase = didKeyMultibaseFromDid(did);

  if (multibase === null) {
    return null;
  }

  try {
    return {
      kty: 'OKP',
      crv: 'Ed25519',
      x: decodeJwkPublicKeyMultibase(multibase),
    };
  } catch {
    return null;
  }
};

const verifiableCredentialObjectsFromPresentation = (
  presentation: JsonObject,
): JsonObject[] | null => {
  const verifiableCredentialValue = presentation.verifiableCredential;

  if (!Array.isArray(verifiableCredentialValue)) {
    return null;
  }

  const credentials: JsonObject[] = [];

  for (const entry of verifiableCredentialValue) {
    const credential = asJsonObject(entry);

    if (credential === null) {
      return null;
    }

    credentials.push(credential);
  }

  return credentials;
};

const statusListReferenceFromCredentialForPresentation = (
  credential: JsonObject,
): CredentialStatusListReference | null => {
  const credentialStatus = asJsonObject(credential.credentialStatus);

  if (credentialStatus === null) {
    return null;
  }

  const type = asNonEmptyString(credentialStatus.type);
  const statusPurpose = asNonEmptyString(credentialStatus.statusPurpose) ?? 'revocation';
  const statusListIndex = asNonEmptyString(credentialStatus.statusListIndex);
  const statusListCredential = asNonEmptyString(credentialStatus.statusListCredential);

  if (
    type === null ||
    statusListIndex === null ||
    statusListCredential === null ||
    statusPurpose !== 'revocation'
  ) {
    return null;
  }

  return {
    id: statusListCredential + '#' + statusListIndex,
    type,
    statusPurpose: 'revocation',
    statusListIndex,
    statusListCredential,
  };
};

const credentialChecksPassPresentationPolicy = (
  checks: CredentialVerificationChecksSummary,
): boolean => {
  return (
    checks.jsonLdSafeMode.status === 'valid' &&
    checks.credentialSchema.status !== 'invalid' &&
    checks.credentialSubject.status === 'valid' &&
    checks.dates.status === 'valid' &&
    checks.credentialStatus.status !== 'invalid'
  );
};

const verifyDidKeyHolderProofSummary = async (
  presentation: JsonObject,
  holderDid: string,
): Promise<CredentialProofVerificationSummary> => {
  const proof = selectCredentialProofObject(presentation);

  if (proof === null) {
    return {
      status: 'unchecked',
      format: null,
      cryptosuite: null,
      verificationMethod: null,
      reason: 'presentation has no proof object',
    };
  }

  const proofType = asNonEmptyString(proof.type);
  const proofValue = asNonEmptyString(proof.proofValue);
  const proofPurpose = asNonEmptyString(proof.proofPurpose);
  const verificationMethod = asNonEmptyString(proof.verificationMethod);
  const expectedVerificationMethod = didKeyVerificationMethod(holderDid);

  if (
    proofType === null ||
    proofValue === null ||
    proofPurpose === null ||
    verificationMethod === null
  ) {
    return {
      status: 'invalid',
      format: proofType,
      cryptosuite: asNonEmptyString(proof.cryptosuite),
      verificationMethod,
      reason: 'proof object is missing required fields',
    };
  }

  if (expectedVerificationMethod === null || verificationMethod !== expectedVerificationMethod) {
    return {
      status: 'invalid',
      format: proofType,
      cryptosuite: asNonEmptyString(proof.cryptosuite),
      verificationMethod,
      reason: 'verificationMethod must match the did:key holder DID',
    };
  }

  if (proofPurpose !== 'assertionMethod') {
    return {
      status: 'invalid',
      format: proofType,
      cryptosuite: asNonEmptyString(proof.cryptosuite),
      verificationMethod,
      reason: 'proofPurpose must be assertionMethod',
    };
  }

  const holderPublicJwk = ed25519PublicJwkFromDidKey(holderDid);

  if (holderPublicJwk === null) {
    return {
      status: 'invalid',
      format: proofType,
      cryptosuite: asNonEmptyString(proof.cryptosuite),
      verificationMethod,
      reason: 'holder DID did:key value is not a valid Ed25519 multibase key',
    };
  }

  if (proofType === 'Ed25519Signature2020') {
    const isValid = await verifyCredentialProofWithEd25519Signature2020({
      credential: {
        ...presentation,
        proof: {
          type: 'Ed25519Signature2020',
          created: asString(proof.created) ?? '',
          proofPurpose: 'assertionMethod',
          verificationMethod,
          proofValue,
        },
      },
      publicJwk: holderPublicJwk,
    });

    return {
      status: isValid ? 'valid' : 'invalid',
      format: proofType,
      cryptosuite: null,
      verificationMethod,
      reason: isValid ? null : 'signature verification failed',
    };
  }

  if (proofType === 'DataIntegrityProof') {
    const cryptosuite = asNonEmptyString(proof.cryptosuite);

    if (cryptosuite !== 'eddsa-rdfc-2022') {
      return {
        status: 'invalid',
        format: proofType,
        cryptosuite,
        verificationMethod,
        reason: 'did:key holder proofs only support DataIntegrity cryptosuite eddsa-rdfc-2022',
      };
    }

    const isValid = await verifyCredentialProofWithDataIntegrity({
      credential: {
        ...presentation,
        proof: {
          type: 'DataIntegrityProof',
          cryptosuite,
          created: asString(proof.created) ?? '',
          proofPurpose: 'assertionMethod',
          verificationMethod,
          proofValue,
        },
      },
      publicJwk: holderPublicJwk,
    });

    return {
      status: isValid ? 'valid' : 'invalid',
      format: proofType,
      cryptosuite,
      verificationMethod,
      reason: isValid ? null : 'signature verification failed',
    };
  }

  return {
    status: 'unchecked',
    format: proofType,
    cryptosuite: asNonEmptyString(proof.cryptosuite),
    verificationMethod,
    reason: 'proof format is not currently supported',
  };
};

const verifyPresentationHolderProofSummary = async (
  c: AppContext,
  presentation: JsonObject,
  holderDid: string,
): Promise<CredentialProofVerificationSummary> => {
  if (holderDid.startsWith('did:key:')) {
    return verifyDidKeyHolderProofSummary(presentation, holderDid);
  }

  return verifyCredentialProofSummary(c, {
    ...presentation,
    issuer: holderDid,
  });
};

const verifyCredentialInPresentation = async (input: {
  context: AppContext;
  credential: JsonObject;
  holderDid: string;
  checkedAt: string;
}): Promise<PresentationCredentialVerificationResult> => {
  const credentialId = asNonEmptyString(input.credential.id);
  const credentialSubject = asJsonObject(input.credential.credentialSubject);
  const subjectId = asNonEmptyString(credentialSubject?.id);
  const binding: PresentationCredentialBindingSummary =
    subjectId === null
      ? {
          status: 'invalid',
          reason: 'credentialSubject.id is missing',
        }
      : subjectId !== input.holderDid
        ? {
            status: 'invalid',
            reason: 'credentialSubject.id must match presentation holder DID',
          }
        : {
            status: 'valid',
            reason: null,
          };
  const checks = await summarizeCredentialVerificationChecks({
    context: input.context,
    credential: input.credential,
    checkedAt: input.checkedAt,
    expectedStatusList: statusListReferenceFromCredentialForPresentation(input.credential),
  });
  const resolvedRevokedAt =
    checks.credentialStatus.status === 'valid'
      ? checks.credentialStatus.revoked
        ? input.checkedAt
        : null
      : null;
  const lifecycle = summarizeCredentialLifecycleVerification(
    input.credential,
    resolvedRevokedAt,
    input.checkedAt,
  );
  const proof = await verifyCredentialProofSummary(input.context, input.credential);
  const status: 'valid' | 'invalid' =
    binding.status === 'valid' &&
    proof.status === 'valid' &&
    credentialChecksPassPresentationPolicy(checks) &&
    lifecycle.state === 'active'
      ? 'valid'
      : 'invalid';

  return {
    credentialId,
    subjectId,
    binding,
    proof,
    checks,
    lifecycle,
    status,
  };
};

const githubUsernameFromUrl = (value: string): string | null => {
  try {
    const parsedUrl = new URL(value);

    if (parsedUrl.hostname !== 'github.com' && parsedUrl.hostname !== 'www.github.com') {
      return null;
    }

    const firstPath = parsedUrl.pathname
      .split('/')
      .map((segment) => segment.trim())
      .find((segment) => segment.length > 0);

    if (firstPath === undefined) {
      return null;
    }

    return firstPath;
  } catch {
    return null;
  }
};

const recipientDisplayNameFromAssertion = (assertion: AssertionRecord): string | null => {
  if (assertion.recipientIdentityType === 'email') {
    const email = assertion.recipientIdentity.trim();
    return email.length === 0 ? null : email;
  }

  if (assertion.recipientIdentityType === 'url') {
    const username = githubUsernameFromUrl(assertion.recipientIdentity);

    if (username !== null) {
      return `@${username}`;
    }

    try {
      const parsedUrl = new URL(assertion.recipientIdentity);
      return parsedUrl.hostname.replace(/^www\./, '');
    } catch {
      return null;
    }
  }

  return null;
};

const githubAvatarUrlForUsername = (username: string): string => {
  return `https://github.com/${encodeURIComponent(username)}.png?size=256`;
};

const recipientAvatarUrlFromAssertion = (assertion: AssertionRecord): string | null => {
  if (assertion.recipientIdentityType !== 'url') {
    return null;
  }

  const username = githubUsernameFromUrl(assertion.recipientIdentity);
  return username === null ? null : githubAvatarUrlForUsername(username);
};

const asNonEmptyString = (value: unknown): string | null => {
  const candidate = asString(value);

  if (candidate === null) {
    return null;
  }

  const trimmed = candidate.trim();
  return trimmed.length === 0 ? null : trimmed;
};

const linkedDataReferenceId = (value: unknown): string | null => {
  const stringValue = asNonEmptyString(value);

  if (stringValue !== null) {
    return stringValue;
  }

  const linkedDataObject = asJsonObject(value);
  return asNonEmptyString(linkedDataObject?.id);
};

const asFiniteNonNegativeInteger = (value: unknown): number | null => {
  if (typeof value !== 'number' || !Number.isFinite(value)) {
    return null;
  }

  const normalized = Math.trunc(value);
  return normalized < 0 ? null : normalized;
};

const hasNextPaginationLink = (linkHeader: string | null): boolean => {
  if (linkHeader === null) {
    return false;
  }

  return /<[^>]+>;\s*rel="next"/.test(linkHeader);
};

const githubProfileUrlForUsername = (githubUsername: string): string => {
  return `https://github.com/${encodeURIComponent(githubUsername.trim())}`;
};

const fetchSakaiCommitCountForUsername = async (
  githubUsername: string,
  githubToken?: string,
): Promise<number> => {
  const normalizedUsername = githubUsername.trim().toLowerCase();
  const requestHeaders = new Headers({
    Accept: 'application/vnd.github+json',
    'User-Agent': 'credtrail-api-worker',
  });
  const trimmedToken = githubToken?.trim();

  if (trimmedToken !== undefined && trimmedToken.length > 0) {
    requestHeaders.set('Authorization', `Bearer ${trimmedToken}`);
  }

  for (let page = 1; page <= 50; page += 1) {
    const contributorsUrl = new URL(
      `https://api.github.com/repos/${SAKAI_REPO_OWNER}/${SAKAI_REPO_NAME}/contributors`,
    );
    contributorsUrl.searchParams.set('per_page', '100');
    contributorsUrl.searchParams.set('page', String(page));
    contributorsUrl.searchParams.set('anon', 'true');

    const response = await fetch(contributorsUrl.toString(), {
      headers: requestHeaders,
    });

    if (!response.ok) {
      throw new Error(
        `GitHub contributors lookup failed: ${String(response.status)} ${response.statusText}`,
      );
    }

    const responseBody = await response.json<unknown>();

    if (!Array.isArray(responseBody)) {
      throw new Error('GitHub contributors lookup returned an invalid payload');
    }

    for (const entry of responseBody) {
      const contributor = asJsonObject(entry);
      const login = asNonEmptyString(contributor?.login)?.toLowerCase();
      const contributions = asFiniteNonNegativeInteger(contributor?.contributions);

      if (login === normalizedUsername) {
        return contributions ?? 0;
      }
    }

    if (!hasNextPaginationLink(response.headers.get('link'))) {
      return 0;
    }
  }

  throw new Error('GitHub contributors lookup exceeded pagination limit');
};

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

interface AchievementDetails {
  badgeClassUri: string | null;
  description: string | null;
  criteriaUri: string | null;
  imageUri: string | null;
}

const achievementDetailsFromCredential = (credential: JsonObject): AchievementDetails => {
  const credentialSubject = asJsonObject(credential.credentialSubject);
  const achievement = asJsonObject(credentialSubject?.achievement);

  return {
    badgeClassUri: linkedDataReferenceId(achievement?.id),
    description: asNonEmptyString(achievement?.description),
    criteriaUri: linkedDataReferenceId(achievement?.criteria),
    imageUri: linkedDataReferenceId(achievement?.image),
  };
};

const imsOb2ValidatorUrl = (targetUrl: string): string => {
  const validatorUrl = new URL(IMS_GLOBAL_OB2_VALIDATOR_BASE_URL);
  validatorUrl.searchParams.set('url', targetUrl);
  return validatorUrl.toString();
};

interface EvidenceDetails {
  uri: string;
  name: string | null;
  description: string | null;
}

const evidenceDetailsFromValue = (value: unknown): EvidenceDetails | null => {
  const uri = linkedDataReferenceId(value);

  if (uri === null) {
    return null;
  }

  const evidenceObject = asJsonObject(value);

  return {
    uri,
    name: asNonEmptyString(evidenceObject?.name),
    description: asNonEmptyString(evidenceObject?.description),
  };
};

const evidenceDetailsFromCredential = (credential: JsonObject): EvidenceDetails[] => {
  const credentialSubject = asJsonObject(credential.credentialSubject);
  const evidence = credentialSubject?.evidence;

  if (Array.isArray(evidence)) {
    const mappedEvidence = evidence.map((entry) => evidenceDetailsFromValue(entry));
    return mappedEvidence.filter((entry): entry is EvidenceDetails => entry !== null);
  }

  const singularEvidence = evidenceDetailsFromValue(evidence);
  return singularEvidence === null ? [] : [singularEvidence];
};

const badgeInitialsFromName = (badgeName: string): string => {
  const trimmedName = badgeName.trim();

  if (trimmedName.length === 0) {
    return 'BD';
  }

  const words = trimmedName.split(/\s+/).filter((word) => word.length > 0);
  const firstWord = words.at(0);

  if (firstWord === undefined) {
    return 'BD';
  }

  const secondWord = words.at(1);
  const firstInitial = firstWord.slice(0, 1);
  const secondInitial = secondWord === undefined ? firstWord.slice(1, 2) : secondWord.slice(0, 1);
  const initials = `${firstInitial}${secondInitial}`.replaceAll(/[^a-zA-Z0-9]/g, '').toUpperCase();

  return initials.length === 0 ? 'BD' : initials;
};

const badgeHeroImageMarkup = (badgeName: string, imageUri: string | null): string => {
  if (imageUri !== null) {
    return `<img
      class="public-badge__hero-image"
      src="${escapeHtml(imageUri)}"
      alt="${escapeHtml(`${badgeName} image`)}"
      loading="lazy"
    />`;
  }

  const initials = badgeInitialsFromName(badgeName);

  return `<svg
    class="public-badge__hero-image public-badge__hero-image--placeholder"
    viewBox="0 0 420 320"
    role="img"
    aria-label="${escapeHtml(`Placeholder image for ${badgeName}`)}"
  >
    <defs>
      <linearGradient id="badge-placeholder-gradient" x1="0" x2="1" y1="0" y2="1">
        <stop offset="0%" stop-color="#166534" />
        <stop offset="100%" stop-color="#14532d" />
      </linearGradient>
    </defs>
    <rect x="0" y="0" width="420" height="320" rx="28" fill="url(#badge-placeholder-gradient)" />
    <circle cx="338" cy="80" r="42" fill="#fbbf24" fill-opacity="0.22" />
    <circle cx="86" cy="232" r="56" fill="#fbbf24" fill-opacity="0.16" />
    <path d="M116 168l42 42 106-106" fill="none" stroke="#fbbf24" stroke-width="20" stroke-linecap="round" stroke-linejoin="round" />
    <text x="210" y="148" text-anchor="middle" dominant-baseline="middle" font-size="54" fill="#f8fafc" font-weight="700">${escapeHtml(initials)}</text>
  </svg>`;
};

interface VerificationViewModel {
  assertion: AssertionRecord;
  credential: JsonObject;
  recipientDisplayName: string | null;
}

type VerificationLookupResult =
  | {
      status: 'ok';
      value: VerificationViewModel;
    }
  | {
      status: 'invalid_id' | 'not_found';
    };

type PublicBadgeLookupResult =
  | {
      status: 'ok';
      value: VerificationViewModel;
    }
  | {
      status: 'redirect';
      canonicalPath: string;
    }
  | {
      status: 'not_found';
    };

const parseTenantScopedCredentialId = (
  credentialId: string,
): { tenantId: string; resourceId: string } | null => {
  try {
    const parsed = splitTenantScopedId(credentialId);

    if (parsed.tenantId.trim().length === 0 || parsed.resourceId.trim().length === 0) {
      return null;
    }

    return parsed;
  } catch {
    return null;
  }
};

const assertionBelongsToTenant = (tenantId: string, assertionId: string): boolean => {
  const scoped = parseTenantScopedCredentialId(assertionId);
  return scoped !== null && scoped.tenantId === tenantId;
};

const publicBadgePermalinkSegment = (assertion: AssertionRecord): string => {
  return assertion.publicId ?? assertion.id;
};

const publicBadgePathForAssertion = (assertion: AssertionRecord): string => {
  return `/badges/${encodeURIComponent(publicBadgePermalinkSegment(assertion))}`;
};

const loadCredentialForAssertion = async (
  store: R2Bucket,
  assertion: AssertionRecord,
): Promise<JsonObject> => {
  const credential = await getImmutableCredentialObject(store, {
    tenantId: assertion.tenantId,
    assertionId: assertion.id,
  });

  if (credential === null) {
    throw new Error(`Assertion "${assertion.id}" is missing its immutable credential object`);
  }

  return credential;
};

const loadRecipientDisplayNameForAssertion = async (
  db: SqlDatabase,
  assertion: AssertionRecord,
): Promise<string | null> => {
  if (assertion.learnerProfileId === null) {
    return null;
  }

  const learnerProfile = await findLearnerProfileById(
    db,
    assertion.tenantId,
    assertion.learnerProfileId,
  );
  return learnerProfile?.displayName ?? null;
};

const loadVerificationViewModel = async (
  db: SqlDatabase,
  store: R2Bucket,
  credentialId: string,
): Promise<VerificationLookupResult> => {
  const tenantScopedCredentialId = parseTenantScopedCredentialId(credentialId);

  if (tenantScopedCredentialId === null) {
    return {
      status: 'invalid_id',
    };
  }

  const assertion = await findAssertionById(db, tenantScopedCredentialId.tenantId, credentialId);

  if (assertion === null) {
    return {
      status: 'not_found',
    };
  }

  const credential = await loadCredentialForAssertion(store, assertion);

  return {
    status: 'ok',
    value: {
      assertion,
      credential,
      recipientDisplayName: null,
    },
  };
};

const loadPublicBadgeViewModel = async (
  db: SqlDatabase,
  store: R2Bucket,
  badgeIdentifier: string,
): Promise<PublicBadgeLookupResult> => {
  const trimmedIdentifier = badgeIdentifier.trim();

  if (trimmedIdentifier.length === 0) {
    return {
      status: 'not_found',
    };
  }

  const assertionByPublicId = await findAssertionByPublicId(db, trimmedIdentifier);

  if (assertionByPublicId !== null) {
    const credential = await loadCredentialForAssertion(store, assertionByPublicId);
    const recipientDisplayName = await loadRecipientDisplayNameForAssertion(
      db,
      assertionByPublicId,
    );

    return {
      status: 'ok',
      value: {
        assertion: assertionByPublicId,
        credential,
        recipientDisplayName,
      },
    };
  }

  const tenantScopedCredentialId = parseTenantScopedCredentialId(trimmedIdentifier);

  if (tenantScopedCredentialId === null) {
    return {
      status: 'not_found',
    };
  }

  const assertion = await findAssertionById(
    db,
    tenantScopedCredentialId.tenantId,
    trimmedIdentifier,
  );

  if (assertion === null) {
    return {
      status: 'not_found',
    };
  }

  if (publicBadgePermalinkSegment(assertion) === trimmedIdentifier) {
    const credential = await loadCredentialForAssertion(store, assertion);
    const recipientDisplayName = await loadRecipientDisplayNameForAssertion(db, assertion);

    return {
      status: 'ok',
      value: {
        assertion,
        credential,
        recipientDisplayName,
      },
    };
  }

  return {
    status: 'redirect',
    canonicalPath: publicBadgePathForAssertion(assertion),
  };
};

const publicBadgeNotFoundPage = (): string => {
  return renderPageShell(
    'Badge not found',
    `<section style="display:grid;gap:1rem;max-width:40rem;">
      <h1 style="margin:0;">Badge not found</h1>
      <p style="margin:0;">The shared badge URL is invalid or the credential does not exist.</p>
    </section>`,
  );
};

const publicBadgePage = (requestUrl: string, model: VerificationViewModel): string => {
  const badgeName = badgeNameFromCredential(model.credential);
  const issuerName = issuerNameFromCredential(model.credential);
  const issuerUrl = issuerUrlFromCredential(model.credential);
  const issuerIdentifier = issuerIdentifierFromCredential(model.credential);
  const recipientIdentifier = recipientFromCredential(model.credential);
  const recipientName =
    model.recipientDisplayName ??
    recipientDisplayNameFromAssertion(model.assertion) ??
    'Badge recipient';
  const recipientAvatarUrl = recipientAvatarUrlFromAssertion(model.assertion);
  const achievementDetails = achievementDetailsFromCredential(model.credential);
  const evidenceDetails = evidenceDetailsFromCredential(model.credential);
  const achievementImage = badgeHeroImageMarkup(badgeName, achievementDetails.imageUri);
  const credentialUri = asString(model.credential.id) ?? model.assertion.id;
  const isRevoked = model.assertion.revokedAt !== null;
  const verificationLabel = isRevoked ? 'Revoked' : 'Verified';
  const publicBadgePath = publicBadgePathForAssertion(model.assertion);
  const publicBadgeUrl = new URL(publicBadgePath, requestUrl).toString();
  const verificationApiPath = `/credentials/v1/${encodeURIComponent(model.assertion.id)}`;
  const verificationApiUrl = new URL(verificationApiPath, requestUrl).toString();
  const ob3JsonPath = `/credentials/v1/${encodeURIComponent(model.assertion.id)}/jsonld`;
  const ob3JsonUrl = new URL(ob3JsonPath, requestUrl).toString();
  const credentialDownloadPath = `/credentials/v1/${encodeURIComponent(model.assertion.id)}/download`;
  const credentialDownloadUrl = new URL(credentialDownloadPath, requestUrl).toString();
  const credentialPdfDownloadPath = `/credentials/v1/${encodeURIComponent(model.assertion.id)}/download.pdf`;
  const credentialPdfDownloadUrl = new URL(credentialPdfDownloadPath, requestUrl).toString();
  const assertionValidationTargetUrl = ob3JsonUrl;
  const badgeClassValidationTargetUrl = achievementDetails.badgeClassUri ?? publicBadgeUrl;
  const issuerValidationTargetUrl =
    issuerUrl ??
    (issuerIdentifier !== null && isWebUrl(issuerIdentifier) ? issuerIdentifier : publicBadgeUrl);
  const assertionValidatorUrl = imsOb2ValidatorUrl(assertionValidationTargetUrl);
  const badgeClassValidatorUrl = imsOb2ValidatorUrl(badgeClassValidationTargetUrl);
  const issuerValidatorUrl = imsOb2ValidatorUrl(issuerValidationTargetUrl);
  const qrCodeImageUrl = new URL('https://api.qrserver.com/v1/create-qr-code/');
  qrCodeImageUrl.searchParams.set('size', '220x220');
  qrCodeImageUrl.searchParams.set('format', 'svg');
  qrCodeImageUrl.searchParams.set('margin', '0');
  qrCodeImageUrl.searchParams.set('data', publicBadgeUrl);
  const linkedInAddProfileUrl = linkedInAddToProfileUrl({
    badgeName,
    issuerName,
    issuedAtIso: model.assertion.issuedAt,
    credentialUrl: publicBadgeUrl,
    credentialId: credentialUri,
  });
  const linkedInShareUrl = new URL('https://www.linkedin.com/sharing/share-offsite/');
  linkedInShareUrl.searchParams.set('url', publicBadgeUrl);
  const issuedAt = `${formatIsoTimestamp(model.assertion.issuedAt)} UTC`;
  const issuerLine =
    issuerUrl === null
      ? `<span>${escapeHtml(issuerName)}</span>`
      : `<a href="${escapeHtml(issuerUrl)}" target="_blank" rel="noopener noreferrer">${escapeHtml(
          issuerName,
        )}</a>`;
  const recipientIdentifierLine = '';
  const recipientAvatarSection =
    recipientAvatarUrl === null
      ? ''
      : `<img
          class="public-badge__recipient-avatar"
          src="${escapeHtml(recipientAvatarUrl)}"
          alt="${escapeHtml(`${recipientName} GitHub avatar`)}"
          loading="lazy"
        />`;
  const criteriaSection =
    achievementDetails.criteriaUri === null
      ? ''
      : `<p class="public-badge__achievement-copy">
          Criteria:
          <a href="${escapeHtml(achievementDetails.criteriaUri)}" target="_blank" rel="noopener noreferrer">
            ${escapeHtml(achievementDetails.criteriaUri)}
          </a>
        </p>`;
  const revokedDetails =
    model.assertion.revokedAt === null
      ? ''
      : `<p class="public-badge__status-note">Revoked at ${escapeHtml(
          formatIsoTimestamp(model.assertion.revokedAt),
        )} UTC</p>`;
  const achievementDescriptionSection =
    achievementDetails.description === null
      ? '<p class="public-badge__achievement-copy">No additional description provided.</p>'
      : `<p class="public-badge__achievement-copy">${escapeHtml(achievementDetails.description)}</p>`;
  const evidenceSection =
    evidenceDetails.length === 0
      ? ''
      : `<section class="public-badge__card public-badge__stack-sm">
          <h2 class="public-badge__section-title">Evidence</h2>
          <ul class="public-badge__evidence-list">
            ${evidenceDetails
              .map((entry) => {
                const label = entry.name ?? entry.uri;
                const description =
                  entry.description === null
                    ? ''
                    : `<p class="public-badge__evidence-description">${escapeHtml(
                        entry.description,
                      )}</p>`;

                return `<li class="public-badge__evidence-item">
                  <a href="${escapeHtml(entry.uri)}" target="_blank" rel="noopener noreferrer">
                    ${escapeHtml(label)}
                  </a>
                  ${description}
                </li>`;
              })
              .join('')}
          </ul>
        </section>`;

  return renderPageShell(
    `${badgeName} | CredTrail`,
    `<style>
      .public-badge {
        display: grid;
        gap: 1.2rem;
        color: #0f172a;
      }

      .public-badge__card {
        background: #ffffff;
        border: 1px solid #d6dfeb;
        border-radius: 1rem;
        box-shadow: 0 16px 36px rgba(15, 23, 42, 0.07);
        padding: 1.25rem;
      }

      .public-badge__stack-sm {
        display: grid;
        gap: 0.65rem;
      }

      .public-badge__status {
        display: flex;
        justify-content: space-between;
        gap: 1rem;
        align-items: center;
        color: #f8fafc;
        font-weight: 600;
      }

      .public-badge__status--verified {
        background: linear-gradient(135deg, #166534 0%, #14532d 65%);
      }

      .public-badge__status--revoked {
        background: linear-gradient(135deg, #b42318 0%, #8f1c13 65%);
      }

      .public-badge__status-note {
        margin: 0;
        color: #7f1d1d;
        font-size: 0.95rem;
      }

      .public-badge__hero {
        display: grid;
        gap: 1.1rem;
      }

      .public-badge__hero-image {
        display: block;
        width: 100%;
        max-width: 420px;
        border: 1px solid #d6dfeb;
        border-radius: 1rem;
        box-shadow: 0 14px 28px rgba(20, 83, 45, 0.18);
      }

      .public-badge__hero-meta {
        display: grid;
        gap: 0.5rem;
      }

      .public-badge__eyebrow {
        margin: 0;
        text-transform: uppercase;
        letter-spacing: 0.08em;
        font-size: 0.8rem;
        color: #166534;
        font-weight: 700;
      }

      .public-badge__title {
        margin: 0;
        font-size: clamp(1.65rem, 3.7vw, 2.45rem);
        line-height: 1.15;
      }

      .public-badge__issuer,
      .public-badge__issued-at,
      .public-badge__recipient-meta {
        margin: 0;
        color: #334155;
      }

      .public-badge__recipient-name {
        margin: 0;
        font-size: 1.35rem;
        font-weight: 700;
      }

      .public-badge__recipient-header {
        display: flex;
        gap: 0.8rem;
        align-items: center;
      }

      .public-badge__recipient-avatar {
        width: 3rem;
        height: 3rem;
        border-radius: 999px;
        border: 1px solid #d6dfeb;
        object-fit: cover;
        background: #f8fafc;
      }

      .public-badge__section-title {
        margin: 0;
        font-size: 1.12rem;
      }

      .public-badge__achievement-copy {
        margin: 0;
        color: #334155;
      }

      .public-badge__actions {
        display: flex;
        flex-wrap: wrap;
        gap: 0.6rem;
        align-items: center;
      }

      .public-badge__button {
        border: 1px solid #166534;
        border-radius: 0.75rem;
        padding: 0.48rem 0.86rem;
        text-decoration: none;
        font-weight: 600;
        color: #166534;
        background: #f8fafc;
        cursor: pointer;
      }

      .public-badge__button--primary {
        background: #166534;
        color: #f8fafc;
      }

      .public-badge__button--accent {
        border-color: #fbbf24;
        background: #fffbeb;
      }

      .public-badge__copy-status {
        margin: 0;
        color: #334155;
        font-size: 0.92rem;
      }

      .public-badge__validator-links {
        display: flex;
        flex-wrap: wrap;
        gap: 0.6rem;
      }

      .public-badge__validator-note {
        margin: 0;
        color: #475569;
        font-size: 0.92rem;
      }

      .public-badge__qr {
        margin: 0;
        display: grid;
        justify-items: start;
        gap: 0.45rem;
      }

      .public-badge__qr-image {
        width: 11rem;
        height: 11rem;
        border-radius: 0.9rem;
        border: 1px solid #d6dfeb;
        background: #ffffff;
      }

      .public-badge__qr-caption {
        color: #475569;
        font-size: 0.9rem;
      }

      .public-badge__evidence-list {
        margin: 0;
        padding-left: 1.2rem;
        display: grid;
        gap: 0.5rem;
      }

      .public-badge__evidence-item a {
        font-weight: 600;
      }

      .public-badge__evidence-description {
        margin: 0.2rem 0 0 0;
        color: #3d4b66;
      }

      .public-badge__technical summary {
        cursor: pointer;
        font-weight: 700;
      }

      .public-badge__technical-grid {
        margin: 0.85rem 0 0 0;
        display: grid;
        grid-template-columns: minmax(9rem, max-content) 1fr;
        gap: 0.45rem 0.8rem;
      }

      .public-badge__technical-grid dt {
        font-weight: 600;
      }

      .public-badge__technical-grid dd {
        margin: 0;
        overflow-wrap: anywhere;
      }

      @media (min-width: 760px) {
        .public-badge__hero {
          grid-template-columns: minmax(260px, 340px) 1fr;
          align-items: start;
        }
      }
    </style>
    <article class="public-badge">
      <section class="public-badge__card public-badge__status public-badge__status--${
        isRevoked ? 'revoked' : 'verified'
      }">
        <span>${escapeHtml(verificationLabel)}</span>
        <span>${escapeHtml(issuedAt)}</span>
      </section>

      <section class="public-badge__card public-badge__hero">
        ${achievementImage}
        <div class="public-badge__hero-meta">
          <p class="public-badge__eyebrow">Open Badges 3.0 Credential</p>
          <h1 class="public-badge__title">${escapeHtml(badgeName)}</h1>
          <p class="public-badge__issuer">Issued by ${issuerLine}</p>
          <p class="public-badge__issued-at">Issued ${escapeHtml(issuedAt)}</p>
          ${revokedDetails}
        </div>
      </section>

      <section class="public-badge__card public-badge__stack-sm">
        <h2 class="public-badge__section-title">Recipient</h2>
        <div class="public-badge__recipient-header">
          ${recipientAvatarSection}
          <p class="public-badge__recipient-name">${escapeHtml(recipientName)}</p>
        </div>
        ${recipientIdentifierLine}
      </section>

      <section class="public-badge__card public-badge__stack-sm">
        <h2 class="public-badge__section-title">Achievement</h2>
        ${achievementDescriptionSection}
        ${criteriaSection}
      </section>

      ${evidenceSection}

      <section class="public-badge__card public-badge__stack-sm">
        <h2 class="public-badge__section-title">Share and verify</h2>
        <div class="public-badge__actions">
          <button
            id="copy-badge-url-button"
            class="public-badge__button public-badge__button--primary"
            type="button"
            data-copy-value="${escapeHtml(publicBadgeUrl)}"
          >
            Copy URL
          </button>
          <a class="public-badge__button" href="${escapeHtml(ob3JsonPath)}">Open Badges 3.0 JSON</a>
          <a class="public-badge__button" href="${escapeHtml(credentialDownloadPath)}">Download VC</a>
          <a class="public-badge__button" href="${escapeHtml(credentialPdfDownloadPath)}">Download PDF</a>
          <a
            class="public-badge__button public-badge__button--accent"
            href="${escapeHtml(linkedInAddProfileUrl)}"
            target="_blank"
            rel="noopener noreferrer"
          >
            Add to LinkedIn Profile
          </a>
          <a
            class="public-badge__button"
            href="${escapeHtml(linkedInShareUrl.toString())}"
            target="_blank"
            rel="noopener noreferrer"
          >
            Share on LinkedIn Feed
          </a>
        </div>
        <p id="copy-badge-url-status" class="public-badge__copy-status" aria-live="polite"></p>
        <div class="public-badge__validator-links">
          <a
            class="public-badge__button"
            href="${escapeHtml(assertionValidatorUrl)}"
            target="_blank"
            rel="noopener noreferrer"
          >
            Validate Assertion (IMS)
          </a>
          <a
            class="public-badge__button"
            href="${escapeHtml(badgeClassValidatorUrl)}"
            target="_blank"
            rel="noopener noreferrer"
          >
            Validate Badge Class (IMS)
          </a>
          <a
            class="public-badge__button"
            href="${escapeHtml(issuerValidatorUrl)}"
            target="_blank"
            rel="noopener noreferrer"
          >
            Validate Issuer (IMS)
          </a>
        </div>
        <p class="public-badge__validator-note">
          Opens IMS Global OB2 validator with pre-filled URLs for assertion, badge class, and issuer checks.
        </p>
        <figure class="public-badge__qr">
          <img
            class="public-badge__qr-image"
            src="${escapeHtml(qrCodeImageUrl.toString())}"
            alt="QR code for this badge URL"
            loading="lazy"
          />
          <figcaption class="public-badge__qr-caption">Scan to open the public badge URL.</figcaption>
        </figure>
      </section>

      <details class="public-badge__card public-badge__technical">
        <summary>Technical details</summary>
        <dl class="public-badge__technical-grid">
          <dt>Issuer ID</dt>
          <dd>${escapeHtml(issuerIdentifier ?? 'Not available')}</dd>
          <dt>Recipient identity</dt>
          <dd>${escapeHtml(model.assertion.recipientIdentity)}</dd>
          <dt>Recipient identity type</dt>
          <dd>${escapeHtml(model.assertion.recipientIdentityType)}</dd>
          <dt>Credential ID</dt>
          <dd>${escapeHtml(credentialUri)}</dd>
          <dt>Assertion ID</dt>
          <dd>${escapeHtml(model.assertion.id)}</dd>
          <dt>Recipient ID</dt>
          <dd>${escapeHtml(recipientIdentifier)}</dd>
          <dt>Verification JSON</dt>
          <dd><a href="${escapeHtml(verificationApiPath)}">${escapeHtml(verificationApiUrl)}</a></dd>
          <dt>Open Badges 3.0 JSON</dt>
          <dd><a href="${escapeHtml(ob3JsonPath)}">${escapeHtml(ob3JsonUrl)}</a></dd>
          <dt>Credential download</dt>
          <dd><a href="${escapeHtml(credentialDownloadPath)}">${escapeHtml(credentialDownloadUrl)}</a></dd>
          <dt>Credential PDF download</dt>
          <dd><a href="${escapeHtml(credentialPdfDownloadPath)}">${escapeHtml(credentialPdfDownloadUrl)}</a></dd>
          <dt>IMS assertion validation</dt>
          <dd><a href="${escapeHtml(assertionValidatorUrl)}">${escapeHtml(assertionValidatorUrl)}</a></dd>
          <dt>IMS badge class validation</dt>
          <dd><a href="${escapeHtml(badgeClassValidatorUrl)}">${escapeHtml(badgeClassValidatorUrl)}</a></dd>
          <dt>IMS issuer validation</dt>
          <dd><a href="${escapeHtml(issuerValidatorUrl)}">${escapeHtml(issuerValidatorUrl)}</a></dd>
        </dl>
      </details>

      <script>
        (() => {
          const button = document.getElementById('copy-badge-url-button');
          const status = document.getElementById('copy-badge-url-status');

          if (!(button instanceof HTMLButtonElement) || !(status instanceof HTMLElement)) {
            return;
          }

          const value = button.dataset.copyValue;

          if (typeof value !== 'string' || value.length === 0) {
            return;
          }

          button.addEventListener('click', async () => {
            try {
              await navigator.clipboard.writeText(value);
              status.textContent = 'Badge URL copied';
            } catch {
              status.textContent = 'Unable to copy URL automatically';
            }
          });
        })();
      </script>
    </article>`,
    `<link rel="canonical" href="${escapeHtml(publicBadgeUrl)}" />
    <link rel="alternate" type="application/ld+json" href="${escapeHtml(ob3JsonPath)}" />`,
  );
};

const credentialDownloadFilename = (assertionId: string): string => {
  const safeAssertionId = assertionId.replaceAll(/[^a-zA-Z0-9_-]+/g, '-').replaceAll(/-+/g, '-');
  const trimmed = safeAssertionId.replaceAll(/^-|-$/g, '');
  const fallback = trimmed.length === 0 ? 'badge' : trimmed;

  return `${fallback}.jsonld`;
};

const credentialPdfDownloadFilename = (assertionId: string): string => {
  const safeAssertionId = assertionId.replaceAll(/[^a-zA-Z0-9_-]+/g, '-').replaceAll(/-+/g, '-');
  const trimmed = safeAssertionId.replaceAll(/^-|-$/g, '');
  const fallback = trimmed.length === 0 ? 'badge' : trimmed;

  return `${fallback}.pdf`;
};

interface BadgePdfDocumentInput {
  badgeName: string;
  recipientName: string;
  recipientIdentifier: string;
  issuerName: string;
  issuedAt: string;
  status: string;
  assertionId: string;
  credentialId: string;
  publicBadgeUrl: string;
  verificationUrl: string;
  ob3JsonUrl: string;
  badgeImageUrl: string | null;
  revokedAt?: string;
}

interface BadgePdfImageAsset {
  bytes: Uint8Array;
  mimeType: 'image/png' | 'image/jpeg';
}

const BADGE_PDF_IMAGE_FETCH_TIMEOUT_MS = 2_500;
const BADGE_PDF_MAX_IMAGE_BYTES = 2_500_000;

const parseBadgePdfDataUrl = (imageUrl: string): BadgePdfImageAsset | null => {
  const match = /^data:(image\/(?:png|jpeg|jpg));base64,([A-Za-z0-9+/=\s]+)$/i.exec(
    imageUrl.trim(),
  );

  if (match === null) {
    return null;
  }

  const mimeType = match[1]?.toLowerCase();
  const base64Payload = match[2]?.replaceAll(/\s+/g, '');

  if (base64Payload === undefined || base64Payload.length === 0) {
    return null;
  }

  try {
    const binary = atob(base64Payload);

    if (binary.length === 0 || binary.length > BADGE_PDF_MAX_IMAGE_BYTES) {
      return null;
    }

    const bytes = Uint8Array.from(binary, (character) => character.charCodeAt(0));

    if (mimeType === 'image/png') {
      return {
        bytes,
        mimeType: 'image/png',
      };
    }

    return {
      bytes,
      mimeType: 'image/jpeg',
    };
  } catch {
    return null;
  }
};

const inferBadgePdfImageMimeType = (
  imageUrl: URL,
  contentTypeHeader: string | null,
): BadgePdfImageAsset['mimeType'] | null => {
  const contentType = contentTypeHeader?.split(';')[0]?.trim().toLowerCase() ?? null;

  if (contentType === 'image/png') {
    return 'image/png';
  }

  if (contentType === 'image/jpeg' || contentType === 'image/jpg') {
    return 'image/jpeg';
  }

  const pathname = imageUrl.pathname.toLowerCase();

  if (pathname.endsWith('.png')) {
    return 'image/png';
  }

  if (pathname.endsWith('.jpg') || pathname.endsWith('.jpeg')) {
    return 'image/jpeg';
  }

  return null;
};

const loadBadgePdfImageAsset = async (imageUrl: string): Promise<BadgePdfImageAsset | null> => {
  const dataUrlAsset = parseBadgePdfDataUrl(imageUrl);

  if (dataUrlAsset !== null) {
    return dataUrlAsset;
  }

  let parsedUrl: URL;

  try {
    parsedUrl = new URL(imageUrl);
  } catch {
    return null;
  }

  if (parsedUrl.protocol !== 'http:' && parsedUrl.protocol !== 'https:') {
    return null;
  }

  const abortController = new AbortController();
  const timeoutId = setTimeout(() => {
    abortController.abort();
  }, BADGE_PDF_IMAGE_FETCH_TIMEOUT_MS);

  try {
    const response = await fetch(parsedUrl.toString(), {
      method: 'GET',
      headers: {
        Accept: 'image/png,image/jpeg,image/*;q=0.8,*/*;q=0.5',
      },
      signal: abortController.signal,
    });

    if (!response.ok) {
      return null;
    }

    const mimeType = inferBadgePdfImageMimeType(parsedUrl, response.headers.get('content-type'));

    if (mimeType === null) {
      return null;
    }

    const imageBuffer = await response.arrayBuffer();

    if (imageBuffer.byteLength === 0 || imageBuffer.byteLength > BADGE_PDF_MAX_IMAGE_BYTES) {
      return null;
    }

    return {
      bytes: new Uint8Array(imageBuffer),
      mimeType,
    };
  } catch {
    return null;
  } finally {
    clearTimeout(timeoutId);
  }
};

const wrapPdfText = (value: string, maxChars: number): string[] => {
  if (value.length <= maxChars) {
    return [value];
  }

  const words = value.split(/\s+/).filter((word) => word.length > 0);

  if (words.length === 0) {
    return [value.slice(0, maxChars)];
  }

  const lines: string[] = [];
  let currentLine = '';

  for (const word of words) {
    let remainingWord = word;

    while (remainingWord.length > maxChars) {
      if (currentLine.length > 0) {
        lines.push(currentLine);
        currentLine = '';
      }

      lines.push(remainingWord.slice(0, maxChars));
      remainingWord = remainingWord.slice(maxChars);
    }

    if (remainingWord.length === 0) {
      continue;
    }

    const nextLine = currentLine.length === 0 ? remainingWord : `${currentLine} ${remainingWord}`;
    if (nextLine.length <= maxChars) {
      currentLine = nextLine;
      continue;
    }

    lines.push(currentLine);
    currentLine = remainingWord;
  }

  if (currentLine.length > 0) {
    lines.push(currentLine);
  }

  return lines;
};

const embedBadgePdfImage = async (
  pdfDocument: PDFDocument,
  asset: BadgePdfImageAsset,
): Promise<PDFImage | null> => {
  try {
    if (asset.mimeType === 'image/png') {
      return await pdfDocument.embedPng(asset.bytes);
    }

    return await pdfDocument.embedJpg(asset.bytes);
  } catch {
    return null;
  }
};

const drawBadgePdfPlaceholder = (
  page: PDFPage,
  badgeName: string,
  frame: {
    x: number;
    y: number;
    width: number;
    height: number;
  },
): void => {
  const initials = badgeInitialsFromName(badgeName);

  page.drawRectangle({
    x: frame.x,
    y: frame.y,
    width: frame.width,
    height: frame.height,
    color: rgb(0.09, 0.31, 0.18),
  });
  page.drawCircle({
    x: frame.x + frame.width - 36,
    y: frame.y + frame.height - 34,
    size: 24,
    color: rgb(0.96, 0.76, 0.14),
    opacity: 0.28,
  });
  page.drawCircle({
    x: frame.x + 34,
    y: frame.y + 34,
    size: 30,
    color: rgb(0.96, 0.76, 0.14),
    opacity: 0.2,
  });
  page.drawText(initials, {
    x: frame.x + frame.width / 2 - 26,
    y: frame.y + frame.height / 2 - 14,
    size: 28,
    color: rgb(0.96, 0.98, 1),
  });
};

const drawPdfTextLines = (
  page: PDFPage,
  lines: readonly string[],
  x: number,
  startY: number,
  options: {
    size: number;
    color: ReturnType<typeof rgb>;
    lineHeight: number;
  },
): number => {
  let currentY = startY;

  for (const line of lines) {
    page.drawText(line, {
      x,
      y: currentY,
      size: options.size,
      color: options.color,
    });
    currentY -= options.lineHeight;
  }

  return currentY;
};

const drawPdfField = (
  page: PDFPage,
  label: string,
  value: string,
  x: number,
  startY: number,
): number => {
  page.drawText(label, {
    x,
    y: startY,
    size: 10,
    color: rgb(0.36, 0.42, 0.49),
  });
  const wrappedValueLines = wrapPdfText(value, 45);
  const nextY = drawPdfTextLines(page, wrappedValueLines, x, startY - 14, {
    size: 12,
    color: rgb(0.08, 0.11, 0.17),
    lineHeight: 14,
  });

  return nextY - 8;
};

const drawPdfLinkBlock = (
  page: PDFPage,
  label: string,
  value: string,
  x: number,
  startY: number,
): number => {
  page.drawText(label, {
    x,
    y: startY,
    size: 10,
    color: rgb(0.36, 0.42, 0.49),
  });
  const wrappedValueLines = wrapPdfText(value, 88);

  return drawPdfTextLines(page, wrappedValueLines, x, startY - 13, {
    size: 10.5,
    color: rgb(0.08, 0.11, 0.17),
    lineHeight: 13,
  });
};

const renderBadgePdfDocument = async (input: BadgePdfDocumentInput): Promise<Uint8Array> => {
  const pdfDocument = await PDFDocument.create();
  const page = pdfDocument.addPage([612, 792]);
  const regularFont = await pdfDocument.embedFont(StandardFonts.Helvetica);
  const boldFont = await pdfDocument.embedFont(StandardFonts.HelveticaBold);

  const pageWidth = page.getWidth();
  const pageHeight = page.getHeight();
  const margin = 30;

  page.drawRectangle({
    x: 0,
    y: 0,
    width: pageWidth,
    height: pageHeight,
    color: rgb(0.97, 0.98, 0.99),
  });
  page.drawRectangle({
    x: margin - 6,
    y: margin - 6,
    width: pageWidth - (margin - 6) * 2,
    height: pageHeight - (margin - 6) * 2,
    borderWidth: 1,
    borderColor: rgb(0.76, 0.81, 0.87),
  });

  const headerY = pageHeight - 96;
  page.drawRectangle({
    x: margin,
    y: headerY,
    width: pageWidth - margin * 2,
    height: 58,
    color: rgb(0.09, 0.35, 0.21),
  });
  page.drawRectangle({
    x: margin + 10,
    y: headerY + 8,
    width: 7,
    height: 42,
    color: rgb(0.96, 0.76, 0.14),
  });
  page.drawText('OFFICIAL BADGE CREDENTIAL', {
    x: margin + 26,
    y: headerY + 33,
    size: 18,
    color: rgb(0.97, 0.98, 1),
    font: boldFont,
  });
  page.drawText('Issued by CredTrail - Open Badges 3.0 Verification Record', {
    x: margin + 26,
    y: headerY + 15,
    size: 10.5,
    color: rgb(0.89, 0.95, 0.92),
    font: regularFont,
  });

  const imageFrame = {
    x: margin + 14,
    y: 408,
    width: 212,
    height: 222,
  };
  page.drawRectangle({
    x: imageFrame.x - 1,
    y: imageFrame.y - 1,
    width: imageFrame.width + 2,
    height: imageFrame.height + 2,
    borderWidth: 1,
    borderColor: rgb(0.72, 0.79, 0.86),
    color: rgb(1, 1, 1),
  });

  let embeddedBadgeImage: PDFImage | null = null;

  if (input.badgeImageUrl !== null) {
    const imageAsset = await loadBadgePdfImageAsset(input.badgeImageUrl);
    embeddedBadgeImage =
      imageAsset === null ? null : await embedBadgePdfImage(pdfDocument, imageAsset);
  }

  if (embeddedBadgeImage === null) {
    drawBadgePdfPlaceholder(page, input.badgeName, imageFrame);
  } else {
    const imageScale = Math.min(
      (imageFrame.width - 10) / embeddedBadgeImage.width,
      (imageFrame.height - 10) / embeddedBadgeImage.height,
    );
    const imageWidth = embeddedBadgeImage.width * imageScale;
    const imageHeight = embeddedBadgeImage.height * imageScale;

    page.drawImage(embeddedBadgeImage, {
      x: imageFrame.x + (imageFrame.width - imageWidth) / 2,
      y: imageFrame.y + (imageFrame.height - imageHeight) / 2,
      width: imageWidth,
      height: imageHeight,
    });
  }

  page.drawText('Badge Artwork', {
    x: imageFrame.x + 4,
    y: imageFrame.y - 16,
    size: 9.5,
    color: rgb(0.36, 0.42, 0.49),
    font: regularFont,
  });

  const statusColor =
    input.status.toLowerCase() === 'revoked' ? rgb(0.66, 0.14, 0.09) : rgb(0.1, 0.41, 0.24);
  page.drawRectangle({
    x: 446,
    y: 618,
    width: 136,
    height: 28,
    color: statusColor,
  });
  page.drawText(input.status.toUpperCase(), {
    x: 474,
    y: 628,
    size: 10.5,
    color: rgb(0.98, 0.99, 1),
    font: boldFont,
  });

  const badgeNameLines = wrapPdfText(input.badgeName, 34);
  let detailY = drawPdfTextLines(page, badgeNameLines, 276, 588, {
    size: 21,
    color: rgb(0.08, 0.11, 0.17),
    lineHeight: 24,
  });
  detailY -= 6;

  detailY = drawPdfField(page, 'Recipient', input.recipientName, 276, detailY);
  detailY = drawPdfField(page, 'Recipient identifier', input.recipientIdentifier, 276, detailY);
  detailY = drawPdfField(page, 'Issuing organization', input.issuerName, 276, detailY);
  detailY = drawPdfField(page, 'Issued at', input.issuedAt, 276, detailY);
  detailY = drawPdfField(page, 'Assertion ID', input.assertionId, 276, detailY);
  detailY = drawPdfField(page, 'Credential ID', input.credentialId, 276, detailY);

  if (input.revokedAt !== undefined) {
    drawPdfField(page, 'Revoked at', input.revokedAt, 276, detailY);
  }

  page.drawLine({
    start: {
      x: margin + 2,
      y: 365,
    },
    end: {
      x: pageWidth - margin - 2,
      y: 365,
    },
    thickness: 1,
    color: rgb(0.79, 0.83, 0.89),
  });

  page.drawText('Verification References', {
    x: margin + 14,
    y: 344,
    size: 14.5,
    color: rgb(0.09, 0.35, 0.21),
    font: boldFont,
  });

  let verificationY = 324;
  verificationY = drawPdfLinkBlock(
    page,
    'Public badge page',
    input.publicBadgeUrl,
    margin + 14,
    verificationY,
  );
  verificationY -= 6;
  verificationY = drawPdfLinkBlock(
    page,
    'Verification JSON endpoint',
    input.verificationUrl,
    margin + 14,
    verificationY,
  );
  verificationY -= 6;
  drawPdfLinkBlock(page, 'Open Badges 3.0 JSON-LD', input.ob3JsonUrl, margin + 14, verificationY);

  page.drawRectangle({
    x: margin + 14,
    y: 90,
    width: pageWidth - (margin + 14) * 2,
    height: 66,
    borderWidth: 1,
    borderColor: rgb(0.8, 0.84, 0.89),
    color: rgb(1, 1, 1),
  });
  page.drawText(
    'This credential record is issued as an official verification document for institutional and hiring workflows.',
    {
      x: margin + 24,
      y: 130,
      size: 10.5,
      color: rgb(0.26, 0.31, 0.38),
      font: regularFont,
    },
  );
  page.drawText('Authenticity can be confirmed using the verification references above.', {
    x: margin + 24,
    y: 114,
    size: 10.5,
    color: rgb(0.26, 0.31, 0.38),
    font: regularFont,
  });

  page.drawLine({
    start: {
      x: margin + 28,
      y: 68,
    },
    end: {
      x: margin + 222,
      y: 68,
    },
    thickness: 1,
    color: rgb(0.64, 0.69, 0.75),
  });
  page.drawLine({
    start: {
      x: pageWidth - margin - 222,
      y: 68,
    },
    end: {
      x: pageWidth - margin - 28,
      y: 68,
    },
    thickness: 1,
    color: rgb(0.64, 0.69, 0.75),
  });
  page.drawText('Issuer signature reference', {
    x: margin + 28,
    y: 55,
    size: 9,
    color: rgb(0.4, 0.46, 0.53),
    font: regularFont,
  });
  page.drawText('Recipient copy', {
    x: pageWidth - margin - 130,
    y: 55,
    size: 9,
    color: rgb(0.4, 0.46, 0.53),
    font: regularFont,
  });

  const pdfBytes = await pdfDocument.save();
  return Uint8Array.from(pdfBytes);
};

export interface SendIssuanceEmailNotificationInput {
  mailtrapApiToken?: string | undefined;
  mailtrapInboxId?: string | undefined;
  mailtrapApiBaseUrl?: string | undefined;
  mailtrapFromEmail?: string | undefined;
  mailtrapFromName?: string | undefined;
  recipientEmail: string;
  badgeTitle: string;
  assertionId: string;
  tenantId: string;
  issuedAtIso: string;
  publicBadgeUrl: string;
  verificationUrl: string;
  credentialDownloadUrl: string;
}

export const sendIssuanceEmailNotification = async (
  input: SendIssuanceEmailNotificationInput,
): Promise<void> => {
  if (
    input.mailtrapApiToken === undefined ||
    input.mailtrapInboxId === undefined ||
    input.mailtrapApiToken.trim().length === 0 ||
    input.mailtrapInboxId.trim().length === 0
  ) {
    return;
  }

  const baseUrl = input.mailtrapApiBaseUrl ?? 'https://sandbox.api.mailtrap.io/api/send';
  const endpoint = `${baseUrl.replaceAll(/\/+$/g, '')}/${encodeURIComponent(input.mailtrapInboxId)}`;
  const subject = `You've earned a new badge: ${input.badgeTitle}`;
  const textBody = [
    `You have earned the "${input.badgeTitle}" badge.`,
    '',
    `Issued at: ${input.issuedAtIso}`,
    `Assertion ID: ${input.assertionId}`,
    `Tenant ID: ${input.tenantId}`,
    '',
    `Public badge page: ${input.publicBadgeUrl}`,
    `Verification JSON: ${input.verificationUrl}`,
    `Download VC: ${input.credentialDownloadUrl}`,
  ].join('\n');

  const response = await fetch(endpoint, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${input.mailtrapApiToken}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      from: {
        email: input.mailtrapFromEmail ?? 'no-reply@credtrail.org',
        name: input.mailtrapFromName ?? 'CredTrail',
      },
      to: [
        {
          email: input.recipientEmail,
        },
      ],
      subject,
      text: textBody,
      category: 'Issuance Notification',
    }),
  });

  if (!response.ok) {
    const errorBody = await response.text();
    throw new Error(
      `Mailtrap API request failed: ${String(response.status)} ${response.statusText} ${errorBody}`,
    );
  }
};

type LearnerDidSettingsNotice = 'updated' | 'cleared' | 'conflict' | 'invalid';

const learnerDidSettingsNoticeFromQuery = (
  value: string | undefined,
): LearnerDidSettingsNotice | null => {
  switch (value) {
    case 'updated':
    case 'cleared':
    case 'conflict':
    case 'invalid':
      return value;
    default:
      return null;
  }
};

const learnerDashboardPage = (
  requestUrl: string,
  tenantId: string,
  badges: readonly LearnerBadgeSummaryRecord[],
  learnerDid: string | null,
  didNotice: LearnerDidSettingsNotice | null,
): string => {
  const didNoticeMarkup =
    didNotice === null
      ? ''
      : didNotice === 'updated'
        ? '<p style="margin:0;color:#166534;font-weight:600;">Learner DID updated. Newly issued badges will use this DID as credentialSubject.id.</p>'
        : didNotice === 'cleared'
          ? '<p style="margin:0;color:#334155;font-weight:600;">Learner DID cleared. Badge issuance will fall back to the default learner subject identifier.</p>'
          : didNotice === 'conflict'
            ? '<p style="margin:0;color:#a32020;font-weight:600;">That DID is already linked to another learner profile in this tenant.</p>'
            : '<p style="margin:0;color:#a32020;font-weight:600;">DID must use one of the supported methods: did:key, did:web, or did:ion.</p>';
  const didValue = learnerDid ?? '';
  const didSummaryMarkup =
    learnerDid === null
      ? '<p style="margin:0;color:#475569;">No learner DID is currently configured.</p>'
      : `<p style="margin:0;color:#0f172a;overflow-wrap:anywhere;">Current DID: <code>${escapeHtml(learnerDid)}</code></p>`;
  const didSettingsCard = `<article style="display:grid;gap:0.75rem;background:#ffffff;border:1px solid #d6dfeb;border-radius:1rem;padding:1rem;">
    <h2 style="margin:0;">Profile settings</h2>
    <p style="margin:0;color:#334155;">
      Set an optional learner DID to issue privacy-preserving badges directly to your wallet identifier.
      Supported methods: <code>did:key</code>, <code>did:web</code>, and <code>did:ion</code>.
    </p>
    ${didNoticeMarkup}
    ${didSummaryMarkup}
    <form method="post" action="/tenants/${encodeURIComponent(tenantId)}/learner/settings/did" style="display:grid;gap:0.6rem;">
      <label style="font-weight:600;display:grid;gap:0.3rem;">
        Learner DID
        <input
          name="did"
          type="text"
          value="${escapeHtml(didValue)}"
          placeholder="did:key:z6Mk..."
          style="padding:0.55rem 0.65rem;border:1px solid #cbd5e1;border-radius:0.5rem;"
        />
      </label>
      <div style="display:flex;gap:0.5rem;flex-wrap:wrap;">
        <button type="submit" style="padding:0.45rem 0.85rem;border-radius:0.5rem;border:1px solid #1d4ed8;background:#1d4ed8;color:#ffffff;font-weight:600;cursor:pointer;">Save DID</button>
        <button
          type="submit"
          name="did"
          value=""
          style="padding:0.45rem 0.85rem;border-radius:0.5rem;border:1px solid #94a3b8;background:#ffffff;color:#1e293b;font-weight:600;cursor:pointer;"
        >
          Clear DID
        </button>
      </div>
    </form>
  </article>`;

  const badgesMarkup =
    badges.length === 0
      ? '<p style="margin:0;">No badges have been issued to this learner account yet.</p>'
      : `<div style="display:grid;gap:0.9rem;">${badges
          .map((badge) => {
            const statusLabel = badge.revokedAt === null ? 'Verified' : 'Revoked';
            const statusVariant = badge.revokedAt === null ? 'success' : 'danger';
            const publicBadgeId = badge.assertionPublicId ?? badge.assertionId;
            const publicBadgePath = `/badges/${encodeURIComponent(publicBadgeId)}`;
            const publicBadgeUrl = new URL(publicBadgePath, requestUrl).toString();
            const descriptionMarkup =
              badge.badgeDescription === null
                ? ''
                : `<p style="margin:0;color:#3d4b66;">${escapeHtml(badge.badgeDescription)}</p>`;
            const revokedAtMarkup =
              badge.revokedAt === null
                ? ''
                : `<p style="margin:0;color:#a32020;">Revoked at ${escapeHtml(formatIsoTimestamp(badge.revokedAt))} UTC</p>`;

            return `<article style="display:grid;gap:0.75rem;background:#ffffff;border:1px solid #d6dfeb;border-radius:1rem;padding:1rem;">
              <div style="display:flex;justify-content:space-between;gap:0.75rem;align-items:center;flex-wrap:wrap;">
                <h3 style="margin:0;">${escapeHtml(badge.badgeTitle)}</h3>
                <sl-badge variant="${statusVariant}" pill>${statusLabel}</sl-badge>
              </div>
              ${descriptionMarkup}
              <p style="margin:0;">Issued at ${escapeHtml(formatIsoTimestamp(badge.issuedAt))} UTC</p>
              ${revokedAtMarkup}
              <p style="margin:0;">
                Public badge page:
                <a href="${escapeHtml(publicBadgePath)}">${escapeHtml(publicBadgeUrl)}</a>
              </p>
            </article>`;
          })
          .join('')}</div>`;

  return renderPageShell(
    'Learner dashboard | CredTrail',
    `<section style="display:grid;gap:1rem;max-width:56rem;">
      <h1 style="margin:0;">Your badges</h1>
      <p style="margin:0;color:#3d4b66;">Tenant: ${escapeHtml(tenantId)}</p>
      ${didSettingsCard}
      ${badgesMarkup}
    </section>`,
  );
};

const tenantBadgeWallPage = (
  requestUrl: string,
  tenantId: string,
  entries: readonly PublicBadgeWallEntryRecord[],
  filterBadgeTemplateId: string | null,
): string => {
  const title =
    filterBadgeTemplateId === null ? `Badge Wall · ${tenantId}` : `Badge Wall · ${tenantId}`;
  const subtitle =
    filterBadgeTemplateId === null
      ? `Public badge URLs issued under tenant "${tenantId}".`
      : `Public badge URLs issued under tenant "${tenantId}" for badge template "${filterBadgeTemplateId}".`;
  const cards =
    entries.length === 0
      ? ''
      : entries
          .map((entry) => {
            const username = githubUsernameFromUrl(entry.recipientIdentity);
            const recipientLabel = username === null ? entry.recipientIdentity : `@${username}`;
            const avatarUrl = username === null ? null : githubAvatarUrlForUsername(username);
            const badgePath = `/badges/${encodeURIComponent(entry.assertionPublicId)}`;
            const badgeUrl = new URL(badgePath, requestUrl).toString();
            const issuedAt = `${formatIsoTimestamp(entry.issuedAt)} UTC`;
            const statusLabel = entry.revokedAt === null ? 'Verified' : 'Revoked';
            const revokedLine =
              entry.revokedAt === null
                ? ''
                : `<p class="badge-wall__meta">Revoked ${escapeHtml(
                    formatIsoTimestamp(entry.revokedAt),
                  )} UTC</p>`;
            const avatarMarkup =
              avatarUrl === null
                ? ''
                : `<img
                    class="badge-wall__avatar"
                    src="${escapeHtml(avatarUrl)}"
                    alt="${escapeHtml(`${recipientLabel} GitHub avatar`)}"
                    loading="lazy"
                  />`;

            return `<li class="badge-wall__item">
              <div class="badge-wall__recipient">
                ${avatarMarkup}
                <div class="badge-wall__stack">
                  <p class="badge-wall__name">${escapeHtml(recipientLabel)}</p>
                  <p class="badge-wall__badge-title">${escapeHtml(entry.badgeTitle)}</p>
                  <p class="badge-wall__meta">${escapeHtml(statusLabel)} · Issued ${escapeHtml(issuedAt)}</p>
                  ${revokedLine}
                </div>
              </div>
              <p class="badge-wall__url">
                <a href="${escapeHtml(badgePath)}">${escapeHtml(badgeUrl)}</a>
              </p>
            </li>`;
          })
          .join('');
  const listMarkup =
    entries.length === 0
      ? '<p class="badge-wall__empty">No public badges found for this showcase.</p>'
      : `<ol class="badge-wall__list">${cards}</ol>`;

  return renderPageShell(
    `${title} | CredTrail`,
    `<style>
      .badge-wall {
        display: grid;
        gap: 1rem;
        color: #0f172a;
      }

      .badge-wall__lead {
        margin: 0;
        color: #475569;
      }

      .badge-wall__count {
        margin: 0;
        font-weight: 600;
      }

      .badge-wall__list {
        margin: 0;
        padding: 0;
        list-style: none;
        display: grid;
        gap: 0.75rem;
      }

      .badge-wall__item {
        border: 1px solid #d6dfeb;
        border-radius: 0.9rem;
        background: #ffffff;
        box-shadow: 0 10px 24px rgba(15, 23, 42, 0.05);
        padding: 0.9rem;
        display: grid;
        gap: 0.65rem;
      }

      .badge-wall__recipient {
        display: flex;
        gap: 0.75rem;
        align-items: center;
      }

      .badge-wall__avatar {
        width: 2.7rem;
        height: 2.7rem;
        border-radius: 999px;
        border: 1px solid #d6dfeb;
        object-fit: cover;
        background: #f8fafc;
      }

      .badge-wall__stack {
        display: grid;
        gap: 0.2rem;
      }

      .badge-wall__name {
        margin: 0;
        font-weight: 700;
      }

      .badge-wall__badge-title {
        margin: 0;
        color: #334155;
      }

      .badge-wall__meta {
        margin: 0;
        color: #475569;
        font-size: 0.92rem;
      }

      .badge-wall__url {
        margin: 0;
        overflow-wrap: anywhere;
      }

      .badge-wall__empty {
        margin: 0;
        color: #475569;
      }
    </style>
    <section class="badge-wall">
      <h1 style="margin:0;">${escapeHtml(title)}</h1>
      <p class="badge-wall__lead">${escapeHtml(subtitle)}</p>
      <p class="badge-wall__count">${escapeHtml(String(entries.length))} issued badges</p>
      ${listMarkup}
    </section>`,
  );
};

app.use('*', async (c, next) => {
  const startedAt = Date.now();
  const requestUrl = new URL(c.req.url);
  const canonicalHost = c.env.PLATFORM_DOMAIN.toLowerCase();
  const requestHost = requestUrl.hostname.toLowerCase();

  if (requestHost === `www.${canonicalHost}` || requestHost === `badges.${canonicalHost}`) {
    requestUrl.hostname = canonicalHost;
    requestUrl.port = '';
    return c.redirect(requestUrl.toString(), 308);
  }

  if (c.req.method === 'GET' && c.env.MARKETING_SITE_ORIGIN !== undefined) {
    const isLandingRequest =
      requestUrl.pathname === '/' ||
      requestUrl.pathname.startsWith(LANDING_ASSET_PATH_PREFIX) ||
      LANDING_STATIC_PATHS.has(requestUrl.pathname);

    if (isLandingRequest) {
      const marketingUrl = new URL(
        `${requestUrl.pathname}${requestUrl.search}`,
        c.env.MARKETING_SITE_ORIGIN,
      );
      return fetch(new Request(marketingUrl.toString(), c.req.raw));
    }
  }

  await next();
  const elapsedMs = Date.now() - startedAt;

  logInfo(observabilityContext(c.env), 'http_request', {
    method: c.req.method,
    path: requestUrl.pathname,
    status: c.res.status,
    elapsedMs,
  });
});

app.onError(async (error, c) => {
  const requestUrl = new URL(c.req.url);
  const details = error instanceof Error ? error.message : 'Unknown error';

  await captureSentryException({
    context: observabilityContext(c.env),
    dsn: c.env.SENTRY_DSN,
    error,
    message: 'Unhandled API worker error',
    tags: {
      path: requestUrl.pathname,
      method: c.req.method,
    },
    extra: {
      status: 500,
      environment: c.env.APP_ENV,
    },
  });

  logError(observabilityContext(c.env), 'api_error', {
    method: c.req.method,
    path: requestUrl.pathname,
    detail: details,
  });

  return c.json(
    {
      error: 'Internal server error',
    },
    500,
  );
});

app.get('/healthz', (c) => {
  return c.json({
    service: 'api-worker',
    status: 'ok',
    environment: c.env.APP_ENV,
  });
});

app.put('/v1/admin/tenants/:tenantId', async (c) => {
  const unauthorizedResponse = requireBootstrapAdmin(c);

  if (unauthorizedResponse !== null) {
    return unauthorizedResponse;
  }

  const pathParams = parseTenantPathParams(c.req.param());
  const payload = await c.req.json<unknown>();
  const request = parseAdminUpsertTenantRequest(payload);
  const issuerDomain = request.issuerDomain ?? `${request.slug}.${c.env.PLATFORM_DOMAIN}`;
  const didWeb = createDidWeb({
    host: c.env.PLATFORM_DOMAIN,
    pathSegments: [pathParams.tenantId],
  });

  try {
    const tenant = await upsertTenant(resolveDatabase(c.env), {
      id: pathParams.tenantId,
      slug: request.slug,
      displayName: request.displayName,
      planTier: request.planTier ?? 'team',
      issuerDomain,
      didWeb,
      isActive: request.isActive,
    });

    await createAuditLog(resolveDatabase(c.env), {
      tenantId: pathParams.tenantId,
      action: 'tenant.upserted',
      targetType: 'tenant',
      targetId: pathParams.tenantId,
      metadata: {
        slug: tenant.slug,
        displayName: tenant.displayName,
        planTier: tenant.planTier,
        issuerDomain: tenant.issuerDomain,
        didWeb: tenant.didWeb,
        isActive: tenant.isActive,
      },
    });

    return c.json(
      {
        tenant,
      },
      201,
    );
  } catch (error: unknown) {
    if (isUniqueConstraintError(error)) {
      return c.json(
        {
          error: 'Tenant slug or issuer domain is already in use',
        },
        409,
      );
    }

    throw error;
  }
});

app.put('/v1/admin/tenants/:tenantId/signing-registration', async (c) => {
  const unauthorizedResponse = requireBootstrapAdmin(c);

  if (unauthorizedResponse !== null) {
    return unauthorizedResponse;
  }

  const pathParams = parseTenantPathParams(c.req.param());
  const payload = await c.req.json<unknown>();
  const request = parseAdminUpsertTenantSigningRegistrationRequest(payload);
  const did = createDidWeb({
    host: c.env.PLATFORM_DOMAIN,
    pathSegments: [pathParams.tenantId],
  });

  try {
    const registration = await upsertTenantSigningRegistration(resolveDatabase(c.env), {
      tenantId: pathParams.tenantId,
      did,
      keyId: request.keyId,
      publicJwkJson: JSON.stringify(request.publicJwk),
      ...(request.privateJwk === undefined
        ? {}
        : {
            privateJwkJson: JSON.stringify(request.privateJwk),
          }),
    });

    await createAuditLog(resolveDatabase(c.env), {
      tenantId: pathParams.tenantId,
      action: 'tenant.signing_registration_upserted',
      targetType: 'tenant_signing_registration',
      targetId: pathParams.tenantId,
      metadata: {
        did: registration.did,
        keyId: registration.keyId,
        hasPrivateKey: registration.privateJwkJson !== null,
      },
    });

    return c.json(
      {
        tenantId: registration.tenantId,
        did: registration.did,
        keyId: registration.keyId,
        hasPrivateKey: registration.privateJwkJson !== null,
      },
      201,
    );
  } catch (error: unknown) {
    if (isUniqueConstraintError(error)) {
      return c.json(
        {
          error: 'Signing registration conflicts with another tenant DID',
        },
        409,
      );
    }

    throw error;
  }
});

app.put('/v1/admin/tenants/:tenantId/badge-templates/:badgeTemplateId', async (c) => {
  const unauthorizedResponse = requireBootstrapAdmin(c);

  if (unauthorizedResponse !== null) {
    return unauthorizedResponse;
  }

  const pathParams = parseBadgeTemplatePathParams(c.req.param());
  const payload = await c.req.json<unknown>();
  const request = parseAdminUpsertBadgeTemplateByIdRequest(payload);

  try {
    const template = await upsertBadgeTemplateById(resolveDatabase(c.env), {
      id: pathParams.badgeTemplateId,
      tenantId: pathParams.tenantId,
      slug: request.slug,
      title: request.title,
      description: request.description,
      criteriaUri: request.criteriaUri,
      imageUri: request.imageUri,
      ownerOrgUnitId: request.ownerOrgUnitId,
    });

    await createAuditLog(resolveDatabase(c.env), {
      tenantId: pathParams.tenantId,
      action: 'badge_template.upserted',
      targetType: 'badge_template',
      targetId: pathParams.badgeTemplateId,
      metadata: {
        slug: template.slug,
        title: template.title,
        description: template.description,
        criteriaUri: template.criteriaUri,
        imageUri: template.imageUri,
        ownerOrgUnitId: template.ownerOrgUnitId,
      },
    });

    return c.json(
      {
        tenantId: pathParams.tenantId,
        template,
      },
      201,
    );
  } catch (error: unknown) {
    if (isUniqueConstraintError(error)) {
      return c.json(
        {
          error: 'Badge template slug already exists for tenant',
        },
        409,
      );
    }

    if (
      error instanceof Error &&
      ((error.message.includes('Org unit') && error.message.includes('not found for tenant')) ||
        error.message.includes('ownership changes must use transferBadgeTemplateOwnership'))
    ) {
      return c.json(
        {
          error: error.message,
        },
        422,
      );
    }

    throw error;
  }
});

app.put('/v1/admin/tenants/:tenantId/users/:userId/role', async (c) => {
  const unauthorizedResponse = requireBootstrapAdmin(c);

  if (unauthorizedResponse !== null) {
    return unauthorizedResponse;
  }

  const pathParams = parseTenantUserPathParams(c.req.param());
  const payload = await c.req.json<unknown>();
  const request = parseAdminUpsertTenantMembershipRoleRequest(payload);
  const roleResult = await upsertTenantMembershipRole(resolveDatabase(c.env), {
    tenantId: pathParams.tenantId,
    userId: pathParams.userId,
    role: request.role,
  });

  await createAuditLog(resolveDatabase(c.env), {
    tenantId: pathParams.tenantId,
    action:
      roleResult.previousRole === null
        ? 'membership.role_assigned'
        : roleResult.previousRole === roleResult.membership.role
          ? 'membership.role_reasserted'
          : 'membership.role_changed',
    targetType: 'membership',
    targetId: `${pathParams.tenantId}:${pathParams.userId}`,
    metadata: {
      userId: pathParams.userId,
      previousRole: roleResult.previousRole,
      role: roleResult.membership.role,
      changed: roleResult.changed,
    },
  });

  return c.json(
    {
      tenantId: pathParams.tenantId,
      userId: pathParams.userId,
      role: roleResult.membership.role,
      previousRole: roleResult.previousRole,
      changed: roleResult.changed,
    },
    201,
  );
});

app.get('/v1/admin/lti/issuer-registrations', async (c) => {
  const unauthorizedResponse = requireBootstrapAdmin(c);

  if (unauthorizedResponse !== null) {
    return unauthorizedResponse;
  }

  const registrations = await listLtiIssuerRegistrations(resolveDatabase(c.env));

  return c.json({
    registrations,
  });
});

app.put('/v1/admin/lti/issuer-registrations', async (c) => {
  const unauthorizedResponse = requireBootstrapAdmin(c);

  if (unauthorizedResponse !== null) {
    return unauthorizedResponse;
  }

  const payload = await c.req.json<unknown>();
  const request = parseAdminUpsertLtiIssuerRegistrationRequest(payload);
  const registration = await upsertLtiIssuerRegistration(resolveDatabase(c.env), {
    issuer: request.issuer,
    tenantId: request.tenantId,
    authorizationEndpoint: request.authorizationEndpoint,
    clientId: request.clientId,
    allowUnsignedIdToken: request.allowUnsignedIdToken,
  });

  await createAuditLog(resolveDatabase(c.env), {
    tenantId: registration.tenantId,
    action: 'lti.issuer_registration_upserted',
    targetType: 'lti_issuer_registration',
    targetId: registration.issuer,
    metadata: {
      issuer: registration.issuer,
      tenantId: registration.tenantId,
      clientId: registration.clientId,
      authorizationEndpoint: registration.authorizationEndpoint,
      allowUnsignedIdToken: registration.allowUnsignedIdToken,
    },
  });

  return c.json(
    {
      registration,
    },
    201,
  );
});

app.delete('/v1/admin/lti/issuer-registrations', async (c) => {
  const unauthorizedResponse = requireBootstrapAdmin(c);

  if (unauthorizedResponse !== null) {
    return unauthorizedResponse;
  }

  const payload = await c.req.json<unknown>();
  const request = parseAdminDeleteLtiIssuerRegistrationRequest(payload);
  const normalizedIssuer = normalizeLtiIssuer(request.issuer);
  const registrations = await listLtiIssuerRegistrations(resolveDatabase(c.env));
  const existingRegistration =
    registrations.find(
      (registration) => normalizeLtiIssuer(registration.issuer) === normalizedIssuer,
    ) ?? null;
  const deleted = await deleteLtiIssuerRegistrationByIssuer(resolveDatabase(c.env), request.issuer);

  if (deleted && existingRegistration !== null) {
    await createAuditLog(resolveDatabase(c.env), {
      tenantId: existingRegistration.tenantId,
      action: 'lti.issuer_registration_deleted',
      targetType: 'lti_issuer_registration',
      targetId: normalizedIssuer,
      metadata: {
        issuer: normalizedIssuer,
        tenantId: existingRegistration.tenantId,
      },
    });
  }

  return c.json({
    status: deleted ? 'deleted' : 'not_found',
    issuer: normalizedIssuer,
  });
});

app.get('/admin/lti/issuer-registrations', async (c) => {
  const token = c.req.query('token') ?? null;
  const unauthorizedResponse = requireBootstrapAdminUiToken(c, token);

  if (unauthorizedResponse !== null) {
    return unauthorizedResponse;
  }

  if (token === null) {
    return c.json(
      {
        error: 'Unauthorized',
      },
      401,
    );
  }

  return ltiIssuerRegistrationAdminPageResponse(c, {
    token,
  });
});

app.post('/admin/lti/issuer-registrations', async (c) => {
  const contentType = c.req.header('content-type') ?? '';

  if (!contentType.toLowerCase().includes('application/x-www-form-urlencoded')) {
    return c.json(
      {
        error: 'Content-Type must be application/x-www-form-urlencoded',
      },
      400,
    );
  }

  const rawBody = await c.req.text();
  const formData = new URLSearchParams(rawBody);
  const token = formData.get('token');
  const unauthorizedResponse = requireBootstrapAdminUiToken(c, token);

  if (unauthorizedResponse !== null) {
    return unauthorizedResponse;
  }

  if (token === null) {
    return c.json(
      {
        error: 'Unauthorized',
      },
      401,
    );
  }

  const formState: LtiIssuerRegistrationFormState = {
    issuer: formData.get('issuer') ?? '',
    tenantId: formData.get('tenantId') ?? '',
    authorizationEndpoint: formData.get('authorizationEndpoint') ?? '',
    clientId: formData.get('clientId') ?? '',
    allowUnsignedIdToken: formData.get('allowUnsignedIdToken') !== null,
  };

  let request;

  try {
    request = parseAdminUpsertLtiIssuerRegistrationRequest({
      issuer: formState.issuer,
      tenantId: formState.tenantId,
      authorizationEndpoint: formState.authorizationEndpoint,
      clientId: formState.clientId,
      allowUnsignedIdToken: formState.allowUnsignedIdToken,
    });
  } catch (error) {
    return ltiIssuerRegistrationAdminPageResponse(c, {
      token,
      status: 400,
      submissionError: error instanceof Error ? error.message : 'Invalid LTI registration payload',
      formState,
    });
  }

  const registration = await upsertLtiIssuerRegistration(resolveDatabase(c.env), {
    issuer: request.issuer,
    tenantId: request.tenantId,
    authorizationEndpoint: request.authorizationEndpoint,
    clientId: request.clientId,
    allowUnsignedIdToken: request.allowUnsignedIdToken,
  });

  await createAuditLog(resolveDatabase(c.env), {
    tenantId: registration.tenantId,
    action: 'lti.issuer_registration_upserted',
    targetType: 'lti_issuer_registration',
    targetId: registration.issuer,
    metadata: {
      issuer: registration.issuer,
      tenantId: registration.tenantId,
      clientId: registration.clientId,
      authorizationEndpoint: registration.authorizationEndpoint,
      allowUnsignedIdToken: registration.allowUnsignedIdToken,
    },
  });

  return c.redirect(`/admin/lti/issuer-registrations?token=${encodeURIComponent(token)}`, 303);
});

app.post('/admin/lti/issuer-registrations/delete', async (c) => {
  const contentType = c.req.header('content-type') ?? '';

  if (!contentType.toLowerCase().includes('application/x-www-form-urlencoded')) {
    return c.json(
      {
        error: 'Content-Type must be application/x-www-form-urlencoded',
      },
      400,
    );
  }

  const rawBody = await c.req.text();
  const formData = new URLSearchParams(rawBody);
  const token = formData.get('token');
  const unauthorizedResponse = requireBootstrapAdminUiToken(c, token);

  if (unauthorizedResponse !== null) {
    return unauthorizedResponse;
  }

  if (token === null) {
    return c.json(
      {
        error: 'Unauthorized',
      },
      401,
    );
  }

  const issuerCandidate = formData.get('issuer');

  if (issuerCandidate === null) {
    return ltiIssuerRegistrationAdminPageResponse(c, {
      token,
      status: 400,
      submissionError: 'issuer is required',
    });
  }

  let request;

  try {
    request = parseAdminDeleteLtiIssuerRegistrationRequest({
      issuer: issuerCandidate,
    });
  } catch (error) {
    return ltiIssuerRegistrationAdminPageResponse(c, {
      token,
      status: 400,
      submissionError: error instanceof Error ? error.message : 'Invalid issuer value',
    });
  }

  const normalizedIssuer = normalizeLtiIssuer(request.issuer);
  const registrations = await listLtiIssuerRegistrations(resolveDatabase(c.env));
  const existingRegistration =
    registrations.find(
      (registration) => normalizeLtiIssuer(registration.issuer) === normalizedIssuer,
    ) ?? null;
  const deleted = await deleteLtiIssuerRegistrationByIssuer(resolveDatabase(c.env), request.issuer);

  if (deleted && existingRegistration !== null) {
    await createAuditLog(resolveDatabase(c.env), {
      tenantId: existingRegistration.tenantId,
      action: 'lti.issuer_registration_deleted',
      targetType: 'lti_issuer_registration',
      targetId: normalizedIssuer,
      metadata: {
        issuer: normalizedIssuer,
        tenantId: existingRegistration.tenantId,
      },
    });
  }

  return c.redirect(`/admin/lti/issuer-registrations?token=${encodeURIComponent(token)}`, 303);
});

app.get(OB3_DISCOVERY_PATH, (c) => {
  c.header('Cache-Control', OB3_DISCOVERY_CACHE_CONTROL);
  return c.json(ob3ServiceDescriptionDocument(c));
});

app.post(`${OB3_BASE_PATH}/oauth/register`, async (c) => {
  const payload = await c.req.json<unknown>().catch(() => null);
  const body = asJsonObject(payload);

  if (body === null) {
    return oauthErrorJson(c, 400, 'invalid_client_metadata', 'Request body must be a JSON object');
  }

  const redirectUris = parseStringArray(body.redirect_uris);

  if (redirectUris === null || redirectUris.length === 0) {
    return oauthErrorJson(
      c,
      400,
      'invalid_client_metadata',
      'redirect_uris is required and must be a non-empty array of URLs',
    );
  }

  for (const redirectUri of redirectUris) {
    const validationError = validateRedirectUri(redirectUri);

    if (validationError === 'invalid_scheme') {
      return oauthErrorJson(c, 400, 'invalid_redirect_uri', 'redirect_uris must use http or https');
    }

    if (validationError === 'invalid_url') {
      return oauthErrorJson(
        c,
        400,
        'invalid_redirect_uri',
        'redirect_uris must contain valid URLs',
      );
    }
  }

  const grantTypes =
    body.grant_types === undefined
      ? [OAUTH_GRANT_TYPE_AUTHORIZATION_CODE]
      : parseStringArray(body.grant_types);

  if (grantTypes?.length !== 1 || grantTypes[0] !== OAUTH_GRANT_TYPE_AUTHORIZATION_CODE) {
    return oauthErrorJson(
      c,
      400,
      'invalid_client_metadata',
      'Only authorization_code grant type is currently supported',
    );
  }

  const responseTypes =
    body.response_types === undefined
      ? [OAUTH_RESPONSE_TYPE_CODE]
      : parseStringArray(body.response_types);

  if (responseTypes?.length !== 1 || responseTypes[0] !== OAUTH_RESPONSE_TYPE_CODE) {
    return oauthErrorJson(
      c,
      400,
      'invalid_client_metadata',
      'Only response_type "code" is currently supported',
    );
  }

  const tokenEndpointAuthMethod =
    asNonEmptyString(body.token_endpoint_auth_method) ??
    OAUTH_TOKEN_ENDPOINT_AUTH_METHOD_CLIENT_SECRET_BASIC;

  if (tokenEndpointAuthMethod !== OAUTH_TOKEN_ENDPOINT_AUTH_METHOD_CLIENT_SECRET_BASIC) {
    return oauthErrorJson(
      c,
      400,
      'invalid_client_metadata',
      'Only token_endpoint_auth_method "client_secret_basic" is supported',
    );
  }

  const scopeFromRequest = asNonEmptyString(body.scope);
  const scopeTokens =
    scopeFromRequest === null
      ? [...OB3_OAUTH_SUPPORTED_SCOPE_URIS]
      : splitSpaceDelimited(scopeFromRequest);

  if (scopeTokens.length === 0 || !allScopesSupported(scopeTokens)) {
    return oauthErrorJson(c, 400, 'invalid_scope', 'Requested scope contains unsupported values');
  }

  const clientId = `oc_${generateOpaqueToken()}`;
  const clientSecret = generateOpaqueToken();
  const clientSecretHash = await sha256Hex(clientSecret);
  const createdClient = await createOAuthClient(resolveDatabase(c.env), {
    clientId,
    clientSecretHash,
    clientName: asNonEmptyString(body.client_name) ?? undefined,
    redirectUrisJson: JSON.stringify(redirectUris),
    grantTypesJson: JSON.stringify(grantTypes),
    responseTypesJson: JSON.stringify(responseTypes),
    scope: scopeTokens.join(' '),
    tokenEndpointAuthMethod,
  });
  const issuedAt = Math.floor(Date.parse(createdClient.createdAt) / 1000);

  return c.json(
    {
      client_id: createdClient.clientId,
      client_secret: clientSecret,
      client_id_issued_at: Number.isFinite(issuedAt) ? issuedAt : Math.floor(Date.now() / 1000),
      client_secret_expires_at: 0,
      redirect_uris: redirectUris,
      grant_types: grantTypes,
      response_types: responseTypes,
      token_endpoint_auth_method: tokenEndpointAuthMethod,
      scope: scopeTokens.join(' '),
      ...(createdClient.clientName === null ? {} : { client_name: createdClient.clientName }),
    },
    201,
  );
});

app.get(`${OB3_BASE_PATH}/oauth/authorize`, async (c) => {
  const clientId = asNonEmptyString(c.req.query('client_id'));
  const responseType = asNonEmptyString(c.req.query('response_type'));
  const redirectUri = asNonEmptyString(c.req.query('redirect_uri'));
  const state = c.req.query('state');
  const db = resolveDatabase(c.env);

  if (clientId === null) {
    return oauthErrorJson(c, 400, 'invalid_request', 'client_id is required');
  }

  const registeredClient = await findOAuthClientById(db, clientId);

  if (registeredClient === null) {
    return oauthErrorJson(c, 400, 'invalid_client', 'Unknown client_id');
  }

  const clientMetadata = parseOAuthClientMetadata(registeredClient);

  if (clientMetadata === null) {
    return oauthErrorJson(c, 500, 'server_error', 'Stored client metadata is invalid');
  }

  if (redirectUri === null || !clientMetadata.redirectUris.includes(redirectUri)) {
    return oauthErrorJson(
      c,
      400,
      'invalid_redirect_uri',
      'redirect_uri is required and must match a registered redirect URI',
    );
  }

  if (state === undefined || state.length === 0) {
    return oauthErrorJson(c, 400, 'invalid_request', 'state is required');
  }

  if (responseType !== OAUTH_RESPONSE_TYPE_CODE) {
    return c.redirect(
      oauthRedirectUriWithParams(redirectUri, {
        error: 'unsupported_response_type',
        state,
      }),
      302,
    );
  }

  const requestedScopeRaw = asNonEmptyString(c.req.query('scope'));

  if (requestedScopeRaw === null) {
    return c.redirect(
      oauthRedirectUriWithParams(redirectUri, {
        error: 'invalid_scope',
        error_description: 'scope is required',
        state,
      }),
      302,
    );
  }

  const requestedScopeTokens = splitSpaceDelimited(requestedScopeRaw);

  if (
    requestedScopeTokens.length === 0 ||
    !allScopesSupported(requestedScopeTokens) ||
    !isSubset(requestedScopeTokens, clientMetadata.scope)
  ) {
    return c.redirect(
      oauthRedirectUriWithParams(redirectUri, {
        error: 'invalid_scope',
        state,
      }),
      302,
    );
  }

  const codeChallenge = c.req.query('code_challenge');
  const codeChallengeMethod = c.req.query('code_challenge_method');

  if (
    codeChallenge === undefined ||
    codeChallenge.length === 0 ||
    codeChallengeMethod === undefined ||
    codeChallengeMethod.length === 0
  ) {
    return c.redirect(
      oauthRedirectUriWithParams(redirectUri, {
        error: 'invalid_request',
        error_description: 'code_challenge and code_challenge_method are required',
        state,
      }),
      302,
    );
  }

  if (codeChallengeMethod !== OAUTH_PKCE_CODE_CHALLENGE_METHOD_S256) {
    return c.redirect(
      oauthRedirectUriWithParams(redirectUri, {
        error: 'invalid_request',
        error_description: 'code_challenge_method must be S256',
        state,
      }),
      302,
    );
  }

  if (!isPkceCodeChallenge(codeChallenge)) {
    return c.redirect(
      oauthRedirectUriWithParams(redirectUri, {
        error: 'invalid_request',
        error_description: 'code_challenge must be a base64url-encoded SHA-256 digest',
        state,
      }),
      302,
    );
  }

  const session = await resolveSessionFromCookie(c);

  if (session === null) {
    return c.redirect(
      oauthRedirectUriWithParams(redirectUri, {
        error: 'access_denied',
        error_description: 'Resource owner is not authenticated',
        state,
      }),
      302,
    );
  }

  const authorizationCode = generateOpaqueToken();
  const authorizationCodeHash = await sha256Hex(authorizationCode);

  await createOAuthAuthorizationCode(db, {
    clientId: clientMetadata.clientId,
    userId: session.userId,
    tenantId: session.tenantId,
    codeHash: authorizationCodeHash,
    redirectUri,
    scope: requestedScopeTokens.join(' '),
    expiresAt: addSecondsToIso(new Date().toISOString(), OAUTH_AUTHORIZATION_CODE_TTL_SECONDS),
    codeChallenge,
    codeChallengeMethod,
  });

  return c.redirect(
    oauthRedirectUriWithParams(redirectUri, {
      code: authorizationCode,
      scope: requestedScopeTokens.join(' '),
      state,
    }),
    302,
  );
});

const handleOAuthTokenRequest = async (
  c: AppContext,
  options?: {
    forceRefreshGrant?: boolean;
  },
): Promise<Response> => {
  const db = resolveDatabase(c.env);
  const authResult = await authenticateOAuthClient(c, db);

  if (authResult instanceof Response) {
    return authResult;
  }

  const { clientMetadata } = authResult;
  const rawBody = await c.req.text();
  const formData = new URLSearchParams(rawBody);
  const requestedGrantType = asNonEmptyString(formData.get('grant_type'));
  const forceRefreshGrant = options?.forceRefreshGrant === true;
  const grantType = forceRefreshGrant
    ? (requestedGrantType ?? OAUTH_GRANT_TYPE_REFRESH_TOKEN)
    : requestedGrantType;

  if (grantType === OAUTH_GRANT_TYPE_AUTHORIZATION_CODE) {
    const code = asNonEmptyString(formData.get('code'));
    const redirectUri = asNonEmptyString(formData.get('redirect_uri'));
    const codeVerifier = formData.get('code_verifier');
    const requestedScope = asNonEmptyString(formData.get('scope'));

    if (
      code === null ||
      redirectUri === null ||
      codeVerifier === null ||
      codeVerifier.length === 0
    ) {
      return oauthTokenErrorJson(
        c,
        400,
        'invalid_request',
        'code, redirect_uri, and code_verifier are required',
      );
    }

    if (!isPkceCodeVerifier(codeVerifier)) {
      return oauthTokenErrorJson(c, 400, 'invalid_request', 'code_verifier is invalid');
    }

    const nowIso = new Date().toISOString();
    const consumedAuthorizationCode = await consumeOAuthAuthorizationCode(db, {
      clientId: clientMetadata.clientId,
      codeHash: await sha256Hex(code),
      redirectUri,
      nowIso,
    });

    if (consumedAuthorizationCode === null) {
      return oauthTokenErrorJson(
        c,
        400,
        'invalid_grant',
        'Authorization code is invalid or expired',
      );
    }

    if (
      consumedAuthorizationCode.codeChallenge === null ||
      consumedAuthorizationCode.codeChallengeMethod !== OAUTH_PKCE_CODE_CHALLENGE_METHOD_S256
    ) {
      return oauthTokenErrorJson(
        c,
        400,
        'invalid_grant',
        'Authorization code is missing PKCE binding',
      );
    }

    const computedCodeChallenge = await sha256Base64Url(codeVerifier);

    if (computedCodeChallenge !== consumedAuthorizationCode.codeChallenge) {
      return oauthTokenErrorJson(c, 400, 'invalid_grant', 'PKCE verification failed');
    }

    if (requestedScope === null) {
      return oauthTokenErrorJson(c, 400, 'invalid_request', 'scope is required');
    }

    const originalScopeTokens = splitSpaceDelimited(consumedAuthorizationCode.scope);
    const requestedScopeTokens = splitSpaceDelimited(requestedScope);

    if (
      requestedScopeTokens.length === 0 ||
      !allScopesSupported(requestedScopeTokens) ||
      !isSubset(requestedScopeTokens, originalScopeTokens)
    ) {
      return oauthTokenErrorJson(
        c,
        400,
        'invalid_scope',
        'Requested scope exceeds authorization grant',
      );
    }

    const issuedTokens = await issueOAuthAccessAndRefreshTokens({
      db,
      clientMetadata,
      userId: consumedAuthorizationCode.userId,
      tenantId: consumedAuthorizationCode.tenantId,
      scopeTokens: requestedScopeTokens,
      nowIso,
    });

    return oauthTokenSuccessJson(c, {
      access_token: issuedTokens.accessToken,
      refresh_token: issuedTokens.refreshToken,
      token_type: 'Bearer',
      expires_in: OAUTH_ACCESS_TOKEN_TTL_SECONDS,
      scope: requestedScopeTokens.join(' '),
    });
  }

  if (grantType === OAUTH_GRANT_TYPE_REFRESH_TOKEN) {
    const refreshToken = asNonEmptyString(formData.get('refresh_token'));
    const requestedScope = asNonEmptyString(formData.get('scope'));

    if (refreshToken === null) {
      return oauthTokenErrorJson(c, 400, 'invalid_request', 'refresh_token is required');
    }

    const nowIso = new Date().toISOString();
    const consumedRefreshToken = await consumeOAuthRefreshToken(db, {
      clientId: clientMetadata.clientId,
      refreshTokenHash: await sha256Hex(refreshToken),
      nowIso,
    });

    if (consumedRefreshToken === null) {
      return oauthTokenErrorJson(c, 400, 'invalid_grant', 'Refresh token is invalid or expired');
    }

    const originallyGrantedScopeTokens = splitSpaceDelimited(consumedRefreshToken.scope);
    const grantedScopeTokens =
      requestedScope === null ? originallyGrantedScopeTokens : splitSpaceDelimited(requestedScope);

    if (
      grantedScopeTokens.length === 0 ||
      !allScopesSupported(grantedScopeTokens) ||
      !isSubset(grantedScopeTokens, originallyGrantedScopeTokens)
    ) {
      return oauthTokenErrorJson(
        c,
        400,
        'invalid_scope',
        'Requested scope exceeds refresh token grant',
      );
    }

    const issuedTokens = await issueOAuthAccessAndRefreshTokens({
      db,
      clientMetadata,
      userId: consumedRefreshToken.userId,
      tenantId: consumedRefreshToken.tenantId,
      scopeTokens: grantedScopeTokens,
      nowIso,
    });

    return oauthTokenSuccessJson(c, {
      access_token: issuedTokens.accessToken,
      refresh_token: issuedTokens.refreshToken,
      token_type: 'Bearer',
      expires_in: OAUTH_ACCESS_TOKEN_TTL_SECONDS,
      scope: grantedScopeTokens.join(' '),
    });
  }

  if (
    forceRefreshGrant &&
    requestedGrantType !== null &&
    requestedGrantType !== OAUTH_GRANT_TYPE_REFRESH_TOKEN
  ) {
    return oauthTokenErrorJson(
      c,
      400,
      'invalid_request',
      'grant_type must be refresh_token for this endpoint',
    );
  }

  return oauthTokenErrorJson(
    c,
    400,
    'unsupported_grant_type',
    'Supported grant_type values are authorization_code and refresh_token',
  );
};

app.post(`${OB3_BASE_PATH}/oauth/token`, async (c) => {
  return handleOAuthTokenRequest(c);
});

app.post(`${OB3_BASE_PATH}/oauth/refresh`, async (c) => {
  return handleOAuthTokenRequest(c, {
    forceRefreshGrant: true,
  });
});

app.post(`${OB3_BASE_PATH}/oauth/revoke`, async (c) => {
  const db = resolveDatabase(c.env);
  const authResult = await authenticateOAuthClient(c, db);

  if (authResult instanceof Response) {
    return authResult;
  }

  const { clientMetadata } = authResult;
  const formData = new URLSearchParams(await c.req.text());
  const token = asNonEmptyString(formData.get('token'));
  const tokenTypeHint = asNonEmptyString(formData.get('token_type_hint'));

  if (token === null || tokenTypeHint === null) {
    return oauthTokenErrorJson(c, 400, 'invalid_request', 'token and token_type_hint are required');
  }

  const tokenHash = await sha256Hex(token);
  const revokedAt = new Date().toISOString();

  if (tokenTypeHint === OAUTH_TOKEN_TYPE_HINT_REFRESH_TOKEN) {
    await revokeOAuthRefreshTokenByHash(db, {
      clientId: clientMetadata.clientId,
      refreshTokenHash: tokenHash,
      revokedAt,
    });
    return c.body(null, 200);
  }

  if (tokenTypeHint === OAUTH_TOKEN_TYPE_HINT_ACCESS_TOKEN) {
    await revokeOAuthAccessTokenByHash(db, {
      clientId: clientMetadata.clientId,
      accessTokenHash: tokenHash,
      revokedAt,
    });
    return c.body(null, 200);
  }

  return oauthTokenErrorJson(
    c,
    400,
    'unsupported_token_type',
    'token_type_hint must be access_token or refresh_token',
  );
});

app.get(`${OB3_BASE_PATH}/credentials`, async (c) => {
  const accessTokenContext = await authenticateOb3AccessToken(
    c,
    OB3_OAUTH_SCOPE_CREDENTIAL_READONLY,
  );

  if (accessTokenContext instanceof Response) {
    return accessTokenContext;
  }

  const parsedLimit = parsePositiveIntegerQueryParam(c.req.query('limit'), {
    minimum: 1,
    fallback: 50,
  });
  const parsedOffset = parsePositiveIntegerQueryParam(c.req.query('offset'), {
    minimum: 0,
    fallback: 0,
  });

  if (parsedLimit === null || parsedOffset === null) {
    return ob3ErrorJson(c, 400, 'limit and offset query parameters must be valid integers');
  }

  const since = normalizeSinceQueryParam(c.req.query('since'));

  if (since === null) {
    return ob3ErrorJson(c, 400, 'since query parameter must be a valid ISO8601 timestamp');
  }

  const limit = Math.min(parsedLimit, 200);
  const offset = parsedOffset;
  const credentialsResult = await listOb3SubjectCredentials(resolveDatabase(c.env), {
    tenantId: accessTokenContext.tenantId,
    userId: accessTokenContext.userId,
    limit,
    offset,
    ...(since === undefined ? {} : { since }),
  });
  const credential: JsonObject[] = [];
  const compactJwsString: string[] = [];

  for (const entry of credentialsResult.credentials) {
    if (entry.payloadJson !== null) {
      try {
        const parsedPayload = asJsonObject(JSON.parse(entry.payloadJson) as unknown);

        if (parsedPayload !== null) {
          credential.push(parsedPayload);
        }
      } catch {
        logWarn(observabilityContext(c.env), 'ob3_credentials_payload_parse_failed', {
          credentialId: entry.credentialId,
        });
      }
      continue;
    }

    if (entry.compactJws !== null) {
      compactJwsString.push(entry.compactJws);
    }
  }

  c.header('X-Total-Count', String(credentialsResult.totalCount));
  c.header(
    'Link',
    ob3CredentialsLinkHeader({
      requestUrl: c.req.url,
      limit,
      offset,
      totalCount: credentialsResult.totalCount,
      since,
    }),
  );

  return c.json({
    credential,
    compactJwsString,
  });
});

app.post(`${OB3_BASE_PATH}/credentials`, async (c) => {
  const accessTokenContext = await authenticateOb3AccessToken(c, OB3_OAUTH_SCOPE_CREDENTIAL_UPSERT);

  if (accessTokenContext instanceof Response) {
    return accessTokenContext;
  }

  const contentType = c.req.header('content-type')?.toLowerCase() ?? '';
  const db = resolveDatabase(c.env);
  const isCredentialJsonContentType =
    contentType.includes('application/json') ||
    contentType.includes('application/ld+json') ||
    contentType.includes('application/vc+ld+json');

  if (isCredentialJsonContentType) {
    const requestPayload = await c.req.json<unknown>().catch(() => null);
    const credentialPayload = asJsonObject(requestPayload);

    if (credentialPayload === null) {
      return ob3ErrorJson(c, 400, 'Request body must be a JSON object');
    }

    const credentialId = asNonEmptyString(credentialPayload.id);

    if (credentialId === null) {
      return ob3ErrorJson(c, 400, 'Credential payload must include a non-empty id');
    }

    const upsertResult = await upsertOb3SubjectCredential(db, {
      tenantId: accessTokenContext.tenantId,
      userId: accessTokenContext.userId,
      credentialId,
      payloadJson: JSON.stringify(credentialPayload),
      issuedAt:
        asNonEmptyString(credentialPayload.validFrom) ??
        asNonEmptyString(credentialPayload.awardedDate) ??
        undefined,
    });

    const responseContentType = contentType.includes('application/vc+ld+json')
      ? 'application/vc+ld+json; charset=utf-8'
      : contentType.includes('application/ld+json')
        ? 'application/ld+json; charset=utf-8'
        : 'application/json; charset=utf-8';
    c.header('Content-Type', responseContentType);
    return c.body(JSON.stringify(credentialPayload), upsertResult.status === 'created' ? 201 : 200);
  }

  if (contentType.includes('text/plain')) {
    const compactJws = (await c.req.text()).trim();

    if (!/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*\.[A-Za-z0-9_-]+$/.test(compactJws)) {
      return ob3ErrorJson(c, 400, 'Request body must be a compact JWS string');
    }

    let credentialId: string;

    try {
      credentialId = resolveOb3CredentialIdFromCompactJws(compactJws);
    } catch (error: unknown) {
      return ob3ErrorJson(
        c,
        400,
        error instanceof Error
          ? error.message
          : 'Request body must contain a valid compact JWS payload',
      );
    }

    const upsertResult = await upsertOb3SubjectCredential(db, {
      tenantId: accessTokenContext.tenantId,
      userId: accessTokenContext.userId,
      credentialId,
      compactJws,
    });

    c.header('Content-Type', 'text/plain; charset=utf-8');
    return c.body(compactJws, upsertResult.status === 'created' ? 201 : 200);
  }

  return ob3ErrorJson(
    c,
    400,
    'content-type must be application/json, application/ld+json, application/vc+ld+json, or text/plain',
  );
});

app.get(`${OB3_BASE_PATH}/profile`, async (c) => {
  const accessTokenContext = await authenticateOb3AccessToken(c, OB3_OAUTH_SCOPE_PROFILE_READONLY);

  if (accessTokenContext instanceof Response) {
    return accessTokenContext;
  }

  const storedProfile = await findOb3SubjectProfile(resolveDatabase(c.env), {
    tenantId: accessTokenContext.tenantId,
    userId: accessTokenContext.userId,
  });
  const user = await findUserById(resolveDatabase(c.env), accessTokenContext.userId);
  let parsedStoredProfile: JsonObject | null = null;

  if (storedProfile !== null) {
    try {
      parsedStoredProfile = asJsonObject(JSON.parse(storedProfile.profileJson) as unknown);
    } catch {
      parsedStoredProfile = null;
    }
  }

  const baseProfile =
    storedProfile === null
      ? defaultOb3Profile({
          tenantId: accessTokenContext.tenantId,
          userId: accessTokenContext.userId,
          ...(user === null ? {} : { email: user.email }),
        })
      : (parsedStoredProfile ??
        defaultOb3Profile({
          tenantId: accessTokenContext.tenantId,
          userId: accessTokenContext.userId,
          ...(user === null ? {} : { email: user.email }),
        }));

  return c.json(
    normalizeOb3Profile({
      profile: baseProfile,
      tenantId: accessTokenContext.tenantId,
      userId: accessTokenContext.userId,
    }),
  );
});

app.put(`${OB3_BASE_PATH}/profile`, async (c) => {
  const accessTokenContext = await authenticateOb3AccessToken(c, OB3_OAUTH_SCOPE_PROFILE_UPDATE);

  if (accessTokenContext instanceof Response) {
    return accessTokenContext;
  }

  const requestPayload = await c.req.json<unknown>().catch(() => null);
  const requestProfile = asJsonObject(requestPayload);

  if (requestProfile === null) {
    return ob3ErrorJson(c, 400, 'Request body must be a JSON object');
  }

  const normalizedProfile = normalizeOb3Profile({
    profile: requestProfile,
    tenantId: accessTokenContext.tenantId,
    userId: accessTokenContext.userId,
  });

  await upsertOb3SubjectProfile(resolveDatabase(c.env), {
    tenantId: accessTokenContext.tenantId,
    userId: accessTokenContext.userId,
    profileJson: JSON.stringify(normalizedProfile),
  });

  return c.json(normalizedProfile);
});

app.get('/.well-known/did.json', async (c): Promise<Response> => {
  const did = didForWellKnownRequest(c.req.url);
  const signingEntry = await resolveSigningEntryForDid(c, did);

  if (signingEntry === null) {
    return c.json(
      {
        error: 'No DID document configured for request host',
        did,
      },
      404,
    );
  }

  const didDocument = didDocumentForSigningEntry({
    did,
    signingEntry,
  });

  if (didDocument === null) {
    return c.json(
      {
        error: 'DID document generation requires an Ed25519 or P-256 public key',
        did,
      },
      422,
    );
  }

  return c.json(didDocument);
});

app.get('/:tenantSlug/did.json', async (c): Promise<Response> => {
  const tenantSlug = c.req.param('tenantSlug');
  const did = didForTenantPathRequest(c.req.url, tenantSlug);
  const signingEntry = await resolveSigningEntryForDid(c, did);

  if (signingEntry === null) {
    return c.json(
      {
        error: 'No DID document configured for tenant path',
        did,
      },
      404,
    );
  }

  const didDocument = didDocumentForSigningEntry({
    did,
    signingEntry,
  });

  if (didDocument === null) {
    return c.json(
      {
        error: 'DID document generation requires an Ed25519 or P-256 public key',
        did,
      },
      422,
    );
  }

  return c.json(didDocument);
});

app.get('/.well-known/jwks.json', async (c): Promise<Response> => {
  const did = didForWellKnownRequest(c.req.url);
  const signingEntry = await resolveSigningEntryForDid(c, did);

  if (signingEntry === null) {
    return c.json(
      {
        error: 'No JWKS configured for request host',
        did,
      },
      404,
    );
  }

  return c.json(
    jwksDocumentForSigningEntry({
      signingEntry,
      historicalKeys: resolveHistoricalSigningKeysForDid(c, did),
    }),
  );
});

app.get('/:tenantSlug/jwks.json', async (c): Promise<Response> => {
  const tenantSlug = c.req.param('tenantSlug');
  const did = didForTenantPathRequest(c.req.url, tenantSlug);
  const signingEntry = await resolveSigningEntryForDid(c, did);

  if (signingEntry === null) {
    return c.json(
      {
        error: 'No JWKS configured for tenant path',
        did,
      },
      404,
    );
  }

  return c.json(
    jwksDocumentForSigningEntry({
      signingEntry,
      historicalKeys: resolveHistoricalSigningKeysForDid(c, did),
    }),
  );
});

app.get('/credentials/v1/:credentialId', async (c) => {
  const pathParams = parseCredentialPathParams(c.req.param());
  const result = await loadVerificationViewModel(
    resolveDatabase(c.env),
    c.env.BADGE_OBJECTS,
    pathParams.credentialId,
  );

  if (result.status !== 'ok') {
    const statusCode = result.status === 'invalid_id' ? 400 : 404;
    const errorMessage =
      result.status === 'invalid_id' ? 'Invalid credential identifier' : 'Credential not found';

    return c.json(
      {
        error: errorMessage,
      },
      statusCode,
    );
  }

  c.header('Cache-Control', 'no-store');

  const statusList: CredentialStatusListReference | null =
    result.value.assertion.statusListIndex === null
      ? null
      : credentialStatusForAssertion(
          revocationStatusListUrlForTenant(c.req.url, result.value.assertion.tenantId),
          result.value.assertion.statusListIndex,
        );
  const checkedAt = new Date().toISOString();
  const checks = await summarizeCredentialVerificationChecks({
    context: c,
    credential: result.value.credential,
    checkedAt,
    expectedStatusList: statusList,
  });
  const resolvedRevokedAt =
    checks.credentialStatus.status === 'valid'
      ? checks.credentialStatus.revoked
        ? checkedAt
        : null
      : result.value.assertion.revokedAt;
  const lifecycle = summarizeCredentialLifecycleVerification(
    result.value.credential,
    resolvedRevokedAt,
    checkedAt,
  );
  const proof = await verifyCredentialProofSummary(c, result.value.credential);

  return c.json({
    assertionId: result.value.assertion.id,
    tenantId: result.value.assertion.tenantId,
    issuedAt: result.value.assertion.issuedAt,
    verification: {
      status: lifecycle.state,
      reason: lifecycle.reason,
      checkedAt: lifecycle.checkedAt,
      expiresAt: lifecycle.expiresAt,
      revokedAt: lifecycle.revokedAt,
      statusList,
      checks,
      proof,
    },
    credential: result.value.credential,
  });
});

app.post('/v1/presentations/create', async (c): Promise<Response> => {
  const session = await resolveSessionFromCookie(c);

  if (session === null) {
    return c.json(
      {
        error: 'Not authenticated',
      },
      401,
    );
  }

  let request: ReturnType<typeof parsePresentationCreateRequest>;

  try {
    request = parsePresentationCreateRequest(await c.req.json<unknown>());
  } catch {
    return c.json(
      {
        error: 'Invalid presentation create request payload',
      },
      400,
    );
  }

  if (!request.holderDid.startsWith('did:key:')) {
    return c.json(
      {
        error: 'Presentation creation currently supports did:key holder DIDs only',
      },
      422,
    );
  }

  const expectedHolderPublicJwk = ed25519PublicJwkFromDidKey(request.holderDid);

  if (expectedHolderPublicJwk === null) {
    return c.json(
      {
        error: 'holderDid is not a valid did:key identifier',
      },
      422,
    );
  }

  if (request.holderPrivateJwk.x !== expectedHolderPublicJwk.x) {
    return c.json(
      {
        error: 'holderPrivateJwk does not match holderDid public key',
      },
      422,
    );
  }

  const holderPrivateJwk: Ed25519PrivateJwk = {
    kty: request.holderPrivateJwk.kty,
    crv: request.holderPrivateJwk.crv,
    x: request.holderPrivateJwk.x,
    d: request.holderPrivateJwk.d,
    ...(request.holderPrivateJwk.kid === undefined ? {} : { kid: request.holderPrivateJwk.kid }),
  };
  const db = resolveDatabase(c.env);
  const learnerBadges = await listLearnerBadgeSummaries(db, {
    tenantId: session.tenantId,
    userId: session.userId,
  });
  const learnerAssertionIds = new Set<string>(learnerBadges.map((badge) => badge.assertionId));
  const selectedCredentials: JsonObject[] = [];

  for (const credentialId of request.credentialIds) {
    const tenantScopedCredentialId = parseTenantScopedCredentialId(credentialId);

    if (tenantScopedCredentialId?.tenantId !== session.tenantId) {
      return c.json(
        {
          error:
            'credentialIds must contain tenant-scoped assertion identifiers for the active session tenant',
          credentialId,
        },
        422,
      );
    }

    if (!learnerAssertionIds.has(credentialId)) {
      return c.json(
        {
          error: 'Credential is not accessible for the authenticated learner account',
          credentialId,
        },
        403,
      );
    }

    const assertion = await findAssertionById(db, session.tenantId, credentialId);

    if (assertion === null) {
      return c.json(
        {
          error: 'Credential not found',
          credentialId,
        },
        404,
      );
    }

    const credential = await loadCredentialForAssertion(c.env.BADGE_OBJECTS, assertion);
    const credentialSubject = asJsonObject(credential.credentialSubject);
    const subjectId = asNonEmptyString(credentialSubject?.id);

    if (subjectId !== request.holderDid) {
      return c.json(
        {
          error: 'Credential subject DID does not match requested presentation holder DID',
          credentialId,
          subjectId,
        },
        422,
      );
    }

    selectedCredentials.push(credential);
  }

  const verificationMethod = didKeyVerificationMethod(request.holderDid);

  if (verificationMethod === null) {
    return c.json(
      {
        error: 'Unable to resolve holder verification method from holder DID',
      },
      422,
    );
  }

  const presentation = await signCredentialWithEd25519Signature2020({
    credential: {
      '@context': [VC_DATA_MODEL_CONTEXT_URL],
      type: ['VerifiablePresentation'],
      holder: request.holderDid,
      verifiableCredential: selectedCredentials,
    },
    privateJwk: holderPrivateJwk,
    verificationMethod,
  });

  c.header('Cache-Control', 'no-store');

  return c.json({
    holderDid: request.holderDid,
    verificationMethod,
    credentialCount: selectedCredentials.length,
    presentation,
  });
});

app.post('/v1/presentations/verify', async (c): Promise<Response> => {
  let request: ReturnType<typeof parsePresentationVerifyRequest>;

  try {
    request = parsePresentationVerifyRequest(await c.req.json<unknown>());
  } catch {
    return c.json(
      {
        error: 'Invalid presentation verification request payload',
      },
      400,
    );
  }

  const presentation = request.presentation;
  const holderDid = asNonEmptyString(presentation.holder);
  const presentationTypes = normalizedStringValues(presentation.type);
  const contextUrls: string[] = [];
  collectContextUrls(presentation['@context'], contextUrls);
  const credentials = verifiableCredentialObjectsFromPresentation(presentation);

  if (
    holderDid === null ||
    !presentationTypes.includes('VerifiablePresentation') ||
    !contextUrls.includes(VC_DATA_MODEL_CONTEXT_URL) ||
    credentials === null ||
    credentials.length === 0
  ) {
    return c.json(
      {
        error:
          'Payload must be a VerifiablePresentation with holder DID and at least one verifiableCredential',
      },
      400,
    );
  }

  const checkedAt = new Date().toISOString();
  const holderProof = await verifyPresentationHolderProofSummary(c, presentation, holderDid);
  const credentialResults: PresentationCredentialVerificationResult[] = [];

  for (const credential of credentials) {
    credentialResults.push(
      await verifyCredentialInPresentation({
        context: c,
        credential,
        holderDid,
        checkedAt,
      }),
    );
  }

  const status: 'valid' | 'invalid' =
    holderProof.status === 'valid' && credentialResults.every((entry) => entry.status === 'valid')
      ? 'valid'
      : 'invalid';

  c.header('Cache-Control', 'no-store');

  return c.json({
    status,
    checkedAt,
    holder: {
      did: holderDid,
      proof: holderProof,
    },
    credentialCount: credentialResults.length,
    credentials: credentialResults,
  });
});

app.get('/credentials/v1/status-lists/:tenantId/revocation', async (c) => {
  const pathParams = parseTenantPathParams(c.req.param());
  const issuerDid = createDidWeb({
    host: c.env.PLATFORM_DOMAIN,
    pathSegments: [pathParams.tenantId],
  });
  const signingEntry = await resolveSigningEntryForDid(c, issuerDid);

  if (signingEntry === null) {
    return c.json(
      {
        error: 'No signing configuration for tenant DID',
        did: issuerDid,
      },
      404,
    );
  }

  if (
    signingEntry.privateJwk !== undefined &&
    !isEd25519SigningPrivateJwk(signingEntry.privateJwk)
  ) {
    return c.json(
      {
        error: 'Revocation status list signing requires an Ed25519 private key',
        did: issuerDid,
      },
      422,
    );
  }

  if (
    signingEntry.privateJwk === undefined &&
    resolveRemoteSignerRegistryEntryForDid(c, issuerDid) === null
  ) {
    return c.json(
      {
        error:
          'Tenant DID is missing private signing key material and no remote signer is configured',
        did: issuerDid,
      },
      500,
    );
  }

  const assertions = await listAssertionStatusListEntries(
    resolveDatabase(c.env),
    pathParams.tenantId,
  );
  const statusEntries = assertions.map((assertion) => {
    return {
      statusListIndex: assertion.statusListIndex,
      revoked: assertion.revokedAt !== null,
    };
  });
  const statusListCredentialInput = await buildRevocationStatusListCredential({
    requestUrl: c.req.url,
    tenantId: pathParams.tenantId,
    issuerDid,
    statusEntries,
  });
  const signedStatusListCredential = await signCredentialForDid({
    context: c,
    did: issuerDid,
    credential: statusListCredentialInput.credential,
    proofType: 'Ed25519Signature2020',
    createdAt: statusListCredentialInput.issuedAt,
    missingPrivateKeyError:
      'Tenant DID is missing private signing key material and no remote signer is configured',
    ed25519KeyRequirementError: 'Revocation status list signing requires an Ed25519 private key',
  });

  if (signedStatusListCredential.status !== 'ok') {
    return c.json(
      {
        error: signedStatusListCredential.error,
        did: issuerDid,
      },
      signedStatusListCredential.statusCode,
    );
  }

  c.header('Cache-Control', 'no-store');
  c.header('Content-Type', 'application/ld+json; charset=utf-8');
  return c.body(JSON.stringify(signedStatusListCredential.credential, null, 2));
});

app.get('/credentials/v1/:credentialId/jsonld', async (c) => {
  const pathParams = parseCredentialPathParams(c.req.param());
  const result = await loadVerificationViewModel(
    resolveDatabase(c.env),
    c.env.BADGE_OBJECTS,
    pathParams.credentialId,
  );

  if (result.status !== 'ok') {
    const statusCode = result.status === 'invalid_id' ? 400 : 404;
    const errorMessage =
      result.status === 'invalid_id' ? 'Invalid credential identifier' : 'Credential not found';

    return c.json(
      {
        error: errorMessage,
      },
      statusCode,
    );
  }

  c.header('Cache-Control', 'no-store');
  c.header('Content-Type', 'application/ld+json; charset=utf-8');

  return c.body(JSON.stringify(result.value.credential, null, 2));
});

app.get('/credentials/v1/:credentialId/download', async (c) => {
  const pathParams = parseCredentialPathParams(c.req.param());
  const result = await loadVerificationViewModel(
    resolveDatabase(c.env),
    c.env.BADGE_OBJECTS,
    pathParams.credentialId,
  );

  if (result.status !== 'ok') {
    const statusCode = result.status === 'invalid_id' ? 400 : 404;
    const errorMessage =
      result.status === 'invalid_id' ? 'Invalid credential identifier' : 'Credential not found';

    return c.json(
      {
        error: errorMessage,
      },
      statusCode,
    );
  }

  c.header('Cache-Control', 'no-store');
  c.header('Content-Type', 'application/ld+json; charset=utf-8');
  c.header(
    'Content-Disposition',
    `attachment; filename="${credentialDownloadFilename(result.value.assertion.id)}"`,
  );

  return c.body(JSON.stringify(result.value.credential, null, 2));
});

app.get('/credentials/v1/:credentialId/download.pdf', async (c) => {
  const pathParams = parseCredentialPathParams(c.req.param());
  const result = await loadVerificationViewModel(
    resolveDatabase(c.env),
    c.env.BADGE_OBJECTS,
    pathParams.credentialId,
  );

  if (result.status !== 'ok') {
    const statusCode = result.status === 'invalid_id' ? 400 : 404;
    const errorMessage =
      result.status === 'invalid_id' ? 'Invalid credential identifier' : 'Credential not found';

    return c.json(
      {
        error: errorMessage,
      },
      statusCode,
    );
  }

  const publicBadgePath = publicBadgePathForAssertion(result.value.assertion);
  const verificationPath = `/credentials/v1/${encodeURIComponent(result.value.assertion.id)}`;
  const ob3JsonPath = `${verificationPath}/jsonld`;
  const credentialId = asString(result.value.credential.id) ?? result.value.assertion.id;
  const achievementDetails = achievementDetailsFromCredential(result.value.credential);
  const recipientName =
    result.value.recipientDisplayName ??
    recipientDisplayNameFromAssertion(result.value.assertion) ??
    'Badge recipient';
  const pdfDocument = await renderBadgePdfDocument({
    badgeName: badgeNameFromCredential(result.value.credential),
    recipientName,
    recipientIdentifier: recipientFromCredential(result.value.credential),
    issuerName: issuerNameFromCredential(result.value.credential),
    issuedAt: `${formatIsoTimestamp(result.value.assertion.issuedAt)} UTC`,
    status: result.value.assertion.revokedAt === null ? 'Verified' : 'Revoked',
    assertionId: result.value.assertion.id,
    credentialId,
    publicBadgeUrl: new URL(publicBadgePath, c.req.url).toString(),
    verificationUrl: new URL(verificationPath, c.req.url).toString(),
    ob3JsonUrl: new URL(ob3JsonPath, c.req.url).toString(),
    badgeImageUrl: achievementDetails.imageUri,
    ...(result.value.assertion.revokedAt === null
      ? {}
      : {
          revokedAt: `${formatIsoTimestamp(result.value.assertion.revokedAt)} UTC`,
        }),
  });
  const pdfBody = Uint8Array.from(pdfDocument).buffer;

  return new Response(pdfBody, {
    status: 200,
    headers: {
      'Cache-Control': 'no-store',
      'Content-Type': 'application/pdf',
      'Content-Disposition': `attachment; filename="${credentialPdfDownloadFilename(result.value.assertion.id)}"`,
    },
  });
});

app.get('/badges/:badgeIdentifier/public_url', (c) => {
  const badgeIdentifier = c.req.param('badgeIdentifier').trim();

  if (badgeIdentifier.length === 0) {
    return c.html(publicBadgeNotFoundPage(), 404);
  }

  return c.redirect(`/badges/${encodeURIComponent(badgeIdentifier)}`, 308);
});

app.get('/badges/:badgeIdentifier', async (c) => {
  const badgeIdentifier = c.req.param('badgeIdentifier');
  const result = await loadPublicBadgeViewModel(
    resolveDatabase(c.env),
    c.env.BADGE_OBJECTS,
    badgeIdentifier,
  );

  c.header('Cache-Control', 'no-store');

  if (result.status === 'not_found') {
    return c.html(publicBadgeNotFoundPage(), 404);
  }

  if (result.status === 'redirect') {
    return c.redirect(result.canonicalPath, 308);
  }

  return c.html(publicBadgePage(c.req.url, result.value));
});

app.get('/showcase/:tenantId', async (c) => {
  const pathParams = parseTenantPathParams(c.req.param());
  const requestedBadgeTemplateId = asNonEmptyString(c.req.query('badgeTemplateId'));
  const badgeTemplateId =
    requestedBadgeTemplateId ??
    (pathParams.tenantId === SAKAI_SHOWCASE_TENANT_ID ? SAKAI_SHOWCASE_TEMPLATE_ID : null);
  const entries = await listPublicBadgeWallEntries(resolveDatabase(c.env), {
    tenantId: pathParams.tenantId,
    ...(badgeTemplateId === null ? {} : { badgeTemplateId }),
  });
  c.header('Cache-Control', 'no-store');
  return c.html(tenantBadgeWallPage(c.req.url, pathParams.tenantId, entries, badgeTemplateId));
});

app.get('/tenants/:tenantId/learner/dashboard', async (c) => {
  const pathParams = parseTenantPathParams(c.req.param());
  const session = await resolveSessionFromCookie(c);

  if (session === null) {
    return c.json(
      {
        error: 'Not authenticated',
      },
      401,
    );
  }

  if (session.tenantId !== pathParams.tenantId) {
    return c.json(
      {
        error: 'Forbidden for requested tenant',
      },
      403,
    );
  }

  const db = resolveDatabase(c.env);
  const user = await findUserById(db, session.userId);

  if (user === null) {
    return c.json(
      {
        error: 'Authenticated user not found',
      },
      404,
    );
  }

  const learnerProfile = await resolveLearnerProfileForIdentity(db, {
    tenantId: pathParams.tenantId,
    identityType: 'email',
    identityValue: user.email,
  });
  const learnerIdentities = await listLearnerIdentitiesByProfile(
    db,
    pathParams.tenantId,
    learnerProfile.id,
  );
  const learnerDid =
    learnerIdentities.find((identity) => identity.identityType === 'did')?.identityValue ?? null;
  const badges = await listLearnerBadgeSummaries(db, {
    tenantId: pathParams.tenantId,
    userId: session.userId,
  });
  const didNotice = learnerDidSettingsNoticeFromQuery(c.req.query('didStatus'));

  c.header('Cache-Control', 'no-store');
  return c.html(
    learnerDashboardPage(c.req.url, pathParams.tenantId, badges, learnerDid, didNotice),
  );
});

app.post('/tenants/:tenantId/learner/settings/did', async (c): Promise<Response> => {
  const pathParams = parseTenantPathParams(c.req.param());
  const session = await resolveSessionFromCookie(c);

  if (session === null) {
    return c.json(
      {
        error: 'Not authenticated',
      },
      401,
    );
  }

  if (session.tenantId !== pathParams.tenantId) {
    return c.json(
      {
        error: 'Forbidden for requested tenant',
      },
      403,
    );
  }

  const dashboardUrl = new URL(
    `/tenants/${encodeURIComponent(pathParams.tenantId)}/learner/dashboard`,
    c.req.url,
  );
  const contentType = c.req.header('content-type') ?? '';

  if (!contentType.toLowerCase().includes('application/x-www-form-urlencoded')) {
    dashboardUrl.searchParams.set('didStatus', 'invalid');
    return c.redirect(dashboardUrl.toString(), 303);
  }

  const rawBody = await c.req.text();
  const formData = new URLSearchParams(rawBody);

  let request: ReturnType<typeof parseLearnerDidSettingsRequest>;

  try {
    request = parseLearnerDidSettingsRequest({
      did: formData.get('did') ?? undefined,
    });
  } catch {
    dashboardUrl.searchParams.set('didStatus', 'invalid');
    return c.redirect(dashboardUrl.toString(), 303);
  }

  const db = resolveDatabase(c.env);
  const user = await findUserById(db, session.userId);

  if (user === null) {
    return c.json(
      {
        error: 'Authenticated user not found',
      },
      404,
    );
  }

  const learnerProfile = await resolveLearnerProfileForIdentity(db, {
    tenantId: pathParams.tenantId,
    identityType: 'email',
    identityValue: user.email,
  });
  const submittedDid = request.did ?? '';

  if (submittedDid.length === 0) {
    await removeLearnerIdentityAliasesByType(db, {
      tenantId: pathParams.tenantId,
      learnerProfileId: learnerProfile.id,
      identityType: 'did',
    });
    dashboardUrl.searchParams.set('didStatus', 'cleared');
    return c.redirect(dashboardUrl.toString(), 303);
  }

  const existingDidProfile = await findLearnerProfileByIdentity(db, {
    tenantId: pathParams.tenantId,
    identityType: 'did',
    identityValue: submittedDid,
  });

  if (existingDidProfile !== null && existingDidProfile.id !== learnerProfile.id) {
    dashboardUrl.searchParams.set('didStatus', 'conflict');
    return c.redirect(dashboardUrl.toString(), 303);
  }

  await removeLearnerIdentityAliasesByType(db, {
    tenantId: pathParams.tenantId,
    learnerProfileId: learnerProfile.id,
    identityType: 'did',
  });
  await addLearnerIdentityAlias(db, {
    tenantId: pathParams.tenantId,
    learnerProfileId: learnerProfile.id,
    identityType: 'did',
    identityValue: submittedDid,
    isPrimary: false,
    isVerified: true,
  });

  dashboardUrl.searchParams.set('didStatus', 'updated');
  return c.redirect(dashboardUrl.toString(), 303);
});

app.post('/v1/tenants/:tenantId/learner/identity-links/email/request', async (c) => {
  const pathParams = parseTenantPathParams(c.req.param());
  const payload = await c.req.json<unknown>();
  const request = parseLearnerIdentityLinkRequest(payload);
  const session = await resolveSessionFromCookie(c);

  if (session === null) {
    return c.json(
      {
        error: 'Not authenticated',
      },
      401,
    );
  }

  if (session.tenantId !== pathParams.tenantId) {
    return c.json(
      {
        error: 'Forbidden for requested tenant',
      },
      403,
    );
  }

  const user = await findUserById(resolveDatabase(c.env), session.userId);

  if (user === null) {
    return c.json(
      {
        error: 'Authenticated user not found',
      },
      404,
    );
  }

  const learnerProfile = await resolveLearnerProfileForIdentity(resolveDatabase(c.env), {
    tenantId: pathParams.tenantId,
    identityType: 'email',
    identityValue: user.email,
  });
  const normalizedEmail = request.email.trim().toLowerCase();
  const existingProfile = await findLearnerProfileByIdentity(resolveDatabase(c.env), {
    tenantId: pathParams.tenantId,
    identityType: 'email',
    identityValue: normalizedEmail,
  });

  if (existingProfile !== null && existingProfile.id !== learnerProfile.id) {
    return c.json(
      {
        error: 'Email is already linked to a different learner profile',
      },
      409,
    );
  }

  if (existingProfile !== null) {
    return c.json({
      status: 'already_linked',
      tenantId: pathParams.tenantId,
      learnerProfileId: learnerProfile.id,
      identityType: 'email',
      identityValue: normalizedEmail,
    });
  }

  const nowIso = new Date().toISOString();
  const expiresAt = addSecondsToIso(nowIso, LEARNER_IDENTITY_LINK_TTL_SECONDS);
  const proofToken = generateOpaqueToken();
  const tokenHash = await sha256Hex(proofToken);

  await createLearnerIdentityLinkProof(resolveDatabase(c.env), {
    tenantId: pathParams.tenantId,
    learnerProfileId: learnerProfile.id,
    requestedByUserId: session.userId,
    identityType: 'email',
    identityValue: normalizedEmail,
    tokenHash,
    expiresAt,
  });

  if (c.env.APP_ENV === 'development') {
    return c.json(
      {
        status: 'sent',
        tenantId: pathParams.tenantId,
        identityType: 'email',
        identityValue: normalizedEmail,
        expiresAt,
        token: proofToken,
      },
      202,
    );
  }

  return c.json(
    {
      status: 'sent',
      tenantId: pathParams.tenantId,
      identityType: 'email',
      identityValue: normalizedEmail,
      expiresAt,
    },
    202,
  );
});

app.post('/v1/tenants/:tenantId/learner/identity-links/email/verify', async (c) => {
  const pathParams = parseTenantPathParams(c.req.param());
  const payload = await c.req.json<unknown>();
  const request = parseLearnerIdentityLinkVerifyRequest(payload);
  const session = await resolveSessionFromCookie(c);

  if (session === null) {
    return c.json(
      {
        error: 'Not authenticated',
      },
      401,
    );
  }

  if (session.tenantId !== pathParams.tenantId) {
    return c.json(
      {
        error: 'Forbidden for requested tenant',
      },
      403,
    );
  }

  const nowIso = new Date().toISOString();
  const proof = await findLearnerIdentityLinkProofByHash(
    resolveDatabase(c.env),
    await sha256Hex(request.token),
  );

  if (proof === null || !isLearnerIdentityLinkProofValid(proof, nowIso)) {
    return c.json(
      {
        error: 'Invalid or expired identity link token',
      },
      400,
    );
  }

  if (proof.tenantId !== pathParams.tenantId || proof.requestedByUserId !== session.userId) {
    return c.json(
      {
        error: 'Forbidden identity link token',
      },
      403,
    );
  }

  const existingProfile = await findLearnerProfileByIdentity(resolveDatabase(c.env), {
    tenantId: pathParams.tenantId,
    identityType: proof.identityType,
    identityValue: proof.identityValue,
  });

  if (existingProfile !== null && existingProfile.id !== proof.learnerProfileId) {
    return c.json(
      {
        error: 'Email is already linked to a different learner profile',
      },
      409,
    );
  }

  if (existingProfile === null) {
    await addLearnerIdentityAlias(resolveDatabase(c.env), {
      tenantId: pathParams.tenantId,
      learnerProfileId: proof.learnerProfileId,
      identityType: proof.identityType,
      identityValue: proof.identityValue,
      isPrimary: true,
      isVerified: true,
    });
  }

  await markLearnerIdentityLinkProofUsed(resolveDatabase(c.env), proof.id, nowIso);

  return c.json({
    status: existingProfile === null ? 'linked' : 'already_linked',
    tenantId: pathParams.tenantId,
    learnerProfileId: proof.learnerProfileId,
    identityType: proof.identityType,
    identityValue: proof.identityValue,
  });
});

const ltiOidcLoginHandler = async (c: AppContext): Promise<Response> => {
  let registry: LtiIssuerRegistry;

  try {
    registry = await resolveLtiIssuerRegistry(c);
  } catch (error) {
    await captureSentryException({
      context: observabilityContext(c.env),
      dsn: c.env.SENTRY_DSN,
      error,
      message: 'LTI issuer registry configuration is invalid',
      tags: {
        path: LTI_OIDC_LOGIN_PATH,
        method: c.req.method,
      },
    });
    return c.json(
      {
        error: 'LTI issuer registry configuration is invalid',
      },
      500,
    );
  }

  let loginRequest: LtiOidcLoginInitiationRequest;

  try {
    loginRequest = parseLtiOidcLoginInitiationRequest(await ltiLoginInputFromRequest(c));
  } catch {
    return c.json(
      {
        error: 'Invalid LTI OIDC login initiation request',
      },
      400,
    );
  }

  const issuerEntry = registry[normalizeLtiIssuer(loginRequest.iss)];

  if (issuerEntry === undefined) {
    return c.json(
      {
        error: 'Unknown LTI issuer',
      },
      400,
    );
  }

  const clientId = loginRequest.client_id ?? issuerEntry.clientId;

  if (loginRequest.client_id !== undefined && loginRequest.client_id !== issuerEntry.clientId) {
    return c.json(
      {
        error: 'client_id does not match configured issuer registration',
      },
      400,
    );
  }

  const nowIso = new Date().toISOString();
  const nonce = generateOpaqueToken();
  const statePayload: LtiStatePayload = {
    iss: normalizeLtiIssuer(loginRequest.iss),
    clientId,
    nonce,
    loginHint: loginRequest.login_hint,
    targetLinkUri: loginRequest.target_link_uri,
    ...(loginRequest.lti_message_hint === undefined
      ? {}
      : {
          ltiMessageHint: loginRequest.lti_message_hint,
        }),
    ...(loginRequest.lti_deployment_id === undefined
      ? {}
      : {
          ltiDeploymentId: loginRequest.lti_deployment_id,
        }),
    issuedAt: nowIso,
    expiresAt: addSecondsToIso(nowIso, LTI_STATE_TTL_SECONDS),
  };
  const stateToken = await signLtiStatePayload(statePayload, ltiStateSigningSecret(c.env));
  const authorizationRequestUrl = new URL(issuerEntry.authorizationEndpoint);
  authorizationRequestUrl.searchParams.set('scope', LTI_OIDC_SCOPE);
  authorizationRequestUrl.searchParams.set('response_type', LTI_OIDC_RESPONSE_TYPE);
  authorizationRequestUrl.searchParams.set('response_mode', LTI_OIDC_RESPONSE_MODE);
  authorizationRequestUrl.searchParams.set('prompt', LTI_OIDC_PROMPT);
  authorizationRequestUrl.searchParams.set('client_id', clientId);
  authorizationRequestUrl.searchParams.set(
    'redirect_uri',
    new URL(LTI_LAUNCH_PATH, c.req.url).toString(),
  );
  authorizationRequestUrl.searchParams.set('login_hint', loginRequest.login_hint);
  authorizationRequestUrl.searchParams.set('state', stateToken);
  authorizationRequestUrl.searchParams.set('nonce', nonce);

  if (loginRequest.lti_message_hint !== undefined) {
    authorizationRequestUrl.searchParams.set('lti_message_hint', loginRequest.lti_message_hint);
  }

  if (loginRequest.lti_deployment_id !== undefined) {
    authorizationRequestUrl.searchParams.set('lti_deployment_id', loginRequest.lti_deployment_id);
  }

  return c.redirect(authorizationRequestUrl.toString(), 302);
};

app.get(LTI_OIDC_LOGIN_PATH, ltiOidcLoginHandler);
app.post(LTI_OIDC_LOGIN_PATH, ltiOidcLoginHandler);

app.post(LTI_LAUNCH_PATH, async (c): Promise<Response> => {
  const formInput = await ltiLaunchFormInputFromRequest(c);

  if (formInput.idToken === null || formInput.idToken.trim().length === 0) {
    return c.json(
      {
        error: 'id_token is required',
      },
      400,
    );
  }

  if (formInput.state === null || formInput.state.trim().length === 0) {
    return c.json(
      {
        error: 'state is required',
      },
      400,
    );
  }

  let registry: LtiIssuerRegistry;

  try {
    registry = await resolveLtiIssuerRegistry(c);
  } catch (error) {
    await captureSentryException({
      context: observabilityContext(c.env),
      dsn: c.env.SENTRY_DSN,
      error,
      message: 'LTI issuer registry configuration is invalid',
      tags: {
        path: LTI_LAUNCH_PATH,
        method: c.req.method,
      },
    });
    return c.json(
      {
        error: 'LTI issuer registry configuration is invalid',
      },
      500,
    );
  }

  const nowIso = new Date().toISOString();
  const validatedState = await validateLtiStateToken(
    formInput.state,
    ltiStateSigningSecret(c.env),
    nowIso,
  );

  if (validatedState.status !== 'ok') {
    return c.json(
      {
        error: `Invalid launch state: ${validatedState.reason}`,
      },
      400,
    );
  }

  const issuerEntry = registry[normalizeLtiIssuer(validatedState.payload.iss)];

  if (issuerEntry === undefined) {
    return c.json(
      {
        error: 'No issuer registration configured for state.iss',
      },
      400,
    );
  }

  const idTokenHeader = parseCompactJwsHeaderObject(formInput.idToken);
  const idTokenPayload = parseCompactJwsPayloadObject(formInput.idToken);

  if (idTokenHeader === null || idTokenPayload === null) {
    return c.json(
      {
        error: 'id_token must be a compact JWT with valid JSON header and payload',
      },
      400,
    );
  }

  const algorithm = asNonEmptyString(idTokenHeader.alg);

  if (algorithm === null || algorithm.toLowerCase() === 'none') {
    return c.json(
      {
        error: 'id_token must specify a JOSE alg and must not use "none"',
      },
      400,
    );
  }

  if (!issuerEntry.allowUnsignedIdToken) {
    return c.json(
      {
        error:
          'LTI issuer requires signature verification configuration; set allowUnsignedIdToken only for test launches',
      },
      501,
    );
  }

  let launchClaims: LtiLaunchClaims;

  try {
    launchClaims = parseLtiLaunchClaims(idTokenPayload);
  } catch {
    return c.json(
      {
        error: 'id_token launch claims are invalid for LTI 1.3',
      },
      400,
    );
  }

  if (normalizeLtiIssuer(launchClaims.iss) !== normalizeLtiIssuer(validatedState.payload.iss)) {
    return c.json(
      {
        error: 'id_token issuer does not match state issuer',
      },
      400,
    );
  }

  if (!ltiAudienceIncludesClientId(launchClaims.aud, validatedState.payload.clientId)) {
    return c.json(
      {
        error: 'id_token aud does not include configured client_id',
      },
      400,
    );
  }

  if (launchClaims.nonce !== validatedState.payload.nonce) {
    return c.json(
      {
        error: 'id_token nonce does not match launch state nonce',
      },
      400,
    );
  }

  const nowEpochSeconds = Math.floor(Date.parse(nowIso) / 1000);

  if (launchClaims.exp <= nowEpochSeconds) {
    return c.json(
      {
        error: 'id_token is expired',
      },
      400,
    );
  }

  if (launchClaims.iat > nowEpochSeconds + 60) {
    return c.json(
      {
        error: 'id_token iat is in the future',
      },
      400,
    );
  }

  if (
    validatedState.payload.ltiDeploymentId !== undefined &&
    launchClaims[LTI_CLAIM_DEPLOYMENT_ID] !== validatedState.payload.ltiDeploymentId
  ) {
    return c.json(
      {
        error: 'id_token deployment_id does not match launch initiation',
      },
      400,
    );
  }

  if (launchClaims[LTI_CLAIM_MESSAGE_TYPE] !== LTI_MESSAGE_TYPE_RESOURCE_LINK_REQUEST) {
    return c.json(
      {
        error: `Unsupported LTI message_type: ${launchClaims[LTI_CLAIM_MESSAGE_TYPE]}`,
      },
      400,
    );
  }

  const targetLinkUriClaim = launchClaims[LTI_CLAIM_TARGET_LINK_URI];
  const normalizedStateTargetLinkUri = normalizeAbsoluteUrlForComparison(
    validatedState.payload.targetLinkUri,
  );
  const normalizedClaimTargetLinkUri =
    targetLinkUriClaim === undefined ? null : normalizeAbsoluteUrlForComparison(targetLinkUriClaim);

  if (
    targetLinkUriClaim !== undefined &&
    normalizedStateTargetLinkUri !== null &&
    normalizedClaimTargetLinkUri !== normalizedStateTargetLinkUri
  ) {
    return c.json(
      {
        error: 'id_token target_link_uri does not match launch initiation',
      },
      400,
    );
  }

  const resourceLinkClaim = launchClaims[LTI_CLAIM_RESOURCE_LINK];

  if (resourceLinkClaim === undefined || asNonEmptyString(resourceLinkClaim.id) === null) {
    return c.json(
      {
        error: 'id_token for LtiResourceLinkRequest must include resource_link.id',
      },
      400,
    );
  }

  const roleKind = resolveLtiRoleKind(launchClaims);
  const db = resolveDatabase(c.env);
  const tenantId = issuerEntry.tenantId;
  const federatedSubject = ltiFederatedSubjectIdentity(launchClaims.iss, launchClaims.sub);
  const displayName = ltiDisplayNameFromClaims(launchClaims);

  let linkedLearnerProfileId: string;
  let linkedUserId: string;
  let linkedMembershipRole: TenantMembershipRole;

  try {
    const learnerProfile = await resolveLearnerProfileForIdentity(db, {
      tenantId,
      identityType: 'saml_subject',
      identityValue: federatedSubject,
      ...(displayName === undefined ? {} : { displayName }),
    });
    linkedLearnerProfileId = learnerProfile.id;

    const claimedEmail = ltiEmailFromClaims(launchClaims);

    if (claimedEmail !== null) {
      const existingEmailProfile = await findLearnerProfileByIdentity(db, {
        tenantId,
        identityType: 'email',
        identityValue: claimedEmail,
      });

      if (existingEmailProfile !== null && existingEmailProfile.id !== learnerProfile.id) {
        throw new Error('LTI email claim is already linked to a different learner profile');
      }

      if (existingEmailProfile === null) {
        await addLearnerIdentityAlias(db, {
          tenantId,
          learnerProfileId: learnerProfile.id,
          identityType: 'email',
          identityValue: claimedEmail,
          isPrimary: false,
          isVerified: true,
        });
      }
    }

    const sourcedId = ltiSourcedIdFromClaims(launchClaims);

    if (sourcedId !== null) {
      const existingSourcedIdProfile = await findLearnerProfileByIdentity(db, {
        tenantId,
        identityType: 'sourced_id',
        identityValue: sourcedId,
      });

      if (existingSourcedIdProfile !== null && existingSourcedIdProfile.id !== learnerProfile.id) {
        throw new Error('LTI sourcedId claim is already linked to a different learner profile');
      }

      if (existingSourcedIdProfile === null) {
        await addLearnerIdentityAlias(db, {
          tenantId,
          learnerProfileId: learnerProfile.id,
          identityType: 'sourced_id',
          identityValue: sourcedId,
          isPrimary: false,
          isVerified: true,
        });
      }
    }

    const user = await upsertUserByEmail(
      db,
      claimedEmail ?? (await ltiSyntheticEmail(tenantId, federatedSubject)),
    );
    linkedUserId = user.id;

    const membershipResult = await ensureTenantMembership(db, tenantId, user.id);
    linkedMembershipRole = membershipResult.membership.role;

    const desiredRole = ltiMembershipRoleFromRoleKind(roleKind);

    if (desiredRole === 'issuer' && linkedMembershipRole === 'viewer') {
      const promotedMembership = await upsertTenantMembershipRole(db, {
        tenantId,
        userId: user.id,
        role: desiredRole,
      });
      linkedMembershipRole = promotedMembership.membership.role;
    }
  } catch (error) {
    await captureSentryException({
      context: observabilityContext(c.env),
      dsn: c.env.SENTRY_DSN,
      error,
      message: 'LTI launch could not be linked to a local user/session',
      tags: {
        path: LTI_LAUNCH_PATH,
        method: c.req.method,
      },
      extra: {
        issuer: launchClaims.iss,
        deploymentId: launchClaims[LTI_CLAIM_DEPLOYMENT_ID],
        subjectId: launchClaims.sub,
      },
    });
    return c.json(
      {
        error: 'Unable to link LTI launch to local account',
      },
      500,
    );
  }

  const sessionToken = generateOpaqueToken();
  const sessionTokenHash = await sha256Hex(sessionToken);
  const session = await createSession(db, {
    tenantId,
    userId: linkedUserId,
    sessionTokenHash,
    expiresAt: addSecondsToIso(nowIso, SESSION_TTL_SECONDS),
  });

  setCookie(c, SESSION_COOKIE_NAME, sessionToken, {
    httpOnly: true,
    secure: sessionCookieSecure(c.env.APP_ENV),
    sameSite: 'Lax',
    path: '/',
    maxAge: SESSION_TTL_SECONDS,
  });

  const dashboardPath = ltiLearnerDashboardPath(session.tenantId);
  c.header('Cache-Control', 'no-store');

  return c.html(
    ltiLaunchResultPage({
      roleKind,
      tenantId: session.tenantId,
      userId: session.userId,
      membershipRole: linkedMembershipRole,
      learnerProfileId: linkedLearnerProfileId,
      issuer: launchClaims.iss,
      deploymentId: launchClaims[LTI_CLAIM_DEPLOYMENT_ID],
      subjectId: launchClaims.sub,
      targetLinkUri:
        launchClaims[LTI_CLAIM_TARGET_LINK_URI] ?? validatedState.payload.targetLinkUri,
      messageType: launchClaims[LTI_CLAIM_MESSAGE_TYPE],
      dashboardPath,
    }),
  );
});

app.get('/', (c) => {
  return c.html(
    renderPageShell(
      'CredTrail',
      `<h1>CredTrail</h1><p>Cloudflare Worker API + server-rendered interface scaffold for ${c.env.PLATFORM_DOMAIN}.</p>`,
    ),
  );
});

app.post('/v1/auth/magic-link/request', async (c) => {
  const payload = await c.req.json<unknown>();
  const request = parseMagicLinkRequest(payload);
  const nowIso = new Date().toISOString();
  const expiresAt = addSecondsToIso(nowIso, MAGIC_LINK_TTL_SECONDS);
  const user = await upsertUserByEmail(resolveDatabase(c.env), request.email);
  const membershipResult = await ensureTenantMembership(
    resolveDatabase(c.env),
    request.tenantId,
    user.id,
  );

  if (membershipResult.created) {
    await createAuditLog(resolveDatabase(c.env), {
      tenantId: request.tenantId,
      actorUserId: user.id,
      action: 'membership.role_assigned',
      targetType: 'membership',
      targetId: `${request.tenantId}:${user.id}`,
      metadata: {
        userId: user.id,
        role: membershipResult.membership.role,
      },
    });
  }

  const magicLinkToken = generateOpaqueToken();
  const magicTokenHash = await sha256Hex(magicLinkToken);

  await createMagicLinkToken(resolveDatabase(c.env), {
    tenantId: request.tenantId,
    userId: user.id,
    magicTokenHash,
    expiresAt,
  });

  if (c.env.APP_ENV === 'development') {
    return c.json(
      {
        status: 'sent',
        tenantId: request.tenantId,
        email: request.email,
        expiresAt,
        magicLinkToken,
      },
      202,
    );
  }

  return c.json(
    {
      status: 'sent',
      tenantId: request.tenantId,
      email: request.email,
      expiresAt,
    },
    202,
  );
});

app.post('/v1/auth/magic-link/verify', async (c) => {
  const payload = await c.req.json<unknown>();
  const request = parseMagicLinkVerifyRequest(payload);
  const nowIso = new Date().toISOString();
  const magicTokenHash = await sha256Hex(request.token);
  const token = await findMagicLinkTokenByHash(resolveDatabase(c.env), magicTokenHash);

  if (token === null || !isMagicLinkTokenValid(token, nowIso)) {
    return c.json(
      {
        error: 'Invalid or expired magic link token',
      },
      400,
    );
  }

  await markMagicLinkTokenUsed(resolveDatabase(c.env), token.id, nowIso);

  const sessionToken = generateOpaqueToken();
  const sessionTokenHash = await sha256Hex(sessionToken);
  const session = await createSession(resolveDatabase(c.env), {
    tenantId: token.tenantId,
    userId: token.userId,
    sessionTokenHash,
    expiresAt: addSecondsToIso(nowIso, SESSION_TTL_SECONDS),
  });

  setCookie(c, SESSION_COOKIE_NAME, sessionToken, {
    httpOnly: true,
    secure: sessionCookieSecure(c.env.APP_ENV),
    sameSite: 'Lax',
    path: '/',
    maxAge: SESSION_TTL_SECONDS,
  });

  return c.json({
    status: 'authenticated',
    tenantId: session.tenantId,
    userId: session.userId,
    expiresAt: session.expiresAt,
  });
});

app.get('/v1/auth/session', async (c) => {
  const session = await resolveSessionFromCookie(c);

  if (session === null) {
    return c.json(
      {
        error: 'Not authenticated',
      },
      401,
    );
  }

  return c.json({
    status: 'authenticated',
    tenantId: session.tenantId,
    userId: session.userId,
    expiresAt: session.expiresAt,
  });
});

app.post('/v1/auth/logout', async (c) => {
  const sessionToken = getCookie(c, SESSION_COOKIE_NAME);

  if (sessionToken !== undefined) {
    const sessionTokenHash = await sha256Hex(sessionToken);
    await revokeSessionByHash(resolveDatabase(c.env), sessionTokenHash, new Date().toISOString());
  }

  deleteCookie(c, SESSION_COOKIE_NAME, {
    path: '/',
  });

  return c.json({
    status: 'signed_out',
  });
});

app.get('/v1/tenants/:tenantId/org-units', async (c) => {
  const pathParams = parseTenantPathParams(c.req.param());
  const query = parseTenantOrgUnitListQuery({
    includeInactive: c.req.query('includeInactive'),
  });
  const roleCheck = await requireTenantRole(c, pathParams.tenantId, ISSUER_ROLES);

  if (roleCheck instanceof Response) {
    return roleCheck;
  }

  const orgUnits = await listTenantOrgUnits(resolveDatabase(c.env), {
    tenantId: pathParams.tenantId,
    includeInactive: query.includeInactive,
  });

  return c.json({
    tenantId: pathParams.tenantId,
    orgUnits,
  });
});

app.post('/v1/tenants/:tenantId/org-units', async (c) => {
  const pathParams = parseTenantPathParams(c.req.param());
  let request: ReturnType<typeof parseCreateTenantOrgUnitRequest>;

  try {
    request = parseCreateTenantOrgUnitRequest(await c.req.json<unknown>());
  } catch {
    return c.json(
      {
        error: 'Invalid org unit request payload',
      },
      400,
    );
  }

  const roleCheck = await requireTenantRole(c, pathParams.tenantId, ADMIN_ROLES);

  if (roleCheck instanceof Response) {
    return roleCheck;
  }

  const { session, membershipRole } = roleCheck;

  try {
    const orgUnit = await createTenantOrgUnit(resolveDatabase(c.env), {
      tenantId: pathParams.tenantId,
      unitType: request.unitType,
      slug: request.slug,
      displayName: request.displayName,
      parentOrgUnitId: request.parentOrgUnitId,
      createdByUserId: session.userId,
    });

    await createAuditLog(resolveDatabase(c.env), {
      tenantId: pathParams.tenantId,
      actorUserId: session.userId,
      action: 'tenant.org_unit_created',
      targetType: 'org_unit',
      targetId: orgUnit.id,
      metadata: {
        role: membershipRole,
        unitType: orgUnit.unitType,
        slug: orgUnit.slug,
        parentOrgUnitId: orgUnit.parentOrgUnitId,
      },
    });

    return c.json(
      {
        tenantId: pathParams.tenantId,
        orgUnit,
      },
      201,
    );
  } catch (error: unknown) {
    if (error instanceof Error) {
      if (error.message.includes('UNIQUE constraint failed')) {
        return c.json(
          {
            error: 'Org unit slug already exists for tenant',
          },
          409,
        );
      }

      if (
        (error.message.includes('Parent org unit') &&
          error.message.includes('not found for tenant')) ||
        error.message.includes('cannot have a parent org unit') ||
        error.message.includes('requires parent org unit type') ||
        error.message.includes('is inactive for tenant')
      ) {
        return c.json(
          {
            error: error.message,
          },
          422,
        );
      }
    }

    throw error;
  }
});

app.get('/v1/tenants/:tenantId/users/:userId/org-unit-scopes', async (c) => {
  const pathParams = parseTenantUserPathParams(c.req.param());
  const roleCheck = await requireTenantRole(c, pathParams.tenantId, ADMIN_ROLES);

  if (roleCheck instanceof Response) {
    return roleCheck;
  }

  const scopes = await listTenantMembershipOrgUnitScopes(resolveDatabase(c.env), {
    tenantId: pathParams.tenantId,
    userId: pathParams.userId,
  });

  return c.json({
    tenantId: pathParams.tenantId,
    userId: pathParams.userId,
    scopes,
  });
});

app.put('/v1/tenants/:tenantId/users/:userId/org-unit-scopes/:orgUnitId', async (c) => {
  const pathParams = parseTenantUserOrgUnitPathParams(c.req.param());
  let request: ReturnType<typeof parseUpsertTenantMembershipOrgUnitScopeRequest>;

  try {
    request = parseUpsertTenantMembershipOrgUnitScopeRequest(await c.req.json<unknown>());
  } catch {
    return c.json(
      {
        error: 'Invalid org-unit scope payload',
      },
      400,
    );
  }

  const roleCheck = await requireTenantRole(c, pathParams.tenantId, ADMIN_ROLES);

  if (roleCheck instanceof Response) {
    return roleCheck;
  }

  const { session, membershipRole } = roleCheck;

  try {
    const result = await upsertTenantMembershipOrgUnitScope(resolveDatabase(c.env), {
      tenantId: pathParams.tenantId,
      userId: pathParams.userId,
      orgUnitId: pathParams.orgUnitId,
      role: request.role,
      createdByUserId: session.userId,
    });

    const action =
      result.previousRole === null
        ? 'membership.org_scope_assigned'
        : result.previousRole === result.scope.role
          ? 'membership.org_scope_reasserted'
          : 'membership.org_scope_changed';

    await createAuditLog(resolveDatabase(c.env), {
      tenantId: pathParams.tenantId,
      actorUserId: session.userId,
      action,
      targetType: 'membership_org_scope',
      targetId: `${pathParams.tenantId}:${pathParams.userId}:${pathParams.orgUnitId}`,
      metadata: {
        role: membershipRole,
        userId: pathParams.userId,
        orgUnitId: pathParams.orgUnitId,
        previousRole: result.previousRole,
        scopeRole: result.scope.role,
        changed: result.changed,
      },
    });

    return c.json(
      {
        tenantId: pathParams.tenantId,
        userId: pathParams.userId,
        orgUnitId: pathParams.orgUnitId,
        scope: result.scope,
        previousRole: result.previousRole,
        changed: result.changed,
      },
      result.previousRole === null ? 201 : 200,
    );
  } catch (error: unknown) {
    if (error instanceof Error) {
      if (error.message.includes('Membership not found for tenant')) {
        return c.json(
          {
            error: error.message,
          },
          422,
        );
      }

      if (error.message.includes('Org unit') && error.message.includes('not found for tenant')) {
        return c.json(
          {
            error: error.message,
          },
          422,
        );
      }
    }

    throw error;
  }
});

app.delete('/v1/tenants/:tenantId/users/:userId/org-unit-scopes/:orgUnitId', async (c) => {
  const pathParams = parseTenantUserOrgUnitPathParams(c.req.param());
  const roleCheck = await requireTenantRole(c, pathParams.tenantId, ADMIN_ROLES);

  if (roleCheck instanceof Response) {
    return roleCheck;
  }

  const { session, membershipRole } = roleCheck;
  const removed = await removeTenantMembershipOrgUnitScope(resolveDatabase(c.env), {
    tenantId: pathParams.tenantId,
    userId: pathParams.userId,
    orgUnitId: pathParams.orgUnitId,
  });

  if (removed) {
    await createAuditLog(resolveDatabase(c.env), {
      tenantId: pathParams.tenantId,
      actorUserId: session.userId,
      action: 'membership.org_scope_removed',
      targetType: 'membership_org_scope',
      targetId: `${pathParams.tenantId}:${pathParams.userId}:${pathParams.orgUnitId}`,
      metadata: {
        role: membershipRole,
        userId: pathParams.userId,
        orgUnitId: pathParams.orgUnitId,
      },
    });
  }

  return c.json({
    tenantId: pathParams.tenantId,
    userId: pathParams.userId,
    orgUnitId: pathParams.orgUnitId,
    removed,
  });
});

app.get('/v1/tenants/:tenantId/users/:userId/issuing-authority-grants', async (c) => {
  const pathParams = parseTenantUserPathParams(c.req.param());
  const query = parseDelegatedIssuingAuthorityGrantListQuery({
    includeRevoked: c.req.query('includeRevoked'),
    includeExpired: c.req.query('includeExpired'),
  });
  const roleCheck = await requireTenantRole(c, pathParams.tenantId, ADMIN_ROLES);

  if (roleCheck instanceof Response) {
    return roleCheck;
  }

  const grants = await listDelegatedIssuingAuthorityGrants(resolveDatabase(c.env), {
    tenantId: pathParams.tenantId,
    delegateUserId: pathParams.userId,
    includeRevoked: query.includeRevoked,
    includeExpired: query.includeExpired,
  });

  return c.json({
    tenantId: pathParams.tenantId,
    userId: pathParams.userId,
    grants,
  });
});

app.post('/v1/tenants/:tenantId/users/:userId/issuing-authority-grants', async (c) => {
  const pathParams = parseTenantUserPathParams(c.req.param());
  let request: ReturnType<typeof parseCreateDelegatedIssuingAuthorityGrantRequest>;

  try {
    request = parseCreateDelegatedIssuingAuthorityGrantRequest(await c.req.json<unknown>());
  } catch {
    return c.json(
      {
        error: 'Invalid delegated authority grant payload',
      },
      400,
    );
  }

  const roleCheck = await requireTenantRole(c, pathParams.tenantId, ADMIN_ROLES);

  if (roleCheck instanceof Response) {
    return roleCheck;
  }

  const { session, membershipRole } = roleCheck;
  const startsAt = request.startsAt ?? new Date().toISOString();

  try {
    const grant = await createDelegatedIssuingAuthorityGrant(resolveDatabase(c.env), {
      tenantId: pathParams.tenantId,
      delegateUserId: pathParams.userId,
      delegatedByUserId: session.userId,
      orgUnitId: request.orgUnitId,
      allowedActions: request.allowedActions,
      badgeTemplateIds: request.badgeTemplateIds,
      startsAt,
      endsAt: request.endsAt,
      reason: request.reason,
    });

    await createAuditLog(resolveDatabase(c.env), {
      tenantId: pathParams.tenantId,
      actorUserId: session.userId,
      action: 'delegated_issuing_authority.granted',
      targetType: 'delegated_issuing_authority_grant',
      targetId: grant.id,
      metadata: {
        role: membershipRole,
        delegateUserId: pathParams.userId,
        orgUnitId: request.orgUnitId,
        allowedActions: request.allowedActions,
        badgeTemplateIds: request.badgeTemplateIds ?? [],
        startsAt,
        endsAt: request.endsAt,
      },
    });

    return c.json(
      {
        tenantId: pathParams.tenantId,
        userId: pathParams.userId,
        grant,
      },
      201,
    );
  } catch (error: unknown) {
    if (error instanceof Error) {
      if (error.message.includes('conflicts with existing grant')) {
        return c.json(
          {
            error: error.message,
          },
          409,
        );
      }

      if (
        error.message.includes('Membership not found for tenant') ||
        (error.message.includes('Org unit') && error.message.includes('not found for tenant')) ||
        (error.message.includes('Badge template') &&
          error.message.includes('not found for tenant')) ||
        error.message.includes('outside delegated org-unit scope') ||
        error.message.includes('is inactive for tenant') ||
        error.message.includes('must be after') ||
        error.message.includes('must be a valid ISO timestamp')
      ) {
        return c.json(
          {
            error: error.message,
          },
          422,
        );
      }
    }

    throw error;
  }
});

app.post(
  '/v1/tenants/:tenantId/users/:userId/issuing-authority-grants/:grantId/revoke',
  async (c) => {
    const pathParams = parseTenantUserDelegatedGrantPathParams(c.req.param());
    let request: ReturnType<typeof parseRevokeDelegatedIssuingAuthorityGrantRequest>;

    try {
      let payload: unknown = {};

      try {
        payload = await c.req.json<unknown>();
      } catch {
        payload = {};
      }

      request = parseRevokeDelegatedIssuingAuthorityGrantRequest(payload);
    } catch {
      return c.json(
        {
          error: 'Invalid delegated authority revoke payload',
        },
        400,
      );
    }

    const roleCheck = await requireTenantRole(c, pathParams.tenantId, ADMIN_ROLES);

    if (roleCheck instanceof Response) {
      return roleCheck;
    }

    const { session, membershipRole } = roleCheck;
    const db = resolveDatabase(c.env);
    const existingGrant = await findDelegatedIssuingAuthorityGrantById(
      db,
      pathParams.tenantId,
      pathParams.grantId,
    );

    if (existingGrant?.delegateUserId !== pathParams.userId) {
      return c.json(
        {
          error: 'Delegated issuing authority grant not found',
        },
        404,
      );
    }

    const revokedAt = request.revokedAt ?? new Date().toISOString();

    try {
      const result = await revokeDelegatedIssuingAuthorityGrant(db, {
        tenantId: pathParams.tenantId,
        grantId: pathParams.grantId,
        revokedByUserId: session.userId,
        revokedReason: request.reason,
        revokedAt,
      });

      if (result.status === 'revoked') {
        await createAuditLog(db, {
          tenantId: pathParams.tenantId,
          actorUserId: session.userId,
          action: 'delegated_issuing_authority.revoked',
          targetType: 'delegated_issuing_authority_grant',
          targetId: pathParams.grantId,
          metadata: {
            role: membershipRole,
            delegateUserId: pathParams.userId,
            revokedAt,
            reason: request.reason,
          },
        });
      }

      return c.json({
        tenantId: pathParams.tenantId,
        userId: pathParams.userId,
        status: result.status,
        grant: result.grant,
      });
    } catch (error: unknown) {
      if (error instanceof Error) {
        if (
          error.message.includes('not found for tenant') ||
          error.message.includes('must be a valid ISO timestamp')
        ) {
          return c.json(
            {
              error: error.message,
            },
            422,
          );
        }
      }

      throw error;
    }
  },
);

app.get(
  '/v1/tenants/:tenantId/users/:userId/issuing-authority-grants/:grantId/events',
  async (c) => {
    const pathParams = parseTenantUserDelegatedGrantPathParams(c.req.param());
    const roleCheck = await requireTenantRole(c, pathParams.tenantId, ADMIN_ROLES);

    if (roleCheck instanceof Response) {
      return roleCheck;
    }

    const limitRaw = c.req.query('limit');
    let limit: number | undefined;

    if (limitRaw !== undefined) {
      const parsed = Number.parseInt(limitRaw, 10);

      if (!Number.isFinite(parsed) || parsed < 1) {
        return c.json(
          {
            error: 'limit must be a positive integer',
          },
          400,
        );
      }

      limit = parsed;
    }

    const db = resolveDatabase(c.env);
    const grant = await findDelegatedIssuingAuthorityGrantById(
      db,
      pathParams.tenantId,
      pathParams.grantId,
    );

    if (grant?.delegateUserId !== pathParams.userId) {
      return c.json(
        {
          error: 'Delegated issuing authority grant not found',
        },
        404,
      );
    }

    const events = await listDelegatedIssuingAuthorityGrantEvents(db, {
      tenantId: pathParams.tenantId,
      grantId: pathParams.grantId,
      ...(limit === undefined ? {} : { limit }),
    });

    return c.json({
      tenantId: pathParams.tenantId,
      userId: pathParams.userId,
      grant,
      events,
    });
  },
);

app.get('/v1/tenants/:tenantId/badge-templates', async (c) => {
  const pathParams = parseTenantPathParams(c.req.param());
  const query = parseBadgeTemplateListQuery({
    includeArchived: c.req.query('includeArchived'),
  });
  const session = await resolveSessionFromCookie(c);

  if (session === null) {
    return c.json(
      {
        error: 'Not authenticated',
      },
      401,
    );
  }

  if (session.tenantId !== pathParams.tenantId) {
    return c.json(
      {
        error: 'Forbidden for requested tenant',
      },
      403,
    );
  }

  const db = resolveDatabase(c.env);
  const membership = await findTenantMembership(db, pathParams.tenantId, session.userId);

  if (membership === null) {
    return c.json(
      {
        error: 'Membership not found for requested tenant',
      },
      403,
    );
  }

  let templates = await listBadgeTemplates(db, {
    tenantId: pathParams.tenantId,
    includeArchived: query.includeArchived,
  });

  if (membership.role === 'issuer') {
    const hasScopedAssignments = await hasTenantMembershipOrgUnitScopeAssignments(
      db,
      pathParams.tenantId,
      session.userId,
    );

    if (hasScopedAssignments) {
      const scopedTemplates: typeof templates = [];

      for (const template of templates) {
        const canViewTemplate = await hasTenantMembershipOrgUnitAccess(db, {
          tenantId: pathParams.tenantId,
          userId: session.userId,
          orgUnitId: template.ownerOrgUnitId,
          requiredRole: 'viewer',
        });

        if (canViewTemplate) {
          scopedTemplates.push(template);
        }
      }

      templates = scopedTemplates;
    }
  }

  return c.json({
    tenantId: pathParams.tenantId,
    templates,
  });
});

app.post('/v1/tenants/:tenantId/badge-templates', async (c) => {
  const pathParams = parseTenantPathParams(c.req.param());
  const payload = await c.req.json<unknown>();
  const request = parseCreateBadgeTemplateRequest(payload);
  const roleCheck = await requireTenantRole(c, pathParams.tenantId, ISSUER_ROLES);

  if (roleCheck instanceof Response) {
    return roleCheck;
  }

  const { session, membershipRole } = roleCheck;
  const db = resolveDatabase(c.env);
  const targetOwnerOrgUnitId =
    request.ownerOrgUnitId ?? defaultInstitutionOrgUnitId(pathParams.tenantId);

  const scopeCheck = await requireScopedOrgUnitPermission(c, {
    db,
    tenantId: pathParams.tenantId,
    userId: session.userId,
    membershipRole,
    orgUnitId: targetOwnerOrgUnitId,
    requiredRole: 'issuer',
    allowWhenNoScopes: true,
  });

  if (scopeCheck !== null) {
    return scopeCheck;
  }

  try {
    const template = await createBadgeTemplate(db, {
      tenantId: pathParams.tenantId,
      slug: request.slug,
      title: request.title,
      description: request.description,
      criteriaUri: request.criteriaUri,
      imageUri: request.imageUri,
      ownerOrgUnitId: request.ownerOrgUnitId,
      createdByUserId: session.userId,
    });

    await createAuditLog(db, {
      tenantId: pathParams.tenantId,
      actorUserId: session.userId,
      action: 'badge_template.created',
      targetType: 'badge_template',
      targetId: template.id,
      metadata: {
        role: membershipRole,
        slug: template.slug,
        title: template.title,
        ownerOrgUnitId: template.ownerOrgUnitId,
      },
    });

    return c.json(
      {
        tenantId: pathParams.tenantId,
        template,
      },
      201,
    );
  } catch (error: unknown) {
    if (error instanceof Error && error.message.includes('UNIQUE constraint failed')) {
      return c.json(
        {
          error: 'Badge template slug already exists for tenant',
        },
        409,
      );
    }

    if (
      error instanceof Error &&
      error.message.includes('Org unit') &&
      error.message.includes('not found for tenant')
    ) {
      return c.json(
        {
          error: error.message,
        },
        422,
      );
    }

    throw error;
  }
});

app.get('/v1/tenants/:tenantId/badge-templates/:badgeTemplateId', async (c) => {
  const pathParams = parseBadgeTemplatePathParams(c.req.param());
  const session = await resolveSessionFromCookie(c);

  if (session === null) {
    return c.json(
      {
        error: 'Not authenticated',
      },
      401,
    );
  }

  if (session.tenantId !== pathParams.tenantId) {
    return c.json(
      {
        error: 'Forbidden for requested tenant',
      },
      403,
    );
  }

  const db = resolveDatabase(c.env);
  const membership = await findTenantMembership(db, pathParams.tenantId, session.userId);

  if (membership === null) {
    return c.json(
      {
        error: 'Membership not found for requested tenant',
      },
      403,
    );
  }

  const template = await findBadgeTemplateById(db, pathParams.tenantId, pathParams.badgeTemplateId);

  if (template === null) {
    return c.json(
      {
        error: 'Badge template not found',
      },
      404,
    );
  }

  if (membership.role === 'issuer') {
    const hasScopedAssignments = await hasTenantMembershipOrgUnitScopeAssignments(
      db,
      pathParams.tenantId,
      session.userId,
    );

    if (hasScopedAssignments) {
      const canViewTemplate = await hasTenantMembershipOrgUnitAccess(db, {
        tenantId: pathParams.tenantId,
        userId: session.userId,
        orgUnitId: template.ownerOrgUnitId,
        requiredRole: 'viewer',
      });

      if (!canViewTemplate) {
        return c.json(
          {
            error: 'Insufficient org-unit scope for requested action',
          },
          403,
        );
      }
    }
  }

  return c.json({
    tenantId: pathParams.tenantId,
    template,
  });
});

app.get('/v1/tenants/:tenantId/badge-templates/:badgeTemplateId/ownership-history', async (c) => {
  const pathParams = parseBadgeTemplatePathParams(c.req.param());
  const roleCheck = await requireTenantRole(c, pathParams.tenantId, ISSUER_ROLES);

  if (roleCheck instanceof Response) {
    return roleCheck;
  }

  const { session, membershipRole } = roleCheck;
  const db = resolveDatabase(c.env);
  const template = await findBadgeTemplateById(db, pathParams.tenantId, pathParams.badgeTemplateId);

  if (template === null) {
    return c.json(
      {
        error: 'Badge template not found',
      },
      404,
    );
  }

  const scopeCheck = await requireScopedOrgUnitPermission(c, {
    db,
    tenantId: pathParams.tenantId,
    userId: session.userId,
    membershipRole,
    orgUnitId: template.ownerOrgUnitId,
    requiredRole: 'viewer',
    allowWhenNoScopes: true,
  });

  if (scopeCheck !== null) {
    return scopeCheck;
  }

  const events = await listBadgeTemplateOwnershipEvents(db, {
    tenantId: pathParams.tenantId,
    badgeTemplateId: pathParams.badgeTemplateId,
  });

  return c.json({
    tenantId: pathParams.tenantId,
    template,
    events,
  });
});

app.post('/v1/tenants/:tenantId/badge-templates/:badgeTemplateId/ownership-transfer', async (c) => {
  const pathParams = parseBadgeTemplatePathParams(c.req.param());
  let request: ReturnType<typeof parseTransferBadgeTemplateOwnershipRequest>;

  try {
    request = parseTransferBadgeTemplateOwnershipRequest(await c.req.json<unknown>());
  } catch {
    return c.json(
      {
        error: 'Invalid ownership transfer request payload',
      },
      400,
    );
  }

  const roleCheck = await requireTenantRole(c, pathParams.tenantId, ADMIN_ROLES);

  if (roleCheck instanceof Response) {
    return roleCheck;
  }

  const { session, membershipRole } = roleCheck;

  try {
    const transition = await transferBadgeTemplateOwnership(resolveDatabase(c.env), {
      tenantId: pathParams.tenantId,
      badgeTemplateId: pathParams.badgeTemplateId,
      toOrgUnitId: request.toOrgUnitId,
      reasonCode: request.reasonCode,
      reason: request.reason,
      governanceMetadataJson:
        request.governanceMetadata === undefined
          ? undefined
          : JSON.stringify(request.governanceMetadata),
      transferredByUserId: session.userId,
      transferredAt: request.transferredAt ?? new Date().toISOString(),
    });

    await createAuditLog(resolveDatabase(c.env), {
      tenantId: pathParams.tenantId,
      actorUserId: session.userId,
      action: 'badge_template.ownership_transferred',
      targetType: 'badge_template',
      targetId: pathParams.badgeTemplateId,
      metadata: {
        role: membershipRole,
        status: transition.status,
        fromOrgUnitId: transition.event?.fromOrgUnitId ?? transition.template.ownerOrgUnitId,
        toOrgUnitId: transition.template.ownerOrgUnitId,
        reasonCode: request.reasonCode,
        reason: request.reason,
        eventId: transition.event?.id ?? null,
      },
    });

    return c.json({
      tenantId: pathParams.tenantId,
      status: transition.status,
      template: transition.template,
      event: transition.event,
    });
  } catch (error: unknown) {
    if (error instanceof Error) {
      if (
        error.message.includes('not found for tenant') &&
        error.message.includes('Badge template')
      ) {
        return c.json(
          {
            error: 'Badge template not found',
          },
          404,
        );
      }

      if (
        error.message.includes('transferredAt must be a valid ISO timestamp') ||
        error.message.includes('Unsupported badge template ownership reason code') ||
        error.message.includes('initial_assignment is reserved') ||
        (error.message.includes('Org unit') && error.message.includes('not found for tenant'))
      ) {
        return c.json(
          {
            error: error.message,
          },
          422,
        );
      }
    }

    throw error;
  }
});

app.patch('/v1/tenants/:tenantId/badge-templates/:badgeTemplateId', async (c) => {
  const pathParams = parseBadgeTemplatePathParams(c.req.param());
  const payload = await c.req.json<unknown>();
  const request = parseUpdateBadgeTemplateRequest(payload);
  const roleCheck = await requireTenantRole(c, pathParams.tenantId, ISSUER_ROLES);

  if (roleCheck instanceof Response) {
    return roleCheck;
  }

  const { session, membershipRole } = roleCheck;
  const db = resolveDatabase(c.env);
  const existingTemplate = await findBadgeTemplateById(
    db,
    pathParams.tenantId,
    pathParams.badgeTemplateId,
  );

  if (existingTemplate === null) {
    return c.json(
      {
        error: 'Badge template not found',
      },
      404,
    );
  }

  const scopeCheck = await requireScopedOrgUnitPermission(c, {
    db,
    tenantId: pathParams.tenantId,
    userId: session.userId,
    membershipRole,
    orgUnitId: existingTemplate.ownerOrgUnitId,
    requiredRole: 'issuer',
    allowWhenNoScopes: true,
  });

  if (scopeCheck !== null) {
    return scopeCheck;
  }

  try {
    const template = await updateBadgeTemplate(db, {
      tenantId: pathParams.tenantId,
      id: pathParams.badgeTemplateId,
      slug: request.slug,
      title: request.title,
      description: request.description,
      criteriaUri: request.criteriaUri,
      imageUri: request.imageUri,
    });

    if (template === null) {
      return c.json(
        {
          error: 'Badge template not found',
        },
        404,
      );
    }

    await createAuditLog(db, {
      tenantId: pathParams.tenantId,
      actorUserId: session.userId,
      action: 'badge_template.updated',
      targetType: 'badge_template',
      targetId: template.id,
      metadata: {
        role: membershipRole,
        slug: template.slug,
        title: template.title,
      },
    });

    return c.json({
      tenantId: pathParams.tenantId,
      template,
    });
  } catch (error) {
    if (error instanceof Error && error.message.includes('UNIQUE constraint failed')) {
      return c.json(
        {
          error: 'Badge template slug already exists for tenant',
        },
        409,
      );
    }

    throw error;
  }
});

app.post('/v1/tenants/:tenantId/badge-templates/:badgeTemplateId/archive', async (c) => {
  const pathParams = parseBadgeTemplatePathParams(c.req.param());
  const roleCheck = await requireTenantRole(c, pathParams.tenantId, ADMIN_ROLES);

  if (roleCheck instanceof Response) {
    return roleCheck;
  }

  const { session, membershipRole } = roleCheck;

  const template = await setBadgeTemplateArchivedState(resolveDatabase(c.env), {
    tenantId: pathParams.tenantId,
    id: pathParams.badgeTemplateId,
    isArchived: true,
  });

  if (template === null) {
    return c.json(
      {
        error: 'Badge template not found',
      },
      404,
    );
  }

  await createAuditLog(resolveDatabase(c.env), {
    tenantId: pathParams.tenantId,
    actorUserId: session.userId,
    action: 'badge_template.archived_state_changed',
    targetType: 'badge_template',
    targetId: template.id,
    metadata: {
      role: membershipRole,
      isArchived: template.isArchived,
    },
  });

  return c.json({
    tenantId: pathParams.tenantId,
    template,
  });
});

app.post('/v1/tenants/:tenantId/badge-templates/:badgeTemplateId/unarchive', async (c) => {
  const pathParams = parseBadgeTemplatePathParams(c.req.param());
  const roleCheck = await requireTenantRole(c, pathParams.tenantId, ADMIN_ROLES);

  if (roleCheck instanceof Response) {
    return roleCheck;
  }

  const { session, membershipRole } = roleCheck;

  const template = await setBadgeTemplateArchivedState(resolveDatabase(c.env), {
    tenantId: pathParams.tenantId,
    id: pathParams.badgeTemplateId,
    isArchived: false,
  });

  if (template === null) {
    return c.json(
      {
        error: 'Badge template not found',
      },
      404,
    );
  }

  await createAuditLog(resolveDatabase(c.env), {
    tenantId: pathParams.tenantId,
    actorUserId: session.userId,
    action: 'badge_template.archived_state_changed',
    targetType: 'badge_template',
    targetId: template.id,
    metadata: {
      role: membershipRole,
      isArchived: template.isArchived,
    },
  });

  return c.json({
    tenantId: pathParams.tenantId,
    template,
  });
});

type DirectIssueBadgeRequest = Pick<
  ManualIssueBadgeRequest,
  | 'badgeTemplateId'
  | 'recipientIdentity'
  | 'recipientIdentityType'
  | 'recipientIdentifiers'
  | 'idempotencyKey'
>;

interface DirectIssueBadgeOptions {
  recipientDisplayName?: string;
  issuerName?: string;
  issuerUrl?: string;
}

interface DirectIssueBadgeResult {
  status: 'issued' | 'already_issued';
  tenantId: string;
  assertionId: string;
  idempotencyKey: string;
  vcR2Key: string;
  credential: JsonObject;
}

const normalizeRecipientIdentifierValue = (
  identifierType: RecipientIdentifierType,
  identifierValue: string,
): string => {
  const trimmedValue = identifierValue.trim();

  if (identifierType === 'emailAddress') {
    return trimmedValue.toLowerCase();
  }

  return trimmedValue;
};

const toDbRecipientIdentifierInput = (entry: {
  identifierType: RecipientIdentifierType;
  identifier: string;
}): RecipientIdentifierInput | null => {
  const normalizedValue = normalizeRecipientIdentifierValue(entry.identifierType, entry.identifier);

  if (normalizedValue.length === 0) {
    return null;
  }

  return {
    identifierType: entry.identifierType,
    identifierValue: normalizedValue,
  };
};

const uniqueRecipientIdentifierInputs = (
  entries: readonly RecipientIdentifierInput[],
): RecipientIdentifierInput[] => {
  const seen = new Set<string>();
  const uniqueEntries: RecipientIdentifierInput[] = [];

  for (const entry of entries) {
    const normalizedValue = normalizeRecipientIdentifierValue(
      entry.identifierType,
      entry.identifierValue,
    );

    if (normalizedValue.length === 0) {
      continue;
    }

    const dedupeKey = entry.identifierType + '::' + normalizedValue;

    if (seen.has(dedupeKey)) {
      continue;
    }

    seen.add(dedupeKey);
    uniqueEntries.push({
      identifierType: entry.identifierType,
      identifierValue: normalizedValue,
    });
  }

  return uniqueEntries;
};

const recipientIdentifiersFromIdentityAliases = (
  identityType: 'email' | 'email_sha256' | 'did' | 'url' | 'saml_subject' | 'sourced_id',
  identityValue: string,
): RecipientIdentifierInput | null => {
  switch (identityType) {
    case 'email':
      return toDbRecipientIdentifierInput({
        identifierType: 'emailAddress',
        identifier: identityValue,
      });
    case 'did':
      return toDbRecipientIdentifierInput({
        identifierType: 'did',
        identifier: identityValue,
      });
    case 'sourced_id':
      return toDbRecipientIdentifierInput({
        identifierType: 'sourcedId',
        identifier: identityValue,
      });
    case 'email_sha256':
    case 'url':
    case 'saml_subject':
      return null;
  }
};

const recipientIdentifiersForIssueRequest = (
  request: DirectIssueBadgeRequest,
  learnerProfileId: string,
  learnerIdentities: readonly {
    identityType: 'email' | 'email_sha256' | 'did' | 'url' | 'saml_subject' | 'sourced_id';
    identityValue: string;
  }[],
): RecipientIdentifierInput[] => {
  const entries: RecipientIdentifierInput[] = [];

  const stableLearnerIdentifier = toDbRecipientIdentifierInput({
    identifierType: 'studentId',
    identifier: learnerProfileId,
  });

  if (stableLearnerIdentifier !== null) {
    entries.push(stableLearnerIdentifier);
  }

  const requestPrimaryIdentifierType =
    request.recipientIdentityType === 'email'
      ? 'emailAddress'
      : request.recipientIdentityType === 'did'
        ? 'did'
        : null;

  if (requestPrimaryIdentifierType !== null) {
    const requestPrimaryIdentifier = toDbRecipientIdentifierInput({
      identifierType: requestPrimaryIdentifierType,
      identifier: request.recipientIdentity,
    });

    if (requestPrimaryIdentifier !== null) {
      entries.push(requestPrimaryIdentifier);
    }
  }

  for (const identity of learnerIdentities) {
    const mappedIdentifier = recipientIdentifiersFromIdentityAliases(
      identity.identityType,
      identity.identityValue,
    );

    if (mappedIdentifier !== null) {
      entries.push(mappedIdentifier);
    }
  }

  for (const requestIdentifier of request.recipientIdentifiers ?? []) {
    const mappedRequestIdentifier = toDbRecipientIdentifierInput({
      identifierType: requestIdentifier.identifierType,
      identifier: requestIdentifier.identifier,
    });

    if (mappedRequestIdentifier !== null) {
      entries.push(mappedRequestIdentifier);
    }
  }

  return uniqueRecipientIdentifierInputs(entries);
};

const issueBadgeForTenant = async (
  c: AppContext,
  tenantId: string,
  request: DirectIssueBadgeRequest,
  issuedByUserId?: string,
  options?: DirectIssueBadgeOptions,
): Promise<DirectIssueBadgeResult> => {
  const db = resolveDatabase(c.env);
  const badgeTemplate = await findBadgeTemplateById(db, tenantId, request.badgeTemplateId);

  if (badgeTemplate === null) {
    throw new HttpErrorResponse(404, {
      error: 'Badge template not found',
    });
  }

  if (badgeTemplate.isArchived) {
    throw new HttpErrorResponse(409, {
      error: 'Badge template is archived',
    });
  }

  const idempotencyKey = request.idempotencyKey ?? crypto.randomUUID();
  const existingAssertion = await findAssertionByIdempotencyKey(db, tenantId, idempotencyKey);

  if (existingAssertion !== null) {
    const existingCredential = await getImmutableCredentialObject(c.env.BADGE_OBJECTS, {
      tenantId,
      assertionId: existingAssertion.id,
    });

    if (existingCredential === null) {
      throw new Error(
        `Existing assertion "${existingAssertion.id}" is missing its immutable credential object`,
      );
    }

    return {
      status: 'already_issued',
      tenantId,
      assertionId: existingAssertion.id,
      idempotencyKey: existingAssertion.idempotencyKey,
      vcR2Key: existingAssertion.vcR2Key,
      credential: existingCredential,
    };
  }

  const issuerDid = createDidWeb({
    host: c.env.PLATFORM_DOMAIN,
    pathSegments: [tenantId],
  });

  const requestBaseUrl = new URL(c.req.url);
  const learnerProfile = await resolveLearnerProfileForIdentity(db, {
    tenantId,
    identityType: request.recipientIdentityType,
    identityValue: request.recipientIdentity,
    ...(options?.recipientDisplayName === undefined
      ? {}
      : { displayName: options.recipientDisplayName }),
  });
  const issuedAt = new Date().toISOString();
  const assertionId = createTenantScopedId(tenantId);
  const statusListIndex = await nextAssertionStatusListIndex(db, tenantId);
  const statusListCredentialUrl = revocationStatusListUrlForTenant(
    requestBaseUrl.toString(),
    tenantId,
  );
  const learnerIdentities = await listLearnerIdentitiesByProfile(db, tenantId, learnerProfile.id);
  const learnerDidSubjectId =
    learnerIdentities.find((identity) => identity.identityType === 'did')?.identityValue ??
    learnerProfile.subjectId;
  const recipientIdentifiers = recipientIdentifiersForIssueRequest(
    request,
    learnerProfile.id,
    learnerIdentities,
  );
  const credentialSubjectIdentifiers: JsonObject[] = recipientIdentifiers.map((entry) => {
    return {
      type: entry.identifierType,
      identifier: entry.identifierValue,
    };
  });
  const issuer =
    options?.issuerName === undefined
      ? issuerDid
      : {
          id: issuerDid,
          name: options.issuerName,
          ...(options.issuerUrl === undefined ? {} : { url: options.issuerUrl }),
        };
  const signedCredentialResult = await signCredentialForDid({
    context: c,
    did: issuerDid,
    proofType: 'Ed25519Signature2020',
    createdAt: issuedAt,
    missingPrivateKeyError:
      'Tenant DID is missing private signing key material and no remote signer is configured',
    ed25519KeyRequirementError: 'Tenant issuance requires an Ed25519 private key',
    credential: {
      '@context': ['https://www.w3.org/ns/credentials/v2'],
      id: `urn:credtrail:assertion:${encodeURIComponent(assertionId)}`,
      type: ['VerifiableCredential', 'OpenBadgeCredential'],
      issuer,
      validFrom: issuedAt,
      credentialStatus: credentialStatusForAssertion(statusListCredentialUrl, statusListIndex),
      credentialSubject: {
        id: learnerDidSubjectId,
        identifier: credentialSubjectIdentifiers,
        achievement: {
          id: `urn:credtrail:badge-template:${encodeURIComponent(badgeTemplate.id)}`,
          type: ['Achievement'],
          name: badgeTemplate.title,
          ...(badgeTemplate.description === null ? {} : { description: badgeTemplate.description }),
          ...(badgeTemplate.criteriaUri === null
            ? {}
            : {
                criteria: {
                  id: badgeTemplate.criteriaUri,
                  type: 'Criteria',
                },
              }),
          ...(badgeTemplate.imageUri === null
            ? {}
            : {
                image: {
                  id: badgeTemplate.imageUri,
                  type: 'Image',
                },
              }),
        },
      },
    },
  });

  if (signedCredentialResult.status !== 'ok') {
    throw new HttpErrorResponse(signedCredentialResult.statusCode, {
      error: signedCredentialResult.error,
      did: issuerDid,
    });
  }

  const signedCredential = signedCredentialResult.credential;

  const stored = await storeImmutableCredentialObject(c.env.BADGE_OBJECTS, {
    tenantId,
    assertionId,
    credential: signedCredential,
  });

  const createdAssertion = await createAssertion(db, {
    id: assertionId,
    tenantId,
    learnerProfileId: learnerProfile.id,
    badgeTemplateId: badgeTemplate.id,
    recipientIdentity: request.recipientIdentity,
    recipientIdentityType: request.recipientIdentityType,
    vcR2Key: stored.key,
    statusListIndex,
    idempotencyKey,
    issuedAt,
    recipientIdentifiers,
    ...(issuedByUserId === undefined ? {} : { issuedByUserId }),
  });

  await createAuditLog(db, {
    tenantId,
    ...(issuedByUserId === undefined ? {} : { actorUserId: issuedByUserId }),
    action: 'assertion.issued',
    targetType: 'assertion',
    targetId: createdAssertion.id,
    metadata: {
      assertionPublicId: createdAssertion.publicId,
      badgeTemplateId: createdAssertion.badgeTemplateId,
      recipientIdentity: createdAssertion.recipientIdentity,
      recipientIdentityType: createdAssertion.recipientIdentityType,
      issuedAt: createdAssertion.issuedAt,
    },
  });

  if (request.recipientIdentityType === 'email') {
    const recipientEmail = request.recipientIdentity.trim().toLowerCase();
    const publicBadgePath = publicBadgePathForAssertion(createdAssertion);
    const verificationPath = `/credentials/v1/${encodeURIComponent(assertionId)}`;
    const credentialDownloadPath = `/credentials/v1/${encodeURIComponent(assertionId)}/download`;

    try {
      await sendIssuanceEmailNotification({
        mailtrapApiToken: c.env.MAILTRAP_API_TOKEN,
        mailtrapInboxId: c.env.MAILTRAP_INBOX_ID,
        mailtrapApiBaseUrl: c.env.MAILTRAP_API_BASE_URL,
        mailtrapFromEmail: c.env.MAILTRAP_FROM_EMAIL,
        mailtrapFromName: c.env.MAILTRAP_FROM_NAME,
        recipientEmail,
        badgeTitle: badgeTemplate.title,
        assertionId,
        tenantId,
        issuedAtIso: issuedAt,
        publicBadgeUrl: new URL(publicBadgePath, requestBaseUrl).toString(),
        verificationUrl: new URL(verificationPath, requestBaseUrl).toString(),
        credentialDownloadUrl: new URL(credentialDownloadPath, requestBaseUrl).toString(),
      });
    } catch (error: unknown) {
      logWarn(observabilityContext(c.env), 'issuance_email_notification_failed', {
        assertionId,
        tenantId,
        recipientEmail,
        detail: error instanceof Error ? error.message : 'Unknown email notification error',
      });
    }
  }

  return {
    status: 'issued',
    tenantId,
    assertionId,
    idempotencyKey,
    vcR2Key: stored.key,
    credential: signedCredential,
  };
};

const manualIssueResponseStatus = (status: DirectIssueBadgeResult['status']): 200 | 201 => {
  return status === 'issued' ? 201 : 200;
};

app.post('/v1/tenants/:tenantId/assertions/manual-issue', async (c): Promise<Response> => {
  const pathParams = parseTenantPathParams(c.req.param());
  const payload = await c.req.json<unknown>();
  const request = parseManualIssueBadgeRequest(payload);
  const roleCheck = await requireTenantRole(c, pathParams.tenantId, TENANT_MEMBER_ROLES);

  if (roleCheck instanceof Response) {
    return roleCheck;
  }

  const { session, membershipRole } = roleCheck;
  const db = resolveDatabase(c.env);
  const template = await findBadgeTemplateById(db, pathParams.tenantId, request.badgeTemplateId);

  if (template === null) {
    return c.json(
      {
        error: 'Badge template not found',
      },
      404,
    );
  }

  const delegatedPermission = await requireDelegatedIssuingAuthorityPermission(c, {
    db,
    tenantId: pathParams.tenantId,
    userId: session.userId,
    membershipRole,
    ownerOrgUnitId: template.ownerOrgUnitId,
    badgeTemplateId: template.id,
    requiredAction: 'issue_badge',
  });

  if (delegatedPermission !== null) {
    return delegatedPermission;
  }

  try {
    const result = await issueBadgeForTenant(c, pathParams.tenantId, request, session.userId);
    return c.json(result, manualIssueResponseStatus(result.status));
  } catch (error: unknown) {
    if (error instanceof HttpErrorResponse) {
      return c.json(error.payload, error.statusCode);
    }

    throw error;
  }
});

app.get('/v1/tenants/:tenantId/assertions/:assertionId/lifecycle', async (c): Promise<Response> => {
  const pathParams = parseAssertionPathParams(c.req.param());
  const roleCheck = await requireTenantRole(c, pathParams.tenantId, ISSUER_ROLES);

  if (roleCheck instanceof Response) {
    return roleCheck;
  }

  if (!assertionBelongsToTenant(pathParams.tenantId, pathParams.assertionId)) {
    return c.json(
      {
        error: 'assertionId must be a tenant-scoped identifier for the active tenant',
      },
      422,
    );
  }

  const db = resolveDatabase(c.env);
  const assertion = await findAssertionById(db, pathParams.tenantId, pathParams.assertionId);

  if (assertion === null) {
    return c.json(
      {
        error: 'Assertion not found',
      },
      404,
    );
  }

  const lifecycle = await resolveAssertionLifecycleState(
    db,
    pathParams.tenantId,
    pathParams.assertionId,
  );

  if (lifecycle === null) {
    return c.json(
      {
        error: 'Assertion not found',
      },
      404,
    );
  }

  const events = await listAssertionLifecycleEvents(db, {
    tenantId: pathParams.tenantId,
    assertionId: pathParams.assertionId,
  });

  c.header('Cache-Control', 'no-store');

  return c.json({
    assertionId: assertion.id,
    tenantId: assertion.tenantId,
    state: lifecycle.state,
    source: lifecycle.source,
    reasonCode: lifecycle.reasonCode,
    reason: lifecycle.reason,
    transitionedAt: lifecycle.transitionedAt,
    revokedAt: lifecycle.revokedAt,
    events,
  });
});

app.post(
  '/v1/tenants/:tenantId/assertions/:assertionId/lifecycle/transition',
  async (c): Promise<Response> => {
    const pathParams = parseAssertionPathParams(c.req.param());
    const roleCheck = await requireTenantRole(c, pathParams.tenantId, TENANT_MEMBER_ROLES);

    if (roleCheck instanceof Response) {
      return roleCheck;
    }

    const { session, membershipRole } = roleCheck;

    if (!assertionBelongsToTenant(pathParams.tenantId, pathParams.assertionId)) {
      return c.json(
        {
          error: 'assertionId must be a tenant-scoped identifier for the active tenant',
        },
        422,
      );
    }

    let request: ReturnType<typeof parseAssertionLifecycleTransitionRequest>;

    try {
      request = parseAssertionLifecycleTransitionRequest(await c.req.json<unknown>());
    } catch {
      return c.json(
        {
          error: 'Invalid lifecycle transition request payload',
        },
        400,
      );
    }

    if (request.transitionSource === 'automation') {
      return c.json(
        {
          error: 'Automation lifecycle transitions are only allowed via trusted internal jobs',
        },
        422,
      );
    }

    const db = resolveDatabase(c.env);
    const assertion = await findAssertionById(db, pathParams.tenantId, pathParams.assertionId);

    if (assertion === null) {
      return c.json(
        {
          error: 'Assertion not found',
        },
        404,
      );
    }

    const badgeTemplate = await findBadgeTemplateById(
      db,
      pathParams.tenantId,
      assertion.badgeTemplateId,
    );

    if (badgeTemplate === null) {
      return c.json(
        {
          error: 'Badge template not found',
        },
        404,
      );
    }

    const requiredAction: DelegatedIssuingAuthorityAction =
      request.toState === 'revoked' ? 'revoke_badge' : 'manage_lifecycle';
    const delegatedPermission = await requireDelegatedIssuingAuthorityPermission(c, {
      db,
      tenantId: pathParams.tenantId,
      userId: session.userId,
      membershipRole,
      ownerOrgUnitId: badgeTemplate.ownerOrgUnitId,
      badgeTemplateId: badgeTemplate.id,
      requiredAction,
    });

    if (delegatedPermission !== null) {
      return delegatedPermission;
    }

    try {
      const transitionResult = await recordAssertionLifecycleTransition(db, {
        tenantId: pathParams.tenantId,
        assertionId: pathParams.assertionId,
        toState: request.toState,
        reasonCode: request.reasonCode,
        ...(request.reason === undefined ? {} : { reason: request.reason }),
        transitionSource: 'manual',
        actorUserId: session.userId,
        transitionedAt: request.transitionedAt ?? new Date().toISOString(),
      });

      if (transitionResult.status === 'invalid_transition') {
        return c.json(
          {
            error: 'Lifecycle transition not allowed',
            fromState: transitionResult.fromState,
            toState: transitionResult.toState,
            currentState: transitionResult.currentState,
            message: transitionResult.message,
          },
          409,
        );
      }

      if (transitionResult.status === 'already_in_state') {
        c.header('Cache-Control', 'no-store');

        return c.json({
          status: transitionResult.status,
          fromState: transitionResult.fromState,
          toState: transitionResult.toState,
          currentState: transitionResult.currentState,
          message: transitionResult.message,
        });
      }

      const event = transitionResult.event;

      if (event === null) {
        throw new Error('Lifecycle transition result is missing event details');
      }

      await createAuditLog(db, {
        tenantId: pathParams.tenantId,
        actorUserId: session.userId,
        action: 'assertion.lifecycle_transitioned',
        targetType: 'assertion',
        targetId: pathParams.assertionId,
        metadata: {
          eventId: event.id,
          fromState: event.fromState,
          toState: event.toState,
          reasonCode: event.reasonCode,
          reason: event.reason,
          transitionSource: event.transitionSource,
          transitionedAt: event.transitionedAt,
        },
      });

      c.header('Cache-Control', 'no-store');

      return c.json({
        status: transitionResult.status,
        fromState: transitionResult.fromState,
        toState: transitionResult.toState,
        currentState: transitionResult.currentState,
        message: transitionResult.message,
        event,
      });
    } catch (error: unknown) {
      if (error instanceof Error) {
        if (error.message.includes('not found for tenant')) {
          return c.json(
            {
              error: 'Assertion not found',
            },
            404,
          );
        }

        if (
          error.message.includes('Manual lifecycle transitions require actorUserId') ||
          error.message.includes('Automated lifecycle transitions must not set actorUserId') ||
          error.message.includes('transitionedAt must be a valid ISO timestamp')
        ) {
          return c.json(
            {
              error: error.message,
            },
            422,
          );
        }
      }

      throw error;
    }
  },
);
app.post('/v1/tenants/:tenantId/assertions/sakai-commit-issue', async (c): Promise<Response> => {
  const pathParams = parseTenantPathParams(c.req.param());
  const payload = await c.req.json<unknown>();
  const request = parseIssueSakaiCommitBadgeRequest(payload);
  const roleCheck = await requireTenantRole(c, pathParams.tenantId, TENANT_MEMBER_ROLES);

  if (roleCheck instanceof Response) {
    return roleCheck;
  }

  const { session, membershipRole } = roleCheck;
  const db = resolveDatabase(c.env);
  const template = await findBadgeTemplateById(db, pathParams.tenantId, request.badgeTemplateId);

  if (template === null) {
    return c.json(
      {
        error: 'Badge template not found',
      },
      404,
    );
  }

  const delegatedPermission = await requireDelegatedIssuingAuthorityPermission(c, {
    db,
    tenantId: pathParams.tenantId,
    userId: session.userId,
    membershipRole,
    ownerOrgUnitId: template.ownerOrgUnitId,
    badgeTemplateId: template.id,
    requiredAction: 'issue_badge',
  });

  if (delegatedPermission !== null) {
    return delegatedPermission;
  }

  let commitCount: number;

  try {
    commitCount = await fetchSakaiCommitCountForUsername(
      request.githubUsername,
      c.env.GITHUB_TOKEN,
    );
  } catch (error: unknown) {
    logWarn(observabilityContext(c.env), 'github_commit_verification_failed', {
      tenantId: pathParams.tenantId,
      githubUsername: request.githubUsername,
      repository: `${SAKAI_REPO_OWNER}/${SAKAI_REPO_NAME}`,
      detail: error instanceof Error ? error.message : 'Unknown GitHub verification error',
    });

    return c.json(
      {
        error: 'Unable to verify GitHub commits',
      },
      502,
    );
  }

  if (commitCount < SAKAI_MIN_COMMIT_COUNT) {
    return c.json(
      {
        error: 'GitHub commit threshold not met',
        githubUsername: request.githubUsername,
        repository: `${SAKAI_REPO_OWNER}/${SAKAI_REPO_NAME}`,
        commitCount,
        requiredCommitCount: SAKAI_MIN_COMMIT_COUNT,
      },
      422,
    );
  }

  const derivedIdempotencyKey =
    request.idempotencyKey ??
    (await sha256Hex(
      `${SAKAI_REPO_OWNER}/${SAKAI_REPO_NAME}:${pathParams.tenantId}:${request.badgeTemplateId}:${request.githubUsername.toLowerCase()}`,
    ));
  const recipientIdentity = githubProfileUrlForUsername(request.githubUsername);

  try {
    const result = await issueBadgeForTenant(
      c,
      pathParams.tenantId,
      {
        badgeTemplateId: request.badgeTemplateId,
        recipientIdentity,
        recipientIdentityType: 'url',
        idempotencyKey: derivedIdempotencyKey,
      },
      session.userId,
      {
        recipientDisplayName: `@${request.githubUsername}`,
        issuerName: SAKAI_ISSUER_NAME,
        issuerUrl: SAKAI_ISSUER_URL,
      },
    );

    return c.json(
      {
        ...result,
        githubUsername: request.githubUsername,
        repository: `${SAKAI_REPO_OWNER}/${SAKAI_REPO_NAME}`,
        commitCount,
        requiredCommitCount: SAKAI_MIN_COMMIT_COUNT,
      },
      manualIssueResponseStatus(result.status),
    );
  } catch (error: unknown) {
    if (error instanceof HttpErrorResponse) {
      return c.json(error.payload, error.statusCode);
    }

    throw error;
  }
});

app.post('/v1/signing/keys/generate', async (c) => {
  const payload = await c.req.json<unknown>();
  const request = parseKeyGenerationRequest(payload);
  const signingMaterial =
    request.keyId === undefined
      ? await generateTenantDidSigningMaterial({
          did: request.did,
        })
      : await generateTenantDidSigningMaterial({
          did: request.did,
          keyId: request.keyId,
        });
  const didDocument = createDidDocument({
    did: signingMaterial.did,
    keyId: signingMaterial.keyId,
    publicJwk: signingMaterial.publicJwk,
  });

  return c.json(
    {
      didDocument,
      keyMaterial: signingMaterial,
    },
    201,
  );
});

app.post('/v1/signing/credentials', async (c) => {
  const payload = await c.req.json<unknown>();
  const request = parseSignCredentialRequest(payload);
  const proofType = request.proofType ?? 'Ed25519Signature2020';
  const signingResult = await signCredentialForDid({
    context: c,
    did: request.did,
    credential: request.credential,
    proofType,
    ...(request.cryptosuite === undefined ? {} : { cryptosuite: request.cryptosuite }),
  });

  if (signingResult.status !== 'ok') {
    return c.json(
      {
        error: signingResult.error,
        did: request.did,
      },
      signingResult.statusCode,
    );
  }

  return c.json(
    {
      did: request.did,
      credential: signingResult.credential,
    },
    201,
  );
});

app.post('/v1/jobs/process', async (c) => {
  const configuredToken = c.env.JOB_PROCESSOR_TOKEN?.trim();

  if (configuredToken !== undefined && configuredToken.length > 0) {
    const authorizationHeader = c.req.header('authorization');
    const expectedAuthorization = `Bearer ${configuredToken}`;

    if (authorizationHeader !== expectedAuthorization) {
      return c.json(
        {
          error: 'Unauthorized',
        },
        401,
      );
    }
  }

  const request = parseProcessQueueRequest(await readJsonBodyOrEmptyObject(c));
  const result = await processQueuedJobs(c, processQueueInputWithDefaults(request));

  return c.json(
    {
      status: 'ok',
      ...result,
    },
    200,
  );
});

app.post('/v1/issue', async (c) => {
  const payload = await c.req.json<unknown>();
  const request = parseIssueBadgeRequest(payload);
  const queued = issueBadgeQueueJobFromRequest(request);

  await enqueueJobQueueMessage(resolveDatabase(c.env), {
    tenantId: queued.job.tenantId,
    jobType: queued.job.jobType,
    payload: queued.job.payload,
    idempotencyKey: queued.job.idempotencyKey,
  });

  return c.json(
    {
      status: 'queued',
      jobType: queued.job.jobType,
      assertionId: queued.assertionId,
      idempotencyKey: queued.job.idempotencyKey,
    },
    202,
  );
});

app.post('/v1/revoke', async (c) => {
  const payload = await c.req.json<unknown>();
  const request = parseRevokeBadgeRequest(payload);
  const queued = revokeBadgeQueueJobFromRequest(request);

  await enqueueJobQueueMessage(resolveDatabase(c.env), {
    tenantId: queued.job.tenantId,
    jobType: queued.job.jobType,
    payload: queued.job.payload,
    idempotencyKey: queued.job.idempotencyKey,
  });

  return c.json(
    {
      status: 'queued',
      jobType: queued.job.jobType,
      assertionId: request.assertionId,
      revocationId: queued.revocationId,
      idempotencyKey: queued.job.idempotencyKey,
    },
    202,
  );
});

const worker: ExportedHandler<AppBindings> = {
  fetch(request, env, executionCtx): Promise<Response> {
    return Promise.resolve(app.fetch(request, env, executionCtx));
  },
  async scheduled(event, env, executionCtx): Promise<void> {
    const request = queueProcessorRequestFromSchedule(env);
    const response = await app.fetch(request, env, executionCtx);
    const responseBody = await response.text();

    if (!response.ok) {
      await captureSentryException({
        context: observabilityContext(env),
        dsn: env.SENTRY_DSN,
        error: new Error('Scheduled queue processing failed'),
        message: 'Scheduled queue processing failed',
        extra: {
          cron: event.cron,
          status: response.status,
          responseBody,
        },
      });

      logError(observabilityContext(env), 'scheduled_queue_processing_failed', {
        cron: event.cron,
        status: response.status,
        responseBody,
      });
      return;
    }

    logInfo(observabilityContext(env), 'scheduled_queue_processing_succeeded', {
      cron: event.cron,
      status: response.status,
      responseBody,
    });
  },
};

export default worker;

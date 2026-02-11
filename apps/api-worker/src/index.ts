import {
  captureSentryException,
  createDidDocument,
  createDidWeb,
  createTenantScopedId,
  splitTenantScopedId,
  type Ed25519PrivateJwk,
  type Ed25519PublicJwk,
  type JsonObject,
  generateTenantDidSigningMaterial,
  getImmutableCredentialObject,
  logError,
  logInfo,
  logWarn,
  signCredentialWithEd25519Signature2020,
  storeImmutableCredentialObject,
  type ObservabilityContext,
} from '@credtrail/core-domain';
import {
  addLearnerIdentityAlias,
  completeJobQueueMessage,
  createAssertion,
  createBadgeTemplate,
  createLearnerIdentityLinkProof,
  createMagicLinkToken,
  createSession,
  enqueueJobQueueMessage,
  failJobQueueMessage,
  ensureTenantMembership,
  findLearnerIdentityLinkProofByHash,
  findLearnerProfileById,
  findLearnerProfileByIdentity,
  findUserById,
  findAssertionById,
  findAssertionByPublicId,
  findAssertionByIdempotencyKey,
  findBadgeTemplateById,
  findActiveSessionByHash,
  isLearnerIdentityLinkProofValid,
  listAssertionStatusListEntries,
  listLearnerBadgeSummaries,
  leaseJobQueueMessages,
  findMagicLinkTokenByHash,
  isMagicLinkTokenValid,
  listBadgeTemplates,
  markLearnerIdentityLinkProofUsed,
  markMagicLinkTokenUsed,
  nextAssertionStatusListIndex,
  resolveLearnerProfileForIdentity,
  recordAssertionRevocation,
  revokeSessionByHash,
  setBadgeTemplateArchivedState,
  touchSession,
  updateBadgeTemplate,
  type AssertionRecord,
  type LearnerBadgeSummaryRecord,
  type SessionRecord,
  upsertUserByEmail,
} from '@credtrail/db';
import { renderPageShell } from '@credtrail/ui-components';
import {
  parseBadgeTemplateListQuery,
  parseBadgeTemplatePathParams,
  parseProcessQueueRequest,
  parseQueueJob,
  parseCredentialPathParams,
  parseCreateBadgeTemplateRequest,
  type IssueBadgeQueueJob,
  type IssueBadgeRequest,
  type ProcessQueueRequest,
  type QueueJob,
  parseIssueBadgeRequest,
  parseKeyGenerationRequest,
  parseLearnerIdentityLinkRequest,
  parseLearnerIdentityLinkVerifyRequest,
  parseManualIssueBadgeRequest,
  parseIssueSakaiCommitBadgeRequest,
  parseMagicLinkRequest,
  parseMagicLinkVerifyRequest,
  parseTenantPathParams,
  type RevokeBadgeQueueJob,
  type RevokeBadgeRequest,
  type ManualIssueBadgeRequest,
  parseRevokeBadgeRequest,
  parseSignCredentialRequest,
  parseTenantSigningRegistry,
  parseUpdateBadgeTemplateRequest,
  type TenantSigningRegistry,
} from '@credtrail/validation';
import { Hono, type Context } from 'hono';
import { deleteCookie, getCookie, setCookie } from 'hono/cookie';

interface AppBindings {
  APP_ENV: string;
  DB: D1Database;
  BADGE_OBJECTS: R2Bucket;
  PLATFORM_DOMAIN: string;
  MARKETING_SITE_ORIGIN?: string;
  SENTRY_DSN?: string;
  TENANT_SIGNING_REGISTRY_JSON?: string;
  MAILTRAP_API_TOKEN?: string;
  MAILTRAP_INBOX_ID?: string;
  MAILTRAP_API_BASE_URL?: string;
  MAILTRAP_FROM_EMAIL?: string;
  MAILTRAP_FROM_NAME?: string;
  GITHUB_TOKEN?: string;
  JOB_PROCESSOR_TOKEN?: string;
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
const SESSION_COOKIE_NAME = 'credtrail_session';
const LANDING_ASSET_PATH_PREFIX = '/_astro/';
const LANDING_STATIC_PATHS = new Set(['/credtrail-logo.png', '/favicon.svg']);
const SAKAI_REPO_OWNER = 'sakaiproject';
const SAKAI_REPO_NAME = 'sakai';
const SAKAI_MIN_COMMIT_COUNT = 1000;
const SAKAI_ISSUER_NAME = 'Sakai Project';
const SAKAI_ISSUER_URL = 'https://www.sakaiproject.org/';
const DEFAULT_JOB_PROCESS_LIMIT = 10;
const DEFAULT_JOB_PROCESS_LEASE_SECONDS = 30;
const DEFAULT_JOB_PROCESS_RETRY_DELAY_SECONDS = 30;

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
  const sessionToken = getCookie(c, SESSION_COOKIE_NAME);

  if (sessionToken === undefined) {
    return null;
  }

  const sessionTokenHash = await sha256Hex(sessionToken);
  const nowIso = new Date().toISOString();
  const session = await findActiveSessionByHash(c.env.DB, sessionTokenHash, nowIso);

  if (session === null) {
    deleteCookie(c, SESSION_COOKIE_NAME, {
      path: '/',
    });
    return null;
  }

  await touchSession(c.env.DB, session.id, nowIso);
  return session;
};

const toEd25519PublicJwk = (jwk: {
  kty: 'OKP';
  crv: 'Ed25519';
  x: string;
  kid?: string | undefined;
}): Ed25519PublicJwk => {
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

const toEd25519PrivateJwk = (jwk: {
  kty: 'OKP';
  crv: 'Ed25519';
  x: string;
  d: string;
  kid?: string | undefined;
}): Ed25519PrivateJwk => {
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

const didForWellKnownRequest = (requestUrl: string): string => {
  const request = new URL(requestUrl);
  return createDidWeb({ host: request.host });
};

const didForTenantPathRequest = (requestUrl: string, tenantSlug: string): string => {
  const request = new URL(requestUrl);
  return createDidWeb({ host: request.host, pathSegments: [tenantSlug] });
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
): JsonObject => {
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
  privateJwk: Ed25519PrivateJwk;
  verificationMethod: string;
  statusEntries: readonly RevocationStatusBitEntry[];
}

const buildRevocationStatusListCredential = async (
  input: BuildRevocationStatusListCredentialInput,
): Promise<JsonObject> => {
  const statusListCredentialUrl = revocationStatusListUrlForTenant(input.requestUrl, input.tenantId);
  const encodedList = await encodeRevocationBitstring(input.statusEntries);
  const issuedAt = new Date().toISOString();

  return signCredentialWithEd25519Signature2020({
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
    privateJwk: input.privateJwk,
    verificationMethod: input.verificationMethod,
    createdAt: issuedAt,
  });
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
          idempotencyKey: job.idempotencyKey,
        },
        job.payload.requestedByUserId,
      );
      return;
    case 'revoke_badge':
      await recordAssertionRevocation(c.env.DB, {
        tenantId: job.tenantId,
        assertionId: job.payload.assertionId,
        revocationId: job.payload.revocationId,
        reason: job.payload.reason,
        idempotencyKey: job.idempotencyKey,
        revokedByUserId: job.payload.requestedByUserId,
        revokedAt: new Date().toISOString(),
      });
      return;
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
  const leasedMessages = await leaseJobQueueMessages(c.env.DB, {
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
      await completeJobQueueMessage(c.env.DB, {
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

      const status = await failJobQueueMessage(c.env.DB, {
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
  public readonly statusCode: 404 | 409 | 500;

  public readonly payload: {
    error: string;
    did?: string | undefined;
  };

  public constructor(
    statusCode: 404 | 409 | 500,
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
  description: string | null;
  criteriaUri: string | null;
  imageUri: string | null;
}

const achievementDetailsFromCredential = (credential: JsonObject): AchievementDetails => {
  const credentialSubject = asJsonObject(credential.credentialSubject);
  const achievement = asJsonObject(credentialSubject?.achievement);

  return {
    description: asNonEmptyString(achievement?.description),
    criteriaUri: linkedDataReferenceId(achievement?.criteria),
    imageUri: linkedDataReferenceId(achievement?.image),
  };
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
  db: D1Database,
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
  db: D1Database,
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
  db: D1Database,
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
    const recipientDisplayName = await loadRecipientDisplayNameForAssertion(db, assertionByPublicId);

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

  const assertion = await findAssertionById(db, tenantScopedCredentialId.tenantId, trimmedIdentifier);

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
          <a
            class="public-badge__button public-badge__button--accent"
            href="${escapeHtml(linkedInShareUrl.toString())}"
            target="_blank"
            rel="noopener noreferrer"
          >
            Share on LinkedIn
          </a>
        </div>
        <p id="copy-badge-url-status" class="public-badge__copy-status" aria-live="polite"></p>
      </section>

      <details class="public-badge__card public-badge__technical">
        <summary>Technical details</summary>
        <dl class="public-badge__technical-grid">
          <dt>Issuer ID</dt>
          <dd>${escapeHtml(issuerIdentifierFromCredential(model.credential) ?? 'Not available')}</dd>
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

const learnerDashboardPage = (
  requestUrl: string,
  tenantId: string,
  badges: readonly LearnerBadgeSummaryRecord[],
): string => {
  if (badges.length === 0) {
    return renderPageShell(
      'Learner dashboard | CredTrail',
      `<section style="display:grid;gap:1rem;max-width:48rem;">
        <h1 style="margin:0;">Your badges</h1>
        <p style="margin:0;">No badges have been issued to this learner account yet.</p>
      </section>`,
    );
  }

  const cards = badges
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
          <h2 style="margin:0;">${escapeHtml(badge.badgeTitle)}</h2>
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
    .join('');

  return renderPageShell(
    'Learner dashboard | CredTrail',
    `<section style="display:grid;gap:1rem;">
      <h1 style="margin:0;">Your badges</h1>
      <p style="margin:0;color:#3d4b66;">Tenant: ${escapeHtml(tenantId)}</p>
      <div style="display:grid;gap:0.9rem;">${cards}</div>
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
      const marketingUrl = new URL(`${requestUrl.pathname}${requestUrl.search}`, c.env.MARKETING_SITE_ORIGIN);
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

app.get('/.well-known/did.json', (c) => {
  const registry = parseSigningRegistryFromEnv(c.env.TENANT_SIGNING_REGISTRY_JSON);
  const did = didForWellKnownRequest(c.req.url);
  const signingEntry = registry[did];

  if (signingEntry === undefined) {
    return c.json(
      {
        error: 'No DID document configured for request host',
        did,
      },
      404,
    );
  }

  return c.json(
    createDidDocument({
      did,
      keyId: signingEntry.keyId,
      publicJwk: toEd25519PublicJwk(signingEntry.publicJwk),
    }),
  );
});

app.get('/:tenantSlug/did.json', (c) => {
  const registry = parseSigningRegistryFromEnv(c.env.TENANT_SIGNING_REGISTRY_JSON);
  const tenantSlug = c.req.param('tenantSlug');
  const did = didForTenantPathRequest(c.req.url, tenantSlug);
  const signingEntry = registry[did];

  if (signingEntry === undefined) {
    return c.json(
      {
        error: 'No DID document configured for tenant path',
        did,
      },
      404,
    );
  }

  return c.json(
    createDidDocument({
      did,
      keyId: signingEntry.keyId,
      publicJwk: toEd25519PublicJwk(signingEntry.publicJwk),
    }),
  );
});

app.get('/credentials/v1/:credentialId', async (c) => {
  const pathParams = parseCredentialPathParams(c.req.param());
  const result = await loadVerificationViewModel(c.env.DB, c.env.BADGE_OBJECTS, pathParams.credentialId);

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

  const statusList =
    result.value.assertion.statusListIndex === null
      ? null
      : credentialStatusForAssertion(
          revocationStatusListUrlForTenant(c.req.url, result.value.assertion.tenantId),
          result.value.assertion.statusListIndex,
        );

  return c.json({
    assertionId: result.value.assertion.id,
    tenantId: result.value.assertion.tenantId,
    issuedAt: result.value.assertion.issuedAt,
    verification: {
      status: result.value.assertion.revokedAt === null ? 'valid' : 'revoked',
      revokedAt: result.value.assertion.revokedAt,
      statusList,
    },
    credential: result.value.credential,
  });
});

app.get('/credentials/v1/status-lists/:tenantId/revocation', async (c) => {
  const pathParams = parseTenantPathParams(c.req.param());
  const registry = parseSigningRegistryFromEnv(c.env.TENANT_SIGNING_REGISTRY_JSON);
  const issuerDid = createDidWeb({
    host: c.env.PLATFORM_DOMAIN,
    pathSegments: [pathParams.tenantId],
  });
  const signingEntry = registry[issuerDid];

  if (signingEntry === undefined) {
    return c.json(
      {
        error: 'No signing configuration for tenant DID',
        did: issuerDid,
      },
      404,
    );
  }

  if (signingEntry.privateJwk === undefined) {
    return c.json(
      {
        error: 'Tenant DID is missing private signing key material',
        did: issuerDid,
      },
      500,
    );
  }

  const assertions = await listAssertionStatusListEntries(c.env.DB, pathParams.tenantId);
  const statusEntries = assertions.map((assertion) => {
    return {
      statusListIndex: assertion.statusListIndex,
      revoked: assertion.revokedAt !== null,
    };
  });
  const statusListCredential = await buildRevocationStatusListCredential({
    requestUrl: c.req.url,
    tenantId: pathParams.tenantId,
    issuerDid,
    privateJwk: toEd25519PrivateJwk(signingEntry.privateJwk),
    verificationMethod: `${issuerDid}#${signingEntry.keyId}`,
    statusEntries,
  });

  c.header('Cache-Control', 'no-store');
  c.header('Content-Type', 'application/ld+json; charset=utf-8');
  return c.body(JSON.stringify(statusListCredential, null, 2));
});

app.get('/credentials/v1/:credentialId/jsonld', async (c) => {
  const pathParams = parseCredentialPathParams(c.req.param());
  const result = await loadVerificationViewModel(c.env.DB, c.env.BADGE_OBJECTS, pathParams.credentialId);

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
  const result = await loadVerificationViewModel(c.env.DB, c.env.BADGE_OBJECTS, pathParams.credentialId);

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

app.get('/badges/:badgeIdentifier/public_url', (c) => {
  const badgeIdentifier = c.req.param('badgeIdentifier').trim();

  if (badgeIdentifier.length === 0) {
    return c.html(publicBadgeNotFoundPage(), 404);
  }

  return c.redirect(`/badges/${encodeURIComponent(badgeIdentifier)}`, 308);
});

app.get('/badges/:badgeIdentifier', async (c) => {
  const badgeIdentifier = c.req.param('badgeIdentifier');
  const result = await loadPublicBadgeViewModel(c.env.DB, c.env.BADGE_OBJECTS, badgeIdentifier);

  c.header('Cache-Control', 'no-store');

  if (result.status === 'not_found') {
    return c.html(publicBadgeNotFoundPage(), 404);
  }

  if (result.status === 'redirect') {
    return c.redirect(result.canonicalPath, 308);
  }

  return c.html(publicBadgePage(c.req.url, result.value));
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

  const badges = await listLearnerBadgeSummaries(c.env.DB, {
    tenantId: pathParams.tenantId,
    userId: session.userId,
  });

  c.header('Cache-Control', 'no-store');
  return c.html(learnerDashboardPage(c.req.url, pathParams.tenantId, badges));
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

  const user = await findUserById(c.env.DB, session.userId);

  if (user === null) {
    return c.json(
      {
        error: 'Authenticated user not found',
      },
      404,
    );
  }

  const learnerProfile = await resolveLearnerProfileForIdentity(c.env.DB, {
    tenantId: pathParams.tenantId,
    identityType: 'email',
    identityValue: user.email,
  });
  const normalizedEmail = request.email.trim().toLowerCase();
  const existingProfile = await findLearnerProfileByIdentity(c.env.DB, {
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

  await createLearnerIdentityLinkProof(c.env.DB, {
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
  const proof = await findLearnerIdentityLinkProofByHash(c.env.DB, await sha256Hex(request.token));

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

  const existingProfile = await findLearnerProfileByIdentity(c.env.DB, {
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
    await addLearnerIdentityAlias(c.env.DB, {
      tenantId: pathParams.tenantId,
      learnerProfileId: proof.learnerProfileId,
      identityType: proof.identityType,
      identityValue: proof.identityValue,
      isPrimary: true,
      isVerified: true,
    });
  }

  await markLearnerIdentityLinkProofUsed(c.env.DB, proof.id, nowIso);

  return c.json({
    status: existingProfile === null ? 'linked' : 'already_linked',
    tenantId: pathParams.tenantId,
    learnerProfileId: proof.learnerProfileId,
    identityType: proof.identityType,
    identityValue: proof.identityValue,
  });
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
  const user = await upsertUserByEmail(c.env.DB, request.email);
  await ensureTenantMembership(c.env.DB, request.tenantId, user.id);

  const magicLinkToken = generateOpaqueToken();
  const magicTokenHash = await sha256Hex(magicLinkToken);

  await createMagicLinkToken(c.env.DB, {
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
  const token = await findMagicLinkTokenByHash(c.env.DB, magicTokenHash);

  if (token === null || !isMagicLinkTokenValid(token, nowIso)) {
    return c.json(
      {
        error: 'Invalid or expired magic link token',
      },
      400,
    );
  }

  await markMagicLinkTokenUsed(c.env.DB, token.id, nowIso);

  const sessionToken = generateOpaqueToken();
  const sessionTokenHash = await sha256Hex(sessionToken);
  const session = await createSession(c.env.DB, {
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
    await revokeSessionByHash(c.env.DB, sessionTokenHash, new Date().toISOString());
  }

  deleteCookie(c, SESSION_COOKIE_NAME, {
    path: '/',
  });

  return c.json({
    status: 'signed_out',
  });
});

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

  const templates = await listBadgeTemplates(c.env.DB, {
    tenantId: pathParams.tenantId,
    includeArchived: query.includeArchived,
  });

  return c.json({
    tenantId: pathParams.tenantId,
    templates,
  });
});

app.post('/v1/tenants/:tenantId/badge-templates', async (c) => {
  const pathParams = parseTenantPathParams(c.req.param());
  const payload = await c.req.json<unknown>();
  const request = parseCreateBadgeTemplateRequest(payload);
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

  try {
    const template = await createBadgeTemplate(c.env.DB, {
      tenantId: pathParams.tenantId,
      slug: request.slug,
      title: request.title,
      description: request.description,
      criteriaUri: request.criteriaUri,
      imageUri: request.imageUri,
      createdByUserId: session.userId,
    });

    return c.json(
      {
        tenantId: pathParams.tenantId,
        template,
      },
      201,
    );
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

  const template = await findBadgeTemplateById(c.env.DB, pathParams.tenantId, pathParams.badgeTemplateId);

  if (template === null) {
    return c.json(
      {
        error: 'Badge template not found',
      },
      404,
    );
  }

  return c.json({
    tenantId: pathParams.tenantId,
    template,
  });
});

app.patch('/v1/tenants/:tenantId/badge-templates/:badgeTemplateId', async (c) => {
  const pathParams = parseBadgeTemplatePathParams(c.req.param());
  const payload = await c.req.json<unknown>();
  const request = parseUpdateBadgeTemplateRequest(payload);
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

  try {
    const template = await updateBadgeTemplate(c.env.DB, {
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

  const template = await setBadgeTemplateArchivedState(c.env.DB, {
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

  return c.json({
    tenantId: pathParams.tenantId,
    template,
  });
});

app.post('/v1/tenants/:tenantId/badge-templates/:badgeTemplateId/unarchive', async (c) => {
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

  const template = await setBadgeTemplateArchivedState(c.env.DB, {
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

  return c.json({
    tenantId: pathParams.tenantId,
    template,
  });
});

type DirectIssueBadgeRequest = Pick<
  ManualIssueBadgeRequest,
  'badgeTemplateId' | 'recipientIdentity' | 'recipientIdentityType' | 'idempotencyKey'
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

const issueBadgeForTenant = async (
  c: AppContext,
  tenantId: string,
  request: DirectIssueBadgeRequest,
  issuedByUserId?: string,
  options?: DirectIssueBadgeOptions,
): Promise<DirectIssueBadgeResult> => {
  const badgeTemplate = await findBadgeTemplateById(c.env.DB, tenantId, request.badgeTemplateId);

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
  const existingAssertion = await findAssertionByIdempotencyKey(c.env.DB, tenantId, idempotencyKey);

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
  const registry = parseSigningRegistryFromEnv(c.env.TENANT_SIGNING_REGISTRY_JSON);
  const signingEntry = registry[issuerDid];

  if (signingEntry === undefined) {
    throw new HttpErrorResponse(404, {
      error: 'No signing configuration for tenant DID',
      did: issuerDid,
    });
  }

  if (signingEntry.privateJwk === undefined) {
    throw new HttpErrorResponse(500, {
      error: 'Tenant DID is missing private signing key material',
      did: issuerDid,
    });
  }

  const requestBaseUrl = new URL(c.req.url);
  const learnerProfile = await resolveLearnerProfileForIdentity(c.env.DB, {
    tenantId,
    identityType: request.recipientIdentityType,
    identityValue: request.recipientIdentity,
    ...(options?.recipientDisplayName === undefined
      ? {}
      : { displayName: options.recipientDisplayName }),
  });
  const issuedAt = new Date().toISOString();
  const assertionId = createTenantScopedId(tenantId);
  const statusListIndex = await nextAssertionStatusListIndex(c.env.DB, tenantId);
  const statusListCredentialUrl = revocationStatusListUrlForTenant(requestBaseUrl.toString(), tenantId);
  const issuer =
    options?.issuerName === undefined
      ? issuerDid
      : {
          id: issuerDid,
          name: options.issuerName,
          ...(options.issuerUrl === undefined ? {} : { url: options.issuerUrl }),
        };
  const signedCredential = await signCredentialWithEd25519Signature2020({
    credential: {
      '@context': ['https://www.w3.org/ns/credentials/v2'],
      id: `urn:credtrail:assertion:${encodeURIComponent(assertionId)}`,
      type: ['VerifiableCredential', 'OpenBadgeCredential'],
      issuer,
      validFrom: issuedAt,
      credentialStatus: credentialStatusForAssertion(statusListCredentialUrl, statusListIndex),
      credentialSubject: {
        id: learnerProfile.subjectId,
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
    privateJwk: toEd25519PrivateJwk(signingEntry.privateJwk),
    verificationMethod: `${issuerDid}#${signingEntry.keyId}`,
  });

  const stored = await storeImmutableCredentialObject(c.env.BADGE_OBJECTS, {
    tenantId,
    assertionId,
    credential: signedCredential,
  });

  const createdAssertion = await createAssertion(c.env.DB, {
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
    ...(issuedByUserId === undefined ? {} : { issuedByUserId }),
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

app.post('/v1/tenants/:tenantId/assertions/sakai-commit-issue', async (c): Promise<Response> => {
  const pathParams = parseTenantPathParams(c.req.param());
  const payload = await c.req.json<unknown>();
  const request = parseIssueSakaiCommitBadgeRequest(payload);
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

  let commitCount: number;

  try {
    commitCount = await fetchSakaiCommitCountForUsername(request.githubUsername, c.env.GITHUB_TOKEN);
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
  const registry = parseSigningRegistryFromEnv(c.env.TENANT_SIGNING_REGISTRY_JSON);
  const signingEntry = registry[request.did];

  if (signingEntry === undefined) {
    return c.json(
      {
        error: 'No signing configuration for requested DID',
        did: request.did,
      },
      404,
    );
  }

  if (signingEntry.privateJwk === undefined) {
    return c.json(
      {
        error: 'DID is missing private signing key material',
        did: request.did,
      },
      500,
    );
  }

  const signedCredential = await signCredentialWithEd25519Signature2020({
    credential: request.credential,
    privateJwk: toEd25519PrivateJwk(signingEntry.privateJwk),
    verificationMethod: `${request.did}#${signingEntry.keyId}`,
  });

  return c.json(
    {
      did: request.did,
      credential: signedCredential,
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

  await enqueueJobQueueMessage(c.env.DB, {
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

  await enqueueJobQueueMessage(c.env.DB, {
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

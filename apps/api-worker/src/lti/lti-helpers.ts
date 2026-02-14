import type { LtiIssuerRegistrationRecord, TenantMembershipRole } from '@credtrail/db';
import { LTI_CLAIM_LIS, type LtiLaunchClaims, type LtiRoleKind } from '@credtrail/lti';
import type { AppBindings, AppContext } from '../app';
import { asJsonObject, asNonEmptyString } from '../utils/value-parsers';

export interface LtiIssuerRegistryEntry {
  authorizationEndpoint: string;
  clientId: string;
  tenantId: string;
  allowUnsignedIdToken: boolean;
}

export type LtiIssuerRegistry = Record<string, LtiIssuerRegistryEntry>;

export interface LtiStatePayload {
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

export type LtiStateValidationResult =
  | {
      status: 'ok';
      payload: LtiStatePayload;
    }
  | {
      status: 'invalid';
      reason: string;
    };

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

const bytesToBase64Url = (bytes: Uint8Array): string => {
  let raw = '';

  for (const byte of bytes) {
    raw += String.fromCharCode(byte);
  }

  return btoa(raw).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
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

const isLikelyEmailAddress = (value: string): boolean => {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);
};

export const normalizeLtiIssuer = (issuer: string): string => {
  return issuer.trim().replace(/\/+$/g, '');
};

export const isAbsoluteHttpUrl = (value: string): boolean => {
  try {
    const parsed = new URL(value);
    return parsed.protocol === 'http:' || parsed.protocol === 'https:';
  } catch {
    return false;
  }
};

export const normalizeAbsoluteUrlForComparison = (value: string): string | null => {
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

export const parseLtiIssuerRegistryFromEnv = (rawRegistry: string | undefined): LtiIssuerRegistry => {
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

export const ltiIssuerRegistryFromStoredRows = (
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

export const ltiStateSigningSecret = (env: AppBindings): string => {
  const configuredSecret = env.LTI_STATE_SIGNING_SECRET?.trim();
  return configuredSecret === undefined || configuredSecret.length === 0
    ? `${env.PLATFORM_DOMAIN}:lti-state-secret`
    : configuredSecret;
};

export const signLtiStatePayload = async (
  payload: LtiStatePayload,
  secret: string,
  sha256Base64Url: (value: string) => Promise<string>,
): Promise<string> => {
  const encodedPayload = textToBase64Url(JSON.stringify(payload));
  const signature = await sha256Base64Url(`${encodedPayload}.${secret}`);
  return `${encodedPayload}.${signature}`;
};

export const validateLtiStateToken = async (
  stateToken: string,
  secret: string,
  nowIso: string,
  sha256Base64Url: (value: string) => Promise<string>,
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

export const ltiAudienceIncludesClientId = (
  audienceClaim: LtiLaunchClaims['aud'],
  clientId: string,
): boolean => {
  if (typeof audienceClaim === 'string') {
    return audienceClaim === clientId;
  }

  return audienceClaim.includes(clientId);
};

export const ltiMembershipRoleFromRoleKind = (roleKind: LtiRoleKind): TenantMembershipRole => {
  return roleKind === 'instructor' ? 'issuer' : 'viewer';
};

export const ltiFederatedSubjectIdentity = (issuer: string, subjectId: string): string => {
  return `${normalizeLtiIssuer(issuer)}::${subjectId}`;
};

export const ltiDisplayNameFromClaims = (claims: LtiLaunchClaims): string | undefined => {
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

export const ltiEmailFromClaims = (claims: LtiLaunchClaims): string | null => {
  const emailClaim = asNonEmptyString(claims.email);

  if (emailClaim === null || !isLikelyEmailAddress(emailClaim)) {
    return null;
  }

  return emailClaim;
};

export const ltiSourcedIdFromClaims = (claims: LtiLaunchClaims): string | null => {
  const lisClaim = asJsonObject(claims[LTI_CLAIM_LIS]);
  return asNonEmptyString(lisClaim?.person_sourcedid);
};

export const ltiSyntheticEmail = async (
  tenantId: string,
  federatedSubject: string,
  sha256Hex: (value: string) => Promise<string>,
): Promise<string> => {
  const digest = await sha256Hex(`${tenantId}:${federatedSubject}`);
  return `lti-${digest.slice(0, 24)}@credtrail-lti.local`;
};

export const ltiLearnerDashboardPath = (tenantId: string): string => {
  return `/tenants/${encodeURIComponent(tenantId)}/learner/dashboard`;
};

export const ltiLoginInputFromRequest = async (c: AppContext): Promise<Record<string, string>> => {
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

export const ltiLaunchFormInputFromRequest = async (
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

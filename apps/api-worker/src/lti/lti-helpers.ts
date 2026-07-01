import { normalizeLtiIssuer, type LtiIssuerRegistrationRecord } from "@credtrail/db";
import { LTI_CLAIM_LIS, type LTI13JwtPayload as LtiLaunchClaims } from "@longsightgroup/lti-tool";
import type { AppBindings, AppContext } from "../app";
import { asJsonObject, asNonEmptyString } from "../utils/value-parsers";

export interface LtiIssuerRegistryEntry {
  authorizationEndpoint: string;
  clientId: string;
  tenantId: string;
  platformJwksEndpoint?: string;
  tokenEndpoint?: string;
}

export type LtiIssuerRegistry = Record<string, LtiIssuerRegistryEntry>;

const isLikelyEmailAddress = (value: string): boolean => {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);
};

export { normalizeLtiIssuer };

export const isAbsoluteHttpUrl = (value: string): boolean => {
  try {
    const parsed = new URL(value);
    return parsed.protocol === "http:" || parsed.protocol === "https:";
  } catch {
    return false;
  }
};

export const normalizeAbsoluteUrlForComparison = (value: string): string | null => {
  try {
    const parsed = new URL(value);

    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
      return null;
    }

    parsed.hash = "";
    return parsed.toString();
  } catch {
    return null;
  }
};

export const parseLtiIssuerRegistryFromEnv = (
  rawRegistry: string | undefined,
): LtiIssuerRegistry => {
  if (rawRegistry === undefined || rawRegistry.trim().length === 0) {
    return {};
  }

  let parsedRegistry: unknown;

  try {
    parsedRegistry = JSON.parse(rawRegistry);
  } catch {
    throw new Error("LTI_ISSUER_REGISTRY_JSON is not valid JSON");
  }

  const registryObject = asJsonObject(parsedRegistry);

  if (registryObject === null) {
    throw new Error("LTI_ISSUER_REGISTRY_JSON must be a JSON object keyed by issuer URL");
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
    const platformJwksEndpointRaw = entryObject.platformJwksEndpoint;
    const tokenEndpointRaw = entryObject.tokenEndpoint;
    let platformJwksEndpoint: string | undefined;
    let tokenEndpoint: string | undefined;

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

    if (platformJwksEndpointRaw !== undefined) {
      const parsedPlatformJwksEndpoint = asNonEmptyString(platformJwksEndpointRaw);

      if (parsedPlatformJwksEndpoint === null || !isAbsoluteHttpUrl(parsedPlatformJwksEndpoint)) {
        throw new Error(
          `LTI_ISSUER_REGISTRY_JSON["${issuer}"].platformJwksEndpoint must be an absolute http(s) URL when provided`,
        );
      }

      platformJwksEndpoint = parsedPlatformJwksEndpoint;
    }

    if (tokenEndpointRaw !== undefined) {
      const parsedTokenEndpoint = asNonEmptyString(tokenEndpointRaw);

      if (parsedTokenEndpoint === null || !isAbsoluteHttpUrl(parsedTokenEndpoint)) {
        throw new Error(
          `LTI_ISSUER_REGISTRY_JSON["${issuer}"].tokenEndpoint must be an absolute http(s) URL when provided`,
        );
      }

      tokenEndpoint = parsedTokenEndpoint;
    }

    registry[normalizeLtiIssuer(issuer)] = {
      authorizationEndpoint,
      clientId,
      tenantId,
      ...(platformJwksEndpoint === undefined ? {} : { platformJwksEndpoint }),
      ...(tokenEndpoint === undefined ? {} : { tokenEndpoint }),
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

    if (row.tokenEndpoint !== null && !isAbsoluteHttpUrl(row.tokenEndpoint)) {
      throw new Error(`Stored LTI issuer "${row.issuer}" has invalid token endpoint URL`);
    }

    if (row.platformJwksEndpoint !== null && !isAbsoluteHttpUrl(row.platformJwksEndpoint)) {
      throw new Error(`Stored LTI issuer "${row.issuer}" has invalid platform JWKS URL`);
    }

    registry[issuer] = {
      authorizationEndpoint: row.authorizationEndpoint,
      clientId,
      tenantId,
      ...(row.platformJwksEndpoint === null
        ? {}
        : { platformJwksEndpoint: row.platformJwksEndpoint }),
      ...(row.tokenEndpoint === null ? {} : { tokenEndpoint: row.tokenEndpoint }),
    };
  }

  return registry;
};

export const ltiStateSigningSecret = (
  env: Pick<AppBindings, "LTI_STATE_SIGNING_SECRET">,
): string => {
  const configuredSecret = env.LTI_STATE_SIGNING_SECRET?.trim();

  if (configuredSecret === undefined || configuredSecret.length === 0) {
    throw new Error("LTI_STATE_SIGNING_SECRET is required");
  }

  return configuredSecret;
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
  if (c.req.method === "GET") {
    return {
      iss: c.req.query("iss") ?? "",
      login_hint: c.req.query("login_hint") ?? "",
      target_link_uri: c.req.query("target_link_uri") ?? "",
      ...(c.req.query("client_id") === undefined
        ? {}
        : { client_id: c.req.query("client_id") ?? "" }),
      ...(c.req.query("lti_message_hint") === undefined
        ? {}
        : {
            lti_message_hint: c.req.query("lti_message_hint") ?? "",
          }),
      ...(c.req.query("lti_deployment_id") === undefined
        ? {}
        : {
            lti_deployment_id: c.req.query("lti_deployment_id") ?? "",
          }),
      ...(c.req.query("lti_storage_target") === undefined
        ? {}
        : {
            lti_storage_target: c.req.query("lti_storage_target") ?? "",
          }),
    };
  }

  const contentType = c.req.header("content-type") ?? "";

  if (!contentType.toLowerCase().includes("application/x-www-form-urlencoded")) {
    return {};
  }

  const rawBody = await c.req.text();
  const formData = new URLSearchParams(rawBody);

  return {
    iss: formData.get("iss") ?? "",
    login_hint: formData.get("login_hint") ?? "",
    target_link_uri: formData.get("target_link_uri") ?? "",
    ...(formData.get("client_id") === null ? {} : { client_id: formData.get("client_id") ?? "" }),
    ...(formData.get("lti_message_hint") === null
      ? {}
      : {
          lti_message_hint: formData.get("lti_message_hint") ?? "",
        }),
    ...(formData.get("lti_deployment_id") === null
      ? {}
      : {
          lti_deployment_id: formData.get("lti_deployment_id") ?? "",
        }),
    ...(formData.get("lti_storage_target") === null
      ? {}
      : {
          lti_storage_target: formData.get("lti_storage_target") ?? "",
        }),
  };
};

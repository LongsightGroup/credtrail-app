import { normalizeLtiIssuer, type LtiIssuerRegistrationRecord } from "@credtrail/db";
import { asJsonObject, asNonEmptyString } from "../utils/value-parsers";
import type { LtiIssuerRegistry } from "./lti-issuer-registry";

const isAbsoluteHttpUrl = (value: string): boolean => {
  try {
    const parsed = new URL(value);
    return parsed.protocol === "http:" || parsed.protocol === "https:";
  } catch {
    return false;
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

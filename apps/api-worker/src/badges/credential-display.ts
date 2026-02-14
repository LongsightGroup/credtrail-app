import type { JsonObject } from '@credtrail/core-domain';
import { linkedDataReferenceId } from './public-badge-helpers';
import { asJsonObject, asNonEmptyString, asString } from '../utils/value-parsers';

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

export const badgeNameFromCredential = (credential: JsonObject): string => {
  const credentialSubject = asJsonObject(credential.credentialSubject);
  const achievement = asJsonObject(credentialSubject?.achievement);
  return asString(achievement?.name) ?? 'Badge credential';
};

export const isWebUrl = (value: string): boolean => {
  try {
    const parsedUrl = new URL(value);
    return parsedUrl.protocol === 'http:' || parsedUrl.protocol === 'https:';
  } catch {
    return false;
  }
};

export const issuerNameFromCredential = (credential: JsonObject): string => {
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

export const issuerUrlFromCredential = (credential: JsonObject): string | null => {
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

export const issuerIdentifierFromCredential = (credential: JsonObject): string | null => {
  const issuerAsString = asNonEmptyString(credential.issuer);

  if (issuerAsString !== null) {
    return issuerAsString;
  }

  const issuerObject = issuerObjectFromCredential(credential);
  return asNonEmptyString(issuerObject?.id);
};

export const recipientFromCredential = (credential: JsonObject): string => {
  const credentialSubject = asJsonObject(credential.credentialSubject);
  return asString(credentialSubject?.id) ?? 'Unknown recipient';
};

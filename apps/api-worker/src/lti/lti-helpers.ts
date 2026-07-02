import { normalizeLtiIssuer } from "@credtrail/db";
import { LTI_CLAIM_LIS, type LTI13JwtPayload as LtiLaunchClaims } from "@longsightgroup/lti-tool";
import type { AppBindings } from "../app";
import { asJsonObject, asNonEmptyString } from "../utils/value-parsers";

const isLikelyEmailAddress = (value: string): boolean => {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);
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

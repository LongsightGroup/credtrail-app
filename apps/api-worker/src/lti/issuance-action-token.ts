import type { AppBindings } from "../app";
import {
  createSignedJsonToken,
  namespacedSigningSecret,
  signedJsonTokenExpiry,
  verifySignedJsonToken,
} from "../signed-json-token";
import { ltiStateSigningSecret } from "./lti-helpers";

type LtiIssuanceActionBindings = Pick<AppBindings, "LTI_STATE_SIGNING_SECRET">;

export interface LtiIssuanceActionPayload {
  tenantId: string;
  ltiSessionId: string;
  issuer: string;
  clientId: string;
  deploymentId: string;
  contextId: string;
  resourceLinkId: string;
  badgeTemplateId: string;
  issuedByUserId: string;
  exp: number;
}

const issuanceActionSigningSecret = (env: LtiIssuanceActionBindings): string => {
  return namespacedSigningSecret(ltiStateSigningSecret(env), "issuance-action");
};

const isNonEmptyString = (value: unknown): value is string => {
  return typeof value === "string" && value.length > 0;
};

const parseLtiIssuanceActionPayload = (value: unknown): LtiIssuanceActionPayload | null => {
  if (value === null || typeof value !== "object") {
    return null;
  }

  const candidate = value as Partial<LtiIssuanceActionPayload>;

  if (
    !isNonEmptyString(candidate.tenantId) ||
    !isNonEmptyString(candidate.ltiSessionId) ||
    !isNonEmptyString(candidate.issuer) ||
    !isNonEmptyString(candidate.clientId) ||
    !isNonEmptyString(candidate.deploymentId) ||
    !isNonEmptyString(candidate.contextId) ||
    !isNonEmptyString(candidate.resourceLinkId) ||
    !isNonEmptyString(candidate.badgeTemplateId) ||
    !isNonEmptyString(candidate.issuedByUserId) ||
    typeof candidate.exp !== "number" ||
    !Number.isInteger(candidate.exp)
  ) {
    return null;
  }

  return {
    tenantId: candidate.tenantId,
    ltiSessionId: candidate.ltiSessionId,
    issuer: candidate.issuer,
    clientId: candidate.clientId,
    deploymentId: candidate.deploymentId,
    contextId: candidate.contextId,
    resourceLinkId: candidate.resourceLinkId,
    badgeTemplateId: candidate.badgeTemplateId,
    issuedByUserId: candidate.issuedByUserId,
    exp: candidate.exp,
  };
};

export const createLtiIssuanceActionToken = async (
  env: LtiIssuanceActionBindings,
  input: Omit<LtiIssuanceActionPayload, "exp"> & {
    ttlSeconds: number;
  },
): Promise<string> => {
  return createSignedJsonToken(issuanceActionSigningSecret(env), {
    tenantId: input.tenantId,
    ltiSessionId: input.ltiSessionId,
    issuer: input.issuer,
    clientId: input.clientId,
    deploymentId: input.deploymentId,
    contextId: input.contextId,
    resourceLinkId: input.resourceLinkId,
    badgeTemplateId: input.badgeTemplateId,
    issuedByUserId: input.issuedByUserId,
    exp: signedJsonTokenExpiry(input.ttlSeconds),
  });
};

export const verifyLtiIssuanceActionToken = async (
  env: LtiIssuanceActionBindings,
  token: string,
): Promise<LtiIssuanceActionPayload | null> => {
  return verifySignedJsonToken(
    issuanceActionSigningSecret(env),
    token,
    parseLtiIssuanceActionPayload,
  );
};

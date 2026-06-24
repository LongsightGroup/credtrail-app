import type { AppBindings } from "../app";
import {
  createSignedJsonToken,
  namespacedSigningSecret,
  signedJsonTokenExpiry,
  verifySignedJsonToken,
} from "../signed-json-token";
import {
  parseLtiCourseBadgeSetupPreset,
  type LtiCourseBadgeSetupRequest,
} from "./course-badge-setup";
import { ltiStateSigningSecret } from "./lti-helpers";

type LtiCourseBadgeSetupTokenBindings = Pick<AppBindings, "LTI_STATE_SIGNING_SECRET">;

export interface LtiCourseBadgeSetupPayload {
  tenantId: string;
  issuer: string;
  clientId: string;
  deploymentId: string;
  contextId: string;
  badgeTemplateId: string;
  setupRequest: LtiCourseBadgeSetupRequest;
  exp: number;
}

const courseBadgeSetupSigningSecret = (env: LtiCourseBadgeSetupTokenBindings): string => {
  return namespacedSigningSecret(ltiStateSigningSecret(env), "course-badge-setup");
};

const isNonEmptyString = (value: unknown): value is string => {
  return typeof value === "string" && value.trim().length > 0;
};

const optionalNumber = (value: unknown): number | undefined => {
  return typeof value === "number" && Number.isFinite(value) ? value : undefined;
};

const optionalString = (value: unknown): string | undefined => {
  return typeof value === "string" && value.trim().length > 0 ? value : undefined;
};

const parseSetupRequest = (value: unknown): LtiCourseBadgeSetupRequest | null => {
  if (value === null || typeof value !== "object") {
    return null;
  }

  const candidate = value as Partial<LtiCourseBadgeSetupRequest>;
  const preset = parseLtiCourseBadgeSetupPreset(candidate.preset);

  if (preset === null) {
    return null;
  }

  return {
    preset,
    scoreThreshold: optionalNumber(candidate.scoreThreshold),
    gradebookItemId: optionalString(candidate.gradebookItemId),
    completionPercent: optionalNumber(candidate.completionPercent),
  };
};

const parseLtiCourseBadgeSetupPayload = (value: unknown): LtiCourseBadgeSetupPayload | null => {
  if (value === null || typeof value !== "object") {
    return null;
  }

  const candidate = value as Partial<LtiCourseBadgeSetupPayload>;
  const setupRequest = parseSetupRequest(candidate.setupRequest);

  if (
    !isNonEmptyString(candidate.tenantId) ||
    !isNonEmptyString(candidate.issuer) ||
    !isNonEmptyString(candidate.clientId) ||
    !isNonEmptyString(candidate.deploymentId) ||
    !isNonEmptyString(candidate.contextId) ||
    !isNonEmptyString(candidate.badgeTemplateId) ||
    setupRequest === null ||
    typeof candidate.exp !== "number" ||
    !Number.isInteger(candidate.exp)
  ) {
    return null;
  }

  return {
    tenantId: candidate.tenantId,
    issuer: candidate.issuer,
    clientId: candidate.clientId,
    deploymentId: candidate.deploymentId,
    contextId: candidate.contextId,
    badgeTemplateId: candidate.badgeTemplateId,
    setupRequest,
    exp: candidate.exp,
  };
};

export const createLtiCourseBadgeSetupToken = async (
  env: LtiCourseBadgeSetupTokenBindings,
  input: Omit<LtiCourseBadgeSetupPayload, "exp"> & {
    ttlSeconds: number;
  },
): Promise<string> => {
  return createSignedJsonToken(courseBadgeSetupSigningSecret(env), {
    tenantId: input.tenantId,
    issuer: input.issuer,
    clientId: input.clientId,
    deploymentId: input.deploymentId,
    contextId: input.contextId,
    badgeTemplateId: input.badgeTemplateId,
    setupRequest: input.setupRequest,
    exp: signedJsonTokenExpiry(input.ttlSeconds),
  });
};

export const verifyLtiCourseBadgeSetupToken = async (
  env: LtiCourseBadgeSetupTokenBindings,
  token: string,
): Promise<LtiCourseBadgeSetupPayload | null> => {
  return verifySignedJsonToken(
    courseBadgeSetupSigningSecret(env),
    token,
    parseLtiCourseBadgeSetupPayload,
  );
};

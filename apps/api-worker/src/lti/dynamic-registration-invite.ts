import type { AppBindings } from "../app";
import {
  createSignedJsonToken,
  namespacedSigningSecret,
  signedJsonTokenExpiry,
  verifySignedJsonToken,
} from "../signed-json-token";
import { ltiStateSigningSecret } from "./lti-helpers";

type LtiDynamicRegistrationInviteBindings = Pick<AppBindings, "LTI_STATE_SIGNING_SECRET">;

export const LTI_DYNAMIC_REGISTRATION_INVITE_TTL_SECONDS = 7 * 24 * 60 * 60;

export interface LtiDynamicRegistrationInvitePayload {
  tenantId: string;
  exp: number;
}

const dynamicRegistrationInviteSigningSecret = (
  env: LtiDynamicRegistrationInviteBindings,
): string => {
  return namespacedSigningSecret(ltiStateSigningSecret(env), "dynamic-registration-invite");
};

const parseLtiDynamicRegistrationInvitePayload = (
  value: unknown,
): LtiDynamicRegistrationInvitePayload | null => {
  if (value === null || typeof value !== "object") {
    return null;
  }

  const candidate = value as Partial<LtiDynamicRegistrationInvitePayload>;

  if (
    typeof candidate.tenantId !== "string" ||
    candidate.tenantId.length === 0 ||
    typeof candidate.exp !== "number" ||
    !Number.isInteger(candidate.exp)
  ) {
    return null;
  }

  return {
    tenantId: candidate.tenantId,
    exp: candidate.exp,
  };
};

export const createLtiDynamicRegistrationInviteToken = async (
  env: LtiDynamicRegistrationInviteBindings,
  input: {
    tenantId: string;
    ttlSeconds?: number | undefined;
  },
): Promise<string> => {
  return createSignedJsonToken(dynamicRegistrationInviteSigningSecret(env), {
    tenantId: input.tenantId,
    exp: signedJsonTokenExpiry(input.ttlSeconds ?? LTI_DYNAMIC_REGISTRATION_INVITE_TTL_SECONDS),
  });
};

export const verifyLtiDynamicRegistrationInviteToken = async (
  env: LtiDynamicRegistrationInviteBindings,
  token: string,
): Promise<LtiDynamicRegistrationInvitePayload | null> => {
  return verifySignedJsonToken(
    dynamicRegistrationInviteSigningSecret(env),
    token,
    parseLtiDynamicRegistrationInvitePayload,
  );
};

export const ltiDynamicRegistrationPath = (tenantId: string, inviteToken: string): string => {
  return `/v1/tenants/${encodeURIComponent(
    tenantId,
  )}/lti/dynamic-registration/${encodeURIComponent(inviteToken)}`;
};

export const ltiDynamicRegistrationUrl = (input: {
  platformDomain: string;
  tenantId: string;
  inviteToken: string;
}): string => {
  return new URL(
    ltiDynamicRegistrationPath(input.tenantId, input.inviteToken),
    `https://${input.platformDomain.trim()}`,
  ).toString();
};

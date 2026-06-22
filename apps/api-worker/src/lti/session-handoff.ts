import type { AppBindings } from "../app";
import {
  createSignedJsonToken,
  signedJsonTokenExpiry,
  verifySignedJsonToken,
} from "../signed-json-token";
import { ltiStateSigningSecret } from "./lti-helpers";

type LtiSessionHandoffBindings = Pick<AppBindings, "LTI_STATE_SIGNING_SECRET">;

export interface LtiSessionHandoffPayload {
  tenantId: string;
  sessionToken: string;
  exp: number;
}

const sessionHandoffSigningSecret = (env: LtiSessionHandoffBindings): string => {
  return ltiStateSigningSecret(env);
};

const parseLtiSessionHandoffPayload = (value: unknown): LtiSessionHandoffPayload | null => {
  if (value === null || typeof value !== "object") {
    return null;
  }

  const candidate = value as Partial<LtiSessionHandoffPayload>;

  if (
    typeof candidate.tenantId !== "string" ||
    candidate.tenantId.length === 0 ||
    typeof candidate.sessionToken !== "string" ||
    candidate.sessionToken.length === 0 ||
    typeof candidate.exp !== "number" ||
    !Number.isInteger(candidate.exp)
  ) {
    return null;
  }

  return {
    tenantId: candidate.tenantId,
    sessionToken: candidate.sessionToken,
    exp: candidate.exp,
  };
};

export const createLtiSessionHandoffToken = async (
  env: LtiSessionHandoffBindings,
  input: {
    tenantId: string;
    sessionToken: string;
    ttlSeconds: number;
  },
): Promise<string> => {
  return createSignedJsonToken(sessionHandoffSigningSecret(env), {
    tenantId: input.tenantId,
    sessionToken: input.sessionToken,
    exp: signedJsonTokenExpiry(input.ttlSeconds),
  });
};

export const verifyLtiSessionHandoffToken = async (
  env: LtiSessionHandoffBindings,
  token: string,
): Promise<LtiSessionHandoffPayload | null> => {
  return verifySignedJsonToken(
    sessionHandoffSigningSecret(env),
    token,
    parseLtiSessionHandoffPayload,
  );
};

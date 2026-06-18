import type { AppBindings } from "../app";
import { ltiStateSigningSecret } from "./lti-helpers";

type LtiDynamicRegistrationInviteBindings = Pick<AppBindings, "LTI_STATE_SIGNING_SECRET">;

export const LTI_DYNAMIC_REGISTRATION_INVITE_TTL_SECONDS = 7 * 24 * 60 * 60;

export interface LtiDynamicRegistrationInvitePayload {
  tenantId: string;
  exp: number;
}

const textEncoder = new TextEncoder();

const base64UrlEncode = (bytes: Uint8Array): string => {
  let binary = "";

  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }

  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
};

const base64UrlDecode = (value: string): Uint8Array | null => {
  try {
    const padded = value
      .replaceAll("-", "+")
      .replaceAll("_", "/")
      .padEnd(Math.ceil(value.length / 4) * 4, "=");
    const binary = atob(padded);
    const bytes = new Uint8Array(binary.length);

    for (let index = 0; index < binary.length; index += 1) {
      bytes[index] = binary.charCodeAt(index);
    }

    return bytes;
  } catch {
    return null;
  }
};

const ltiDynamicRegistrationInviteSecret = (env: LtiDynamicRegistrationInviteBindings): string => {
  return `${ltiStateSigningSecret(env)}:dynamic-registration-invite`;
};

const sign = async (
  env: LtiDynamicRegistrationInviteBindings,
  payload: string,
): Promise<string> => {
  const key = await crypto.subtle.importKey(
    "raw",
    textEncoder.encode(ltiDynamicRegistrationInviteSecret(env)),
    {
      name: "HMAC",
      hash: "SHA-256",
    },
    false,
    ["sign"],
  );
  const signature = await crypto.subtle.sign("HMAC", key, textEncoder.encode(payload));
  return base64UrlEncode(new Uint8Array(signature));
};

const signaturesMatch = (left: string, right: string): boolean => {
  if (left.length !== right.length) {
    return false;
  }

  let mismatch = 0;

  for (let index = 0; index < left.length; index += 1) {
    mismatch |= left.charCodeAt(index) ^ right.charCodeAt(index);
  }

  return mismatch === 0;
};

export const createLtiDynamicRegistrationInviteToken = async (
  env: LtiDynamicRegistrationInviteBindings,
  input: {
    tenantId: string;
    ttlSeconds?: number | undefined;
  },
): Promise<string> => {
  const payload = base64UrlEncode(
    textEncoder.encode(
      JSON.stringify({
        tenantId: input.tenantId,
        exp:
          Math.floor(Date.now() / 1000) +
          (input.ttlSeconds ?? LTI_DYNAMIC_REGISTRATION_INVITE_TTL_SECONDS),
      } satisfies LtiDynamicRegistrationInvitePayload),
    ),
  );
  const signature = await sign(env, payload);
  return `${payload}.${signature}`;
};

export const verifyLtiDynamicRegistrationInviteToken = async (
  env: LtiDynamicRegistrationInviteBindings,
  token: string,
): Promise<LtiDynamicRegistrationInvitePayload | null> => {
  const [payload, signature, extra] = token.split(".");

  if (
    payload === undefined ||
    payload.length === 0 ||
    signature === undefined ||
    signature.length === 0 ||
    extra !== undefined
  ) {
    return null;
  }

  const expectedSignature = await sign(env, payload);

  if (!signaturesMatch(signature, expectedSignature)) {
    return null;
  }

  const decoded = base64UrlDecode(payload);

  if (decoded === null) {
    return null;
  }

  let parsed: unknown;

  try {
    parsed = JSON.parse(new TextDecoder().decode(decoded));
  } catch {
    return null;
  }

  if (parsed === null || typeof parsed !== "object") {
    return null;
  }

  const candidate = parsed as Partial<LtiDynamicRegistrationInvitePayload>;

  if (
    typeof candidate.tenantId !== "string" ||
    candidate.tenantId.length === 0 ||
    typeof candidate.exp !== "number" ||
    !Number.isInteger(candidate.exp)
  ) {
    return null;
  }

  if (candidate.exp < Math.floor(Date.now() / 1000)) {
    return null;
  }

  return {
    tenantId: candidate.tenantId,
    exp: candidate.exp,
  };
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

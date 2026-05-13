import type { AppBindings } from "../app";
import { ltiStateSigningSecret } from "./lti-helpers";

type LtiSessionHandoffBindings = Pick<AppBindings, "LTI_STATE_SIGNING_SECRET">;

export interface LtiSessionHandoffPayload {
  tenantId: string;
  sessionToken: string;
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

const sign = async (env: LtiSessionHandoffBindings, payload: string): Promise<string> => {
  const key = await crypto.subtle.importKey(
    "raw",
    textEncoder.encode(ltiStateSigningSecret(env)),
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

export const createLtiSessionHandoffToken = async (
  env: LtiSessionHandoffBindings,
  input: {
    tenantId: string;
    sessionToken: string;
    ttlSeconds: number;
  },
): Promise<string> => {
  const payload = base64UrlEncode(
    textEncoder.encode(
      JSON.stringify({
        tenantId: input.tenantId,
        sessionToken: input.sessionToken,
        exp: Math.floor(Date.now() / 1000) + input.ttlSeconds,
      } satisfies LtiSessionHandoffPayload),
    ),
  );
  const signature = await sign(env, payload);
  return `${payload}.${signature}`;
};

export const verifyLtiSessionHandoffToken = async (
  env: LtiSessionHandoffBindings,
  token: string,
): Promise<LtiSessionHandoffPayload | null> => {
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

  const candidate = parsed as Partial<LtiSessionHandoffPayload>;

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

  if (candidate.exp < Math.floor(Date.now() / 1000)) {
    return null;
  }

  return {
    tenantId: candidate.tenantId,
    sessionToken: candidate.sessionToken,
    exp: candidate.exp,
  };
};

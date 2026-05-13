import type { AppBindings } from "../app";
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

const textEncoder = new TextEncoder();

const ltiIssuanceActionSecret = (env: LtiIssuanceActionBindings): string => {
  return `${ltiStateSigningSecret(env)}:issuance-action`;
};

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

const sign = async (env: LtiIssuanceActionBindings, payload: string): Promise<string> => {
  const key = await crypto.subtle.importKey(
    "raw",
    textEncoder.encode(ltiIssuanceActionSecret(env)),
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

const isNonEmptyString = (value: unknown): value is string => {
  return typeof value === "string" && value.length > 0;
};

export const createLtiIssuanceActionToken = async (
  env: LtiIssuanceActionBindings,
  input: Omit<LtiIssuanceActionPayload, "exp"> & {
    ttlSeconds: number;
  },
): Promise<string> => {
  const payload = base64UrlEncode(
    textEncoder.encode(
      JSON.stringify({
        tenantId: input.tenantId,
        ltiSessionId: input.ltiSessionId,
        issuer: input.issuer,
        clientId: input.clientId,
        deploymentId: input.deploymentId,
        contextId: input.contextId,
        resourceLinkId: input.resourceLinkId,
        badgeTemplateId: input.badgeTemplateId,
        issuedByUserId: input.issuedByUserId,
        exp: Math.floor(Date.now() / 1000) + input.ttlSeconds,
      } satisfies LtiIssuanceActionPayload),
    ),
  );
  const signature = await sign(env, payload);
  return `${payload}.${signature}`;
};

export const verifyLtiIssuanceActionToken = async (
  env: LtiIssuanceActionBindings,
  token: string,
): Promise<LtiIssuanceActionPayload | null> => {
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

  const candidate = parsed as Partial<LtiIssuanceActionPayload>;

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

  if (candidate.exp < Math.floor(Date.now() / 1000)) {
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

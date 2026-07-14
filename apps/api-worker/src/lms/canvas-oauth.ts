import { asJsonObject, asNonEmptyString } from "../utils/value-parsers";
import type { AppBindings } from "../app";
import { withCredTrailUserAgent } from "../http/outbound-user-agent";

const bytesToBase64Url = (bytes: Uint8Array): string => {
  let raw = "";

  for (const byte of bytes) {
    raw += String.fromCharCode(byte);
  }

  return btoa(raw).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
};

const textToBase64Url = (value: string): string => {
  return bytesToBase64Url(new TextEncoder().encode(value));
};

const base64UrlToText = (value: string): string | null => {
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
  const padded = `${normalized}${"=".repeat((4 - (normalized.length % 4)) % 4)}`;

  try {
    return atob(padded);
  } catch {
    return null;
  }
};

const sha256Base64Url = async (value: string): Promise<string> => {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return bytesToBase64Url(new Uint8Array(digest));
};

export interface CanvasOAuthStatePayload {
  tenantId: string;
  nonce: string;
  issuedAt: string;
  expiresAt: string;
}

export type CanvasOAuthStateValidationResult =
  | {
      status: "ok";
      payload: CanvasOAuthStatePayload;
    }
  | {
      status: "invalid";
      reason: string;
    };

const isIsoTimestamp = (value: string): boolean => {
  return Number.isFinite(Date.parse(value));
};

const parseCanvasOAuthStatePayload = (input: unknown): CanvasOAuthStatePayload | null => {
  const payload = asJsonObject(input);

  if (payload === null) {
    return null;
  }

  const tenantId = asNonEmptyString(payload.tenantId);
  const nonce = asNonEmptyString(payload.nonce);
  const issuedAt = asNonEmptyString(payload.issuedAt);
  const expiresAt = asNonEmptyString(payload.expiresAt);

  if (tenantId === null || nonce === null || issuedAt === null || expiresAt === null) {
    return null;
  }

  if (!isIsoTimestamp(issuedAt) || !isIsoTimestamp(expiresAt)) {
    return null;
  }

  return {
    tenantId,
    nonce,
    issuedAt,
    expiresAt,
  };
};

export const canvasOAuthStateSigningSecret = (env: AppBindings): string => {
  const configuredSecret = env.CANVAS_OAUTH_STATE_SIGNING_SECRET?.trim();
  return configuredSecret === undefined || configuredSecret.length === 0
    ? `${env.PLATFORM_DOMAIN}:canvas-oauth-state-secret`
    : configuredSecret;
};

export const signCanvasOAuthStatePayload = async (
  payload: CanvasOAuthStatePayload,
  secret: string,
): Promise<string> => {
  const payloadJson = JSON.stringify(payload);
  const payloadEncoded = textToBase64Url(payloadJson);
  const signature = await sha256Base64Url(`${payloadEncoded}.${secret}`);
  return `${payloadEncoded}.${signature}`;
};

export const validateCanvasOAuthStateToken = async (
  stateToken: string,
  secret: string,
  nowIso: string,
): Promise<CanvasOAuthStateValidationResult> => {
  const tokenParts = stateToken.split(".");

  if (tokenParts.length !== 2) {
    return {
      status: "invalid",
      reason: "state token format is invalid",
    };
  }

  const [payloadEncoded, signature] = tokenParts;

  if (payloadEncoded === undefined || signature === undefined) {
    return {
      status: "invalid",
      reason: "state token format is invalid",
    };
  }

  const expectedSignature = await sha256Base64Url(`${payloadEncoded}.${secret}`);

  if (signature !== expectedSignature) {
    return {
      status: "invalid",
      reason: "state token signature is invalid",
    };
  }

  const payloadJson = base64UrlToText(payloadEncoded);

  if (payloadJson === null) {
    return {
      status: "invalid",
      reason: "state payload encoding is invalid",
    };
  }

  let parsedPayload: unknown;

  try {
    parsedPayload = JSON.parse(payloadJson);
  } catch {
    return {
      status: "invalid",
      reason: "state payload is not valid JSON",
    };
  }

  const payload = parseCanvasOAuthStatePayload(parsedPayload);

  if (payload === null) {
    return {
      status: "invalid",
      reason: "state payload is missing required fields",
    };
  }

  const nowMs = Date.parse(nowIso);
  const issuedAtMs = Date.parse(payload.issuedAt);
  const expiresAtMs = Date.parse(payload.expiresAt);

  if (!Number.isFinite(nowMs) || !Number.isFinite(issuedAtMs) || !Number.isFinite(expiresAtMs)) {
    return {
      status: "invalid",
      reason: "state payload timestamps are invalid",
    };
  }

  if (issuedAtMs > nowMs + 30_000) {
    return {
      status: "invalid",
      reason: "state token issuedAt is in the future",
    };
  }

  if (expiresAtMs <= nowMs) {
    return {
      status: "invalid",
      reason: "state token is expired",
    };
  }

  return {
    status: "ok",
    payload,
  };
};

const parseCanvasTokenResponse = (
  input: unknown,
): {
  accessToken: string;
  refreshToken?: string | undefined;
  expiresInSeconds?: number | undefined;
  refreshTokenExpiresInSeconds?: number | undefined;
  scope?: string | undefined;
} => {
  const payload = asJsonObject(input);

  if (payload === null) {
    throw new Error("Canvas token response must be a JSON object");
  }

  const accessToken = asNonEmptyString(payload.access_token);

  if (accessToken === null) {
    throw new Error("Canvas token response is missing access_token");
  }

  const refreshToken = asNonEmptyString(payload.refresh_token) ?? undefined;
  const scope = asNonEmptyString(payload.scope) ?? undefined;

  const expiresInRaw = payload.expires_in;
  const refreshTokenExpiresInRaw = payload.refresh_token_expires_in;
  let expiresInSeconds: number | undefined;
  let refreshTokenExpiresInSeconds: number | undefined;

  if (typeof expiresInRaw === "number" && Number.isFinite(expiresInRaw) && expiresInRaw > 0) {
    expiresInSeconds = Math.floor(expiresInRaw);
  }

  if (
    typeof refreshTokenExpiresInRaw === "number" &&
    Number.isFinite(refreshTokenExpiresInRaw) &&
    refreshTokenExpiresInRaw > 0
  ) {
    refreshTokenExpiresInSeconds = Math.floor(refreshTokenExpiresInRaw);
  }

  return {
    accessToken,
    ...(refreshToken === undefined ? {} : { refreshToken }),
    ...(expiresInSeconds === undefined ? {} : { expiresInSeconds }),
    ...(refreshTokenExpiresInSeconds === undefined ? {} : { refreshTokenExpiresInSeconds }),
    ...(scope === undefined ? {} : { scope }),
  };
};

export const exchangeCanvasAuthorizationCode = async (input: {
  tokenEndpoint: string;
  clientId: string;
  clientSecret: string;
  code: string;
  redirectUri: string;
  fetchImpl?: typeof fetch;
}): Promise<{
  accessToken: string;
  refreshToken?: string | undefined;
  expiresInSeconds?: number | undefined;
  refreshTokenExpiresInSeconds?: number | undefined;
  scope?: string | undefined;
}> => {
  const fetchImpl = input.fetchImpl ?? fetch;
  const response = await fetchImpl(input.tokenEndpoint, {
    method: "POST",
    headers: withCredTrailUserAgent({
      "content-type": "application/x-www-form-urlencoded",
      accept: "application/json",
    }),
    body: new URLSearchParams({
      grant_type: "authorization_code",
      client_id: input.clientId,
      client_secret: input.clientSecret,
      code: input.code,
      redirect_uri: input.redirectUri,
    }).toString(),
  });

  if (!response.ok) {
    throw new Error(`Canvas token exchange failed (${String(response.status)})`);
  }

  const responseBody = await response.json<unknown>().catch(() => null);
  return parseCanvasTokenResponse(responseBody);
};

export const refreshCanvasAccessToken = async (input: {
  tokenEndpoint: string;
  clientId: string;
  clientSecret: string;
  refreshToken: string;
  fetchImpl?: typeof fetch;
}): Promise<{
  accessToken: string;
  refreshToken?: string | undefined;
  expiresInSeconds?: number | undefined;
  refreshTokenExpiresInSeconds?: number | undefined;
  scope?: string | undefined;
}> => {
  const fetchImpl = input.fetchImpl ?? fetch;
  const response = await fetchImpl(input.tokenEndpoint, {
    method: "POST",
    headers: withCredTrailUserAgent({
      "content-type": "application/x-www-form-urlencoded",
      accept: "application/json",
    }),
    body: new URLSearchParams({
      grant_type: "refresh_token",
      client_id: input.clientId,
      client_secret: input.clientSecret,
      refresh_token: input.refreshToken,
    }).toString(),
  });

  if (!response.ok) {
    throw new Error(`Canvas token refresh failed (${String(response.status)})`);
  }

  const responseBody = await response.json<unknown>().catch(() => null);
  return parseCanvasTokenResponse(responseBody);
};

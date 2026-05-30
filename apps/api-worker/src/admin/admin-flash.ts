import { deleteCookie, getCookie, setCookie } from "hono/cookie";
import type { AppBindings, AppContext } from "../app";

export type AdminFlashKind = "api_key_secret";

export interface AdminFlashConsumeInput {
  kind: AdminFlashKind;
  tenantId: string;
  userId: string;
}

const ADMIN_FLASH_COOKIE_PREFIX = "ct_admin_flash_";
const ADMIN_FLASH_MAX_AGE_SECONDS = 120;
const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();

const adminFlashSigningSecret = (bindings: Pick<AppBindings, "BETTER_AUTH_SECRET">): string => {
  const trimmed = bindings.BETTER_AUTH_SECRET?.trim();

  if (trimmed === undefined || trimmed.length === 0) {
    throw new Error("BETTER_AUTH_SECRET is required for admin flash cookies");
  }

  return trimmed;
};

const adminFlashCookieName = (tenantId: string, kind: AdminFlashKind): string => {
  return `${ADMIN_FLASH_COOKIE_PREFIX}${kind}_${tenantId}`;
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

const signAdminFlashPayload = async (
  bindings: Pick<AppBindings, "BETTER_AUTH_SECRET">,
  payload: string,
): Promise<string> => {
  const key = await crypto.subtle.importKey(
    "raw",
    textEncoder.encode(adminFlashSigningSecret(bindings)),
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

interface AdminFlashPayload {
  kind: AdminFlashKind;
  tenantId: string;
  userId: string;
  value: string;
  exp: number;
}

export const setAdminFlashCookie = async (
  c: AppContext,
  input: {
    kind: AdminFlashKind;
    tenantId: string;
    userId: string;
    value: string;
  },
): Promise<void> => {
  const payload = base64UrlEncode(
    textEncoder.encode(
      JSON.stringify({
        kind: input.kind,
        tenantId: input.tenantId,
        userId: input.userId,
        value: input.value,
        exp: Math.floor(Date.now() / 1000) + ADMIN_FLASH_MAX_AGE_SECONDS,
      } satisfies AdminFlashPayload),
    ),
  );
  const signature = await signAdminFlashPayload(c.env, payload);
  const cookieValue = `${payload}.${signature}`;

  setCookie(c, adminFlashCookieName(input.tenantId, input.kind), cookieValue, {
    httpOnly: true,
    secure: c.env.APP_ENV !== "development",
    sameSite: "Lax",
    path: "/",
    maxAge: ADMIN_FLASH_MAX_AGE_SECONDS,
  });
};

export const consumeAdminFlashCookie = async (
  c: AppContext,
  input: AdminFlashConsumeInput,
): Promise<string | null> => {
  const cookieName = adminFlashCookieName(input.tenantId, input.kind);
  const rawToken = getCookie(c, cookieName)?.trim();

  deleteCookie(c, cookieName, { path: "/" });

  if (rawToken === undefined || rawToken.length === 0) {
    return null;
  }

  const [payload, signature, extra] = rawToken.split(".");

  if (
    payload === undefined ||
    payload.length === 0 ||
    signature === undefined ||
    signature.length === 0 ||
    extra !== undefined
  ) {
    return null;
  }

  const expectedSignature = await signAdminFlashPayload(c.env, payload);

  if (!signaturesMatch(signature, expectedSignature)) {
    return null;
  }

  const decoded = base64UrlDecode(payload);

  if (decoded === null) {
    return null;
  }

  let parsed: AdminFlashPayload;

  try {
    parsed = JSON.parse(textDecoder.decode(decoded)) as AdminFlashPayload;
  } catch {
    return null;
  }

  if (
    parsed.kind !== input.kind ||
    parsed.tenantId !== input.tenantId ||
    parsed.userId !== input.userId ||
    typeof parsed.value !== "string" ||
    parsed.value.length === 0 ||
    typeof parsed.exp !== "number" ||
    parsed.exp < Math.floor(Date.now() / 1000)
  ) {
    return null;
  }

  return parsed.value;
};

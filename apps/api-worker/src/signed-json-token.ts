export interface ExpiringSignedJsonTokenPayload {
  exp: number;
}

export type SignedJsonTokenPayloadParser<TPayload extends ExpiringSignedJsonTokenPayload> = (
  value: unknown,
) => TPayload | null;

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();

export const namespacedSigningSecret = (baseSecret: string, namespace?: string): string => {
  const trimmedNamespace = namespace?.trim();

  if (trimmedNamespace === undefined || trimmedNamespace.length === 0) {
    return baseSecret;
  }

  return `${baseSecret}:${trimmedNamespace}`;
};

export const signedJsonTokenExpiry = (ttlSeconds: number): number => {
  return Math.floor(Date.now() / 1000) + ttlSeconds;
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

const signPayload = async (signingSecret: string, payload: string): Promise<string> => {
  const key = await crypto.subtle.importKey(
    "raw",
    textEncoder.encode(signingSecret),
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

const encodePayload = (payload: ExpiringSignedJsonTokenPayload): string => {
  return base64UrlEncode(textEncoder.encode(JSON.stringify(payload)));
};

const decodePayloadJson = (encodedPayload: string): unknown => {
  const decoded = base64UrlDecode(encodedPayload);

  if (decoded === null) {
    return null;
  }

  try {
    return JSON.parse(textDecoder.decode(decoded));
  } catch {
    return null;
  }
};

const splitSignedJsonToken = (
  token: string,
): {
  encodedPayload: string;
  signature: string;
} | null => {
  const [encodedPayload, signature, extra] = token.split(".");

  if (
    encodedPayload === undefined ||
    encodedPayload.length === 0 ||
    signature === undefined ||
    signature.length === 0 ||
    extra !== undefined
  ) {
    return null;
  }

  return {
    encodedPayload,
    signature,
  };
};

const isExpired = (exp: number): boolean => {
  return exp < Math.floor(Date.now() / 1000);
};

export const createSignedJsonToken = async <TPayload extends ExpiringSignedJsonTokenPayload>(
  signingSecret: string,
  payload: TPayload,
): Promise<string> => {
  const encodedPayload = encodePayload(payload);
  const signature = await signPayload(signingSecret, encodedPayload);

  return `${encodedPayload}.${signature}`;
};

export const verifySignedJsonToken = async <TPayload extends ExpiringSignedJsonTokenPayload>(
  signingSecret: string,
  token: string,
  parsePayload: SignedJsonTokenPayloadParser<TPayload>,
): Promise<TPayload | null> => {
  const parts = splitSignedJsonToken(token);

  if (parts === null) {
    return null;
  }

  const expectedSignature = await signPayload(signingSecret, parts.encodedPayload);

  if (!signaturesMatch(parts.signature, expectedSignature)) {
    return null;
  }

  const parsed = decodePayloadJson(parts.encodedPayload);

  if (parsed === null || typeof parsed !== "object") {
    return null;
  }

  const payload = parsePayload(parsed);

  if (payload === null || isExpired(payload.exp)) {
    return null;
  }

  return payload;
};

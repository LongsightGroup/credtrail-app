import type { P256PrivateJwk, P256PublicJwk } from "@credtrail/core-domain";

const requireJwkString = (value: string | undefined, field: string): string => {
  if (typeof value !== "string" || value.length === 0) {
    throw new Error(`Missing ${field} in exported JWK`);
  }

  return value;
};

export const generateP256SigningMaterial = async (
  kid = "key-p256",
): Promise<{ publicJwk: P256PublicJwk; privateJwk: P256PrivateJwk }> => {
  const generated = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, [
    "sign",
    "verify",
  ]);
  const exportedPublicJwk = await crypto.subtle.exportKey("jwk", generated.publicKey);
  const exportedPrivateJwk = await crypto.subtle.exportKey("jwk", generated.privateKey);

  const publicJwk: P256PublicJwk = {
    kty: "EC",
    crv: "P-256",
    x: requireJwkString(exportedPublicJwk.x, "x"),
    y: requireJwkString(exportedPublicJwk.y, "y"),
    kid,
  };
  const privateJwk: P256PrivateJwk = {
    ...publicJwk,
    d: requireJwkString(exportedPrivateJwk.d, "d"),
  };

  return {
    publicJwk,
    privateJwk,
  };
};

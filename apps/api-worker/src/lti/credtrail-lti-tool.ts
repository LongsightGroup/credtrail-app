import { LTITool } from "@lti-tool/core";
import { createLtiToolKey, findActiveLtiToolKey, type SqlDatabase } from "@credtrail/db";
import { ltiStateSigningSecret } from "./lti-helpers";
import { CredTrailLtiStorage } from "./credtrail-lti-storage";
import type { AppBindings } from "../app";

const LTI_TOOL_KEY_ID = "credtrail-lti-main";

const rsaAlgorithm: RsaHashedImportParams | RsaHashedKeyGenParams = {
  name: "RSASSA-PKCS1-v1_5",
  hash: "SHA-256",
};

const generateRsaSigningKeyPair = async (): Promise<{
  keyPair: CryptoKeyPair;
  publicJwk: JsonWebKey;
  privateJwk: JsonWebKey;
}> => {
  const keyPair = await crypto.subtle.generateKey(
    {
      ...rsaAlgorithm,
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
    },
    true,
    ["sign", "verify"],
  );
  const publicJwk = await crypto.subtle.exportKey("jwk", keyPair.publicKey);
  const privateJwk = await crypto.subtle.exportKey("jwk", keyPair.privateKey);

  return {
    keyPair,
    publicJwk,
    privateJwk,
  };
};

const importStoredKeyPair = async (input: {
  publicJwkJson: string;
  privateJwkJson: string;
}): Promise<CryptoKeyPair> => {
  const publicJwk = JSON.parse(input.publicJwkJson) as JsonWebKey;
  const privateJwk = JSON.parse(input.privateJwkJson) as JsonWebKey;
  const publicKey = await crypto.subtle.importKey("jwk", publicJwk, rsaAlgorithm, true, ["verify"]);
  const privateKey = await crypto.subtle.importKey("jwk", privateJwk, rsaAlgorithm, true, ["sign"]);

  return {
    publicKey,
    privateKey,
  };
};

const loadOrCreateLtiToolKeyPair = async (db: SqlDatabase): Promise<CryptoKeyPair> => {
  const activeKey = await findActiveLtiToolKey(db);

  if (activeKey !== null) {
    return importStoredKeyPair({
      publicJwkJson: activeKey.publicJwkJson,
      privateJwkJson: activeKey.privateJwkJson,
    });
  }

  const generated = await generateRsaSigningKeyPair();
  await createLtiToolKey(db, {
    keyId: LTI_TOOL_KEY_ID,
    publicJwkJson: JSON.stringify(generated.publicJwk),
    privateJwkJson: JSON.stringify(generated.privateJwk),
    isActive: true,
  });

  return generated.keyPair;
};

export const createCredTrailLtiTool = async (input: {
  db: SqlDatabase;
  env: AppBindings;
  defaultTenantId?: string | undefined;
}): Promise<LTITool> => {
  const keyPair = await loadOrCreateLtiToolKeyPair(input.db);

  return new LTITool({
    stateSecret: new TextEncoder().encode(ltiStateSigningSecret(input.env)),
    keyPair,
    storage: new CredTrailLtiStorage(input.db, {
      defaultTenantId: input.defaultTenantId,
    }),
    security: {
      keyId: LTI_TOOL_KEY_ID,
      stateExpirationSeconds: 600,
      nonceExpirationSeconds: 600,
    },
  });
};

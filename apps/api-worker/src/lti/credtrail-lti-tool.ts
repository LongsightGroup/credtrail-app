import { LTITool, importLtiToolKeyPairFromJwk, type LTIConfig } from "@lti-tool/core";
import { createLtiToolKey, findActiveLtiToolKey, type SqlDatabase } from "@credtrail/db";
import { ltiStateSigningSecret } from "./lti-helpers";
import { CredTrailLtiStorage } from "./credtrail-lti-storage";
import type { AppBindings } from "../app";

const LTI_TOOL_KEY_ID = "credtrail-lti-main";

type DynamicRegistrationConfig = NonNullable<LTIConfig["dynamicRegistration"]>;

const rsaAlgorithm: RsaHashedKeyGenParams = {
  name: "RSASSA-PKCS1-v1_5",
  hash: "SHA-256",
  modulusLength: 2048,
  publicExponent: new Uint8Array([1, 0, 1]),
};

const generateRsaSigningKeyPair = async (): Promise<{
  keyPair: CryptoKeyPair;
  publicJwk: JsonWebKey;
  privateJwk: JsonWebKey;
}> => {
  const keyPair = await crypto.subtle.generateKey(rsaAlgorithm, true, ["sign", "verify"]);
  const publicJwk = {
    ...(await crypto.subtle.exportKey("jwk", keyPair.publicKey)),
    kid: LTI_TOOL_KEY_ID,
  };
  const privateJwk = {
    ...(await crypto.subtle.exportKey("jwk", keyPair.privateKey)),
    kid: LTI_TOOL_KEY_ID,
  };

  return {
    keyPair,
    publicJwk,
    privateJwk,
  };
};

const importStoredKeyPair = async (input: {
  keyId: string;
  privateJwkJson: string;
}): Promise<CryptoKeyPair> => {
  const privateJwk = JSON.parse(input.privateJwkJson) as JsonWebKey & { kid?: string };
  const imported = await importLtiToolKeyPairFromJwk({
    ...privateJwk,
    kid: typeof privateJwk.kid === "string" ? privateJwk.kid : input.keyId,
  });

  return imported.keyPair;
};

const loadOrCreateLtiToolKeyPair = async (db: SqlDatabase): Promise<CryptoKeyPair> => {
  const activeKey = await findActiveLtiToolKey(db);

  if (activeKey !== null) {
    return importStoredKeyPair({
      keyId: activeKey.keyId,
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
  dynamicRegistration?: DynamicRegistrationConfig | undefined;
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
    ...(input.dynamicRegistration === undefined
      ? {}
      : { dynamicRegistration: input.dynamicRegistration }),
  });
};

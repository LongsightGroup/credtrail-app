import {
  LtiDynamicRegistration,
  LTITool,
  importLtiToolKeyPairFromJwk,
  type LTIConfig,
} from "@longsightgroup/lti-tool";
import { createLtiToolKey, findActiveLtiToolKey, type SqlDatabase } from "@credtrail/db";
import { ltiStateSigningSecret } from "./lti-helpers";
import { CredTrailLtiStorage } from "./credtrail-lti-storage";
import { LTI_STATE_TTL_SECONDS } from "./constants";
import type { AppBindings, AppContext } from "../app";

const LTI_TOOL_KEY_ID = "credtrail-lti-main";

export type DynamicRegistrationConfig = NonNullable<LTIConfig["dynamicRegistration"]>;

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

export interface CreateCredTrailLtiToolInput {
  db: SqlDatabase;
  env: AppBindings;
  defaultTenantId?: string | undefined;
  dynamicRegistration?: DynamicRegistrationConfig | undefined;
}

export const createCredTrailLtiConfig = async (
  input: CreateCredTrailLtiToolInput,
): Promise<LTIConfig> => {
  const keyPair = await loadOrCreateLtiToolKeyPair(input.db);

  return {
    stateSecret: new TextEncoder().encode(ltiStateSigningSecret(input.env)),
    keyPair,
    storage: new CredTrailLtiStorage(input.db, {
      defaultTenantId: input.defaultTenantId,
    }),
    security: {
      keyId: LTI_TOOL_KEY_ID,
      stateExpirationSeconds: LTI_STATE_TTL_SECONDS,
    },
    ...(input.dynamicRegistration === undefined
      ? {}
      : { dynamicRegistration: input.dynamicRegistration }),
  };
};

export const createCredTrailLtiTool = async (
  input: CreateCredTrailLtiToolInput,
): Promise<LTITool> => {
  return new LTITool(await createCredTrailLtiConfig(input));
};

export const resolveCredTrailLtiTool = async (
  c: AppContext,
  resolveDatabase: (bindings: AppBindings) => SqlDatabase,
  options: Omit<CreateCredTrailLtiToolInput, "db" | "env"> = {},
): Promise<LTITool> => {
  return createCredTrailLtiTool({
    db: resolveDatabase(c.env),
    env: c.env,
    ...options,
  });
};

export const createCredTrailLtiDynamicRegistration = async (
  input: CreateCredTrailLtiToolInput,
): Promise<LtiDynamicRegistration> => {
  return new LtiDynamicRegistration(await createCredTrailLtiConfig(input));
};

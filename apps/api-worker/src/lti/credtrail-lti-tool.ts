import {
  LtiDynamicRegistration,
  LTITool,
  importLtiToolKeyPairFromJwk,
  type JWKS,
  type LTIConfig,
} from "@longsightgroup/lti-tool";
import {
  createLtiToolKey,
  findActiveLtiToolKey,
  type LtiToolKeyRecord,
  type SqlDatabase,
} from "@credtrail/db";
import { ltiStateSigningSecret } from "./lti-helpers";
import { CredTrailLtiStorage } from "./credtrail-lti-storage";
import { LTI_STATE_TTL_SECONDS } from "./constants";
import type { AppBindings } from "../app";

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

interface StoredJwkRecord {
  readonly [key: string]: unknown;
  readonly kid?: string | undefined;
}

const parseStoredLtiToolJwk = (input: {
  keyId: string;
  jwkJson: string;
  keyKind: "private" | "public";
}): StoredJwkRecord => {
  let parsed: unknown;

  try {
    parsed = JSON.parse(input.jwkJson) as unknown;
  } catch (cause: unknown) {
    throw new Error(`Stored LTI tool ${input.keyKind} JWK is not valid JSON`, { cause });
  }

  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error(`Stored LTI tool ${input.keyKind} JWK must be a JSON object`);
  }

  // SAFETY: the object boundary has been checked above; JWK fields remain unknown
  // until Web Crypto/package import validates private key material.
  const record = parsed as Record<string, unknown>;

  if (typeof record.kty !== "string" || record.kty.trim().length === 0) {
    throw new Error(`Stored LTI tool ${input.keyKind} JWK is missing kty`);
  }

  return {
    ...record,
    kid: typeof record.kid === "string" && record.kid.trim().length > 0 ? record.kid : input.keyId,
  };
};

const importStoredKeyPair = async (input: {
  keyId: string;
  privateJwkJson: string;
}): Promise<CryptoKeyPair> => {
  const privateJwk = parseStoredLtiToolJwk({
    keyId: input.keyId,
    jwkJson: input.privateJwkJson,
    keyKind: "private",
  });

  // SAFETY: importLtiToolKeyPairFromJwk performs the cryptographic JWK validation
  // that TypeScript cannot express for the parsed JSON object.
  const imported = await importLtiToolKeyPairFromJwk({
    ...privateJwk,
  } as JsonWebKey & { kid?: string });

  return imported.keyPair;
};

interface LoadedLtiToolKey {
  readonly key: LtiToolKeyRecord;
  readonly generatedKeyPair?: CryptoKeyPair | undefined;
}

const loadOrCreateLtiToolKey = async (db: SqlDatabase): Promise<LoadedLtiToolKey> => {
  const activeKey = await findActiveLtiToolKey(db);

  if (activeKey !== null) {
    return { key: activeKey };
  }

  const generated = await generateRsaSigningKeyPair();
  const key = await createLtiToolKey(db, {
    keyId: LTI_TOOL_KEY_ID,
    publicJwkJson: JSON.stringify(generated.publicJwk),
    privateJwkJson: JSON.stringify(generated.privateJwk),
    isActive: true,
  });

  return {
    key,
    generatedKeyPair: generated.keyPair,
  };
};

const loadOrCreateLtiToolKeyPair = async (db: SqlDatabase): Promise<CryptoKeyPair> => {
  const loaded = await loadOrCreateLtiToolKey(db);

  if (loaded.generatedKeyPair !== undefined) {
    return loaded.generatedKeyPair;
  }

  return importStoredKeyPair({
    keyId: loaded.key.keyId,
    privateJwkJson: loaded.key.privateJwkJson,
  });
};

/**
 * Resolves the public CredTrail LTI tool JWKS without constructing the full LTI protocol facade.
 *
 * The helper still owns first-use key creation so the public endpoint can bootstrap a new
 * environment, but steady-state reads only project the stored public JWK.
 */
export const getCredTrailLtiToolJwks = async (db: SqlDatabase): Promise<JWKS> => {
  const loaded = await loadOrCreateLtiToolKey(db);
  const publicJwk = parseStoredLtiToolJwk({
    keyId: loaded.key.keyId,
    jwkJson: loaded.key.publicJwkJson,
    keyKind: "public",
  });

  return {
    keys: [
      {
        ...publicJwk,
        use: "sig",
        alg: "RS256",
        kid: LTI_TOOL_KEY_ID,
      },
    ],
  };
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

export const createCredTrailLtiDynamicRegistration = async (
  input: CreateCredTrailLtiToolInput,
): Promise<LtiDynamicRegistration> => {
  return new LtiDynamicRegistration(await createCredTrailLtiConfig(input));
};

import type { SqlDatabase } from '@credtrail/db';
import {
  parseTenantSigningRegistry,
  parseTenantSigningRegistryEntry,
  type TenantSigningRegistry,
  type TenantSigningRegistryEntry,
} from '@credtrail/validation';
import type { SigningPublicJwk } from './key-material';

export interface HistoricalSigningKeyEntry {
  keyId: string;
  publicJwk: SigningPublicJwk;
}

export interface RemoteSignerRegistryEntry {
  url: string;
  authorizationHeader: string | null;
  timeoutMs: number;
}

type SigningKeyHistoryRegistry = Record<string, HistoricalSigningKeyEntry[]>;
type RemoteSignerRegistry = Record<string, RemoteSignerRegistryEntry>;

const DEFAULT_REMOTE_SIGNER_TIMEOUT_MS = 10_000;
const MAX_REMOTE_SIGNER_TIMEOUT_MS = 60_000;

const parseSigningRegistryFromEnv = (rawRegistry: string | undefined): TenantSigningRegistry => {
  if (rawRegistry === undefined || rawRegistry.trim().length === 0) {
    return {};
  }

  let parsedRegistry: unknown;

  try {
    parsedRegistry = JSON.parse(rawRegistry) as unknown;
  } catch {
    throw new Error('TENANT_SIGNING_REGISTRY_JSON is not valid JSON');
  }

  return parseTenantSigningRegistry(parsedRegistry);
};

const parseSigningKeyHistoryRegistryFromEnv = (
  rawRegistry: string | undefined,
): SigningKeyHistoryRegistry => {
  if (rawRegistry === undefined || rawRegistry.trim().length === 0) {
    return {};
  }

  let parsedRegistry: unknown;

  try {
    parsedRegistry = JSON.parse(rawRegistry) as unknown;
  } catch {
    throw new Error('TENANT_SIGNING_KEY_HISTORY_JSON is not valid JSON');
  }

  if (
    parsedRegistry === null ||
    typeof parsedRegistry !== 'object' ||
    Array.isArray(parsedRegistry)
  ) {
    throw new Error('TENANT_SIGNING_KEY_HISTORY_JSON must be an object keyed by DID');
  }

  const output: SigningKeyHistoryRegistry = {};

  for (const [did, registryValue] of Object.entries(parsedRegistry as Record<string, unknown>)) {
    if (!Array.isArray(registryValue)) {
      throw new Error(`TENANT_SIGNING_KEY_HISTORY_JSON["${did}"] must be an array`);
    }

    const parsedEntries: HistoricalSigningKeyEntry[] = [];

    for (const [index, entry] of registryValue.entries()) {
      if (entry === null || typeof entry !== 'object' || Array.isArray(entry)) {
        throw new Error(
          `TENANT_SIGNING_KEY_HISTORY_JSON["${did}"][${String(index)}] must be an object`,
        );
      }

      const entryObject = entry as Record<string, unknown>;
      const keyIdRaw = entryObject.keyId;
      const keyId = typeof keyIdRaw === 'string' ? keyIdRaw.trim() : '';

      if (keyId.length === 0) {
        throw new Error(
          `TENANT_SIGNING_KEY_HISTORY_JSON["${did}"][${String(index)}].keyId must be a non-empty string`,
        );
      }

      if (!Object.hasOwn(entryObject, 'publicJwk')) {
        throw new Error(
          `TENANT_SIGNING_KEY_HISTORY_JSON["${did}"][${String(index)}].publicJwk is required`,
        );
      }

      const parsedPublicJwk = entryObject.publicJwk;

      const parsedEntry = parseTenantSigningRegistryEntry({
        tenantId: did,
        keyId,
        publicJwk: parsedPublicJwk,
      });

      parsedEntries.push({
        keyId,
        publicJwk: parsedEntry.publicJwk,
      });
    }

    output[did] = parsedEntries;
  }

  return output;
};

const parseRemoteSignerRegistryFromEnv = (
  rawRegistry: string | undefined,
): RemoteSignerRegistry => {
  if (rawRegistry === undefined || rawRegistry.trim().length === 0) {
    return {};
  }

  let parsedRegistry: unknown;

  try {
    parsedRegistry = JSON.parse(rawRegistry) as unknown;
  } catch {
    throw new Error('TENANT_REMOTE_SIGNER_REGISTRY_JSON is not valid JSON');
  }

  if (
    parsedRegistry === null ||
    typeof parsedRegistry !== 'object' ||
    Array.isArray(parsedRegistry)
  ) {
    throw new Error('TENANT_REMOTE_SIGNER_REGISTRY_JSON must be an object keyed by DID');
  }

  const output: RemoteSignerRegistry = {};

  for (const [did, entry] of Object.entries(parsedRegistry as Record<string, unknown>)) {
    if (entry === null || typeof entry !== 'object' || Array.isArray(entry)) {
      throw new Error(`TENANT_REMOTE_SIGNER_REGISTRY_JSON["${did}"] must be an object`);
    }

    const entryObject = entry as Record<string, unknown>;
    const urlRaw = entryObject.url;
    const url = typeof urlRaw === 'string' ? urlRaw : null;

    if (url === null || url.trim().length === 0) {
      throw new Error(
        `TENANT_REMOTE_SIGNER_REGISTRY_JSON["${did}"].url must be a non-empty string`,
      );
    }

    let normalizedAuthorizationHeader: string | null = null;
    const authorizationHeader = entryObject.authorizationHeader;

    if (authorizationHeader !== undefined && authorizationHeader !== null) {
      if (typeof authorizationHeader !== 'string' || authorizationHeader.trim().length === 0) {
        throw new Error(
          `TENANT_REMOTE_SIGNER_REGISTRY_JSON["${did}"].authorizationHeader must be a non-empty string when provided`,
        );
      }

      normalizedAuthorizationHeader = authorizationHeader.trim();
    }

    const timeoutMs = entryObject.timeoutMs;
    let normalizedTimeoutMs = DEFAULT_REMOTE_SIGNER_TIMEOUT_MS;

    if (timeoutMs !== undefined) {
      if (
        typeof timeoutMs !== 'number' ||
        !Number.isInteger(timeoutMs) ||
        timeoutMs <= 0 ||
        timeoutMs > MAX_REMOTE_SIGNER_TIMEOUT_MS
      ) {
        throw new Error(
          `TENANT_REMOTE_SIGNER_REGISTRY_JSON["${did}"].timeoutMs must be an integer between 1 and ${String(MAX_REMOTE_SIGNER_TIMEOUT_MS)}`,
        );
      }

      normalizedTimeoutMs = timeoutMs;
    }

    output[did] = {
      url: url.trim(),
      authorizationHeader: normalizedAuthorizationHeader,
      timeoutMs: normalizedTimeoutMs,
    };
  }

  return output;
};

const parseSigningEntryFromStoredJson = (
  tenantId: string,
  keyId: string,
  publicJwkJson: string,
  privateJwkJson: string | null,
): TenantSigningRegistryEntry => {
  let parsedPublicJwk: unknown;
  let parsedPrivateJwk: unknown = undefined;

  try {
    parsedPublicJwk = JSON.parse(publicJwkJson) as unknown;
  } catch {
    throw new Error(`Invalid stored public JWK JSON for tenant "${tenantId}"`);
  }

  if (privateJwkJson !== null) {
    try {
      parsedPrivateJwk = JSON.parse(privateJwkJson) as unknown;
    } catch {
      throw new Error(`Invalid stored private JWK JSON for tenant "${tenantId}"`);
    }
  }

  return parseTenantSigningRegistryEntry({
    tenantId,
    keyId,
    publicJwk: parsedPublicJwk,
    ...(parsedPrivateJwk === undefined ? {} : { privateJwk: parsedPrivateJwk }),
  });
};

interface SigningRegistrationRow {
  tenantId: string;
  keyId: string;
  publicJwkJson: string;
  privateJwkJson: string | null;
}

interface SigningRegistryBindings {
  TENANT_SIGNING_REGISTRY_JSON?: string | undefined;
  TENANT_SIGNING_KEY_HISTORY_JSON?: string | undefined;
  TENANT_REMOTE_SIGNER_REGISTRY_JSON?: string | undefined;
}

interface CreateSigningRegistryResolversInput<
  BindingsType extends SigningRegistryBindings,
> {
  resolveDatabase: (bindings: BindingsType) => SqlDatabase;
  findTenantSigningRegistrationByDid: (
    db: SqlDatabase,
    did: string,
  ) => Promise<SigningRegistrationRow | null>;
}

export const createSigningRegistryResolvers = <
  ContextType extends { env: BindingsType },
  BindingsType extends SigningRegistryBindings,
>(
  input: CreateSigningRegistryResolversInput<BindingsType>,
): {
  resolveSigningEntryForDid: (
    context: ContextType,
    did: string,
  ) => Promise<TenantSigningRegistryEntry | null>;
  resolveHistoricalSigningKeysForDid: (
    context: ContextType,
    did: string,
  ) => readonly HistoricalSigningKeyEntry[];
  resolveRemoteSignerRegistryEntryForDid: (
    context: ContextType,
    did: string,
  ) => RemoteSignerRegistryEntry | null;
} => {
  const resolveSigningEntryForDid = async (
    context: ContextType,
    did: string,
  ): Promise<TenantSigningRegistryEntry | null> => {
    const dbSigningRegistration = await input.findTenantSigningRegistrationByDid(
      input.resolveDatabase(context.env),
      did,
    );

    if (dbSigningRegistration !== null) {
      return parseSigningEntryFromStoredJson(
        dbSigningRegistration.tenantId,
        dbSigningRegistration.keyId,
        dbSigningRegistration.publicJwkJson,
        dbSigningRegistration.privateJwkJson,
      );
    }

    const envRegistry = parseSigningRegistryFromEnv(context.env.TENANT_SIGNING_REGISTRY_JSON);
    return envRegistry[did] ?? null;
  };

  const resolveHistoricalSigningKeysForDid = (
    context: ContextType,
    did: string,
  ): readonly HistoricalSigningKeyEntry[] => {
    const historyRegistry = parseSigningKeyHistoryRegistryFromEnv(
      context.env.TENANT_SIGNING_KEY_HISTORY_JSON,
    );
    return historyRegistry[did] ?? [];
  };

  const resolveRemoteSignerRegistryEntryForDid = (
    context: ContextType,
    did: string,
  ): RemoteSignerRegistryEntry | null => {
    const remoteSignerRegistry = parseRemoteSignerRegistryFromEnv(
      context.env.TENANT_REMOTE_SIGNER_REGISTRY_JSON,
    );
    return remoteSignerRegistry[did] ?? null;
  };

  return {
    resolveSigningEntryForDid,
    resolveHistoricalSigningKeysForDid,
    resolveRemoteSignerRegistryEntryForDid,
  };
};

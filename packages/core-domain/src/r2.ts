import type { JsonObject } from "./index";

export interface ImmutableCredentialObjectIds {
  tenantId: string;
  assertionId: string;
}

export interface StoreImmutableCredentialInput extends ImmutableCredentialObjectIds {
  credential: JsonObject;
}

export interface StoredImmutableCredentialObject extends ImmutableCredentialObjectIds {
  key: string;
  etag: string;
  version: string;
  size: number;
  uploadedAt: string;
}

export interface ImmutableCredentialStoreHeadObject {
  key: string;
}

export interface ImmutableCredentialStoreGetObject {
  readonly size: number;
  text(): Promise<string>;
}

export interface ImmutableCredentialStorePutObject extends ImmutableCredentialStoreHeadObject {
  etag: string;
  version: string;
  size: number;
  uploaded: Date;
}

export interface ImmutableCredentialStore {
  head(key: string): Promise<ImmutableCredentialStoreHeadObject | null>;
  get(key: string): Promise<ImmutableCredentialStoreGetObject | null>;
  put(
    key: string,
    value: string,
    options?: {
      httpMetadata?: {
        contentType?: string;
        cacheControl?: string;
      };
      customMetadata?: Record<string, string>;
    },
  ): Promise<ImmutableCredentialStorePutObject | null>;
  delete(key: string): Promise<void>;
}

const VC_OBJECT_CONTENT_TYPE = "application/ld+json";
const VC_OBJECT_CACHE_CONTROL = "public, max-age=31536000, immutable";

const encodePathSegment = (value: string): string => {
  const trimmed = value.trim();

  if (trimmed.length === 0) {
    throw new Error("Object storage path segments must not be empty");
  }

  return encodeURIComponent(trimmed);
};

const parseJsonObject = (serialized: string): JsonObject => {
  const parsed = JSON.parse(serialized) as unknown;

  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error("Stored credential object is not a JSON object");
  }

  return parsed as JsonObject;
};

export const immutableCredentialObjectKey = (ids: ImmutableCredentialObjectIds): string => {
  return `tenants/${encodePathSegment(ids.tenantId)}/assertions/${encodePathSegment(ids.assertionId)}.jsonld`;
};

export const storeImmutableCredentialObject = async (
  store: ImmutableCredentialStore,
  input: StoreImmutableCredentialInput,
): Promise<StoredImmutableCredentialObject> => {
  const key = immutableCredentialObjectKey(input);
  const existing = await store.head(key);

  if (existing !== null) {
    throw new Error(`Immutable credential already exists for key "${key}"`);
  }

  const putResult = await store.put(key, JSON.stringify(input.credential), {
    httpMetadata: {
      contentType: VC_OBJECT_CONTENT_TYPE,
      cacheControl: VC_OBJECT_CACHE_CONTROL,
    },
    customMetadata: {
      tenantId: input.tenantId,
      assertionId: input.assertionId,
      artifactType: "open-badges-3-vc",
      storagePolicy: "immutable",
    },
  });

  if (putResult === null) {
    throw new Error(`Object storage put operation returned null for key "${key}"`);
  }

  return {
    tenantId: input.tenantId,
    assertionId: input.assertionId,
    key,
    etag: putResult.etag,
    version: putResult.version,
    size: putResult.size,
    uploadedAt: putResult.uploaded.toISOString(),
  };
};

export const getImmutableCredentialObject = async (
  store: ImmutableCredentialStore,
  ids: ImmutableCredentialObjectIds,
): Promise<JsonObject | null> => {
  const key = immutableCredentialObjectKey(ids);
  const object = await store.get(key);

  if (object === null) {
    return null;
  }

  const serialized = await object.text();
  return parseJsonObject(serialized);
};

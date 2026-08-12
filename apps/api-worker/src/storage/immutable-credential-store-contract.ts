import {
  getImmutableCredentialObject,
  immutableCredentialObjectKey,
  storeImmutableCredentialObject,
  type ImmutableCredentialStore,
} from "@credtrail/core-domain";
import { expect, it } from "vitest";

interface RunImmutableCredentialStoreContractInput {
  createStore: () => ImmutableCredentialStore;
}

export const runImmutableCredentialStoreContract = (
  input: RunImmutableCredentialStoreContractInput,
): void => {
  it("stores and loads immutable credential objects", async () => {
    const store = input.createStore();
    const ids = {
      tenantId: "tenant-a",
      assertionId: "tenant-a:assertion-001",
    };
    const stored = await storeImmutableCredentialObject(store, {
      ...ids,
      credential: {
        "@context": ["https://www.w3.org/ns/credentials/v2"],
        type: ["VerifiableCredential", "OpenBadgeCredential"],
      },
    });

    expect(stored.key).toBe(immutableCredentialObjectKey(ids));
    await expect(store.head(stored.key)).resolves.toEqual({
      key: stored.key,
    });
    await expect(store.get(stored.key)).resolves.toMatchObject({
      size: stored.size,
    });

    await expect(getImmutableCredentialObject(store, ids)).resolves.toEqual({
      "@context": ["https://www.w3.org/ns/credentials/v2"],
      type: ["VerifiableCredential", "OpenBadgeCredential"],
    });
  });

  it("returns null for missing objects", async () => {
    const store = input.createStore();

    await expect(
      getImmutableCredentialObject(store, {
        tenantId: "tenant-missing",
        assertionId: "tenant-missing:assertion-missing",
      }),
    ).resolves.toBeNull();
  });

  it("prevents immutable overwrite", async () => {
    const store = input.createStore();
    const payload = {
      tenantId: "tenant-a",
      assertionId: "tenant-a:assertion-001",
      credential: {
        id: "urn:vc:1",
      },
    };

    await storeImmutableCredentialObject(store, payload);

    await expect(storeImmutableCredentialObject(store, payload)).rejects.toThrowError(
      "Immutable credential already exists",
    );
  });

  it("returns null when immutable put is attempted for an existing key", async () => {
    const store = input.createStore();
    const key = immutableCredentialObjectKey({
      tenantId: "tenant-a",
      assertionId: "tenant-a:assertion-direct-put",
    });

    const firstPut = await store.put(key, '{"id":"urn:vc:1"}', {
      httpMetadata: {
        contentType: "application/ld+json",
        cacheControl: "public, max-age=31536000, immutable",
      },
      customMetadata: {
        tenantId: "tenant-a",
      },
    });

    expect(firstPut).not.toBeNull();
    await expect(
      store.put(key, '{"id":"urn:vc:2"}', {
        httpMetadata: {
          contentType: "application/ld+json",
          cacheControl: "public, max-age=31536000, immutable",
        },
      }),
    ).resolves.toBeNull();
  });

  it("deletes objects and treats missing deletes as idempotent", async () => {
    const store = input.createStore();
    const key = immutableCredentialObjectKey({
      tenantId: "tenant-delete",
      assertionId: "tenant-delete:assertion-001",
    });

    const created = await store.put(key, '{"id":"urn:vc:delete"}', {
      httpMetadata: {
        contentType: "application/ld+json",
        cacheControl: "public, max-age=31536000, immutable",
      },
      customMetadata: {
        tenantId: "tenant-delete",
      },
    });

    expect(created).not.toBeNull();
    await expect(store.head(key)).resolves.toEqual({
      key,
    });

    await expect(store.delete(key)).resolves.toBeUndefined();
    await expect(store.head(key)).resolves.toBeNull();
    await expect(store.get(key)).resolves.toBeNull();
    await expect(store.delete(key)).resolves.toBeUndefined();
  });
};

import { describe, expect, it } from "vitest";

import {
  getImmutableCredentialObject,
  immutableCredentialObjectKey,
  storeImmutableCredentialObject,
  type ImmutableCredentialStore,
} from "./r2";

interface StoredMockObject {
  key: string;
  body: string;
  etag: string;
  version: string;
  size: number;
  uploaded: Date;
}

const createMockStore = (): ImmutableCredentialStore => {
  const objects = new Map<string, StoredMockObject>();
  let sequence = 0;

  return {
    head: (key: string): Promise<{ key: string } | null> => {
      const found = objects.get(key);

      if (found === undefined) {
        return Promise.resolve(null);
      }

      return Promise.resolve({
        key: found.key,
      });
    },
    get: (key: string): Promise<{ readonly size: number; text(): Promise<string> } | null> => {
      const found = objects.get(key);

      if (found === undefined) {
        return Promise.resolve(null);
      }

      return Promise.resolve({
        size: found.size,
        text: (): Promise<string> => Promise.resolve(found.body),
      });
    },
    put: (key: string, value: string): Promise<StoredMockObject> => {
      sequence += 1;
      const sequenceText = String(sequence);
      const object: StoredMockObject = {
        key,
        body: value,
        etag: `etag-${sequenceText}`,
        version: `version-${sequenceText}`,
        size: value.length,
        uploaded: new Date("2026-02-10T00:00:00.000Z"),
      };
      objects.set(key, object);
      return Promise.resolve(object);
    },
    delete: (key: string): Promise<void> => {
      objects.delete(key);
      return Promise.resolve();
    },
  };
};

describe("immutableCredentialObjectKey", () => {
  it("builds tenant-prefixed object keys", () => {
    expect(
      immutableCredentialObjectKey({
        tenantId: "tenant-a",
        assertionId: "tenant-a:assertion-123",
      }),
    ).toBe("tenants/tenant-a/assertions/tenant-a%3Aassertion-123.jsonld");
  });

  it("encodes reserved characters in path segments", () => {
    expect(
      immutableCredentialObjectKey({
        tenantId: "tenant/a",
        assertionId: "assertion/123",
      }),
    ).toBe("tenants/tenant%2Fa/assertions/assertion%2F123.jsonld");
  });
});

describe("immutable credential object store adapter", () => {
  it("stores and retrieves immutable VC objects", async () => {
    const store = createMockStore();
    const stored = await storeImmutableCredentialObject(store, {
      tenantId: "tenant-a",
      assertionId: "tenant-a:assertion-001",
      credential: {
        "@context": ["https://www.w3.org/ns/credentials/v2"],
        type: ["VerifiableCredential", "OpenBadgeCredential"],
      },
    });

    expect(stored.key).toBe("tenants/tenant-a/assertions/tenant-a%3Aassertion-001.jsonld");

    const loaded = await getImmutableCredentialObject(store, {
      tenantId: "tenant-a",
      assertionId: "tenant-a:assertion-001",
    });

    expect(loaded).not.toBeNull();
    expect(loaded?.type).toEqual(["VerifiableCredential", "OpenBadgeCredential"]);
  });

  it("rejects overwriting existing immutable objects", async () => {
    const store = createMockStore();
    const payload = {
      tenantId: "tenant-a",
      assertionId: "tenant-a:assertion-001",
      credential: {
        id: "urn:vc:1",
      },
    };

    await storeImmutableCredentialObject(store, payload);

    await expect(async () => {
      await storeImmutableCredentialObject(store, payload);
    }).rejects.toThrowError("Immutable credential already exists");
  });
});

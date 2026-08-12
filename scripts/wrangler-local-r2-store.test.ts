import { readFileSync, writeFileSync } from "node:fs";
import type { ImmutableCredentialStore } from "@credtrail/core-domain";
import { describe, expect, it } from "vitest";
import { createWranglerLocalR2Store, ensureWranglerLocalR2Object } from "./wrangler-local-r2-store";

interface RecordingWrangler {
  readonly objects: ReadonlyMap<string, string>;
  readonly putCount: () => number;
  readonly runCommand: (arguments_: readonly string[]) => {
    readonly status: number;
    readonly stdout: string;
    readonly stderr: string;
  };
}

const argumentValue = (arguments_: readonly string[], name: string): string => {
  const index = arguments_.indexOf(name);
  const value = index < 0 ? undefined : arguments_[index + 1];

  if (value === undefined) {
    throw new Error(`Missing command argument ${name}`);
  }

  return value;
};

const createRecordingWrangler = (): RecordingWrangler => {
  const objects = new Map<string, string>();
  let writes = 0;

  return {
    objects,
    putCount: () => writes,
    runCommand: (arguments_) => {
      const operation = arguments_[2];
      const objectPath = arguments_[3];

      if (objectPath === undefined) {
        throw new Error("Missing Wrangler R2 object path");
      }

      if (operation === "get") {
        const value = objects.get(objectPath);

        if (value === undefined) {
          return { status: 1, stdout: "", stderr: "The specified key does not exist" };
        }

        writeFileSync(argumentValue(arguments_, "--file"), value, "utf8");
        return { status: 0, stdout: "", stderr: "" };
      }

      if (operation === "put") {
        objects.set(objectPath, readFileSync(argumentValue(arguments_, "--file"), "utf8"));
        writes += 1;
        return { status: 0, stdout: "", stderr: "" };
      }

      if (operation === "delete") {
        objects.delete(objectPath);
        return { status: 0, stdout: "", stderr: "" };
      }

      throw new Error(`Unexpected Wrangler operation ${operation ?? "missing"}`);
    },
  };
};

describe("Wrangler local immutable R2 store", () => {
  it("reuses identical bytes and rejects a changed object at the same key", async () => {
    const wrangler = createRecordingWrangler();
    const store = createWranglerLocalR2Store({
      bucketName: "credtrail-badges-local",
      persistTo: ".wrangler/state",
      runCommand: wrangler.runCommand,
    });
    const object = {
      key: "tenants/tenant_123/assertions/assertion_123.jsonld",
      value: '{"id":"urn:credential:123"}',
      contentType: "application/ld+json",
      cacheControl: "public, max-age=31536000, immutable",
    };

    await expect(ensureWranglerLocalR2Object(store, object)).resolves.toMatchObject({
      status: "seeded",
      key: object.key,
    });
    await expect(ensureWranglerLocalR2Object(store, object)).resolves.toMatchObject({
      status: "reused",
      key: object.key,
    });
    await expect(
      ensureWranglerLocalR2Object(store, {
        ...object,
        value: '{"id":"urn:credential:changed"}',
      }),
    ).rejects.toThrow(`Local immutable R2 object differs at key "${object.key}"`);

    expect(wrangler.putCount()).toBe(1);
    expect(wrangler.objects.get(`credtrail-badges-local/${object.key}`)).toBe(object.value);
  });

  it("rejects direct overwrite attempts through the adapter", async () => {
    const wrangler = createRecordingWrangler();
    const store = createWranglerLocalR2Store({
      bucketName: "credtrail-badges-local",
      persistTo: ".wrangler/state",
      runCommand: wrangler.runCommand,
    });

    await expect(store.put("immutable/key", "first")).resolves.not.toBeNull();
    await expect(store.put("immutable/key", "second")).resolves.toBeNull();

    expect(wrangler.putCount()).toBe(1);
    expect(wrangler.objects.get("credtrail-badges-local/immutable/key")).toBe("first");
  });

  it("serializes independent writers before checking immutable state", async () => {
    const wrangler = createRecordingWrangler();
    const config = {
      bucketName: "credtrail-badges-local",
      persistTo: ".wrangler/state",
      runCommand: wrangler.runCommand,
    };
    const firstStore = createWranglerLocalR2Store(config);
    const secondStore = createWranglerLocalR2Store(config);
    const [first, second] = await Promise.all([
      firstStore.put("immutable/concurrent-key", "first"),
      secondStore.put("immutable/concurrent-key", "second"),
    ]);

    expect([first, second].filter((result) => result !== null)).toHaveLength(1);
    expect(wrangler.putCount()).toBe(1);
    expect(wrangler.objects.get("credtrail-badges-local/immutable/concurrent-key")).toBe("first");
  });

  it("treats concurrent identical ensure operations as one seed and one replay", async () => {
    const wrangler = createRecordingWrangler();
    const config = {
      bucketName: "credtrail-badges-local",
      persistTo: ".wrangler/state",
      runCommand: wrangler.runCommand,
    };
    const object = {
      key: "immutable/concurrent-ensure",
      value: "same bytes",
      contentType: "text/plain",
      cacheControl: "public, max-age=31536000, immutable",
    };

    const results = await Promise.all([
      ensureWranglerLocalR2Object(createWranglerLocalR2Store(config), object),
      ensureWranglerLocalR2Object(createWranglerLocalR2Store(config), object),
    ]);

    expect(results.map((result) => result.status).sort()).toEqual(["reused", "seeded"]);
    expect(wrangler.putCount()).toBe(1);
  });

  it("reconciles an identical object written after the initial read", async () => {
    const value = "same bytes";
    let reads = 0;
    const store: ImmutableCredentialStore = {
      head: () => Promise.resolve(null),
      get: () => {
        reads += 1;
        return Promise.resolve(
          reads === 1
            ? null
            : {
                size: value.length,
                text: () => Promise.resolve(value),
              },
        );
      },
      put: () => Promise.resolve(null),
      delete: () => Promise.resolve(),
    };

    await expect(
      ensureWranglerLocalR2Object(store, {
        key: "immutable/race-winner",
        value,
        contentType: "text/plain",
        cacheControl: "public, max-age=31536000, immutable",
      }),
    ).resolves.toEqual({
      status: "reused",
      key: "immutable/race-winner",
      size: value.length,
    });
  });

  it("rejects the losing concurrent ensure operation when its bytes differ", async () => {
    const wrangler = createRecordingWrangler();
    const config = {
      bucketName: "credtrail-badges-local",
      persistTo: ".wrangler/state",
      runCommand: wrangler.runCommand,
    };
    const key = "immutable/concurrent-conflict";
    const outcomes = await Promise.allSettled([
      ensureWranglerLocalR2Object(createWranglerLocalR2Store(config), {
        key,
        value: "first",
        contentType: "text/plain",
        cacheControl: "public, max-age=31536000, immutable",
      }),
      ensureWranglerLocalR2Object(createWranglerLocalR2Store(config), {
        key,
        value: "second",
        contentType: "text/plain",
        cacheControl: "public, max-age=31536000, immutable",
      }),
    ]);

    expect(outcomes.filter((outcome) => outcome.status === "fulfilled")).toHaveLength(1);
    expect(outcomes.filter((outcome) => outcome.status === "rejected")).toHaveLength(1);
    expect(wrangler.putCount()).toBe(1);
  });
});

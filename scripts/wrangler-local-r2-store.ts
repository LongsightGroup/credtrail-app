import { spawnSync } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

import type { ImmutableCredentialStore } from "@credtrail/core-domain";

interface WranglerCommandResult {
  readonly status: number | null;
  readonly stdout: string;
  readonly stderr: string;
}

type RunWranglerCommand = (arguments_: readonly string[]) => WranglerCommandResult;

/** Configuration for the Wrangler-backed local immutable-object adapter. */
export interface WranglerLocalR2StoreConfig {
  readonly bucketName: string;
  readonly persistTo: string;
  readonly runCommand?: RunWranglerCommand | undefined;
}

/** One immutable local R2 object to create or verify. */
export interface EnsureWranglerLocalR2ObjectInput {
  readonly key: string;
  readonly value: string;
  readonly contentType: string;
  readonly cacheControl: string;
}

/** Result of creating or reusing one immutable local R2 object. */
export interface EnsuredWranglerLocalR2Object {
  readonly status: "seeded" | "reused";
  readonly key: string;
  readonly size: number;
}

const defaultRunWranglerCommand: RunWranglerCommand = (arguments_) => {
  const result = spawnSync("pnpm", ["exec", "wrangler", ...arguments_], {
    cwd: process.cwd(),
    encoding: "utf8",
    timeout: 2 * 60_000,
  });

  if (result.error !== undefined) {
    throw new Error(`Unable to run Wrangler: ${result.error.message}`);
  }

  return {
    status: result.status,
    stdout: result.stdout,
    stderr: result.stderr,
  };
};

const wranglerLocalR2ObjectPath = (bucketName: string, key: string): string => {
  return `${bucketName}/${key.replaceAll("%", "%25")}`;
};

const OBJECT_WRITE_LOCK_RETRY_MS = 25;
const OBJECT_WRITE_LOCK_TIMEOUT_MS = 30_000;
const OBJECT_WRITE_LOCK_OWNER_FILE = "owner";

const wait = async (milliseconds: number): Promise<void> => {
  await new Promise<void>((resolveWait) => {
    setTimeout(resolveWait, milliseconds);
  });
};

const errorCode = (error: unknown): string | null => {
  if (error === null || typeof error !== "object" || !("code" in error)) {
    return null;
  }

  return typeof error.code === "string" ? error.code : null;
};

const objectWriteLockDirectory = (identity: string): string => {
  const digest = createHash("sha256").update(identity).digest("hex");
  return join(tmpdir(), `credtrail-local-r2-${digest}.lock`);
};

const releaseObjectWriteLock = (lockDirectory: string, ownerToken: string): void => {
  let recordedOwner: string;

  try {
    recordedOwner = readFileSync(join(lockDirectory, OBJECT_WRITE_LOCK_OWNER_FILE), "utf8");
  } catch {
    return;
  }

  if (recordedOwner === ownerToken) {
    rmSync(lockDirectory, { recursive: true, force: true });
  }
};

const withObjectWriteLock = async <Result>(
  identity: string,
  operation: () => Result,
): Promise<Result> => {
  const lockDirectory = objectWriteLockDirectory(identity);
  const deadline = Date.now() + OBJECT_WRITE_LOCK_TIMEOUT_MS;
  const ownerToken = `${process.pid}:${randomUUID()}`;

  while (true) {
    try {
      mkdirSync(lockDirectory);
      writeFileSync(join(lockDirectory, OBJECT_WRITE_LOCK_OWNER_FILE), ownerToken, {
        encoding: "utf8",
        flag: "wx",
      });
      break;
    } catch (error: unknown) {
      if (errorCode(error) !== "EEXIST") {
        releaseObjectWriteLock(lockDirectory, ownerToken);
        throw error;
      }

      if (Date.now() >= deadline) {
        throw new Error(`Timed out waiting for local R2 immutable-object lock "${identity}"`);
      }

      await wait(OBJECT_WRITE_LOCK_RETRY_MS);
    }
  }

  try {
    return operation();
  } finally {
    releaseObjectWriteLock(lockDirectory, ownerToken);
  }
};

const isMissingLocalR2ObjectResult = (output: string): boolean => {
  return /specified key does not exist|no such key|not found/iu.test(output);
};

const commandFailureDetail = (result: WranglerCommandResult): string => {
  return `${result.stderr}\n${result.stdout}`.trim();
};

const withTemporaryFile = <Result>(
  prefix: string,
  operation: (filePath: string) => Result,
): Result => {
  const temporaryDirectory = mkdtempSync(join(tmpdir(), prefix));
  const temporaryFile = join(temporaryDirectory, "object");

  try {
    return operation(temporaryFile);
  } finally {
    rmSync(temporaryDirectory, { recursive: true, force: true });
  }
};

/**
 * Creates the sole local-development adapter for immutable objects persisted through Wrangler R2.
 * The adapter rejects every overwrite; callers may use `ensureWranglerLocalR2Object` for replay.
 */
export const createWranglerLocalR2Store = (
  config: WranglerLocalR2StoreConfig,
): ImmutableCredentialStore => {
  const runCommand = config.runCommand ?? defaultRunWranglerCommand;
  const objectBodies = new Map<string, string>();
  const objectPath = (key: string): string => wranglerLocalR2ObjectPath(config.bucketName, key);
  const objectLockIdentity = (key: string): string => {
    return `${resolve(config.persistTo)}\0${config.bucketName}\0${key}`;
  };

  const loadObject = (key: string): string | null => {
    const cached = objectBodies.get(key);

    if (cached !== undefined) {
      return cached;
    }

    const persisted = withTemporaryFile("credtrail-local-r2-read-", (temporaryFile) => {
      const result = runCommand([
        "r2",
        "object",
        "get",
        objectPath(key),
        "--file",
        temporaryFile,
        "--local",
        "--persist-to",
        config.persistTo,
      ]);

      if (result.status === 0) {
        return readFileSync(temporaryFile, "utf8");
      }

      const detail = commandFailureDetail(result);

      if (isMissingLocalR2ObjectResult(detail)) {
        return null;
      }

      throw new Error(
        `Unable to read local R2 object "${objectPath(key)}"${
          detail.length === 0 ? "" : `: ${detail}`
        }`,
      );
    });

    if (persisted !== null) {
      objectBodies.set(key, persisted);
    }

    return persisted;
  };

  return {
    head: (key) => Promise.resolve(loadObject(key) === null ? null : { key }),
    get: (key) => {
      const body = loadObject(key);
      return Promise.resolve(
        body === null
          ? null
          : {
              size: new TextEncoder().encode(body).byteLength,
              text: () => Promise.resolve(body),
            },
      );
    },
    put: async (key, value, options) => {
      return withObjectWriteLock(objectLockIdentity(key), () => {
        if (loadObject(key) !== null) {
          return null;
        }

        const result = withTemporaryFile("credtrail-local-r2-write-", (temporaryFile) => {
          writeFileSync(temporaryFile, value, "utf8");
          return runCommand([
            "r2",
            "object",
            "put",
            objectPath(key),
            "--file",
            temporaryFile,
            "--content-type",
            options?.httpMetadata?.contentType ?? "application/octet-stream",
            "--cache-control",
            options?.httpMetadata?.cacheControl ?? "public, max-age=31536000, immutable",
            "--local",
            "--persist-to",
            config.persistTo,
          ]);
        });

        if (result.status !== 0) {
          const detail = commandFailureDetail(result);
          throw new Error(
            `Unable to write local R2 object "${objectPath(key)}"${
              detail.length === 0 ? "" : `: ${detail}`
            }`,
          );
        }

        objectBodies.set(key, value);
        const size = new TextEncoder().encode(value).byteLength;

        return {
          key,
          etag: "local-dev-seed",
          version: "local-dev-seed",
          size,
          uploaded: new Date(),
        };
      });
    },
    delete: async (key) => {
      await withObjectWriteLock(objectLockIdentity(key), () => {
        const result = runCommand([
          "r2",
          "object",
          "delete",
          objectPath(key),
          "--local",
          "--persist-to",
          config.persistTo,
        ]);

        if (result.status !== 0) {
          const detail = commandFailureDetail(result);

          if (!isMissingLocalR2ObjectResult(detail)) {
            throw new Error(
              `Unable to delete local R2 object "${objectPath(key)}"${
                detail.length === 0 ? "" : `: ${detail}`
              }`,
            );
          }
        }

        objectBodies.delete(key);
      });
    },
  };
};

/** Ensures one local R2 object exists without permitting its immutable bytes to change. */
export const ensureWranglerLocalR2Object = async (
  store: ImmutableCredentialStore,
  input: EnsureWranglerLocalR2ObjectInput,
): Promise<EnsuredWranglerLocalR2Object> => {
  const existing = await store.get(input.key);
  const size = new TextEncoder().encode(input.value).byteLength;

  if (existing !== null) {
    const existingValue = await existing.text();

    if (existingValue !== input.value) {
      throw new Error(`Local immutable R2 object differs at key "${input.key}"`);
    }

    return { status: "reused", key: input.key, size };
  }

  const stored = await store.put(input.key, input.value, {
    httpMetadata: {
      contentType: input.contentType,
      cacheControl: input.cacheControl,
    },
  });

  if (stored === null) {
    const concurrentlyStored = await store.get(input.key);

    if (concurrentlyStored === null || (await concurrentlyStored.text()) !== input.value) {
      throw new Error(`Local immutable R2 object differs at key "${input.key}"`);
    }

    return { status: "reused", key: input.key, size };
  }

  return { status: "seeded", key: stored.key, size: stored.size };
};

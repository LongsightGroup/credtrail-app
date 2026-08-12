import { beforeEach, describe, expect, it, vi } from "vitest";
import { runImmutableCredentialStoreContract } from "./immutable-credential-store-contract";

interface MockCommand {
  commandType: "head" | "get" | "put" | "delete";
  input: Record<string, unknown>;
}

interface StoredMockObject {
  body: string;
  metadata: Record<string, string> | undefined;
  contentType: string | undefined;
  cacheControl: string | undefined;
  etag: string;
  versionId: string;
}

const s3MockState = vi.hoisted(() => {
  return {
    sentCommands: [] as MockCommand[],
    objects: new Map<string, StoredMockObject>(),
    sequence: 0,
    omitGetContentLength: false,
  };
});

const notFoundError = (): Error & { name: string; $metadata: { httpStatusCode: number } } => {
  const error = new Error("Not found") as Error & {
    name: string;
    $metadata: { httpStatusCode: number };
  };
  error.name = "NotFound";
  error.$metadata = { httpStatusCode: 404 };
  return error;
};

const preconditionError = (): Error & { name: string; $metadata: { httpStatusCode: number } } => {
  const error = new Error("Precondition failed") as Error & {
    name: string;
    $metadata: { httpStatusCode: number };
  };
  error.name = "PreconditionFailed";
  error.$metadata = { httpStatusCode: 412 };
  return error;
};

const defaultSendHandler = (command: MockCommand): Promise<unknown> => {
  const bucket = command.input.Bucket;
  const key = command.input.Key;

  if (typeof bucket !== "string" || typeof key !== "string") {
    throw new Error("Bucket and Key are required");
  }

  switch (command.commandType) {
    case "head": {
      const found = s3MockState.objects.get(`${bucket}/${key}`);

      if (found === undefined) {
        return Promise.reject(notFoundError());
      }

      return Promise.resolve({
        ETag: found.etag,
      });
    }
    case "get": {
      const found = s3MockState.objects.get(`${bucket}/${key}`);

      if (found === undefined) {
        return Promise.reject(notFoundError());
      }

      return Promise.resolve({
        Body: {
          transformToString: (): Promise<string> => Promise.resolve(found.body),
        },
        ...(s3MockState.omitGetContentLength
          ? {}
          : { ContentLength: new TextEncoder().encode(found.body).byteLength }),
      });
    }
    case "put": {
      const objectKey = `${bucket}/${key}`;
      const ifNoneMatch = command.input.IfNoneMatch;
      const existing = s3MockState.objects.get(objectKey);

      if (ifNoneMatch === "*" && existing !== undefined) {
        return Promise.reject(preconditionError());
      }

      const body = command.input.Body;

      if (typeof body !== "string") {
        throw new Error("Mock S3 put expects string body");
      }

      s3MockState.sequence += 1;
      const nextSequence = String(s3MockState.sequence);
      const stored: StoredMockObject = {
        body,
        metadata:
          command.input.Metadata !== undefined
            ? (command.input.Metadata as Record<string, string>)
            : undefined,
        contentType:
          typeof command.input.ContentType === "string" ? command.input.ContentType : undefined,
        cacheControl:
          typeof command.input.CacheControl === "string" ? command.input.CacheControl : undefined,
        etag: `"etag-${nextSequence}"`,
        versionId: `version-${nextSequence}`,
      };
      s3MockState.objects.set(objectKey, stored);

      return Promise.resolve({
        ETag: stored.etag,
        VersionId: stored.versionId,
      });
    }
    case "delete": {
      const objectKey = `${bucket}/${key}`;
      const existing = s3MockState.objects.get(objectKey);

      if (existing === undefined) {
        return Promise.reject(notFoundError());
      }

      s3MockState.objects.delete(objectKey);
      return Promise.resolve({});
    }
  }
};

vi.mock("@aws-sdk/client-s3", () => {
  class S3Client {
    public send(command: MockCommand): Promise<unknown> {
      s3MockState.sentCommands.push(command);
      return defaultSendHandler(command);
    }
  }

  class HeadObjectCommand {
    public readonly commandType = "head" as const;
    public readonly input: Record<string, unknown>;

    public constructor(input: Record<string, unknown>) {
      this.input = input;
    }
  }

  class GetObjectCommand {
    public readonly commandType = "get" as const;
    public readonly input: Record<string, unknown>;

    public constructor(input: Record<string, unknown>) {
      this.input = input;
    }
  }

  class PutObjectCommand {
    public readonly commandType = "put" as const;
    public readonly input: Record<string, unknown>;

    public constructor(input: Record<string, unknown>) {
      this.input = input;
    }
  }

  class DeleteObjectCommand {
    public readonly commandType = "delete" as const;
    public readonly input: Record<string, unknown>;

    public constructor(input: Record<string, unknown>) {
      this.input = input;
    }
  }

  return {
    S3Client,
    HeadObjectCommand,
    GetObjectCommand,
    PutObjectCommand,
    DeleteObjectCommand,
  };
});

import { createS3ImmutableCredentialStore } from "./s3-immutable-credential-store";

describe("createS3ImmutableCredentialStore", () => {
  beforeEach(() => {
    s3MockState.sentCommands.length = 0;
    s3MockState.objects.clear();
    s3MockState.sequence = 0;
    s3MockState.omitGetContentLength = false;
  });

  const createStore = (): ReturnType<typeof createS3ImmutableCredentialStore> => {
    return createS3ImmutableCredentialStore({
      bucket: "credtrail-objects",
      region: "us-east-1",
      accessKeyId: "test-access-key",
      secretAccessKey: "test-secret-key",
      endpoint: "http://minio:9000",
      forcePathStyle: true,
    });
  };

  describe("contract", () => {
    runImmutableCredentialStoreContract({
      createStore,
    });
  });

  it("sets immutable-write and metadata fields on put", async () => {
    const store = createStore();
    const stored = await store.put("tenants/a/assertions/1.jsonld", '{"v":1}', {
      httpMetadata: {
        contentType: "application/ld+json",
        cacheControl: "public, max-age=31536000, immutable",
      },
      customMetadata: {
        tenantId: "a",
      },
    });

    expect(stored).not.toBeNull();
    const putCommand = s3MockState.sentCommands.find((command) => command.commandType === "put");
    expect(putCommand?.input).toMatchObject({
      Bucket: "credtrail-objects",
      Key: "tenants/a/assertions/1.jsonld",
      IfNoneMatch: "*",
      ContentType: "application/ld+json",
      CacheControl: "public, max-age=31536000, immutable",
      Metadata: {
        tenantId: "a",
      },
    });
    expect(
      s3MockState.objects.get("credtrail-objects/tenants/a/assertions/1.jsonld"),
    ).toMatchObject({
      contentType: "application/ld+json",
      cacheControl: "public, max-age=31536000, immutable",
      metadata: {
        tenantId: "a",
      },
    });
  });

  it("rejects get responses without trustworthy size metadata", async () => {
    const store = createStore();
    await store.put("tenants/a/assertions/1.jsonld", '{"v":1}');
    s3MockState.omitGetContentLength = true;

    await expect(store.get("tenants/a/assertions/1.jsonld")).rejects.toThrowError(
      "did not include a valid content length",
    );
  });
});

import {
  DeleteObjectCommand,
  GetObjectCommand,
  HeadObjectCommand,
  PutObjectCommand,
  S3Client,
} from "@aws-sdk/client-s3";
import type { ImmutableCredentialStore } from "@credtrail/core-domain";

interface CreateS3ImmutableCredentialStoreOptions {
  bucket: string;
  region: string;
  endpoint?: string;
  forcePathStyle?: boolean;
  accessKeyId: string;
  secretAccessKey: string;
  sessionToken?: string;
}

interface AwsErrorLike {
  name?: string;
  message?: string;
  $metadata?: {
    httpStatusCode?: number;
  };
}

const asAwsErrorLike = (error: unknown): AwsErrorLike => {
  if (error === null || typeof error !== "object") {
    return {};
  }

  return error as AwsErrorLike;
};

const statusCodeFromError = (error: unknown): number | undefined => {
  return asAwsErrorLike(error).$metadata?.httpStatusCode;
};

const errorNameFromError = (error: unknown): string => {
  return asAwsErrorLike(error).name ?? "";
};

const isNotFoundError = (error: unknown): boolean => {
  const statusCode = statusCodeFromError(error);
  const name = errorNameFromError(error);
  return statusCode === 404 || name === "NotFound" || name === "NoSuchKey";
};

const isConflictError = (error: unknown): boolean => {
  const statusCode = statusCodeFromError(error);
  const name = errorNameFromError(error);
  return statusCode === 412 || name === "PreconditionFailed";
};

const readBodyAsText = async (body: unknown): Promise<string> => {
  if (body !== null && typeof body === "object" && "transformToString" in body) {
    const transformToString = (body as { transformToString: () => Promise<string> })
      .transformToString;
    return transformToString();
  }

  if (body instanceof Uint8Array) {
    return new TextDecoder().decode(body);
  }

  if (typeof body === "string") {
    return body;
  }

  if (
    body !== null &&
    typeof body === "object" &&
    Symbol.asyncIterator in (body as Record<PropertyKey, unknown>)
  ) {
    const chunks: Uint8Array[] = [];

    for await (const chunk of body as AsyncIterable<unknown>) {
      if (chunk instanceof Uint8Array) {
        chunks.push(chunk);
        continue;
      }

      if (typeof chunk === "string") {
        chunks.push(new TextEncoder().encode(chunk));
        continue;
      }

      throw new Error("Unexpected S3 response chunk type");
    }

    const totalLength = chunks.reduce((acc, chunk) => acc + chunk.length, 0);
    const merged = new Uint8Array(totalLength);
    let offset = 0;

    for (const chunk of chunks) {
      merged.set(chunk, offset);
      offset += chunk.length;
    }

    return new TextDecoder().decode(merged);
  }

  throw new Error("Unable to read S3 object body");
};

export const createS3ImmutableCredentialStore = (
  options: CreateS3ImmutableCredentialStoreOptions,
): ImmutableCredentialStore => {
  const client = new S3Client({
    region: options.region,
    ...(options.endpoint === undefined ? {} : { endpoint: options.endpoint }),
    ...(options.forcePathStyle === undefined ? {} : { forcePathStyle: options.forcePathStyle }),
    credentials: {
      accessKeyId: options.accessKeyId,
      secretAccessKey: options.secretAccessKey,
      ...(options.sessionToken === undefined ? {} : { sessionToken: options.sessionToken }),
    },
  });

  return {
    async head(key) {
      try {
        await client.send(
          new HeadObjectCommand({
            Bucket: options.bucket,
            Key: key,
          }),
        );
      } catch (error: unknown) {
        if (isNotFoundError(error)) {
          return null;
        }

        throw error;
      }

      return {
        key,
      };
    },
    async get(key) {
      try {
        const object = (await client.send(
          new GetObjectCommand({
            Bucket: options.bucket,
            Key: key,
          }),
        )) as { Body?: unknown; ContentLength?: unknown };

        if (object.Body === undefined) {
          return null;
        }

        if (
          typeof object.ContentLength !== "number" ||
          !Number.isSafeInteger(object.ContentLength) ||
          object.ContentLength < 0
        ) {
          throw new Error(`S3 object "${key}" did not include a valid content length`);
        }

        return {
          size: object.ContentLength,
          text: () => readBodyAsText(object.Body),
        };
      } catch (error: unknown) {
        if (isNotFoundError(error)) {
          return null;
        }

        throw error;
      }
    },
    async put(key, value, putOptions) {
      try {
        const result = (await client.send(
          new PutObjectCommand({
            Bucket: options.bucket,
            Key: key,
            Body: value,
            ContentType: putOptions?.httpMetadata?.contentType,
            CacheControl: putOptions?.httpMetadata?.cacheControl,
            Metadata: putOptions?.customMetadata,
            IfNoneMatch: "*",
          }),
        )) as { ETag?: string; VersionId?: string };

        return {
          key,
          etag: result.ETag ?? "",
          version: result.VersionId ?? "",
          size: new TextEncoder().encode(value).length,
          uploaded: new Date(),
        };
      } catch (error: unknown) {
        if (isConflictError(error)) {
          return null;
        }

        throw error;
      }
    },
    async delete(key) {
      try {
        await client.send(
          new DeleteObjectCommand({
            Bucket: options.bucket,
            Key: key,
          }),
        );
      } catch (error: unknown) {
        if (isNotFoundError(error)) {
          return;
        }

        throw error;
      }
    },
  };
};

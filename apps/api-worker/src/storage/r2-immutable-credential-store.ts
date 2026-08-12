import type { ImmutableCredentialStore } from "@credtrail/core-domain";

export const createR2ImmutableCredentialStore = (bucket: R2Bucket): ImmutableCredentialStore => {
  return {
    async head(key) {
      const object = await bucket.head(key);

      if (object === null) {
        return null;
      }

      return {
        key: object.key,
      };
    },
    async get(key) {
      const object = await bucket.get(key);

      if (object === null) {
        return null;
      }

      return {
        size: object.size,
        text: () => object.text(),
      };
    },
    async put(key, value, options) {
      const object = await bucket.put(key, value, {
        ...(options?.httpMetadata === undefined ? {} : { httpMetadata: options.httpMetadata }),
        ...(options?.customMetadata === undefined
          ? {}
          : { customMetadata: options.customMetadata }),
        onlyIf: {
          etagDoesNotMatch: "*",
        },
      });

      if (object === null) {
        return null;
      }

      return {
        key: object.key,
        etag: object.etag,
        version: object.version,
        size: object.size,
        uploaded: object.uploaded,
      };
    },
    async delete(key) {
      await bucket.delete(key);
    },
  };
};

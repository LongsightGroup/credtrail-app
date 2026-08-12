import type { ImmutableCredentialStore } from "@credtrail/core-domain";
import { describe, expect, it } from "vitest";
import {
  BADGE_TEMPLATE_IMAGE_MAX_BYTES,
  BADGE_TEMPLATE_IMAGE_MAX_FILENAME_CHARACTERS,
  readBadgeTemplateImage,
  storeBadgeTemplateImage,
} from "./template-image-storage";

const storedImage = (overrides: Record<string, unknown> = {}): string => {
  return JSON.stringify({
    version: 1,
    mimeType: "image/png",
    byteSize: 8,
    base64Data: "iVBORw0KGgo=",
    uploadedAt: "2026-08-12T10:00:00.000Z",
    originalFilename: "badge.png",
    ...overrides,
  });
};

const imageStore = (serialized: string, declaredSize?: number): ImmutableCredentialStore => ({
  head: () => Promise.resolve(null),
  get: () =>
    Promise.resolve({
      size: declaredSize ?? new TextEncoder().encode(serialized).byteLength,
      text: () => Promise.resolve(serialized),
    }),
  put: () => Promise.resolve(null),
  delete: () => Promise.resolve(),
});

const imageIds = {
  tenantId: "tenant_123",
  badgeTemplateId: "template_123",
  assetId: "asset_456",
};

describe("readBadgeTemplateImage", () => {
  it("loads a bounded valid image payload", async () => {
    await expect(
      readBadgeTemplateImage(imageStore(storedImage()), imageIds),
    ).resolves.toMatchObject({
      status: "found",
      image: { mimeType: "image/png", byteSize: 8 },
    });
  });

  it("rejects an oversized declared image before decoding it", async () => {
    await expect(
      readBadgeTemplateImage(
        imageStore(storedImage({ byteSize: BADGE_TEMPLATE_IMAGE_MAX_BYTES + 1 })),
        imageIds,
      ),
    ).resolves.toEqual({ status: "invalid", reason: "payload_too_large" });
  });

  it("rejects an oversized encoded payload before decoding it", async () => {
    const oversizedBase64 = "A".repeat(Math.ceil(BADGE_TEMPLATE_IMAGE_MAX_BYTES / 3) * 4 + 1);

    await expect(
      readBadgeTemplateImage(
        imageStore(
          storedImage({ byteSize: BADGE_TEMPLATE_IMAGE_MAX_BYTES, base64Data: oversizedBase64 }),
        ),
        imageIds,
      ),
    ).resolves.toEqual({ status: "invalid", reason: "payload_too_large" });
  });

  it("rejects an oversized object from metadata before reading its body", async () => {
    let bodyRead = false;
    const store: ImmutableCredentialStore = {
      ...imageStore(storedImage()),
      get: () =>
        Promise.resolve({
          size: BADGE_TEMPLATE_IMAGE_MAX_BYTES * 2,
          text: () => {
            bodyRead = true;
            return Promise.resolve(storedImage());
          },
        }),
    };

    await expect(readBadgeTemplateImage(store, imageIds)).resolves.toEqual({
      status: "invalid",
      reason: "payload_too_large",
    });
    expect(bodyRead).toBe(false);
  });
});

describe("storeBadgeTemplateImage", () => {
  it("rejects filenames that would violate the stored-object contract before writing", async () => {
    let putCalled = false;
    const store: ImmutableCredentialStore = {
      ...imageStore(storedImage()),
      put: () => {
        putCalled = true;
        return Promise.resolve(null);
      },
    };

    await expect(
      storeBadgeTemplateImage(store, {
        ...imageIds,
        mimeType: "image/png",
        bytes: new Uint8Array([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
        originalFilename: "a".repeat(BADGE_TEMPLATE_IMAGE_MAX_FILENAME_CHARACTERS + 1),
      }),
    ).rejects.toThrow("filename must not exceed");
    expect(putCalled).toBe(false);
  });
});

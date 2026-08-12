import type { ImmutableCredentialStore } from "@credtrail/core-domain";
import {
  badgeTemplateImageObjectKey,
  badgeTemplateImagePublicPath,
  readBadgeTemplateImage,
  storeBadgeTemplateImage,
  type BadgeTemplateImageMimeType,
} from "../apps/api-worker/src/badges/template-image-storage";
import { canonicalAppUrl } from "../apps/api-worker/src/http/canonical-app-url";

const sha256Hex = async (bytes: Uint8Array): Promise<string> => {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
  return [...digest].map((value) => value.toString(16).padStart(2, "0")).join("");
};

const bytesEqual = (left: Uint8Array, right: Uint8Array): boolean => {
  return (
    left.byteLength === right.byteLength && left.every((value, index) => value === right[index])
  );
};

/**
 * Ensures local demo artwork exists at a content-addressed immutable key.
 * Repeated seeds reuse identical bytes; changed artwork receives a new public URI.
 */
export const ensureLocalDevBadgeTemplateArtwork = async (input: {
  readonly store: ImmutableCredentialStore;
  readonly publicAppOrigin: string;
  readonly tenantId: string;
  readonly badgeTemplateId: string;
  readonly mimeType: BadgeTemplateImageMimeType;
  readonly bytes: Uint8Array;
  readonly originalFilename: string;
}): Promise<string> => {
  const assetId = `sha256_${await sha256Hex(input.bytes)}`;
  const objectIds = {
    tenantId: input.tenantId,
    badgeTemplateId: input.badgeTemplateId,
    assetId,
  };
  const existing = await readBadgeTemplateImage(input.store, objectIds);

  if (existing.status === "invalid") {
    throw new Error(
      `Local demo artwork is invalid for immutable key "${badgeTemplateImageObjectKey(objectIds)}" (${existing.reason})`,
    );
  }

  if (existing.status === "found" && !bytesEqual(existing.image.bytes, input.bytes)) {
    throw new Error(
      `Local demo artwork differs at content-addressed key "${badgeTemplateImageObjectKey(objectIds)}"`,
    );
  }

  if (existing.status === "missing") {
    await storeBadgeTemplateImage(input.store, {
      ...objectIds,
      mimeType: input.mimeType,
      bytes: input.bytes,
      originalFilename: input.originalFilename,
    });
  }

  return canonicalAppUrl(input.publicAppOrigin, badgeTemplateImagePublicPath(objectIds));
};

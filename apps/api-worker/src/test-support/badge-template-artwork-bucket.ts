import { badgeTemplateImageObjectKey } from "../badges/template-image-storage";

interface BadgeTemplateArtworkFixture {
  readonly tenantId: string;
  readonly badgeTemplateId: string;
  readonly assetId: string;
}

const pngObject = JSON.stringify({
  version: 1,
  mimeType: "image/png",
  byteSize: 8,
  base64Data: "iVBORw0KGgo=",
  uploadedAt: "2026-02-18T12:00:00.000Z",
  originalFilename: "badge.png",
});

const defaultArtwork: BadgeTemplateArtworkFixture = {
  tenantId: "tenant_123",
  badgeTemplateId: "badge_template_001",
  assetId: "asset_typescript",
};

/** Creates a test R2 bucket containing valid immutable badge-template artwork. */
export const createBadgeTemplateArtworkBucket = (
  fixtures: readonly BadgeTemplateArtworkFixture[] = [defaultArtwork],
): R2Bucket => {
  const objects = new Map(
    fixtures.map((fixture) => [badgeTemplateImageObjectKey(fixture), pngObject] as const),
  );

  return {
    get: async (key: string) => {
      const serialized = objects.get(key);

      if (serialized === undefined) {
        return null;
      }

      return {
        size: new TextEncoder().encode(serialized).byteLength,
        text: async () => serialized,
      };
    },
    // SAFETY: issuance tests exercise only the R2 get contract used to resolve artwork snapshots.
  } as unknown as R2Bucket;
};

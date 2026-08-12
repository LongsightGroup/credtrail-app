import type { ImmutableCredentialStore } from "@credtrail/core-domain";
import type { BadgeTemplateRecord } from "@credtrail/db";
import { describe, expect, it } from "vitest";
import { badgeTemplateImageObjectKey } from "./template-image-storage";
import {
  resolveExpectedBadgeTemplateRevision,
  resolveIssuableBadgeAchievementSnapshot,
} from "./badge-achievement-snapshot";

const snapshot = (imageUri: string | null) => ({
  badgeTemplateId: "template_123",
  title: "Immutable badge",
  description: null,
  criteriaUri: null,
  imageUri,
  trustedCredentialMetadataJson: null,
});

const storedPng = JSON.stringify({
  version: 1,
  mimeType: "image/png",
  byteSize: 8,
  base64Data: "iVBORw0KGgo=",
  uploadedAt: "2026-08-12T10:00:00.000Z",
  originalFilename: "badge.png",
});

const imageStore = (storedValue: string | null): ImmutableCredentialStore => ({
  head: () => Promise.resolve(null),
  get: (key) =>
    Promise.resolve(
      key ===
        badgeTemplateImageObjectKey({
          tenantId: "tenant_123",
          badgeTemplateId: "template_123",
          assetId: "asset_456",
        }) && storedValue !== null
        ? {
            size: new TextEncoder().encode(storedValue).byteLength,
            text: () => Promise.resolve(storedValue),
          }
        : null,
    ),
  put: () => Promise.resolve(null),
  delete: () => Promise.resolve(),
});

const unavailableImageStore = (): ImmutableCredentialStore => ({
  ...imageStore(null),
  get: () => Promise.reject(new Error("R2 unavailable")),
});

const template = (imageUri: string | null): BadgeTemplateRecord => ({
  id: "template_123",
  tenantId: "tenant_123",
  slug: "immutable-badge",
  title: "Immutable badge",
  description: null,
  criteriaUri: null,
  imageUri,
  trustedCredentialMetadataJson: null,
  createdByUserId: "usr_123",
  ownerOrgUnitId: "tenant_123:org:institution",
  governanceMetadataJson: null,
  isArchived: false,
  createdAt: "2026-08-12T09:00:00.000Z",
  updatedAt: "2026-08-12T10:00:00.000Z",
});

describe("resolveIssuableBadgeAchievementSnapshot", () => {
  it("verifies managed artwork and canonicalizes the public host", async () => {
    const result = await resolveIssuableBadgeAchievementSnapshot({
      store: imageStore(storedPng),
      publicAppOrigin: "https://credtrail.org",
      tenantId: "tenant_123",
      snapshot: snapshot(
        "https://old-host.example/badges/assets/tenant_123/template_123/asset_456",
      ),
    });

    expect(result).toEqual({
      status: "resolved",
      snapshot: snapshot("https://credtrail.org/badges/assets/tenant_123/template_123/asset_456"),
    });
  });

  it("rejects external and missing artwork", async () => {
    await expect(
      resolveIssuableBadgeAchievementSnapshot({
        store: imageStore(storedPng),
        publicAppOrigin: "https://credtrail.org",
        tenantId: "tenant_123",
        snapshot: snapshot(null),
      }),
    ).resolves.toEqual({ status: "missing_artwork" });

    await expect(
      resolveIssuableBadgeAchievementSnapshot({
        store: imageStore(storedPng),
        publicAppOrigin: "https://credtrail.org",
        tenantId: "tenant_123",
        snapshot: snapshot("https://cdn.example/badge.png"),
      }),
    ).resolves.toEqual({ status: "unmanaged_artwork" });

    await expect(
      resolveIssuableBadgeAchievementSnapshot({
        store: imageStore(null),
        publicAppOrigin: "https://credtrail.org",
        tenantId: "tenant_123",
        snapshot: snapshot("https://credtrail.org/badges/assets/tenant_123/template_123/asset_456"),
      }),
    ).resolves.toEqual({ status: "missing_artwork" });
  });

  it("returns typed failures for corrupt artwork and unavailable storage", async () => {
    await expect(
      resolveIssuableBadgeAchievementSnapshot({
        store: imageStore("not-json"),
        publicAppOrigin: "https://credtrail.org",
        tenantId: "tenant_123",
        snapshot: snapshot("https://credtrail.org/badges/assets/tenant_123/template_123/asset_456"),
      }),
    ).resolves.toEqual({ status: "invalid_artwork" });

    const result = await resolveIssuableBadgeAchievementSnapshot({
      store: unavailableImageStore(),
      publicAppOrigin: "https://credtrail.org",
      tenantId: "tenant_123",
      snapshot: snapshot("https://credtrail.org/badges/assets/tenant_123/template_123/asset_456"),
    });

    expect(result).toMatchObject({ status: "storage_unavailable" });
  });
});

describe("resolveExpectedBadgeTemplateRevision", () => {
  it("returns the exact verified template revision", async () => {
    const badgeTemplate = template(
      "https://credtrail.org/badges/assets/tenant_123/template_123/asset_456",
    );

    await expect(
      resolveExpectedBadgeTemplateRevision({
        store: imageStore(storedPng),
        publicAppOrigin: "https://credtrail.org",
        template: badgeTemplate,
      }),
    ).resolves.toEqual({
      status: "ready",
      revision: {
        updatedAt: badgeTemplate.updatedAt,
        achievementSnapshot: snapshot(badgeTemplate.imageUri),
      },
    });
  });

  it("distinguishes missing, unmanaged, and non-canonical artwork", async () => {
    await expect(
      resolveExpectedBadgeTemplateRevision({
        store: imageStore(storedPng),
        publicAppOrigin: "https://credtrail.org",
        template: template(null),
      }),
    ).resolves.toEqual({ status: "missing_artwork" });
    await expect(
      resolveExpectedBadgeTemplateRevision({
        store: imageStore(storedPng),
        publicAppOrigin: "https://credtrail.org",
        template: template("https://cdn.example/badge.png"),
      }),
    ).resolves.toEqual({ status: "unmanaged_artwork" });
    await expect(
      resolveExpectedBadgeTemplateRevision({
        store: imageStore(storedPng),
        publicAppOrigin: "https://credtrail.org",
        template: template(
          "https://old-host.example/badges/assets/tenant_123/template_123/asset_456",
        ),
      }),
    ).resolves.toEqual({ status: "unmanaged_artwork" });
  });

  it("does not throw when stored artwork is corrupt or temporarily unavailable", async () => {
    await expect(
      resolveExpectedBadgeTemplateRevision({
        store: imageStore("not-json"),
        publicAppOrigin: "https://credtrail.org",
        template: template("https://credtrail.org/badges/assets/tenant_123/template_123/asset_456"),
      }),
    ).resolves.toEqual({ status: "invalid_artwork" });

    await expect(
      resolveExpectedBadgeTemplateRevision({
        store: unavailableImageStore(),
        publicAppOrigin: "https://credtrail.org",
        template: template("https://credtrail.org/badges/assets/tenant_123/template_123/asset_456"),
      }),
    ).resolves.toMatchObject({ status: "storage_unavailable" });
  });
});

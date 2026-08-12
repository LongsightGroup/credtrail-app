import { describe, expect, it } from "vitest";

import {
  managedBadgeTemplateImagePath,
  resolveManagedBadgeTemplateImageReference,
  usesManagedBadgeTemplateImageReference,
} from "./managed-badge-template-image.js";

describe("managed badge-template image references", () => {
  it("builds and resolves the canonical immutable asset path", () => {
    const path = managedBadgeTemplateImagePath({
      tenantId: "tenant_123",
      badgeTemplateId: "badge_template_001",
      assetId: "asset_456",
    });

    expect(path).toBe("/badges/assets/tenant_123/badge_template_001/asset_456");
    expect(
      resolveManagedBadgeTemplateImageReference({
        imageUri: `https://private-worker.invalid${path}`,
        tenantId: "tenant_123",
        badgeTemplateId: "badge_template_001",
      }),
    ).toEqual({
      tenantId: "tenant_123",
      badgeTemplateId: "badge_template_001",
      assetId: "asset_456",
      path,
    });
  });

  it("rejects external artwork and another template's managed artwork", () => {
    expect(
      resolveManagedBadgeTemplateImageReference({
        imageUri: "https://cdn.example.edu/badges/example.png",
        tenantId: "tenant_123",
        badgeTemplateId: "badge_template_001",
      }),
    ).toBeNull();
    expect(
      resolveManagedBadgeTemplateImageReference({
        imageUri: "https://credtrail.test/badges/assets/tenant_123/other_template/asset_456",
        tenantId: "tenant_123",
        badgeTemplateId: "badge_template_001",
      }),
    ).toBeNull();
  });

  it("rejects mutable URL variants", () => {
    expect(
      resolveManagedBadgeTemplateImageReference({
        imageUri:
          "https://credtrail.test/badges/assets/tenant_123/badge_template_001/asset_456?revision=2",
        tenantId: "tenant_123",
        badgeTemplateId: "badge_template_001",
      }),
    ).toBeNull();
  });

  it("reports whether a template uses its own managed artwork namespace", () => {
    const identity = {
      tenantId: "tenant_123",
      badgeTemplateId: "badge_template_001",
    } as const;

    expect(
      usesManagedBadgeTemplateImageReference({
        ...identity,
        imageUri: "https://credtrail.test/badges/assets/tenant_123/badge_template_001/asset_456",
      }),
    ).toBe(true);
    expect(usesManagedBadgeTemplateImageReference({ ...identity, imageUri: null })).toBe(false);
    expect(
      usesManagedBadgeTemplateImageReference({
        ...identity,
        imageUri: "https://cdn.example.edu/badges/example.png",
      }),
    ).toBe(false);
  });
});

import { describe, expect, it } from "vitest";
import type { BadgeTemplateRecord } from "@credtrail/db";
import {
  buildBadgeTemplateFieldChanges,
  buildBadgeTemplateImageUriChange,
} from "./badge-template-audit-metadata";

const sampleTemplate = (overrides?: Partial<BadgeTemplateRecord>): BadgeTemplateRecord => {
  return {
    id: "badge_template_001",
    tenantId: "tenant_123",
    slug: "typescript-foundations",
    title: "TypeScript Foundations",
    description: "Awarded for TypeScript basics.",
    criteriaUri: "https://example.edu/criteria",
    imageUri: "https://example.edu/badges/typescript.png",
    createdByUserId: "usr_admin",
    ownerOrgUnitId: "tenant_123:org:institution",
    governanceMetadataJson: null,
    isArchived: false,
    createdAt: "2026-02-18T12:00:00.000Z",
    updatedAt: "2026-02-18T12:00:00.000Z",
    ...overrides,
  };
};

describe("badge template audit metadata", () => {
  it("builds field-level changes for template updates", () => {
    const existing = sampleTemplate();
    const updated = sampleTemplate({
      title: "TypeScript Foundations (2026)",
      slug: "typescript-foundations-2026",
    });

    const changes = buildBadgeTemplateFieldChanges(existing, updated, {
      title: "TypeScript Foundations (2026)",
      slug: "typescript-foundations-2026",
    });

    expect(changes).toEqual([
      {
        field: "slug",
        from: "typescript-foundations",
        to: "typescript-foundations-2026",
      },
      {
        field: "title",
        from: "TypeScript Foundations",
        to: "TypeScript Foundations (2026)",
      },
    ]);
  });

  it("builds image URI changes when artwork changes", () => {
    expect(
      buildBadgeTemplateImageUriChange(
        "https://example.edu/badges/old.png",
        "https://example.edu/badges/new.png",
      ),
    ).toEqual({
      field: "imageUri",
      from: "https://example.edu/badges/old.png",
      to: "https://example.edu/badges/new.png",
    });
    expect(
      buildBadgeTemplateImageUriChange(
        "https://example.edu/badges/old.png",
        "https://example.edu/badges/old.png",
      ),
    ).toBeNull();
  });
});

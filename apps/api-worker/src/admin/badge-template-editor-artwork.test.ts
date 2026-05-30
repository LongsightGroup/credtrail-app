import type { BadgeTemplateRecord } from "@credtrail/db";
import { describe, expect, it } from "vitest";
import { badgeTemplateEditorReadyState } from "./badge-template-editor-artwork";

const sampleTemplate = (input: Partial<BadgeTemplateRecord> = {}): BadgeTemplateRecord => {
  return {
    id: "badge_template_001",
    tenantId: "tenant_123",
    slug: "typescript",
    title: "TypeScript Foundations",
    description: "Foundational TypeScript skills.",
    criteriaUri: "https://example.edu/criteria",
    imageUri: "https://example.edu/badges/typescript.png",
    ownerOrgUnitId: "org_unit_root",
    createdByUserId: "usr_admin",
    governanceMetadataJson: null,
    isArchived: false,
    createdAt: "2026-01-01T00:00:00.000Z",
    updatedAt: "2026-01-02T00:00:00.000Z",
    ...input,
  };
};

describe("badgeTemplateEditorReadyState", () => {
  it("reports ready when artwork exists", () => {
    expect(badgeTemplateEditorReadyState(sampleTemplate())).toEqual({
      label: "Ready for rules",
      tone: "active",
    });
  });

  it("reports needs image when artwork is missing", () => {
    expect(badgeTemplateEditorReadyState(sampleTemplate({ imageUri: null }))).toEqual({
      label: "Needs image",
      tone: "warning",
    });
  });
});

import { expect, it } from "vitest";

import {
  createBadgeTemplateImageGeneration,
  findBadgeTemplateImageGenerationById,
  updateBadgeTemplateImageGeneration,
} from "./badge-template-images";
import {
  cleanupTestResources,
  createTestTenantFixture,
  describeDbIntegration,
  seedBadgeTemplate,
} from "./postgres-test-support";

describeDbIntegration("badge template image generations", () => {
  it("returns current generation state directly from create and update writes", async () => {
    const fixture = await createTestTenantFixture({
      displayName: "Badge Image Test Tenant",
    });

    try {
      const badgeTemplateId = await seedBadgeTemplate(fixture.db, {
        tenantId: fixture.tenantId,
      });
      const generation = await createBadgeTemplateImageGeneration(fixture.db, {
        tenantId: fixture.tenantId,
        badgeTemplateId,
        promptText: "A blue lightning bolt achievement badge",
        stylePreset: "minimal",
        accentColor: "#0055aa",
      });

      expect(generation).toMatchObject({
        tenantId: fixture.tenantId,
        badgeTemplateId,
        status: "queued",
        resultImageUri: null,
        completedAt: null,
      });

      const completedAt = "2026-08-13T10:15:00.000Z";
      const resultImageUri = "https://credtrail.org/badges/assets/test/generated-image";
      const updatedGeneration = await updateBadgeTemplateImageGeneration(fixture.db, {
        tenantId: fixture.tenantId,
        id: generation.id,
        status: "succeeded",
        resultImageUri,
        completedAt,
      });

      expect(updatedGeneration).toMatchObject({
        id: generation.id,
        status: "succeeded",
        resultImageUri,
        completedAt,
      });
      await expect(
        findBadgeTemplateImageGenerationById(fixture.db, fixture.tenantId, generation.id),
      ).resolves.toEqual(updatedGeneration);
    } finally {
      await cleanupTestResources(fixture.db, {
        tenantIds: [fixture.tenantId],
      });
    }
  });
});

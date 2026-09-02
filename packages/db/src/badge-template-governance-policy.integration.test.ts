import { expect, it } from "vitest";

import {
  compareAndSetBadgeTemplateGovernanceMetadata,
  findBadgeTemplateById,
} from "./badge-templates";
import {
  cleanupTestResources,
  createTestTenantFixture,
  describeDbIntegration,
  seedBadgeTemplate,
} from "./postgres-test-support";

describeDbIntegration("badge template governance policy updates with Postgres", () => {
  it("updates governance metadata within one tenant and returns the persisted record", async () => {
    const fixture = await createTestTenantFixture({
      displayName: "Badge Template Governance Tenant",
    });
    const otherFixture = await createTestTenantFixture({
      displayName: "Other Badge Template Governance Tenant",
    });

    try {
      const badgeTemplateId = await seedBadgeTemplate(fixture.db, {
        tenantId: fixture.tenantId,
      });
      const governanceMetadataJson = '{"stability":"institution_registry","approval":"registrar"}';

      await expect(
        compareAndSetBadgeTemplateGovernanceMetadata(fixture.db, {
          tenantId: otherFixture.tenantId,
          id: badgeTemplateId,
          expectedGovernanceMetadataJson: '{"stability":"institution_registry"}',
          governanceMetadataJson,
        }),
      ).resolves.toEqual({ status: "not_found" });

      const unchanged = await findBadgeTemplateById(fixture.db, fixture.tenantId, badgeTemplateId);
      expect(unchanged?.governanceMetadataJson).toBe('{"stability":"institution_registry"}');

      const updateResult = await compareAndSetBadgeTemplateGovernanceMetadata(fixture.db, {
        tenantId: fixture.tenantId,
        id: badgeTemplateId,
        expectedGovernanceMetadataJson: '{"stability":"institution_registry"}',
        governanceMetadataJson,
      });

      expect(updateResult.status).toBe("updated");
      const updated = await findBadgeTemplateById(fixture.db, fixture.tenantId, badgeTemplateId);
      expect(updated?.governanceMetadataJson).toBe(governanceMetadataJson);
      await expect(
        compareAndSetBadgeTemplateGovernanceMetadata(fixture.db, {
          tenantId: fixture.tenantId,
          id: badgeTemplateId,
          expectedGovernanceMetadataJson: '{"stability":"institution_registry"}',
          governanceMetadataJson: '{"stability":"changed"}',
        }),
      ).resolves.toEqual({ status: "conflict" });
    } finally {
      await cleanupTestResources(fixture.db, {
        tenantIds: [fixture.tenantId, otherFixture.tenantId],
      });
    }
  });
});

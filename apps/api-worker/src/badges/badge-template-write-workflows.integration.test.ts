import { findBadgeTemplateById, listAuditLogs } from "@credtrail/db";
import { expect, it } from "vitest";
import {
  cleanupTestResources,
  createTestTenantFixture,
  describeDbIntegration,
  seedBadgeTemplate,
  uniqueTestId,
} from "../../../../packages/db/src/postgres-test-support";
import { updateBadgeTemplateLtiPlacementPolicyWithAudit } from "./badge-template-write-workflows";

describeDbIntegration("badge template LMS placement policy workflow with Postgres", () => {
  it("persists the policy and audit record in one transaction", async () => {
    const fixture = await createTestTenantFixture({
      displayName: "LMS Placement Policy Tenant",
    });
    const userId = uniqueTestId("usr_lms_placement");

    try {
      await fixture.db
        .prepare("INSERT INTO users (id, email) VALUES (?, ?)")
        .bind(userId, `${userId}@example.edu`)
        .run();
      const badgeTemplateId = await seedBadgeTemplate(fixture.db, {
        tenantId: fixture.tenantId,
      });
      const existingTemplate = await findBadgeTemplateById(
        fixture.db,
        fixture.tenantId,
        badgeTemplateId,
      );

      expect(existingTemplate).not.toBeNull();
      if (existingTemplate === null) {
        throw new Error("Expected the seeded badge template to exist");
      }

      const result = await updateBadgeTemplateLtiPlacementPolicyWithAudit(fixture.db, {
        tenantId: fixture.tenantId,
        badgeTemplateId,
        existingTemplate,
        request: { enabled: true },
        actorUserId: userId,
        membershipRole: "admin",
      });

      expect(result.status).toBe("updated");
      const updatedTemplate = await findBadgeTemplateById(
        fixture.db,
        fixture.tenantId,
        badgeTemplateId,
      );
      expect(updatedTemplate?.governanceMetadataJson).toBe(
        '{"stability":"institution_registry","ltiInstructorPlacement":{"enabled":true}}',
      );

      const auditLogs = await listAuditLogs(fixture.db, {
        tenantId: fixture.tenantId,
        action: "badge_template.updated",
        targetType: "badge_template",
        targetId: badgeTemplateId,
      });
      expect(auditLogs).toHaveLength(1);
      expect(auditLogs[0]?.actorUserId).toBe(userId);
      expect(auditLogs[0]?.metadataJson).toBe(
        '{"role":"admin","changes":[{"field":"ltiInstructorPlacement","from":"Not allowed","to":"Allowed"}]}',
      );
    } finally {
      await cleanupTestResources(fixture.db, {
        tenantIds: [fixture.tenantId],
        userIds: [userId],
      });
    }
  });

  it("rolls back the policy write when its audit record cannot be persisted", async () => {
    const fixture = await createTestTenantFixture({
      displayName: "LMS Placement Audit Rollback Tenant",
    });

    try {
      const badgeTemplateId = await seedBadgeTemplate(fixture.db, {
        tenantId: fixture.tenantId,
      });
      const existingTemplate = await findBadgeTemplateById(
        fixture.db,
        fixture.tenantId,
        badgeTemplateId,
      );

      expect(existingTemplate).not.toBeNull();
      if (existingTemplate === null) {
        throw new Error("Expected the seeded badge template to exist");
      }

      const result = await updateBadgeTemplateLtiPlacementPolicyWithAudit(fixture.db, {
        tenantId: fixture.tenantId,
        badgeTemplateId,
        existingTemplate,
        request: { enabled: true },
        actorUserId: uniqueTestId("usr_missing"),
        membershipRole: "admin",
      });

      expect(result.status).toBe("persistence_failed");
      const unchangedTemplate = await findBadgeTemplateById(
        fixture.db,
        fixture.tenantId,
        badgeTemplateId,
      );
      expect(unchangedTemplate?.governanceMetadataJson).toBe(
        '{"stability":"institution_registry"}',
      );
    } finally {
      await cleanupTestResources(fixture.db, {
        tenantIds: [fixture.tenantId],
      });
    }
  });
});

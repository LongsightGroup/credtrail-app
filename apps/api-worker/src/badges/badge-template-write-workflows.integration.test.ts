import { findBadgeTemplateById, listAuditLogs } from "@credtrail/db";
import { expect, it } from "vitest";
import {
  cleanupTestResources,
  createTestTenantFixture,
  describeDbIntegration,
  seedBadgeTemplate,
  uniqueTestId,
} from "../../../../packages/db/src/postgres-test-support";
import { updateBadgeTemplateWithAudit } from "./badge-template-write-workflows";

describeDbIntegration("badge template write workflow with Postgres", () => {
  it("persists ordinary template changes with an audit record", async () => {
    const fixture = await createTestTenantFixture({ displayName: "Template Write Tenant" });
    const userId = uniqueTestId("usr_template_write");

    try {
      await fixture.db
        .prepare("INSERT INTO users (id, email) VALUES (?, ?)")
        .bind(userId, `${userId}@example.edu`)
        .run();
      const badgeTemplateId = await seedBadgeTemplate(fixture.db, { tenantId: fixture.tenantId });
      const existingTemplate = await findBadgeTemplateById(
        fixture.db,
        fixture.tenantId,
        badgeTemplateId,
      );

      if (existingTemplate === null) {
        throw new Error("Expected the seeded badge template to exist");
      }

      const updated = await updateBadgeTemplateWithAudit(fixture.db, {
        tenantId: fixture.tenantId,
        badgeTemplateId,
        existingTemplate,
        request: {
          slug: existingTemplate.slug,
          title: "Updated governed badge",
          description: existingTemplate.description,
          criteriaUri: existingTemplate.criteriaUri,
        },
        actorUserId: userId,
        membershipRole: "admin",
      });

      expect(updated?.title).toBe("Updated governed badge");
      const auditLogs = await listAuditLogs(fixture.db, {
        tenantId: fixture.tenantId,
        action: "badge_template.updated",
        targetType: "badge_template",
        targetId: badgeTemplateId,
      });
      expect(auditLogs).toHaveLength(1);
      expect(auditLogs[0]?.actorUserId).toBe(userId);
      expect(auditLogs[0]?.metadataJson).toContain('"field":"title"');
    } finally {
      await cleanupTestResources(fixture.db, {
        tenantIds: [fixture.tenantId],
        userIds: [userId],
      });
    }
  });
});

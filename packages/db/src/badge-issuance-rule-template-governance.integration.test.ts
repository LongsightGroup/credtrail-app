import { expect, it } from "vitest";

import * as dbModule from "./index";
import {
  cleanupTestResources,
  createBadgeRuleIntegrationFixture,
  describeDbIntegration,
  loadExpectedBadgeTemplateRevision,
  seedBadgeTemplate,
  selectCount,
} from "./postgres-test-support";

const createRuleWithVerifiedTemplate = async (
  fixture: Awaited<ReturnType<typeof createBadgeRuleIntegrationFixture>>,
  input: Omit<dbModule.CreateBadgeIssuanceRuleAuthoringInput, "expectedBadgeTemplateRevision">,
): Promise<dbModule.BadgeIssuanceRuleAuthoringResult> => {
  return dbModule.createBadgeIssuanceRuleWithAction(fixture.db, {
    ...input,
    expectedBadgeTemplateRevision: await loadExpectedBadgeTemplateRevision(fixture.db, {
      tenantId: input.tenantId,
      badgeTemplateId: input.badgeTemplateId,
    }),
  });
};

const updateRuleWithVerifiedTemplate = async (
  fixture: Awaited<ReturnType<typeof createBadgeRuleIntegrationFixture>>,
  input: Omit<dbModule.UpdateBadgeIssuanceRuleAuthoringInput, "expectedBadgeTemplateRevision">,
): Promise<dbModule.BadgeIssuanceRuleAuthoringResult> => {
  return dbModule.updateBadgeIssuanceRuleWithAction(fixture.db, {
    ...input,
    expectedBadgeTemplateRevision: await loadExpectedBadgeTemplateRevision(fixture.db, {
      tenantId: input.tenantId,
      badgeTemplateId: input.badgeTemplateId,
    }),
  });
};

describeDbIntegration("badge issuance rule template governance with Postgres", () => {
  it("requires explicit acknowledgement when any other rule version used the template", async () => {
    const fixture = await createBadgeRuleIntegrationFixture();

    try {
      const replacementTemplateIdValue = `${fixture.badgeTemplateId}_replacement`;
      const replacementTemplateId = await seedBadgeTemplate(fixture.db, {
        tenantId: fixture.tenantId,
        id: replacementTemplateIdValue,
        title: "Replacement achievement",
        imageUri: `https://credtrail.test/badges/assets/${fixture.tenantId}/${replacementTemplateIdValue}/asset_test`,
      });
      const ruleJson =
        '{"conditions":{"type":"grade_threshold","courseId":"course_101","minScore":80}}';
      const original = await createRuleWithVerifiedTemplate(fixture, {
        tenantId: fixture.tenantId,
        name: "Original template rule",
        badgeTemplateId: fixture.badgeTemplateId,
        badgeTemplateReuseAcknowledged: false,
        lmsProviderKind: "canvas",
        lmsConnectionId: fixture.lmsConnectionId,
        ruleJson,
        action: "save_draft",
        actorUserId: fixture.userId,
        actorRole: "admin",
      });

      expect(original.status).toBe("completed");

      if (original.status !== "completed") {
        throw new Error("Expected original authoring command to complete");
      }

      const moved = await updateRuleWithVerifiedTemplate(fixture, {
        tenantId: fixture.tenantId,
        ruleId: original.rule.id,
        name: "Original template rule",
        badgeTemplateId: replacementTemplateId,
        badgeTemplateReuseAcknowledged: false,
        lmsProviderKind: "canvas",
        lmsConnectionId: fixture.lmsConnectionId,
        ruleJson,
        action: "save_draft",
        actorUserId: fixture.userId,
        actorRole: "admin",
      });
      const historicalUsages = await dbModule.listBadgeTemplateRuleUsages(fixture.db, {
        tenantId: fixture.tenantId,
        badgeTemplateIds: [fixture.badgeTemplateId],
      });
      const rejected = await createRuleWithVerifiedTemplate(fixture, {
        tenantId: fixture.tenantId,
        name: "Unacknowledged reuse",
        badgeTemplateId: fixture.badgeTemplateId,
        badgeTemplateReuseAcknowledged: false,
        lmsProviderKind: "canvas",
        lmsConnectionId: fixture.lmsConnectionId,
        ruleJson,
        action: "save_draft",
        actorUserId: fixture.userId,
        actorRole: "admin",
      });
      const acknowledged = await createRuleWithVerifiedTemplate(fixture, {
        tenantId: fixture.tenantId,
        name: "Acknowledged reuse",
        badgeTemplateId: fixture.badgeTemplateId,
        badgeTemplateReuseAcknowledged: true,
        lmsProviderKind: "canvas",
        lmsConnectionId: fixture.lmsConnectionId,
        ruleJson,
        action: "save_draft",
        actorUserId: fixture.userId,
        actorRole: "admin",
      });

      expect(moved.status).toBe("completed");
      expect(historicalUsages).toMatchObject([
        {
          badgeTemplateId: fixture.badgeTemplateId,
          ruleId: original.rule.id,
          isActiveVersion: false,
        },
      ]);
      expect(rejected).toEqual({
        status: "failed",
        reason: "template_reuse_confirmation_required",
      });
      expect(acknowledged.status).toBe("completed");
    } finally {
      await cleanupTestResources(fixture.db, {
        tenantIds: [fixture.tenantId],
        userIds: [fixture.userId],
      });
    }
  });

  it("rejects rule authoring until external template artwork is uploaded to managed storage", async () => {
    const fixture = await createBadgeRuleIntegrationFixture();

    try {
      await fixture.db
        .prepare("UPDATE badge_templates SET image_uri = ? WHERE tenant_id = ? AND id = ?")
        .bind(
          "https://cdn.example.edu/badges/mutable.png",
          fixture.tenantId,
          fixture.badgeTemplateId,
        )
        .run();

      const result = await createRuleWithVerifiedTemplate(fixture, {
        tenantId: fixture.tenantId,
        name: "Unsafe artwork rule",
        badgeTemplateId: fixture.badgeTemplateId,
        badgeTemplateReuseAcknowledged: false,
        lmsProviderKind: "canvas",
        lmsConnectionId: fixture.lmsConnectionId,
        ruleJson: '{"conditions":{"type":"grade_threshold","courseId":"course_101","minScore":80}}',
        action: "save_draft",
        actorUserId: fixture.userId,
        actorRole: "admin",
      });
      const ruleCount = await selectCount(
        fixture.db,
        "SELECT COUNT(*) AS totalCount FROM badge_issuance_rules WHERE tenant_id = ?",
        [fixture.tenantId],
      );

      expect(result).toEqual({
        status: "failed",
        reason: "template_artwork_not_immutable",
      });
      expect(ruleCount).toBe(0);
    } finally {
      await cleanupTestResources(fixture.db, {
        tenantIds: [fixture.tenantId],
        userIds: [fixture.userId],
      });
    }
  });

  it("rejects a template revision that changed after artwork verification", async () => {
    const fixture = await createBadgeRuleIntegrationFixture();

    try {
      const verifiedRevision = await loadExpectedBadgeTemplateRevision(fixture.db, {
        tenantId: fixture.tenantId,
        badgeTemplateId: fixture.badgeTemplateId,
      });
      const changedAt = new Date(Date.parse(verifiedRevision.updatedAt) + 1_000).toISOString();
      await fixture.db
        .prepare(
          "UPDATE badge_templates SET title = ?, updated_at = ? WHERE tenant_id = ? AND id = ?",
        )
        .bind("Changed after verification", changedAt, fixture.tenantId, fixture.badgeTemplateId)
        .run();

      const result = await dbModule.createBadgeIssuanceRuleWithAction(fixture.db, {
        tenantId: fixture.tenantId,
        name: "Stale template rule",
        badgeTemplateId: fixture.badgeTemplateId,
        expectedBadgeTemplateRevision: verifiedRevision,
        badgeTemplateReuseAcknowledged: false,
        lmsProviderKind: "canvas",
        lmsConnectionId: fixture.lmsConnectionId,
        ruleJson: '{"conditions":{"type":"grade_threshold","courseId":"course_101","minScore":80}}',
        action: "save_draft",
        actorUserId: fixture.userId,
        actorRole: "admin",
      });

      expect(result).toEqual({ status: "failed", reason: "template_changed" });
    } finally {
      await cleanupTestResources(fixture.db, {
        tenantIds: [fixture.tenantId],
        userIds: [fixture.userId],
      });
    }
  });
});

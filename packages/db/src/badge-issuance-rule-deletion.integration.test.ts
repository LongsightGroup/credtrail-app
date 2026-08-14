import { expect, it } from "vitest";

import * as dbModule from "./index";
import { createBadgeIssuanceRuleVersion } from "./badge-issuance-rule-writes";
import { createFixtureRule } from "./badge-issuance-rule-test-fixtures";
import {
  cleanupTestResources,
  createBadgeRuleIntegrationFixture,
  describeDbIntegration,
  selectCount,
  uniqueTestId,
  type BadgeRuleIntegrationFixture,
} from "./postgres-test-support";

const deleteNeverActiveRule = (
  fixture: BadgeRuleIntegrationFixture,
  ruleId: string,
  actorUserId = fixture.userId,
): Promise<dbModule.DeleteNeverActiveBadgeIssuanceRuleResult> => {
  return dbModule.deleteNeverActiveBadgeIssuanceRule(fixture.db, {
    tenantId: fixture.tenantId,
    ruleId,
    actorUserId,
    actorRole: "admin",
  });
};

const createIncompleteRule = async (fixture: BadgeRuleIntegrationFixture): Promise<string> => {
  const ruleId = uniqueTestId("brl_incomplete");

  await fixture.db
    .prepare(
      `
      INSERT INTO badge_issuance_rules (
        id,
        tenant_id,
        name,
        description,
        badge_template_id,
        org_unit_id,
        owner_org_unit_id,
        lms_provider_kind,
        lms_connection_id,
        active_version_id,
        created_by_user_id,
        created_at,
        updated_at
      )
      SELECT
        ?,
        templates.tenant_id,
        'Incomplete cleanup rule',
        NULL,
        templates.id,
        templates.owner_org_unit_id,
        templates.owner_org_unit_id,
        'canvas',
        NULL,
        NULL,
        ?,
        CURRENT_TIMESTAMP,
        CURRENT_TIMESTAMP
      FROM badge_templates AS templates
      WHERE templates.tenant_id = ?
        AND templates.id = ?
    `,
    )
    .bind(ruleId, fixture.userId, fixture.tenantId, fixture.badgeTemplateId)
    .run();

  return ruleId;
};

describeDbIntegration("badge issuance rule deletion with Postgres", () => {
  it("blocks deletion when a rule has governed active history", async () => {
    const fixture = await createBadgeRuleIntegrationFixture();

    try {
      const created = await createFixtureRule(fixture);

      await fixture.db
        .prepare(
          `
          UPDATE badge_issuance_rule_versions
          SET status = 'active',
              activated_by_user_id = ?,
              activated_at = CURRENT_TIMESTAMP
          WHERE id = ?
        `,
        )
        .bind(fixture.userId, created.version.id)
        .run();
      await fixture.db
        .prepare("UPDATE badge_issuance_rules SET active_version_id = ? WHERE id = ?")
        .bind(created.version.id, created.rule.id)
        .run();

      const rejectedVersion = await createBadgeIssuanceRuleVersion(fixture.db, {
        tenantId: fixture.tenantId,
        ruleId: created.rule.id,
        ruleJson: '{"conditions":{"type":"grade_threshold","courseId":"course_101","minScore":90}}',
        changeSummary: "Rejected follow-up draft",
        createdByUserId: fixture.userId,
      });

      await fixture.db
        .prepare("UPDATE badge_issuance_rule_versions SET status = 'rejected' WHERE id = ?")
        .bind(rejectedVersion.id)
        .run();

      const result = await deleteNeverActiveRule(fixture, created.rule.id);
      const ruleCount = await selectCount(
        fixture.db,
        "SELECT COUNT(*) AS totalCount FROM badge_issuance_rules WHERE tenant_id = ? AND id = ?",
        [fixture.tenantId, created.rule.id],
      );
      const versionCount = await selectCount(
        fixture.db,
        "SELECT COUNT(*) AS totalCount FROM badge_issuance_rule_versions WHERE tenant_id = ? AND rule_id = ?",
        [fixture.tenantId, created.rule.id],
      );

      expect(result.status).toBe("not_deletable");
      expect(ruleCount).toBe(1);
      expect(versionCount).toBe(2);
    } finally {
      await cleanupTestResources(fixture.db, {
        tenantIds: [fixture.tenantId],
        userIds: [fixture.userId],
      });
    }
  });

  it("deletes and audits never-active draft and rejected rules with real cascades", async () => {
    const fixture = await createBadgeRuleIntegrationFixture();

    try {
      const created = await createFixtureRule(fixture);

      await fixture.db
        .prepare("UPDATE badge_issuance_rule_versions SET status = 'rejected' WHERE id = ?")
        .bind(created.version.id)
        .run();

      await createBadgeIssuanceRuleVersion(fixture.db, {
        tenantId: fixture.tenantId,
        ruleId: created.rule.id,
        ruleJson: '{"conditions":{"type":"grade_threshold","courseId":"course_101","minScore":90}}',
        changeSummary: "New draft",
        createdByUserId: fixture.userId,
      });

      const result = await deleteNeverActiveRule(fixture, created.rule.id);
      const ruleCount = await selectCount(
        fixture.db,
        "SELECT COUNT(*) AS totalCount FROM badge_issuance_rules WHERE tenant_id = ?",
        [fixture.tenantId],
      );
      const versionCount = await selectCount(
        fixture.db,
        "SELECT COUNT(*) AS totalCount FROM badge_issuance_rule_versions WHERE tenant_id = ?",
        [fixture.tenantId],
      );
      const approvalStepCount = await selectCount(
        fixture.db,
        "SELECT COUNT(*) AS totalCount FROM badge_issuance_rule_approval_steps WHERE tenant_id = ?",
        [fixture.tenantId],
      );
      const auditLogs = await dbModule.listAuditLogs(fixture.db, {
        tenantId: fixture.tenantId,
        action: "badge_rule.deleted",
        targetId: created.rule.id,
      });

      expect(result.status).toBe("deleted");
      expect(ruleCount).toBe(0);
      expect(versionCount).toBe(0);
      expect(approvalStepCount).toBe(0);
      expect(auditLogs).toHaveLength(1);
      expect(auditLogs[0]?.actorUserId).toBe(fixture.userId);
      expect(auditLogs[0]?.metadataJson).toContain('"role":"admin"');
    } finally {
      await cleanupTestResources(fixture.db, {
        tenantIds: [fixture.tenantId],
        userIds: [fixture.userId],
      });
    }
  });

  it("deletes and audits incomplete rules that never received a first version", async () => {
    const fixture = await createBadgeRuleIntegrationFixture();

    try {
      const ruleId = await createIncompleteRule(fixture);
      const result = await deleteNeverActiveRule(fixture, ruleId);
      const ruleCount = await selectCount(
        fixture.db,
        "SELECT COUNT(*) AS totalCount FROM badge_issuance_rules WHERE tenant_id = ? AND id = ?",
        [fixture.tenantId, ruleId],
      );
      const auditLogs = await dbModule.listAuditLogs(fixture.db, {
        tenantId: fixture.tenantId,
        action: "badge_rule.deleted",
        targetId: ruleId,
      });

      expect(result).toMatchObject({
        status: "deleted",
        rule: { id: ruleId },
        versions: [],
      });
      expect(ruleCount).toBe(0);
      expect(auditLogs).toHaveLength(1);
    } finally {
      await cleanupTestResources(fixture.db, {
        tenantIds: [fixture.tenantId],
        userIds: [fixture.userId],
      });
    }
  });

  it("rolls back deletion when the audit record cannot be written", async () => {
    const fixture = await createBadgeRuleIntegrationFixture();

    try {
      const created = await createFixtureRule(fixture);

      await expect(
        deleteNeverActiveRule(fixture, created.rule.id, uniqueTestId("usr_missing")),
      ).rejects.toThrow("foreign key constraint");

      const ruleCount = await selectCount(
        fixture.db,
        "SELECT COUNT(*) AS totalCount FROM badge_issuance_rules WHERE tenant_id = ? AND id = ?",
        [fixture.tenantId, created.rule.id],
      );
      const versionCount = await selectCount(
        fixture.db,
        "SELECT COUNT(*) AS totalCount FROM badge_issuance_rule_versions WHERE tenant_id = ? AND rule_id = ?",
        [fixture.tenantId, created.rule.id],
      );
      const auditLogs = await dbModule.listAuditLogs(fixture.db, {
        tenantId: fixture.tenantId,
        action: "badge_rule.deleted",
        targetId: created.rule.id,
      });

      expect(ruleCount).toBe(1);
      expect(versionCount).toBe(1);
      expect(auditLogs).toHaveLength(0);
    } finally {
      await cleanupTestResources(fixture.db, {
        tenantIds: [fixture.tenantId],
        userIds: [fixture.userId],
      });
    }
  });
});

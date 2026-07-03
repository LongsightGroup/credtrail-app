import { expect, it } from "vitest";

import * as dbModule from "./index";
import { createFixtureRule } from "./badge-issuance-rule-test-fixtures";
import {
  cleanupTestResources,
  createBadgeRuleIntegrationFixture,
  createDepartmentCourseOrgUnitHierarchy,
  describeDbIntegration,
  selectCount,
} from "./postgres-test-support";

describeDbIntegration("badge issuance rule draft DB helpers with Postgres", () => {
  it("persists incomplete builder drafts without creating rule versions", async () => {
    const fixture = await createBadgeRuleIntegrationFixture();

    try {
      const draft = await dbModule.saveBadgeIssuanceRuleBuilderDraft(fixture.db, {
        tenantId: fixture.tenantId,
        userId: fixture.userId,
        currentStep: "metadata",
        draftJson: JSON.stringify({
          badgeTemplateId: fixture.badgeTemplateId,
          definitionJson: "",
        }),
      });
      const loaded = await dbModule.findBadgeIssuanceRuleBuilderDraft(fixture.db, {
        tenantId: fixture.tenantId,
        userId: fixture.userId,
      });
      const versionCount = await selectCount(
        fixture.db,
        "SELECT COUNT(*) AS totalCount FROM badge_issuance_rule_versions WHERE tenant_id = ?",
        [fixture.tenantId],
      );

      expect(draft.currentStep).toBe("metadata");
      expect(loaded?.draftJson).toContain(fixture.badgeTemplateId);
      expect(versionCount).toBe(0);
    } finally {
      await cleanupTestResources(fixture.db, {
        tenantIds: [fixture.tenantId],
        userIds: [fixture.userId],
      });
    }
  });

  it("deletes saved builder drafts for a user and rule scope", async () => {
    const fixture = await createBadgeRuleIntegrationFixture();

    try {
      await dbModule.saveBadgeIssuanceRuleBuilderDraft(fixture.db, {
        tenantId: fixture.tenantId,
        userId: fixture.userId,
        currentStep: "conditions",
        draftJson: JSON.stringify({ definitionJson: "{}" }),
      });

      const deleted = await dbModule.deleteBadgeIssuanceRuleBuilderDraft(fixture.db, {
        tenantId: fixture.tenantId,
        userId: fixture.userId,
      });
      const loaded = await dbModule.findBadgeIssuanceRuleBuilderDraft(fixture.db, {
        tenantId: fixture.tenantId,
        userId: fixture.userId,
      });

      expect(deleted).toBe(true);
      expect(loaded).toBeNull();
    } finally {
      await cleanupTestResources(fixture.db, {
        tenantIds: [fixture.tenantId],
        userIds: [fixture.userId],
      });
    }
  });

  it("creates and lists rules by explicit org-unit descendant scope", async () => {
    const fixture = await createBadgeRuleIntegrationFixture();

    try {
      const { department, course } = await createDepartmentCourseOrgUnitHierarchy(fixture.db, {
        tenantId: fixture.tenantId,
        userId: fixture.userId,
      });
      const created = await dbModule.createBadgeIssuanceRule(fixture.db, {
        tenantId: fixture.tenantId,
        name: "CS101 Rule",
        badgeTemplateId: fixture.badgeTemplateId,
        orgUnitId: course.id,
        lmsProviderKind: "canvas",
        lmsConnectionId: fixture.lmsConnectionId,
        ruleJson: '{"conditions":{"type":"grade_threshold","courseId":"course_101","minScore":80}}',
        createdByUserId: fixture.userId,
      });

      const scopedRules = await dbModule.listBadgeIssuanceRules(fixture.db, {
        tenantId: fixture.tenantId,
        scope: {
          type: "descendants",
          rootOrgUnitIds: [department.id],
        },
      });
      const siblingRules = await dbModule.listBadgeIssuanceRules(fixture.db, {
        tenantId: fixture.tenantId,
        scope: {
          type: "org_unit",
          orgUnitId: department.id,
        },
      });
      const updated = await dbModule.updateBadgeIssuanceRuleDraft(fixture.db, {
        tenantId: fixture.tenantId,
        ruleId: created.rule.id,
        name: "CS101 Rule Revised",
        badgeTemplateId: fixture.badgeTemplateId,
        lmsProviderKind: "canvas",
        lmsConnectionId: fixture.lmsConnectionId,
        ruleJson: '{"conditions":{"type":"grade_threshold","courseId":"course_101","minScore":85}}',
        createdByUserId: fixture.userId,
      });

      expect(created.rule.orgUnitId).toBe(course.id);
      expect(created.rule.ownerOrgUnitId).toBe(`${fixture.tenantId}:org:institution`);
      expect(scopedRules.map((rule) => rule.id)).toContain(created.rule.id);
      expect(siblingRules.map((rule) => rule.id)).not.toContain(created.rule.id);
      expect(updated.status === "updated" ? updated.rule.orgUnitId : null).toBe(course.id);
    } finally {
      await cleanupTestResources(fixture.db, {
        tenantIds: [fixture.tenantId],
        userIds: [fixture.userId],
      });
    }
  });

  it("allows course org units under departments and programs only", async () => {
    const fixture = await createBadgeRuleIntegrationFixture();

    try {
      const { college, department, course, program, programCourse } =
        await createDepartmentCourseOrgUnitHierarchy(fixture.db, {
          tenantId: fixture.tenantId,
          userId: fixture.userId,
          includeProgram: true,
        });

      await expect(
        dbModule.createTenantOrgUnit(fixture.db, {
          tenantId: fixture.tenantId,
          unitType: "course",
          slug: "invalid-course",
          displayName: "Invalid Course",
          parentOrgUnitId: college.id,
          createdByUserId: fixture.userId,
        }),
      ).rejects.toThrow("requires parent org unit type department or program");

      expect(course.parentOrgUnitId).toBe(department.id);
      expect(programCourse?.parentOrgUnitId).toBe(program?.id);
    } finally {
      await cleanupTestResources(fixture.db, {
        tenantIds: [fixture.tenantId],
        userIds: [fixture.userId],
      });
    }
  });

  it("updates a rejected latest version by creating the next draft version", async () => {
    const fixture = await createBadgeRuleIntegrationFixture();

    try {
      const created = await createFixtureRule(fixture);

      await fixture.db
        .prepare("UPDATE badge_issuance_rule_versions SET status = 'rejected' WHERE id = ?")
        .bind(created.version.id)
        .run();

      const result = await dbModule.updateBadgeIssuanceRuleDraft(fixture.db, {
        tenantId: fixture.tenantId,
        ruleId: created.rule.id,
        name: "CS101 Rule Revised",
        description: "Updated description.",
        badgeTemplateId: fixture.badgeTemplateId,
        lmsProviderKind: "canvas",
        lmsConnectionId: fixture.lmsConnectionId,
        ruleJson: '{"conditions":{"type":"grade_threshold","courseId":"course_101","minScore":90}}',
        changeSummary: "Raise score threshold",
        createdByUserId: fixture.userId,
      });

      expect(result.status).toBe("updated");
      expect(result.status === "updated" ? result.version.versionNumber : null).toBe(2);
      expect(result.status === "updated" ? result.version.status : null).toBe("draft");

      const savedRule = await dbModule.findBadgeIssuanceRuleById(
        fixture.db,
        fixture.tenantId,
        created.rule.id,
      );
      const versions = await dbModule.listBadgeIssuanceRuleVersions(fixture.db, {
        tenantId: fixture.tenantId,
        ruleId: created.rule.id,
      });
      const approvalStepCount = await selectCount(
        fixture.db,
        "SELECT COUNT(*) AS totalCount FROM badge_issuance_rule_approval_steps WHERE tenant_id = ?",
        [fixture.tenantId],
      );

      expect(savedRule?.name).toBe("CS101 Rule Revised");
      expect(savedRule?.description).toBe("Updated description.");
      expect(versions).toHaveLength(2);
      expect(versions[0]?.versionNumber).toBe(2);
      expect(approvalStepCount).toBe(0);
    } finally {
      await cleanupTestResources(fixture.db, {
        tenantIds: [fixture.tenantId],
        userIds: [fixture.userId],
      });
    }
  });

  it("allows active rules to carry an editable latest replacement draft", async () => {
    const fixture = await createBadgeRuleIntegrationFixture();

    try {
      const created = await createFixtureRule(fixture);

      await fixture.db
        .prepare(
          `
          UPDATE badge_issuance_rule_versions
          SET status = 'active', activated_by_user_id = ?, activated_at = ?
          WHERE id = ?
        `,
        )
        .bind(fixture.userId, new Date().toISOString(), created.version.id)
        .run();
      await fixture.db
        .prepare("UPDATE badge_issuance_rules SET active_version_id = ? WHERE id = ?")
        .bind(created.version.id, created.rule.id)
        .run();

      const draftVersion = await dbModule.createBadgeIssuanceRuleVersion(fixture.db, {
        tenantId: fixture.tenantId,
        ruleId: created.rule.id,
        ruleJson: '{"conditions":{"type":"grade_threshold","courseId":"course_101","minScore":85}}',
        changeSummary: "Replacement draft",
        createdByUserId: fixture.userId,
      });
      const versionsBeforeUpdate = await dbModule.listBadgeIssuanceRuleVersions(fixture.db, {
        tenantId: fixture.tenantId,
        ruleId: created.rule.id,
      });
      const activeRule = await dbModule.findBadgeIssuanceRuleById(
        fixture.db,
        fixture.tenantId,
        created.rule.id,
      );

      expect(activeRule?.activeVersionId).toBe(created.version.id);
      expect(
        activeRule === null
          ? false
          : dbModule.canEditBadgeIssuanceRuleDraft(activeRule, versionsBeforeUpdate),
      ).toBe(true);

      const result = await dbModule.updateBadgeIssuanceRuleDraft(fixture.db, {
        tenantId: fixture.tenantId,
        ruleId: created.rule.id,
        name: "CS101 Replacement",
        badgeTemplateId: fixture.badgeTemplateId,
        lmsProviderKind: "canvas",
        lmsConnectionId: fixture.lmsConnectionId,
        ruleJson: '{"conditions":{"type":"grade_threshold","courseId":"course_101","minScore":90}}',
        changeSummary: "Raise score threshold",
        createdByUserId: fixture.userId,
      });

      expect(draftVersion.status).toBe("draft");
      expect(result.status).toBe("updated");
      expect(result.status === "updated" ? result.rule.activeVersionId : null).toBe(
        created.version.id,
      );
      expect(result.status === "updated" ? result.version.versionNumber : null).toBe(3);
    } finally {
      await cleanupTestResources(fixture.db, {
        tenantIds: [fixture.tenantId],
        userIds: [fixture.userId],
      });
    }
  });

  it("blocks pending latest versions without changing metadata", async () => {
    const fixture = await createBadgeRuleIntegrationFixture();

    try {
      const created = await createFixtureRule(fixture);

      await fixture.db
        .prepare("UPDATE badge_issuance_rule_versions SET status = 'pending_approval' WHERE id = ?")
        .bind(created.version.id)
        .run();

      const result = await dbModule.updateBadgeIssuanceRuleDraft(fixture.db, {
        tenantId: fixture.tenantId,
        ruleId: created.rule.id,
        name: "Should not save",
        badgeTemplateId: fixture.badgeTemplateId,
        lmsProviderKind: "canvas",
        lmsConnectionId: fixture.lmsConnectionId,
        ruleJson: '{"conditions":{"type":"grade_threshold","courseId":"course_101","minScore":90}}',
        createdByUserId: fixture.userId,
      });

      const savedRule = await dbModule.findBadgeIssuanceRuleById(
        fixture.db,
        fixture.tenantId,
        created.rule.id,
      );
      const versions = await dbModule.listBadgeIssuanceRuleVersions(fixture.db, {
        tenantId: fixture.tenantId,
        ruleId: created.rule.id,
      });

      expect(result.status).toBe("not_editable");
      expect(savedRule?.name).toBe("CS101 Rule");
      expect(versions).toHaveLength(1);
    } finally {
      await cleanupTestResources(fixture.db, {
        tenantIds: [fixture.tenantId],
        userIds: [fixture.userId],
      });
    }
  });

  it("rolls back metadata updates when badge template ownership cannot be resolved", async () => {
    const fixture = await createBadgeRuleIntegrationFixture();

    try {
      const created = await createFixtureRule(fixture);

      await fixture.db
        .prepare("UPDATE badge_issuance_rule_versions SET status = 'rejected' WHERE id = ?")
        .bind(created.version.id)
        .run();

      await expect(
        dbModule.updateBadgeIssuanceRuleDraft(fixture.db, {
          tenantId: fixture.tenantId,
          ruleId: created.rule.id,
          name: "Partially saved name",
          badgeTemplateId: "missing_badge_template",
          lmsProviderKind: "canvas",
          lmsConnectionId: fixture.lmsConnectionId,
          ruleJson:
            '{"conditions":{"type":"grade_threshold","courseId":"course_101","minScore":90}}',
          createdByUserId: fixture.userId,
        }),
      ).rejects.toThrow('Badge template "missing_badge_template" not found');

      const savedRule = await dbModule.findBadgeIssuanceRuleById(
        fixture.db,
        fixture.tenantId,
        created.rule.id,
      );
      const versions = await dbModule.listBadgeIssuanceRuleVersions(fixture.db, {
        tenantId: fixture.tenantId,
        ruleId: created.rule.id,
      });

      expect(savedRule?.name).toBe("CS101 Rule");
      expect(savedRule?.badgeTemplateId).toBe(fixture.badgeTemplateId);
      expect(versions).toHaveLength(1);
    } finally {
      await cleanupTestResources(fixture.db, {
        tenantIds: [fixture.tenantId],
        userIds: [fixture.userId],
      });
    }
  });

  it("blocks historical active rules from draft delete", async () => {
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

      const rejectedVersion = await dbModule.createBadgeIssuanceRuleVersion(fixture.db, {
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

      const result = await dbModule.deleteDraftBadgeIssuanceRule(fixture.db, {
        tenantId: fixture.tenantId,
        ruleId: created.rule.id,
      });
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

  it("deletes never-active draft and rejected rules with real cascade behavior", async () => {
    const fixture = await createBadgeRuleIntegrationFixture();

    try {
      const created = await createFixtureRule(fixture);

      await fixture.db
        .prepare("UPDATE badge_issuance_rule_versions SET status = 'rejected' WHERE id = ?")
        .bind(created.version.id)
        .run();

      await dbModule.createBadgeIssuanceRuleVersion(fixture.db, {
        tenantId: fixture.tenantId,
        ruleId: created.rule.id,
        ruleJson: '{"conditions":{"type":"grade_threshold","courseId":"course_101","minScore":90}}',
        changeSummary: "New draft",
        createdByUserId: fixture.userId,
      });

      const result = await dbModule.deleteDraftBadgeIssuanceRule(fixture.db, {
        tenantId: fixture.tenantId,
        ruleId: created.rule.id,
      });
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

      expect(result.status).toBe("deleted");
      expect(ruleCount).toBe(0);
      expect(versionCount).toBe(0);
      expect(approvalStepCount).toBe(0);
    } finally {
      await cleanupTestResources(fixture.db, {
        tenantIds: [fixture.tenantId],
        userIds: [fixture.userId],
      });
    }
  });
});

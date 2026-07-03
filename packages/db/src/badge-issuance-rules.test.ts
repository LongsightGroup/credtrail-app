import { readFileSync } from "node:fs";

import { describe, expect, it } from "vitest";

import * as dbModule from "./index";
import {
  cleanupTestResources,
  createBadgeRuleIntegrationFixture,
  describeDbIntegration,
  selectCount,
  type BadgeRuleIntegrationFixture,
} from "./postgres-test-support";

const createFixtureRule = async (
  fixture: BadgeRuleIntegrationFixture,
): Promise<dbModule.CreateBadgeIssuanceRuleResult> => {
  return dbModule.createBadgeIssuanceRule(fixture.db, {
    tenantId: fixture.tenantId,
    name: "CS101 Rule",
    description: "Award for CS101 completion.",
    badgeTemplateId: fixture.badgeTemplateId,
    lmsProviderKind: "canvas",
    lmsConnectionId: fixture.lmsConnectionId,
    ruleJson: '{"conditions":{"type":"grade_threshold","courseId":"course_101","minScore":80}}',
    changeSummary: "Initial draft",
    createdByUserId: fixture.userId,
  });
};

describe("badge rule review queue schema", () => {
  it("adds badge rule review queue columns through a forward migration", () => {
    const sql = readFileSync(
      new URL("../migrations/0040_badge_rule_review_queue.sql", import.meta.url),
      "utf8",
    );

    expect(sql).toContain("ALTER TABLE badge_issuance_rule_evaluations");
    expect(sql).toContain("ADD COLUMN IF NOT EXISTS review_status TEXT");
    expect(sql).toContain("ADD COLUMN IF NOT EXISTS review_decision TEXT");
    expect(sql).toContain("ADD COLUMN IF NOT EXISTS review_comment TEXT");
    expect(sql).toContain("ADD COLUMN IF NOT EXISTS reviewed_by_user_id TEXT");
    expect(sql).toContain("ADD COLUMN IF NOT EXISTS reviewed_at TEXT");
    expect(sql).toContain("idx_badge_issuance_rule_evaluations_review_queue");
  });

  it("adds badge rule approval policy and rule org-unit scope through a forward migration", () => {
    const sql = readFileSync(
      new URL("../migrations/0050_badge_rule_approval_policies.sql", import.meta.url),
      "utf8",
    );

    expect(sql).toContain("ADD COLUMN IF NOT EXISTS owner_org_unit_id TEXT");
    expect(sql).toContain("CREATE TABLE IF NOT EXISTS badge_rule_approval_policies");
    expect(sql).toContain("approval_requirement TEXT NOT NULL");
    expect(sql).toContain("approval_steps_json TEXT NOT NULL");
    expect(sql).toContain("idx_badge_rule_approval_policies_tenant_default");
    expect(sql).toContain("idx_badge_rule_approval_policies_tenant_org_unit");
  });
});

describe("badge issuance rule draft predicates", () => {
  const sampleRule = (
    overrides?: Partial<dbModule.BadgeIssuanceRuleRecord>,
  ): dbModule.BadgeIssuanceRuleRecord => {
    return {
      id: "brl_123",
      tenantId: "tenant_123",
      name: "CS101 Rule",
      description: "Award for CS101 completion.",
      badgeTemplateId: "badge_template_123",
      ownerOrgUnitId: "tenant_123:org:institution",
      lmsProviderKind: "canvas",
      lmsConnectionId: "lms_123",
      activeVersionId: null,
      createdByUserId: "usr_admin",
      createdAt: "2026-02-18T12:00:00.000Z",
      updatedAt: "2026-02-18T12:00:00.000Z",
      ...overrides,
    };
  };
  const sampleVersion = (
    overrides?: Partial<dbModule.BadgeIssuanceRuleVersionRecord>,
  ): dbModule.BadgeIssuanceRuleVersionRecord => {
    return {
      id: "brv_123",
      tenantId: "tenant_123",
      ruleId: "brl_123",
      versionNumber: 1,
      status: "draft",
      ruleJson: '{"conditions":{"type":"grade_threshold","courseId":"course_101","minScore":80}}',
      changeSummary: "Initial draft",
      createdByUserId: "usr_admin",
      approvedByUserId: null,
      approvedAt: null,
      activatedByUserId: null,
      activatedAt: null,
      createdAt: "2026-02-18T12:00:00.000Z",
      updatedAt: "2026-02-18T12:00:00.000Z",
      ...overrides,
    };
  };

  it("uses shared editability helpers for draft, rejected, pending, and historical rules", () => {
    const neverActiveRule = sampleRule();
    const historicalRule = sampleRule({
      activeVersionId: "brv_active",
    });

    expect(
      dbModule.canEditBadgeIssuanceRuleDraft(neverActiveRule, [
        sampleVersion({
          id: "brv_rejected",
          versionNumber: 2,
          status: "rejected",
        }),
        sampleVersion({
          id: "brv_draft",
          versionNumber: 1,
          status: "draft",
        }),
      ]),
    ).toBe(true);
    expect(
      dbModule.canEditBadgeIssuanceRuleDraft(neverActiveRule, [
        sampleVersion({
          id: "brv_pending",
          versionNumber: 2,
          status: "pending_approval",
        }),
        sampleVersion({
          id: "brv_rejected",
          versionNumber: 1,
          status: "rejected",
        }),
      ]),
    ).toBe(false);
    expect(
      dbModule.canDeleteBadgeIssuanceRuleDraft(historicalRule, [
        sampleVersion({
          id: "brv_rejected",
          versionNumber: 2,
          status: "rejected",
        }),
        sampleVersion({
          id: "brv_active",
          versionNumber: 1,
          status: "active",
        }),
      ]),
    ).toBe(false);
  });
});

describeDbIntegration("badge issuance rule draft DB helpers with Postgres", () => {
  it("resolves default and org-unit badge rule approval policies", async () => {
    const fixture = await createBadgeRuleIntegrationFixture();

    try {
      const ownerOrgUnitId = `${fixture.tenantId}:org:institution`;
      const defaultPolicy = await dbModule.resolveBadgeRuleApprovalPolicy(fixture.db, {
        tenantId: fixture.tenantId,
        orgUnitId: ownerOrgUnitId,
      });

      expect(defaultPolicy.approvalRequirement).toBe("always");
      expect(defaultPolicy.approvalSteps[0]?.requiredRole).toBe("admin");

      await dbModule.upsertBadgeRuleApprovalPolicy(fixture.db, {
        tenantId: fixture.tenantId,
        approvalRequirement: "always",
        approvalSteps: [{ requiredRole: "admin", label: "Tenant registrar" }],
        createdByUserId: fixture.userId,
      });
      await dbModule.upsertBadgeRuleApprovalPolicy(fixture.db, {
        tenantId: fixture.tenantId,
        orgUnitId: ownerOrgUnitId,
        approvalRequirement: "always",
        approvalSteps: [{ requiredRole: "owner", label: "Institution owner" }],
        createdByUserId: fixture.userId,
      });

      const resolved = await dbModule.resolveBadgeRuleApprovalPolicy(fixture.db, {
        tenantId: fixture.tenantId,
        orgUnitId: ownerOrgUnitId,
      });

      expect(resolved.orgUnitId).toBe(ownerOrgUnitId);
      expect(resolved.approvalSteps[0]?.requiredRole).toBe("owner");
      expect(resolved.approvalSteps[0]?.label).toBe("Institution owner");
    } finally {
      await cleanupTestResources(fixture.db, {
        tenantIds: [fixture.tenantId],
        userIds: [fixture.userId],
      });
    }
  });

  it("derives approval steps from policy when submitting a rule version", async () => {
    const fixture = await createBadgeRuleIntegrationFixture();

    try {
      const created = await createFixtureRule(fixture);

      await dbModule.upsertBadgeRuleApprovalPolicy(fixture.db, {
        tenantId: fixture.tenantId,
        orgUnitId: created.rule.ownerOrgUnitId,
        approvalRequirement: "always",
        approvalSteps: [
          { requiredRole: "owner", label: "Owner review" },
          { requiredRole: "admin", label: "Registrar review" },
        ],
        createdByUserId: fixture.userId,
      });

      const submitted = await dbModule.submitBadgeIssuanceRuleVersionForApproval(fixture.db, {
        tenantId: fixture.tenantId,
        ruleId: created.rule.id,
        versionId: created.version.id,
        actorUserId: fixture.userId,
        actorRole: "issuer",
      });
      const steps = await dbModule.listBadgeIssuanceRuleVersionApprovalSteps(fixture.db, {
        tenantId: fixture.tenantId,
        ruleId: created.rule.id,
        versionId: created.version.id,
      });

      expect(submitted?.status).toBe("pending_approval");
      expect(steps.map((step) => step.requiredRole)).toEqual(["owner", "admin"]);
      expect(steps[0]?.status).toBe("pending");
      expect(steps[1]?.status).toBe("queued");
    } finally {
      await cleanupTestResources(fixture.db, {
        tenantIds: [fixture.tenantId],
        userIds: [fixture.userId],
      });
    }
  });

  it("approves submitted rule versions immediately when policy does not require approval", async () => {
    const fixture = await createBadgeRuleIntegrationFixture();

    try {
      const created = await createFixtureRule(fixture);

      await dbModule.upsertBadgeRuleApprovalPolicy(fixture.db, {
        tenantId: fixture.tenantId,
        orgUnitId: created.rule.ownerOrgUnitId,
        approvalRequirement: "never",
        approvalSteps: [],
        createdByUserId: fixture.userId,
      });

      const submitted = await dbModule.submitBadgeIssuanceRuleVersionForApproval(fixture.db, {
        tenantId: fixture.tenantId,
        ruleId: created.rule.id,
        versionId: created.version.id,
        actorUserId: fixture.userId,
        actorRole: "admin",
      });
      const steps = await dbModule.listBadgeIssuanceRuleVersionApprovalSteps(fixture.db, {
        tenantId: fixture.tenantId,
        ruleId: created.rule.id,
        versionId: created.version.id,
      });

      expect(submitted?.status).toBe("approved");
      expect(submitted?.approvedByUserId).toBe(fixture.userId);
      expect(steps).toHaveLength(0);
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

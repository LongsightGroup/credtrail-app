import { expect, it } from "vitest";
import {
  createBadgeIssuanceRule,
  createBadgeIssuanceRuleVersion,
} from "./badge-issuance-rule-writes";
import { loadBadgeWorkflowHomeSummary } from "./badge-workflow-summary";
import {
  resolveBadgeRuleApprovalPolicies,
  resolveBadgeRuleApprovalPolicy,
  upsertBadgeRuleApprovalPolicy,
} from "./badge-rule-approval-policies";
import { submitBadgeIssuanceRuleVersionForApproval } from "./badge-issuance-rule-submission";
import {
  cleanupTestResources,
  createBadgeRuleIntegrationFixture,
  createDepartmentCourseOrgUnitHierarchy,
  describeDbIntegration,
} from "./postgres-test-support";

const createRule = async (
  fixture: Awaited<ReturnType<typeof createBadgeRuleIntegrationFixture>>,
  name: string,
  orgUnitId?: string,
) =>
  createBadgeIssuanceRule(fixture.db, {
    tenantId: fixture.tenantId,
    name,
    badgeTemplateId: fixture.badgeTemplateId,
    ...(orgUnitId === undefined ? {} : { orgUnitId }),
    lmsProviderKind: "canvas",
    lmsConnectionId: fixture.lmsConnectionId,
    ruleJson: JSON.stringify({
      conditions: { type: "course_completion", minCompletionPercent: 100, courseId: "course" },
    }),
    createdByUserId: fixture.userId,
  });

describeDbIntegration("workflow Home with Postgres", () => {
  it("counts beyond a registry page, caps tasks at five, and respects tenant and org scope", async () => {
    const fixture = await createBadgeRuleIntegrationFixture();
    try {
      const hierarchy = await createDepartmentCourseOrgUnitHierarchy(fixture.db, fixture);
      for (let index = 0; index < 27; index += 1)
        await createRule(fixture, `Rule ${String(index)}`);
      await createRule(fixture, "Department rule", hierarchy.course.id);
      const actor = {
        tenantId: fixture.tenantId,
        actorUserId: fixture.userId,
        actorRole: "admin" as const,
      };
      const summary = await loadBadgeWorkflowHomeSummary(fixture.db, actor);
      expect(summary).toMatchObject({
        ruleCount: 28,
        actionCount: 28,
        activeRuleCount: 0,
        waitingCount: 0,
      });
      expect(summary.tasks).toHaveLength(5);
      expect(summary.tasks.every((task) => task.action === "submit")).toBe(true);
      const scoped = await loadBadgeWorkflowHomeSummary(fixture.db, {
        ...actor,
        scope: { type: "descendants", rootOrgUnitIds: [hierarchy.department.id] },
      });
      expect(scoped).toMatchObject({ ruleCount: 1, actionCount: 1 });
      expect(scoped.tasks[0]?.version.snapshot.name).toBe("Department rule");
      expect(
        await loadBadgeWorkflowHomeSummary(fixture.db, { ...actor, tenantId: "another-tenant" }),
      ).toMatchObject({ ruleCount: 0, tasks: [] });
      expect(
        await loadBadgeWorkflowHomeSummary(fixture.db, { ...actor, actorRole: "viewer" }),
      ).toMatchObject({ ruleCount: 28, actionCount: 0, tasks: [] });
    } finally {
      await cleanupTestResources(fixture.db, {
        tenantIds: [fixture.tenantId],
        userIds: [fixture.userId],
      });
    }
  });

  it("separates author waiting from a named review and flags a missing reviewer", async () => {
    const fixture = await createBadgeRuleIntegrationFixture();
    const reviewer = `reviewer_${crypto.randomUUID()}`;
    try {
      await fixture.db
        .prepare("INSERT INTO users (id, email) VALUES (?, ?)")
        .bind(reviewer, `${reviewer}@example.edu`)
        .run();
      await fixture.db
        .prepare("INSERT INTO memberships (tenant_id, user_id, role) VALUES (?, ?, 'approver')")
        .bind(fixture.tenantId, reviewer)
        .run();
      const created = await createRule(fixture, "Independent review");
      await upsertBadgeRuleApprovalPolicy(fixture.db, {
        tenantId: fixture.tenantId,
        approvalRequirement: "always",
        approvalSteps: [{ targetType: "user", targetUserId: reviewer }],
      });
      await submitBadgeIssuanceRuleVersionForApproval(fixture.db, {
        tenantId: fixture.tenantId,
        ruleId: created.rule.id,
        versionId: created.version.id,
        actorUserId: fixture.userId,
        actorRole: "admin",
      });
      const author = {
        tenantId: fixture.tenantId,
        actorUserId: fixture.userId,
        actorRole: "admin" as const,
      };
      expect(await loadBadgeWorkflowHomeSummary(fixture.db, author)).toMatchObject({
        actionCount: 0,
        waitingCount: 1,
        tasks: [],
      });
      const review = await loadBadgeWorkflowHomeSummary(fixture.db, {
        ...author,
        actorUserId: reviewer,
        actorRole: "approver",
      });
      expect(review.tasks[0]).toMatchObject({
        action: "review",
        version: { id: created.version.id },
      });
      await fixture.db
        .prepare("DELETE FROM memberships WHERE tenant_id = ? AND user_id = ?")
        .bind(fixture.tenantId, reviewer)
        .run();
      const blocked = await loadBadgeWorkflowHomeSummary(fixture.db, author);
      expect(blocked.tasks[0]?.action).toBe("configure_approval");
    } finally {
      await cleanupTestResources(fixture.db, {
        tenantIds: [fixture.tenantId],
        userIds: [fixture.userId, reviewer],
      });
    }
  });

  it("counts the active version while routing work to a newer draft", async () => {
    const fixture = await createBadgeRuleIntegrationFixture();
    try {
      const created = await createRule(fixture, "Versioned awarding");
      await fixture.db
        .prepare(
          "UPDATE badge_issuance_rule_versions SET status = 'active' WHERE tenant_id = ? AND id = ?",
        )
        .bind(fixture.tenantId, created.version.id)
        .run();
      await fixture.db
        .prepare(
          "UPDATE badge_issuance_rules SET active_version_id = ? WHERE tenant_id = ? AND id = ?",
        )
        .bind(created.version.id, fixture.tenantId, created.rule.id)
        .run();
      const newer = await createBadgeIssuanceRuleVersion(fixture.db, {
        tenantId: fixture.tenantId,
        ruleId: created.rule.id,
        ruleJson: JSON.stringify({
          conditions: { type: "course_completion", courseId: "course", minCompletionPercent: 100 },
          options: { issuanceTiming: "manual" },
        }),
        createdByUserId: fixture.userId,
      });
      const home = await loadBadgeWorkflowHomeSummary(fixture.db, {
        tenantId: fixture.tenantId,
        actorUserId: fixture.userId,
        actorRole: "admin",
      });
      expect(home).toMatchObject({ ruleCount: 1, activeRuleCount: 1, actionCount: 1 });
      expect(home.tasks[0]).toMatchObject({
        action: "submit",
        current: false,
        version: { id: newer.id, versionNumber: 2 },
      });
    } finally {
      await cleanupTestResources(fixture.db, {
        tenantIds: [fixture.tenantId],
        userIds: [fixture.userId],
      });
    }
  });

  it("bulk policy lookup agrees with inherited and tenant-default approval", async () => {
    const fixture = await createBadgeRuleIntegrationFixture();
    try {
      const hierarchy = await createDepartmentCourseOrgUnitHierarchy(fixture.db, fixture);
      await upsertBadgeRuleApprovalPolicy(fixture.db, {
        tenantId: fixture.tenantId,
        orgUnitId: hierarchy.department.id,
        approvalRequirement: "never",
        allowSelfCertification: true,
        approvalSteps: [],
      });
      const ids = [hierarchy.course.id, hierarchy.college.id];
      const policies = await resolveBadgeRuleApprovalPolicies(fixture.db, {
        tenantId: fixture.tenantId,
        orgUnitIds: ids,
      });
      for (const id of ids)
        expect(policies.get(id)).toEqual(
          await resolveBadgeRuleApprovalPolicy(fixture.db, {
            tenantId: fixture.tenantId,
            orgUnitId: id,
          }),
        );
      expect(policies.get(hierarchy.course.id)?.approvalRequirement).toBe("never");
      expect(policies.get(hierarchy.college.id)?.approvalRequirement).toBe("always");
    } finally {
      await cleanupTestResources(fixture.db, {
        tenantIds: [fixture.tenantId],
        userIds: [fixture.userId],
      });
    }
  });
});

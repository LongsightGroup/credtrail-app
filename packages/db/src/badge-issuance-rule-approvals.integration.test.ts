import { describe, expect, it } from "vitest";

import * as dbModule from "./index";
import { createFixtureRule, createFixtureTenantMember } from "./badge-issuance-rule-test-fixtures";
import {
  addBadgeRuleApproverGroupMember,
  createBadgeRuleApproverGroup,
  removeBadgeRuleApproverGroup,
  removeBadgeRuleApproverGroupMember,
} from "./badge-rule-approver-groups";
import {
  cleanupTestResources,
  createBadgeRuleIntegrationFixture,
  createDepartmentCourseOrgUnitHierarchy,
  describeDbIntegration,
} from "./postgres-test-support";

describeDbIntegration("badge issuance rule approval flows with Postgres", () => {
  it("stores no approval steps when approval is not required", async () => {
    const fixture = await createBadgeRuleIntegrationFixture();

    try {
      const policy = await dbModule.upsertBadgeRuleApprovalPolicy(fixture.db, {
        tenantId: fixture.tenantId,
        approvalRequirement: "never",
        allowSelfCertification: true,
        approvalSteps: [{ requiredRole: "admin", label: "Should be ignored" }],
        createdByUserId: fixture.userId,
      });
      const stored = await fixture.db
        .prepare(
          `
          SELECT approval_steps_json AS approvalStepsJson
          FROM badge_rule_approval_policies
          WHERE tenant_id = ?
            AND org_unit_id IS NULL
          LIMIT 1
        `,
        )
        .bind(fixture.tenantId)
        .first<{ approvalStepsJson: string }>();

      expect(policy.approvalSteps).toEqual([]);
      expect(stored?.approvalStepsJson).toBe("[]");
    } finally {
      await cleanupTestResources(fixture.db, {
        tenantIds: [fixture.tenantId],
        userIds: [fixture.userId],
      });
    }
  });

  it("resolves default and org-unit badge rule approval policies", async () => {
    const fixture = await createBadgeRuleIntegrationFixture();

    try {
      const ownerOrgUnitId = `${fixture.tenantId}:org:institution`;
      const defaultPolicy = await dbModule.resolveBadgeRuleApprovalPolicy(fixture.db, {
        tenantId: fixture.tenantId,
        orgUnitId: ownerOrgUnitId,
      });

      expect(defaultPolicy.approvalRequirement).toBe("always");
      expect(defaultPolicy.id).toBe(
        dbModule.tenantDefaultBadgeRuleApprovalPolicyId(fixture.tenantId),
      );
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

  it("resolves badge rule approval policy through course org-unit ancestors", async () => {
    const fixture = await createBadgeRuleIntegrationFixture();

    try {
      const { department, course } = await createDepartmentCourseOrgUnitHierarchy(fixture.db, {
        tenantId: fixture.tenantId,
        userId: fixture.userId,
      });

      await dbModule.upsertBadgeRuleApprovalPolicy(fixture.db, {
        tenantId: fixture.tenantId,
        orgUnitId: department.id,
        approvalRequirement: "always",
        approvalSteps: [{ requiredRole: "owner", label: "Department chair" }],
        createdByUserId: fixture.userId,
      });

      const resolved = await dbModule.resolveBadgeRuleApprovalPolicy(fixture.db, {
        tenantId: fixture.tenantId,
        orgUnitId: course.id,
      });

      expect(resolved.orgUnitId).toBe(department.id);
      expect(resolved.approvalSteps[0]?.requiredRole).toBe("owner");
      expect(resolved.approvalSteps[0]?.label).toBe("Department chair");
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
        orgUnitId: created.rule.orgUnitId,
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

      expect(submitted.status).toBe("submitted");
      expect(submitted).toMatchObject({
        status: "submitted",
        version: { status: "pending_approval" },
      });
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

  it("blocks rule creators and submitters from deciding approval steps", async () => {
    const fixture = await createBadgeRuleIntegrationFixture();

    try {
      const created = await createFixtureRule(fixture);

      await dbModule.upsertBadgeRuleApprovalPolicy(fixture.db, {
        tenantId: fixture.tenantId,
        orgUnitId: created.rule.orgUnitId,
        approvalRequirement: "always",
        approvalSteps: [{ requiredRole: "admin", label: "Registrar review" }],
        createdByUserId: fixture.userId,
      });

      await dbModule.submitBadgeIssuanceRuleVersionForApproval(fixture.db, {
        tenantId: fixture.tenantId,
        ruleId: created.rule.id,
        versionId: created.version.id,
        actorUserId: fixture.userId,
        actorRole: "admin",
      });

      const decision = await dbModule.decideBadgeIssuanceRuleVersion(fixture.db, {
        tenantId: fixture.tenantId,
        ruleId: created.rule.id,
        versionId: created.version.id,
        decision: "approved",
        actorUserId: fixture.userId,
        actorRole: "admin",
      });

      expect(decision.status).toBe("separation_of_duties");
    } finally {
      await cleanupTestResources(fixture.db, {
        tenantIds: [fixture.tenantId],
        userIds: [fixture.userId],
      });
    }
  });

  it("lets only the submitter withdraw a pending version to draft", async () => {
    const fixture = await createBadgeRuleIntegrationFixture();
    const reviewerUserId = await createFixtureTenantMember(fixture, { role: "admin" });

    try {
      const created = await createFixtureRule(fixture);

      await dbModule.upsertBadgeRuleApprovalPolicy(fixture.db, {
        tenantId: fixture.tenantId,
        orgUnitId: created.rule.orgUnitId,
        approvalRequirement: "always",
        approvalSteps: [{ requiredRole: "admin", label: "Registrar review" }],
        createdByUserId: fixture.userId,
      });
      await dbModule.submitBadgeIssuanceRuleVersionForApproval(fixture.db, {
        tenantId: fixture.tenantId,
        ruleId: created.rule.id,
        versionId: created.version.id,
        actorUserId: fixture.userId,
        actorRole: "admin",
      });

      const forbidden = await dbModule.withdrawBadgeIssuanceRuleVersionSubmission(fixture.db, {
        tenantId: fixture.tenantId,
        ruleId: created.rule.id,
        versionId: created.version.id,
        actorUserId: reviewerUserId,
        actorRole: "admin",
      });
      const withdrawn = await dbModule.withdrawBadgeIssuanceRuleVersionSubmission(fixture.db, {
        tenantId: fixture.tenantId,
        ruleId: created.rule.id,
        versionId: created.version.id,
        actorUserId: fixture.userId,
        actorRole: "admin",
        occurredAt: "2026-07-28T12:00:00.000Z",
      });
      const events = await dbModule.listBadgeIssuanceRuleVersionApprovalEvents(fixture.db, {
        tenantId: fixture.tenantId,
        ruleId: created.rule.id,
        versionId: created.version.id,
      });
      const steps = await dbModule.listBadgeIssuanceRuleVersionApprovalSteps(fixture.db, {
        tenantId: fixture.tenantId,
        ruleId: created.rule.id,
        versionId: created.version.id,
      });
      const audit = await fixture.db
        .prepare(
          "SELECT action FROM audit_logs WHERE tenant_id = ? AND target_id = ? AND action = 'badge_rule.version_submission_withdrawn'",
        )
        .bind(fixture.tenantId, created.version.id)
        .first<{ action: string }>();

      expect(forbidden.status).toBe("forbidden");
      expect(withdrawn).toMatchObject({
        status: "withdrawn",
        version: {
          status: "draft",
          submittedByUserId: null,
          submittedAt: null,
        },
      });
      expect(steps).toEqual([]);
      expect(events.map((event) => event.action)).toEqual(["submitted", "withdrawn"]);
      expect(audit?.action).toBe("badge_rule.version_submission_withdrawn");
    } finally {
      await cleanupTestResources(fixture.db, {
        tenantIds: [fixture.tenantId],
        userIds: [fixture.userId, reviewerUserId],
      });
    }
  });

  it("lets the final approver reopen an approved version before activation", async () => {
    const fixture = await createBadgeRuleIntegrationFixture();
    const reviewerUserId = await createFixtureTenantMember(fixture, { role: "admin" });
    const unrelatedUserId = await createFixtureTenantMember(fixture, { role: "viewer" });

    try {
      const created = await createFixtureRule(fixture);

      await dbModule.upsertBadgeRuleApprovalPolicy(fixture.db, {
        tenantId: fixture.tenantId,
        orgUnitId: created.rule.orgUnitId,
        approvalRequirement: "always",
        approvalSteps: [{ requiredRole: "admin", label: "Registrar review" }],
        createdByUserId: fixture.userId,
      });
      await dbModule.submitBadgeIssuanceRuleVersionForApproval(fixture.db, {
        tenantId: fixture.tenantId,
        ruleId: created.rule.id,
        versionId: created.version.id,
        actorUserId: fixture.userId,
        actorRole: "admin",
      });
      await dbModule.decideBadgeIssuanceRuleVersion(fixture.db, {
        tenantId: fixture.tenantId,
        ruleId: created.rule.id,
        versionId: created.version.id,
        decision: "approved",
        actorUserId: reviewerUserId,
        actorRole: "admin",
      });

      const forbidden = await dbModule.reopenApprovedBadgeIssuanceRuleVersion(fixture.db, {
        tenantId: fixture.tenantId,
        ruleId: created.rule.id,
        versionId: created.version.id,
        actorUserId: unrelatedUserId,
        actorRole: "viewer",
        comment: "This should not be allowed.",
      });
      const reopened = await dbModule.reopenApprovedBadgeIssuanceRuleVersion(fixture.db, {
        tenantId: fixture.tenantId,
        ruleId: created.rule.id,
        versionId: created.version.id,
        actorUserId: reviewerUserId,
        actorRole: "admin",
        comment: "Approved before checking the revised threshold.",
        occurredAt: "2026-07-28T12:30:00.000Z",
      });
      const events = await dbModule.listBadgeIssuanceRuleVersionApprovalEvents(fixture.db, {
        tenantId: fixture.tenantId,
        ruleId: created.rule.id,
        versionId: created.version.id,
      });
      const steps = await dbModule.listBadgeIssuanceRuleVersionApprovalSteps(fixture.db, {
        tenantId: fixture.tenantId,
        ruleId: created.rule.id,
        versionId: created.version.id,
      });

      expect(forbidden.status).toBe("forbidden");
      expect(reopened).toMatchObject({
        status: "reopened",
        version: {
          status: "draft",
          submittedByUserId: null,
          submittedAt: null,
          approvedByUserId: null,
          approvedAt: null,
        },
      });
      expect(events.map((event) => event.action)).toEqual(["submitted", "approved", "reopened"]);
      expect(events.at(-1)?.comment).toBe("Approved before checking the revised threshold.");
      expect(steps).toEqual([]);
    } finally {
      await cleanupTestResources(fixture.db, {
        tenantIds: [fixture.tenantId],
        userIds: [fixture.userId, reviewerUserId, unrelatedUserId],
      });
    }
  });

  it("returns versions to draft when an approver requests changes", async () => {
    const fixture = await createBadgeRuleIntegrationFixture();
    const reviewerUserId = await createFixtureTenantMember(fixture, { role: "admin" });

    try {
      const created = await createFixtureRule(fixture);

      await dbModule.upsertBadgeRuleApprovalPolicy(fixture.db, {
        tenantId: fixture.tenantId,
        orgUnitId: created.rule.orgUnitId,
        approvalRequirement: "always",
        approvalSteps: [{ requiredRole: "admin", label: "Registrar review" }],
        createdByUserId: fixture.userId,
      });

      await dbModule.submitBadgeIssuanceRuleVersionForApproval(fixture.db, {
        tenantId: fixture.tenantId,
        ruleId: created.rule.id,
        versionId: created.version.id,
        actorUserId: fixture.userId,
        actorRole: "admin",
      });

      const changed = await dbModule.decideBadgeIssuanceRuleVersion(fixture.db, {
        tenantId: fixture.tenantId,
        ruleId: created.rule.id,
        versionId: created.version.id,
        decision: "changes_requested",
        actorUserId: reviewerUserId,
        actorRole: "admin",
        comment: "Clarify the course criteria before approval.",
      });
      const steps = await dbModule.listBadgeIssuanceRuleVersionApprovalSteps(fixture.db, {
        tenantId: fixture.tenantId,
        ruleId: created.rule.id,
        versionId: created.version.id,
      });
      const events = await dbModule.listBadgeIssuanceRuleVersionApprovalEvents(fixture.db, {
        tenantId: fixture.tenantId,
        ruleId: created.rule.id,
        versionId: created.version.id,
      });
      const decisionAudit = await fixture.db
        .prepare(
          "SELECT action FROM audit_logs WHERE tenant_id = ? AND target_id = ? AND action = 'badge_rule.version_approval_decided'",
        )
        .bind(fixture.tenantId, created.version.id)
        .first<{ action: string }>();
      const notifications = await fixture.db
        .prepare(
          "SELECT payload_json AS payloadJson FROM job_queue_messages WHERE tenant_id = ? AND job_type = 'send_badge_rule_approval_notification' ORDER BY created_at ASC, id ASC",
        )
        .bind(fixture.tenantId)
        .all<{ payloadJson: string }>();

      expect(changed.status).toBe("decided");
      expect(changed).toMatchObject({
        status: "decided",
        version: { status: "draft" },
      });
      expect(steps[0]?.status).toBe("changes_requested");
      expect(steps[0]?.decisionComment).toBe("Clarify the course criteria before approval.");
      expect(events.map((event) => event.action)).toEqual(["submitted", "changes_requested"]);
      expect(decisionAudit?.action).toBe("badge_rule.version_approval_decided");
      const notificationPayloads = notifications.results.map(
        ({ payloadJson }) => JSON.parse(payloadJson) as unknown,
      );
      expect(notificationPayloads).toHaveLength(2);
      expect(notificationPayloads).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            notificationType: "approval_submitted",
            ruleId: created.rule.id,
            versionId: created.version.id,
          }),
          expect.objectContaining({
            notificationType: "approval_decision",
            ruleId: created.rule.id,
            versionId: created.version.id,
            decision: "changes_requested",
          }),
        ]),
      );
    } finally {
      await cleanupTestResources(fixture.db, {
        tenantIds: [fixture.tenantId],
        userIds: [fixture.userId, reviewerUserId],
      });
    }
  });

  it("supports named user and approver group approval targets", async () => {
    const fixture = await createBadgeRuleIntegrationFixture();
    const namedApproverUserId = await createFixtureTenantMember(fixture, { role: "viewer" });
    const groupApproverUserId = await createFixtureTenantMember(fixture, { role: "admin" });
    const approverGroup = await createBadgeRuleApproverGroup(fixture.db, {
      tenantId: fixture.tenantId,
      orgUnitId: `${fixture.tenantId}:org:institution`,
      name: "Registrar office",
      createdByUserId: fixture.userId,
    });

    try {
      await addBadgeRuleApproverGroupMember(fixture.db, {
        tenantId: fixture.tenantId,
        groupId: approverGroup.id,
        userId: groupApproverUserId,
        createdByUserId: fixture.userId,
      });

      const created = await createFixtureRule(fixture);

      await dbModule.upsertBadgeRuleApprovalPolicy(fixture.db, {
        tenantId: fixture.tenantId,
        orgUnitId: created.rule.orgUnitId,
        approvalRequirement: "always",
        approvalSteps: [
          {
            targetType: "user",
            targetUserId: namedApproverUserId,
            label: "Department chair",
          },
          {
            targetType: "approver_group",
            targetApproverGroupId: approverGroup.id,
            requiredRole: "admin",
            label: "Registrar office",
          },
        ],
        createdByUserId: fixture.userId,
      });

      await dbModule.submitBadgeIssuanceRuleVersionForApproval(fixture.db, {
        tenantId: fixture.tenantId,
        ruleId: created.rule.id,
        versionId: created.version.id,
        actorUserId: fixture.userId,
        actorRole: "admin",
      });

      const firstDecision = await dbModule.decideBadgeIssuanceRuleVersion(fixture.db, {
        tenantId: fixture.tenantId,
        ruleId: created.rule.id,
        versionId: created.version.id,
        decision: "approved",
        actorUserId: namedApproverUserId,
        actorRole: "viewer",
      });
      const finalDecision = await dbModule.decideBadgeIssuanceRuleVersion(fixture.db, {
        tenantId: fixture.tenantId,
        ruleId: created.rule.id,
        versionId: created.version.id,
        decision: "approved",
        actorUserId: groupApproverUserId,
        actorRole: "admin",
      });

      expect(firstDecision.status).toBe("decided");
      expect(firstDecision).toMatchObject({
        status: "decided",
        version: { status: "pending_approval" },
      });
      expect(finalDecision.status).toBe("decided");
      expect(finalDecision).toMatchObject({
        status: "decided",
        version: { status: "approved" },
      });
    } finally {
      await cleanupTestResources(fixture.db, {
        tenantIds: [fixture.tenantId],
        userIds: [fixture.userId, namedApproverUserId, groupApproverUserId],
      });
    }
  });

  it("lists pending approvals by canonical decision authorization before applying limits", async () => {
    const fixture = await createBadgeRuleIntegrationFixture();
    const reviewerUserId = await createFixtureTenantMember(fixture, { role: "admin" });

    try {
      const ownerOnlyRule = await createFixtureRule(fixture);

      await dbModule.upsertBadgeRuleApprovalPolicy(fixture.db, {
        tenantId: fixture.tenantId,
        orgUnitId: ownerOnlyRule.rule.orgUnitId,
        approvalRequirement: "always",
        approvalSteps: [{ requiredRole: "owner", label: "Owner review" }],
        createdByUserId: fixture.userId,
      });
      await dbModule.submitBadgeIssuanceRuleVersionForApproval(fixture.db, {
        tenantId: fixture.tenantId,
        ruleId: ownerOnlyRule.rule.id,
        versionId: ownerOnlyRule.version.id,
        actorUserId: fixture.userId,
        actorRole: "issuer",
      });

      const adminRule = await createFixtureRule(fixture);

      await dbModule.upsertBadgeRuleApprovalPolicy(fixture.db, {
        tenantId: fixture.tenantId,
        orgUnitId: adminRule.rule.orgUnitId,
        approvalRequirement: "always",
        approvalSteps: [{ requiredRole: "admin", label: "Registrar review" }],
        createdByUserId: fixture.userId,
      });
      await dbModule.submitBadgeIssuanceRuleVersionForApproval(fixture.db, {
        tenantId: fixture.tenantId,
        ruleId: adminRule.rule.id,
        versionId: adminRule.version.id,
        actorUserId: fixture.userId,
        actorRole: "issuer",
      });

      const pendingApprovals = await dbModule.listPendingBadgeIssuanceRuleApprovalsForActor(
        fixture.db,
        {
          tenantId: fixture.tenantId,
          actorUserId: reviewerUserId,
          actorRole: "admin",
          limit: 1,
        },
      );

      expect(pendingApprovals).toHaveLength(1);
      expect(pendingApprovals[0]?.ruleId).toBe(adminRule.rule.id);
    } finally {
      await cleanupTestResources(fixture.db, {
        tenantIds: [fixture.tenantId],
        userIds: [fixture.userId, reviewerUserId],
      });
    }
  });

  it("approves submitted rule versions immediately when policy does not require approval", async () => {
    const fixture = await createBadgeRuleIntegrationFixture();

    try {
      const created = await createFixtureRule(fixture);

      await dbModule.upsertBadgeRuleApprovalPolicy(fixture.db, {
        tenantId: fixture.tenantId,
        orgUnitId: created.rule.orgUnitId,
        approvalRequirement: "never",
        allowSelfCertification: true,
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

      expect(submitted.status).toBe("submitted");
      expect(submitted).toMatchObject({
        status: "submitted",
        version: {
          status: "approved",
          approvedByUserId: fixture.userId,
        },
      });
      expect(steps).toHaveLength(0);
    } finally {
      await cleanupTestResources(fixture.db, {
        tenantIds: [fixture.tenantId],
        userIds: [fixture.userId],
      });
    }
  });

  it("requires explicit self-certification before automatic approval", async () => {
    const fixture = await createBadgeRuleIntegrationFixture();

    try {
      const created = await createFixtureRule(fixture);

      await dbModule.upsertBadgeRuleApprovalPolicy(fixture.db, {
        tenantId: fixture.tenantId,
        orgUnitId: created.rule.orgUnitId,
        approvalRequirement: "never",
        allowSelfCertification: false,
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

      expect(submitted.status).toBe("self_certification_required");
    } finally {
      await cleanupTestResources(fixture.db, {
        tenantIds: [fixture.tenantId],
        userIds: [fixture.userId],
      });
    }
  });

  it("reports version lifecycle state before evaluating submission policy", async () => {
    const fixture = await createBadgeRuleIntegrationFixture();

    try {
      const created = await createFixtureRule(fixture);

      await dbModule.upsertBadgeRuleApprovalPolicy(fixture.db, {
        tenantId: fixture.tenantId,
        orgUnitId: created.rule.orgUnitId,
        approvalRequirement: "never",
        allowSelfCertification: false,
        approvalSteps: [],
        createdByUserId: fixture.userId,
      });
      await fixture.db
        .prepare(
          "UPDATE badge_issuance_rule_versions SET status = 'pending_approval' WHERE tenant_id = ? AND id = ?",
        )
        .bind(fixture.tenantId, created.version.id)
        .run();

      const submitted = await dbModule.submitBadgeIssuanceRuleVersionForApproval(fixture.db, {
        tenantId: fixture.tenantId,
        ruleId: created.rule.id,
        versionId: created.version.id,
        actorUserId: fixture.userId,
        actorRole: "admin",
      });

      expect(submitted.status).toBe("not_submittable");
    } finally {
      await cleanupTestResources(fixture.db, {
        tenantIds: [fixture.tenantId],
        userIds: [fixture.userId],
      });
    }
  });

  it("enforces active rule lifecycle windows, suspension, resume, and expiry", async () => {
    const fixture = await createBadgeRuleIntegrationFixture();

    try {
      const created = await createFixtureRule(fixture);

      await dbModule.upsertBadgeRuleApprovalPolicy(fixture.db, {
        tenantId: fixture.tenantId,
        orgUnitId: created.rule.orgUnitId,
        approvalRequirement: "always",
        recertificationIntervalMonths: 6,
        approvalSteps: [{ requiredRole: "admin", label: "Registrar review" }],
        createdByUserId: fixture.userId,
      });
      await fixture.db
        .prepare("UPDATE badge_issuance_rule_versions SET status = 'approved' WHERE id = ?")
        .bind(created.version.id)
        .run();

      const activated = await dbModule.activateBadgeIssuanceRuleVersion(fixture.db, {
        tenantId: fixture.tenantId,
        ruleId: created.rule.id,
        versionId: created.version.id,
        actorUserId: fixture.userId,
        activatedAt: "2026-01-10T00:00:00.000Z",
        effectiveStartsAt: "2026-02-01T00:00:00.000Z",
        expiresAt: "2026-05-31T23:59:59.000Z",
      });
      const beforeEffective = await dbModule.findActiveBadgeIssuanceRuleVersion(fixture.db, {
        tenantId: fixture.tenantId,
        ruleId: created.rule.id,
        nowIso: "2026-01-31T23:59:59.000Z",
      });
      const duringWindow = await dbModule.findActiveBadgeIssuanceRuleVersion(fixture.db, {
        tenantId: fixture.tenantId,
        ruleId: created.rule.id,
        nowIso: "2026-03-01T00:00:00.000Z",
      });

      expect(activated).toMatchObject({
        status: "active",
        effectiveStartsAt: "2026-02-01T00:00:00.000Z",
        expiresAt: "2026-05-31T23:59:59.000Z",
        recertificationDueAt: "2026-07-10T00:00:00.000Z",
      });
      expect(beforeEffective).toBeNull();
      expect(duringWindow?.id).toBe(created.version.id);

      const suspended = await dbModule.suspendBadgeIssuanceRuleVersion(fixture.db, {
        tenantId: fixture.tenantId,
        ruleId: created.rule.id,
        versionId: created.version.id,
        actorUserId: fixture.userId,
        reason: "Investigating criteria evidence.",
        occurredAt: "2026-03-15T00:00:00.000Z",
      });
      const whileSuspended = await dbModule.findActiveBadgeIssuanceRuleVersion(fixture.db, {
        tenantId: fixture.tenantId,
        ruleId: created.rule.id,
        nowIso: "2026-03-16T00:00:00.000Z",
      });

      expect(suspended).toMatchObject({
        status: "suspended",
        suspensionReason: "Investigating criteria evidence.",
      });
      expect(whileSuspended).toBeNull();

      const resumed = await dbModule.resumeBadgeIssuanceRuleVersion(fixture.db, {
        tenantId: fixture.tenantId,
        ruleId: created.rule.id,
        versionId: created.version.id,
        actorUserId: fixture.userId,
        occurredAt: "2026-03-20T00:00:00.000Z",
      });
      const afterResume = await dbModule.findActiveBadgeIssuanceRuleVersion(fixture.db, {
        tenantId: fixture.tenantId,
        ruleId: created.rule.id,
        nowIso: "2026-03-21T00:00:00.000Z",
      });

      expect(resumed?.status).toBe("active");
      expect(afterResume?.id).toBe(created.version.id);

      const afterExpiryWindow = await dbModule.findActiveBadgeIssuanceRuleVersion(fixture.db, {
        tenantId: fixture.tenantId,
        ruleId: created.rule.id,
        nowIso: "2026-06-01T00:00:00.000Z",
      });
      const expired = await dbModule.expireBadgeIssuanceRuleVersion(fixture.db, {
        tenantId: fixture.tenantId,
        ruleId: created.rule.id,
        versionId: created.version.id,
        occurredAt: "2026-06-01T00:00:00.000Z",
      });
      const savedRule = await dbModule.findBadgeIssuanceRuleById(
        fixture.db,
        fixture.tenantId,
        created.rule.id,
      );

      expect(afterExpiryWindow).toBeNull();
      expect(expired).toMatchObject({
        status: "expired",
        expiredAt: "2026-06-01T00:00:00.000Z",
      });
      expect(savedRule?.activeVersionId).toBeNull();
    } finally {
      await cleanupTestResources(fixture.db, {
        tenantIds: [fixture.tenantId],
        userIds: [fixture.userId],
      });
    }
  });
});

describe("badge rule approver group helpers", () => {
  it("exports create and membership helpers for named approval targets", () => {
    expect(typeof createBadgeRuleApproverGroup).toBe("function");
    expect(typeof addBadgeRuleApproverGroupMember).toBe("function");
  });
});

describeDbIntegration("badge rule approver group helpers with Postgres", () => {
  it("validates approver group membership invariants in the DB module", async () => {
    const fixture = await createBadgeRuleIntegrationFixture();
    let reviewerId: string | null = null;

    try {
      reviewerId = await createFixtureTenantMember(fixture, { role: "approver" });
      const group = await createBadgeRuleApproverGroup(fixture.db, {
        tenantId: fixture.tenantId,
        name: "Registrar office",
        createdByUserId: fixture.userId,
      });

      const missingGroup = await addBadgeRuleApproverGroupMember(fixture.db, {
        tenantId: fixture.tenantId,
        groupId: "brag_missing",
        userId: reviewerId,
        createdByUserId: fixture.userId,
      });
      const missingMembership = await addBadgeRuleApproverGroupMember(fixture.db, {
        tenantId: fixture.tenantId,
        groupId: group.id,
        userId: "usr_missing",
        createdByUserId: fixture.userId,
      });
      const added = await addBadgeRuleApproverGroupMember(fixture.db, {
        tenantId: fixture.tenantId,
        groupId: group.id,
        userId: reviewerId,
        createdByUserId: fixture.userId,
      });
      const duplicate = await addBadgeRuleApproverGroupMember(fixture.db, {
        tenantId: fixture.tenantId,
        groupId: group.id,
        userId: reviewerId,
        createdByUserId: fixture.userId,
      });
      const removed = await removeBadgeRuleApproverGroupMember(fixture.db, {
        tenantId: fixture.tenantId,
        groupId: group.id,
        userId: reviewerId,
      });
      const missingMember = await removeBadgeRuleApproverGroupMember(fixture.db, {
        tenantId: fixture.tenantId,
        groupId: group.id,
        userId: reviewerId,
      });
      const removedGroup = await removeBadgeRuleApproverGroup(fixture.db, {
        tenantId: fixture.tenantId,
        groupId: group.id,
      });
      const missingGroupRemoval = await removeBadgeRuleApproverGroup(fixture.db, {
        tenantId: fixture.tenantId,
        groupId: group.id,
      });

      expect(missingGroup).toEqual({ status: "group_not_found" });
      expect(missingMembership).toEqual({ status: "membership_not_found" });
      expect(added).toEqual({ status: "added" });
      expect(duplicate).toEqual({ status: "already_member" });
      expect(removed).toEqual({ status: "removed" });
      expect(missingMember).toEqual({ status: "member_not_found" });
      expect(removedGroup).toEqual({ status: "removed" });
      expect(missingGroupRemoval).toEqual({ status: "group_not_found" });
    } finally {
      await cleanupTestResources(fixture.db, {
        tenantIds: [fixture.tenantId],
        userIds: reviewerId === null ? [fixture.userId] : [fixture.userId, reviewerId],
      });
    }
  });
});

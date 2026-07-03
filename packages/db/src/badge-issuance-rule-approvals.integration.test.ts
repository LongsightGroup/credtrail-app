import { describe, expect, it } from "vitest";

import * as dbModule from "./index";
import { createFixtureRule, createFixtureTenantMember } from "./badge-issuance-rule-test-fixtures";
import {
  addBadgeRuleApproverGroupMember,
  createBadgeRuleApproverGroup,
} from "./badge-rule-approver-groups";
import {
  cleanupTestResources,
  createBadgeRuleIntegrationFixture,
  describeDbIntegration,
} from "./postgres-test-support";

describeDbIntegration("badge issuance rule approval flows with Postgres", () => {
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
        orgUnitId: created.rule.ownerOrgUnitId,
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

  it("returns versions to draft when an approver requests changes", async () => {
    const fixture = await createBadgeRuleIntegrationFixture();
    const reviewerUserId = await createFixtureTenantMember(fixture, { role: "admin" });

    try {
      const created = await createFixtureRule(fixture);

      await dbModule.upsertBadgeRuleApprovalPolicy(fixture.db, {
        tenantId: fixture.tenantId,
        orgUnitId: created.rule.ownerOrgUnitId,
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

      expect(changed.status).toBe("decided");
      expect(changed).toMatchObject({
        status: "decided",
        version: { status: "draft" },
      });
      expect(steps[0]?.status).toBe("changes_requested");
      expect(steps[0]?.decisionComment).toBe("Clarify the course criteria before approval.");
      expect(events.map((event) => event.action)).toEqual(["submitted", "changes_requested"]);
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
        orgUnitId: created.rule.ownerOrgUnitId,
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

  it("approves submitted rule versions immediately when policy does not require approval", async () => {
    const fixture = await createBadgeRuleIntegrationFixture();

    try {
      const created = await createFixtureRule(fixture);

      await dbModule.upsertBadgeRuleApprovalPolicy(fixture.db, {
        tenantId: fixture.tenantId,
        orgUnitId: created.rule.ownerOrgUnitId,
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
        orgUnitId: created.rule.ownerOrgUnitId,
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
});

describe("badge rule approver group helpers", () => {
  it("exports create and membership helpers for named approval targets", () => {
    expect(typeof createBadgeRuleApproverGroup).toBe("function");
    expect(typeof addBadgeRuleApproverGroupMember).toBe("function");
  });
});

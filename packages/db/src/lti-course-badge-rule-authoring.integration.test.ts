import { expect, it } from "vitest";

import {
  createLtiCourseBadgeRule,
  type CreateLtiCourseBadgeRuleInput,
} from "./lti-course-badge-rule-authoring.js";
import {
  type BadgeRuleIntegrationFixture,
  cleanupTestResources,
  createBadgeRuleIntegrationFixture,
  describeDbIntegration,
  selectCount,
  uniqueTestId,
} from "./postgres-test-support.js";
import { upsertBadgeRuleApprovalPolicy } from "./badge-rule-approval-policies.js";
import { createTenantOrgUnit } from "./tenant-org-units.js";

const createCourseParentOrgUnit = async (fixture: BadgeRuleIntegrationFixture): Promise<string> => {
  const college = await createTenantOrgUnit(fixture.db, {
    tenantId: fixture.tenantId,
    unitType: "college",
    slug: "lti-authoring-college",
    displayName: "LTI Authoring College",
    parentOrgUnitId: `${fixture.tenantId}:org:institution`,
    createdByUserId: fixture.userId,
  });
  const department = await createTenantOrgUnit(fixture.db, {
    tenantId: fixture.tenantId,
    unitType: "department",
    slug: "lti-authoring-department",
    displayName: "LTI Authoring Department",
    parentOrgUnitId: college.id,
    createdByUserId: fixture.userId,
  });

  return department.id;
};

const createInput = (
  fixture: BadgeRuleIntegrationFixture,
  parentOrgUnitId: string,
): CreateLtiCourseBadgeRuleInput => {
  const courseId = uniqueTestId("course");

  return {
    tenantId: fixture.tenantId,
    course: {
      parentOrgUnitId,
      externalSystemId: fixture.lmsConnectionId,
      externalCourseId: courseId,
      title: "LTI authoring test course",
    },
    rule: {
      name: "LTI course badge rule",
      description: "Created by the LTI authoring integration test.",
      badgeTemplateId: fixture.badgeTemplateId,
      lmsProviderKind: "canvas",
      lmsConnectionId: fixture.lmsConnectionId,
      ruleJson: JSON.stringify({
        conditions: {
          type: "course_completion",
          courseId,
          minCompletionPercent: 100,
        },
      }),
      changeSummary: "Created from an LTI placement.",
    },
    placement: {
      issuer: "https://lti-authoring.example.test",
      clientId: uniqueTestId("client"),
      deploymentId: uniqueTestId("deployment"),
      contextId: courseId,
      resourceLinkId: uniqueTestId("resource"),
      delegatedGrantId: null,
    },
    actorUserId: fixture.userId,
    actorRole: "admin",
  };
};

describeDbIntegration("LTI course badge-rule authoring with Postgres", () => {
  it("converges concurrent and repeated setup requests on one persistence graph", async () => {
    const fixture = await createBadgeRuleIntegrationFixture();

    try {
      const input = createInput(fixture, await createCourseParentOrgUnit(fixture));
      const concurrentResults = await Promise.all([
        createLtiCourseBadgeRule(fixture.db, input),
        createLtiCourseBadgeRule(fixture.db, input),
      ]);
      const repeated = await createLtiCourseBadgeRule(fixture.db, input);

      expect(concurrentResults.every((result) => result.status === "completed")).toBe(true);
      expect(
        concurrentResults
          .filter((result) => result.status === "completed")
          .map((result) => result.writeStatus)
          .sort(),
      ).toEqual(["created", "replayed"]);
      expect(repeated).toMatchObject({ status: "completed", writeStatus: "replayed" });

      const createdResult = concurrentResults.find(
        (result) => result.status === "completed" && result.writeStatus === "created",
      );
      const replayedResult = concurrentResults.find(
        (result) => result.status === "completed" && result.writeStatus === "replayed",
      );

      if (createdResult?.status !== "completed" || replayedResult?.status !== "completed") {
        throw new Error("Expected one created LTI graph and one replayed LTI graph");
      }

      expect(replayedResult).toMatchObject({
        rule: { id: createdResult.rule.id },
        version: { id: createdResult.version.id },
        placement: { id: createdResult.placement.id },
      });
      expect(
        await selectCount(
          fixture.db,
          "SELECT COUNT(*) AS totalCount FROM badge_issuance_rules WHERE tenant_id = ?",
          [fixture.tenantId],
        ),
      ).toBe(1);
      const auditActions = await fixture.db
        .prepare(
          `
            SELECT action
            FROM audit_logs
            WHERE tenant_id = ?
              AND action IN (
                'badge_rule.created',
                'badge_rule.version_submitted_for_approval',
                'lti.course_badge_setup_submitted',
                'lti.resource_link_placement_upserted'
              )
            ORDER BY action ASC
          `,
        )
        .bind(fixture.tenantId)
        .all<{ action: string }>();
      expect(auditActions.results.map(({ action }) => action)).toEqual([
        "badge_rule.created",
        "badge_rule.version_submitted_for_approval",
        "lti.course_badge_setup_submitted",
        "lti.resource_link_placement_upserted",
      ]);
      expect(
        await selectCount(
          fixture.db,
          "SELECT COUNT(*) AS totalCount FROM badge_issuance_rule_versions WHERE tenant_id = ?",
          [fixture.tenantId],
        ),
      ).toBe(1);
      expect(
        await selectCount(
          fixture.db,
          "SELECT COUNT(*) AS totalCount FROM lti_resource_link_placements WHERE tenant_id = ?",
          [fixture.tenantId],
        ),
      ).toBe(1);
      expect(
        await selectCount(
          fixture.db,
          "SELECT COUNT(*) AS totalCount FROM job_queue_messages WHERE tenant_id = ? AND job_type = 'send_badge_rule_approval_notification'",
          [fixture.tenantId],
        ),
      ).toBe(1);
    } finally {
      await cleanupTestResources(fixture.db, {
        tenantIds: [fixture.tenantId],
        userIds: [fixture.userId],
      });
    }
  });

  it("rejects changed setup for an occupied placement without replacing its rule", async () => {
    const fixture = await createBadgeRuleIntegrationFixture();

    try {
      const input = createInput(fixture, await createCourseParentOrgUnit(fixture));
      const created = await createLtiCourseBadgeRule(fixture.db, input);
      const conflict = await createLtiCourseBadgeRule(fixture.db, {
        ...input,
        rule: {
          ...input.rule,
          ruleJson: JSON.stringify({
            conditions: {
              type: "course_completion",
              courseId: input.course.externalCourseId,
              minCompletionPercent: 80,
            },
          }),
        },
      });

      expect(created).toMatchObject({ status: "completed", writeStatus: "created" });
      expect(conflict).toEqual({ status: "placement_conflict" });
      expect(
        await selectCount(
          fixture.db,
          "SELECT COUNT(*) AS totalCount FROM badge_issuance_rules WHERE tenant_id = ?",
          [fixture.tenantId],
        ),
      ).toBe(1);
    } finally {
      await cleanupTestResources(fixture.db, {
        tenantIds: [fixture.tenantId],
        userIds: [fixture.userId],
      });
    }
  });

  it("rolls back a newly created course scope when approval policy rejects authoring", async () => {
    const fixture = await createBadgeRuleIntegrationFixture();

    try {
      const input = createInput(fixture, await createCourseParentOrgUnit(fixture));
      await upsertBadgeRuleApprovalPolicy(fixture.db, {
        tenantId: fixture.tenantId,
        orgUnitId: input.course.parentOrgUnitId,
        approvalRequirement: "never",
        allowSelfCertification: false,
        approvalSteps: [],
        createdByUserId: fixture.userId,
      });

      const result = await createLtiCourseBadgeRule(fixture.db, input);

      expect(result).toEqual({
        status: "authoring_failed",
        reason: "self_certification_required",
      });
      expect(
        await selectCount(
          fixture.db,
          "SELECT COUNT(*) AS totalCount FROM tenant_org_units WHERE tenant_id = ? AND unit_type = 'course'",
          [fixture.tenantId],
        ),
      ).toBe(0);
      expect(
        await selectCount(
          fixture.db,
          "SELECT COUNT(*) AS totalCount FROM badge_issuance_rules WHERE tenant_id = ?",
          [fixture.tenantId],
        ),
      ).toBe(0);
      expect(
        await selectCount(
          fixture.db,
          "SELECT COUNT(*) AS totalCount FROM lti_resource_link_placements WHERE tenant_id = ?",
          [fixture.tenantId],
        ),
      ).toBe(0);
    } finally {
      await cleanupTestResources(fixture.db, {
        tenantIds: [fixture.tenantId],
        userIds: [fixture.userId],
      });
    }
  });
});

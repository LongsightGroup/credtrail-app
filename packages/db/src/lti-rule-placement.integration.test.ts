import { expect, it } from "vitest";

import { createAuditLog } from "./audit-logs.js";
import { createFixtureRule } from "./badge-issuance-rule-test-fixtures.js";
import type { BadgeIssuanceRuleVersionRecord } from "./badge-issuance-rule-types.js";
import { createBadgeIssuanceRuleVersion } from "./badge-issuance-rule-writes.js";
import {
  findBadgeRulePlacementAvailability,
  replaceBadgeRulePlacementAvailability,
} from "./badge-rule-placement-availability.js";
import {
  assignLmsCourseContextOrgUnit,
  upsertCatalogLmsCourseContext,
  type TenantLmsCourseContextRecord,
} from "./lti-course-contexts.js";
import {
  findLtiResourceLinkPlacement,
  retireLtiResourceLinkPlacement,
  upsertLtiResourceLinkPlacement,
} from "./lti-resource-link-placements.js";
import {
  placeStableLtiBadgeRule,
  type PlaceStableLtiBadgeRuleInput,
} from "./lti-rule-placement.js";
import type { BadgeRuleIntegrationFixture } from "./postgres-test-support.js";
import {
  cleanupTestResources,
  createBadgeRuleIntegrationFixture,
  createDepartmentCourseOrgUnitHierarchy,
  describeDbIntegration,
  selectCount,
  uniqueTestId,
} from "./postgres-test-support.js";
import { createTenantOrgUnit } from "./tenant-org-units.js";

const ISSUER = "https://stable-placement.example.test";
const CLIENT_ID = "stable-placement-client";
const DEPLOYMENT_ID = "stable-placement-deployment";
const EVALUATED_AT = "2026-09-02T12:00:00.000Z";
const COURSE_RELATIVE_AUTHORING_ACTION = ["lti.course", "badge", "setup", "submitted"].join("_");

const configureLtiRegistration = async (fixture: BadgeRuleIntegrationFixture): Promise<void> => {
  await fixture.db
    .prepare(
      `
      UPDATE tenant_lms_connections
      SET lti_issuer = ?,
          lti_client_id = ?,
          lti_deployment_id = ?
      WHERE tenant_id = ?
        AND id = ?
    `,
    )
    .bind(ISSUER, CLIENT_ID, DEPLOYMENT_ID, fixture.tenantId, fixture.lmsConnectionId)
    .run();
};

const activateFixtureRule = async (
  fixture: BadgeRuleIntegrationFixture,
  options: { readonly expiresAt?: string | null | undefined } = {},
) => {
  const created = await createFixtureRule(fixture);
  await fixture.db
    .prepare(
      `
      UPDATE badge_issuance_rule_versions
      SET status = 'active',
          effective_starts_at = '2026-01-01T00:00:00.000Z',
          expires_at = ?
      WHERE tenant_id = ?
        AND rule_id = ?
        AND id = ?
    `,
    )
    .bind(options.expiresAt ?? null, fixture.tenantId, created.rule.id, created.version.id)
    .run();
  await fixture.db
    .prepare(
      `
      UPDATE badge_issuance_rules
      SET active_version_id = ?
      WHERE tenant_id = ?
        AND id = ?
    `,
    )
    .bind(created.version.id, fixture.tenantId, created.rule.id)
    .run();
  return created;
};

const activateReplacementVersion = async (
  fixture: BadgeRuleIntegrationFixture,
  input: { readonly ruleId: string; readonly previousVersionId: string },
): Promise<BadgeIssuanceRuleVersionRecord> => {
  const version = await createBadgeIssuanceRuleVersion(fixture.db, {
    tenantId: fixture.tenantId,
    ruleId: input.ruleId,
    ruleJson: '{"conditions":{"type":"grade_threshold","courseId":"course_101","minScore":90}}',
    changeSummary: "Raise the passing score",
    createdByUserId: fixture.userId,
  });
  await fixture.db
    .prepare(
      `
      UPDATE badge_issuance_rule_versions
      SET status = CASE WHEN id = ? THEN 'active' ELSE 'deprecated' END,
          effective_starts_at = CASE WHEN id = ? THEN '2026-08-01T00:00:00.000Z' ELSE effective_starts_at END
      WHERE tenant_id = ?
        AND rule_id = ?
        AND id IN (?, ?)
    `,
    )
    .bind(
      version.id,
      version.id,
      fixture.tenantId,
      input.ruleId,
      version.id,
      input.previousVersionId,
    )
    .run();
  await fixture.db
    .prepare("UPDATE badge_issuance_rules SET active_version_id = ? WHERE tenant_id = ? AND id = ?")
    .bind(version.id, fixture.tenantId, input.ruleId)
    .run();
  return version;
};

const createCourseContext = async (
  fixture: BadgeRuleIntegrationFixture,
  contextId: string,
): Promise<TenantLmsCourseContextRecord> => {
  return upsertCatalogLmsCourseContext(fixture.db, {
    tenantId: fixture.tenantId,
    lmsConnectionId: fixture.lmsConnectionId,
    contextId,
    displayName: contextId,
    createdByUserId: fixture.userId,
  });
};

const mapCourseContext = async (
  fixture: BadgeRuleIntegrationFixture,
  input: { readonly contextId: string; readonly courseOrgUnitId: string },
): Promise<TenantLmsCourseContextRecord> => {
  const context = await createCourseContext(fixture, input.contextId);
  const assigned = await assignLmsCourseContextOrgUnit(fixture.db, {
    tenantId: fixture.tenantId,
    courseContextId: context.id,
    courseOrgUnitId: input.courseOrgUnitId,
  });

  if (assigned.status !== "assigned" && assigned.status !== "unchanged") {
    throw new Error(`Unable to map test course context: ${assigned.status}`);
  }

  return assigned.courseContext;
};

const allowTenant = async (fixture: BadgeRuleIntegrationFixture, ruleId: string): Promise<void> => {
  const result = await replaceBadgeRulePlacementAvailability(fixture.db, {
    tenantId: fixture.tenantId,
    ruleId,
    availability: { scope: "tenant" },
    actorUserId: fixture.userId,
    actorRole: "admin",
    evaluatedAt: EVALUATED_AT,
  });

  if (result.status !== "updated" && result.status !== "unchanged") {
    throw new Error(`Unable to allow test rule: ${result.status}`);
  }
};

const placementInput = (
  fixture: BadgeRuleIntegrationFixture,
  input: {
    readonly contextId: string;
    readonly resourceLinkId: string;
    readonly ruleId?: string | null | undefined;
    readonly badgeTemplateId?: string | null | undefined;
  },
): PlaceStableLtiBadgeRuleInput => ({
  tenantId: fixture.tenantId,
  lmsConnectionId: fixture.lmsConnectionId,
  contextId: input.contextId,
  issuer: ISSUER,
  clientId: CLIENT_ID,
  deploymentId: DEPLOYMENT_ID,
  resourceLinkId: input.resourceLinkId,
  incomingRuleId: input.ruleId ?? null,
  incomingBadgeTemplateId: input.badgeTemplateId ?? null,
  linkedUserId: fixture.userId,
  roleKind: "instructor",
  evaluatedAt: EVALUATED_AT,
});

describeDbIntegration("stable LTI rule placement with Postgres", () => {
  it("places a copied stable link, preserves exact links, follows the active version, and reactivates history", async () => {
    const fixture = await createBadgeRuleIntegrationFixture();

    try {
      await configureLtiRegistration(fixture);
      const created = await activateFixtureRule(fixture);
      await allowTenant(fixture, created.rule.id);
      const firstContext = await createCourseContext(fixture, "term-fall");
      const copiedContext = await createCourseContext(fixture, "term-spring");
      const copiedInput = placementInput(fixture, {
        contextId: copiedContext.contextId,
        resourceLinkId: "copied-stable-link",
        ruleId: created.rule.id,
        badgeTemplateId: fixture.badgeTemplateId,
      });

      const placed = await placeStableLtiBadgeRule(fixture.db, copiedInput);
      expect(placed).toMatchObject({
        status: "placed",
        rule: { id: created.rule.id },
        version: { id: created.version.id },
        badgeTemplate: { id: fixture.badgeTemplateId },
        placement: {
          contextId: copiedContext.contextId,
          ruleId: created.rule.id,
          status: "active",
        },
      });
      expect(await placeStableLtiBadgeRule(fixture.db, copiedInput)).toMatchObject({
        status: "existing",
        placement: { id: placed.status === "placed" ? placed.placement.id : "unreachable" },
      });

      if (placed.status !== "placed") {
        throw new Error("Expected a placed rule fixture");
      }

      expect(
        await retireLtiResourceLinkPlacement(fixture.db, {
          tenantId: fixture.tenantId,
          ruleId: created.rule.id,
          placementId: placed.placement.id,
          actorUserId: fixture.userId,
          actorRole: "admin",
        }),
      ).toMatchObject({ status: "retired" });
      expect(await placeStableLtiBadgeRule(fixture.db, copiedInput)).toMatchObject({
        status: "reactivated",
        placement: { id: placed.placement.id, status: "active" },
      });

      const oldLink = await upsertLtiResourceLinkPlacement(fixture.db, {
        tenantId: fixture.tenantId,
        issuer: ISSUER,
        clientId: CLIENT_ID,
        deploymentId: DEPLOYMENT_ID,
        contextId: null,
        resourceLinkId: "existing-link-without-hints",
        badgeTemplateId: fixture.badgeTemplateId,
        ruleId: created.rule.id,
        createdByUserId: fixture.userId,
      });
      const replacementVersion = await activateReplacementVersion(fixture, {
        ruleId: created.rule.id,
        previousVersionId: created.version.id,
      });
      const preserved = await placeStableLtiBadgeRule(
        fixture.db,
        placementInput(fixture, {
          contextId: firstContext.contextId,
          resourceLinkId: oldLink.resourceLinkId,
        }),
      );

      expect(preserved).toMatchObject({
        status: "existing",
        placement: {
          id: oldLink.id,
          contextId: firstContext.contextId,
          ruleId: created.rule.id,
        },
        version: { id: replacementVersion.id, versionNumber: 2 },
      });
      expect(
        await placeStableLtiBadgeRule(
          fixture.db,
          placementInput(fixture, {
            contextId: firstContext.contextId,
            resourceLinkId: "old-link-without-placement",
            badgeTemplateId: fixture.badgeTemplateId,
          }),
        ),
      ).toEqual({ status: "replace_link_required" });
    } finally {
      await cleanupTestResources(fixture.db, {
        tenantIds: [fixture.tenantId],
        userIds: [fixture.userId],
      });
    }
  });

  it("denies stale, mismatched, unavailable, and course-relative launch evidence without writing", async () => {
    const fixture = await createBadgeRuleIntegrationFixture();

    try {
      await configureLtiRegistration(fixture);
      const active = await activateFixtureRule(fixture);
      const noPolicy = await activateFixtureRule(fixture);
      const expired = await activateFixtureRule(fixture);
      const inactive = await createFixtureRule(fixture);
      const selected = await createCourseContext(fixture, "selected-course");
      const outside = await createCourseContext(fixture, "outside-course");
      await replaceBadgeRulePlacementAvailability(fixture.db, {
        tenantId: fixture.tenantId,
        ruleId: active.rule.id,
        availability: { scope: "selected_courses", courseContextIds: [selected.id] },
        actorUserId: fixture.userId,
        actorRole: "admin",
        evaluatedAt: EVALUATED_AT,
      });
      await allowTenant(fixture, expired.rule.id);
      await fixture.db
        .prepare(
          "UPDATE badge_issuance_rule_versions SET expires_at = ? WHERE tenant_id = ? AND id = ?",
        )
        .bind("2026-08-01T00:00:00.000Z", fixture.tenantId, expired.version.id)
        .run();

      const cases = [
        {
          expected: "outside_availability",
          input: placementInput(fixture, {
            contextId: outside.contextId,
            resourceLinkId: "outside",
            ruleId: active.rule.id,
          }),
        },
        {
          expected: "course_context_not_found",
          input: placementInput(fixture, {
            contextId: "missing-course",
            resourceLinkId: "missing-course",
            ruleId: active.rule.id,
          }),
        },
        {
          expected: "outside_availability",
          input: placementInput(fixture, {
            contextId: selected.contextId,
            resourceLinkId: "no-policy",
            ruleId: noPolicy.rule.id,
          }),
        },
        {
          expected: "outside_availability",
          input: {
            ...placementInput(fixture, {
              contextId: selected.contextId,
              resourceLinkId: "wrong-lms-connection",
              ruleId: active.rule.id,
            }),
            lmsConnectionId: uniqueTestId("wrong_lms_connection"),
          },
        },
        {
          expected: "rule_not_active",
          input: placementInput(fixture, {
            contextId: selected.contextId,
            resourceLinkId: "inactive",
            ruleId: inactive.rule.id,
          }),
        },
        {
          expected: "rule_not_active",
          input: placementInput(fixture, {
            contextId: selected.contextId,
            resourceLinkId: "expired",
            ruleId: expired.rule.id,
          }),
        },
        {
          expected: "template_mismatch",
          input: placementInput(fixture, {
            contextId: selected.contextId,
            resourceLinkId: "template-mismatch",
            ruleId: active.rule.id,
            badgeTemplateId: uniqueTestId("wrong_template"),
          }),
        },
      ] as const;

      for (const testCase of cases) {
        expect((await placeStableLtiBadgeRule(fixture.db, testCase.input)).status).toBe(
          testCase.expected,
        );
      }

      await createAuditLog(fixture.db, {
        tenantId: fixture.tenantId,
        actorUserId: fixture.userId,
        action: COURSE_RELATIVE_AUTHORING_ACTION,
        targetType: "badge_issuance_rule",
        targetId: active.rule.id,
      });
      expect(
        await placeStableLtiBadgeRule(
          fixture.db,
          placementInput(fixture, {
            contextId: selected.contextId,
            resourceLinkId: "course-relative-copy",
            ruleId: active.rule.id,
          }),
        ),
      ).toEqual({ status: "course_relative_rule_not_supported" });

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

  it("authorizes org-unit descendants and rejects unmapped, sibling, and inactive course paths", async () => {
    const fixture = await createBadgeRuleIntegrationFixture();

    try {
      await configureLtiRegistration(fixture);
      const created = await activateFixtureRule(fixture);
      const hierarchy = await createDepartmentCourseOrgUnitHierarchy(fixture.db, {
        tenantId: fixture.tenantId,
        userId: fixture.userId,
        includeProgram: true,
      });
      const siblingCollege = await createTenantOrgUnit(fixture.db, {
        tenantId: fixture.tenantId,
        unitType: "college",
        slug: "placement-arts",
        displayName: "Placement Arts",
        parentOrgUnitId: `${fixture.tenantId}:org:institution`,
        createdByUserId: fixture.userId,
      });
      const siblingDepartment = await createTenantOrgUnit(fixture.db, {
        tenantId: fixture.tenantId,
        unitType: "department",
        slug: "placement-history-department",
        displayName: "Placement History Department",
        parentOrgUnitId: siblingCollege.id,
        createdByUserId: fixture.userId,
      });
      const siblingCourse = await createTenantOrgUnit(fixture.db, {
        tenantId: fixture.tenantId,
        unitType: "course",
        slug: "placement-history",
        displayName: "Placement History",
        parentOrgUnitId: siblingDepartment.id,
        createdByUserId: fixture.userId,
      });

      if (hierarchy.programCourse === undefined) {
        throw new Error("Expected program-course fixture");
      }

      const descendant = await mapCourseContext(fixture, {
        contextId: "org-descendant-placement",
        courseOrgUnitId: hierarchy.programCourse.id,
      });
      const sibling = await mapCourseContext(fixture, {
        contextId: "org-sibling-placement",
        courseOrgUnitId: siblingCourse.id,
      });
      const unmapped = await createCourseContext(fixture, "org-unmapped-placement");
      await replaceBadgeRulePlacementAvailability(fixture.db, {
        tenantId: fixture.tenantId,
        ruleId: created.rule.id,
        availability: { scope: "org_unit_subtree", rootOrgUnitId: hierarchy.college.id },
        actorUserId: fixture.userId,
        actorRole: "admin",
        evaluatedAt: EVALUATED_AT,
      });

      expect(
        await placeStableLtiBadgeRule(
          fixture.db,
          placementInput(fixture, {
            contextId: descendant.contextId,
            resourceLinkId: "org-descendant",
            ruleId: created.rule.id,
          }),
        ),
      ).toMatchObject({ status: "placed" });
      expect(
        await placeStableLtiBadgeRule(
          fixture.db,
          placementInput(fixture, {
            contextId: sibling.contextId,
            resourceLinkId: "org-sibling",
            ruleId: created.rule.id,
          }),
        ),
      ).toEqual({ status: "outside_availability" });
      expect(
        await placeStableLtiBadgeRule(
          fixture.db,
          placementInput(fixture, {
            contextId: unmapped.contextId,
            resourceLinkId: "org-unmapped",
            ruleId: created.rule.id,
          }),
        ),
      ).toEqual({ status: "course_unmapped" });

      await fixture.db
        .prepare("UPDATE tenant_org_units SET is_active = 0 WHERE tenant_id = ? AND id = ?")
        .bind(fixture.tenantId, hierarchy.programCourse.id)
        .run();
      expect(
        await placeStableLtiBadgeRule(
          fixture.db,
          placementInput(fixture, {
            contextId: descendant.contextId,
            resourceLinkId: "org-inactive",
            ruleId: created.rule.id,
          }),
        ),
      ).toEqual({ status: "outside_availability" });
    } finally {
      await cleanupTestResources(fixture.db, {
        tenantIds: [fixture.tenantId],
        userIds: [fixture.userId],
      });
    }
  });

  it("serializes conflicting copies and remains consistent when policy narrows concurrently", async () => {
    const fixture = await createBadgeRuleIntegrationFixture();

    try {
      await configureLtiRegistration(fixture);
      const firstRule = await activateFixtureRule(fixture);
      const secondRule = await activateFixtureRule(fixture);
      await allowTenant(fixture, firstRule.rule.id);
      await allowTenant(fixture, secondRule.rule.id);
      const course = await createCourseContext(fixture, "race-course");
      const conflictIdentity = {
        contextId: course.contextId,
        resourceLinkId: "concurrent-conflicting-copy",
      };
      const [first, second] = await Promise.all([
        placeStableLtiBadgeRule(
          fixture.db,
          placementInput(fixture, { ...conflictIdentity, ruleId: firstRule.rule.id }),
        ),
        placeStableLtiBadgeRule(
          fixture.db,
          placementInput(fixture, { ...conflictIdentity, ruleId: secondRule.rule.id }),
        ),
      ]);

      expect([first.status, second.status].sort()).toEqual(["placed", "placement_conflict"]);
      expect(
        await selectCount(
          fixture.db,
          `
          SELECT COUNT(*) AS totalCount
          FROM lti_resource_link_placements
          WHERE issuer = ?
            AND client_id = ?
            AND deployment_id = ?
            AND resource_link_id = ?
        `,
          [ISSUER, CLIENT_ID, DEPLOYMENT_ID, conflictIdentity.resourceLinkId],
        ),
      ).toBe(1);

      const selected = await createCourseContext(fixture, "race-selected");
      const replacement = await createCourseContext(fixture, "race-replacement");
      await replaceBadgeRulePlacementAvailability(fixture.db, {
        tenantId: fixture.tenantId,
        ruleId: firstRule.rule.id,
        availability: { scope: "selected_courses", courseContextIds: [selected.id] },
        actorUserId: fixture.userId,
        actorRole: "admin",
        evaluatedAt: EVALUATED_AT,
      });
      const narrowingResourceLinkId = "policy-narrowing-race";
      const [launch, narrowing] = await Promise.all([
        placeStableLtiBadgeRule(
          fixture.db,
          placementInput(fixture, {
            contextId: selected.contextId,
            resourceLinkId: narrowingResourceLinkId,
            ruleId: firstRule.rule.id,
          }),
        ),
        replaceBadgeRulePlacementAvailability(fixture.db, {
          tenantId: fixture.tenantId,
          ruleId: firstRule.rule.id,
          availability: { scope: "selected_courses", courseContextIds: [replacement.id] },
          actorUserId: fixture.userId,
          actorRole: "admin",
          evaluatedAt: EVALUATED_AT,
        }),
      ]);

      expect(narrowing.status).toBe("updated");
      expect(["placed", "outside_availability"]).toContain(launch.status);
      expect(
        await findBadgeRulePlacementAvailability(fixture.db, {
          tenantId: fixture.tenantId,
          ruleId: firstRule.rule.id,
        }),
      ).toMatchObject({
        scope: "selected_courses",
        courseContextIds: [replacement.id],
      });
      const finalPlacement = await findLtiResourceLinkPlacement(fixture.db, {
        issuer: ISSUER,
        clientId: CLIENT_ID,
        deploymentId: DEPLOYMENT_ID,
        resourceLinkId: narrowingResourceLinkId,
      });
      expect(finalPlacement === null ? "outside_availability" : "placed").toBe(launch.status);
    } finally {
      await cleanupTestResources(fixture.db, {
        tenantIds: [fixture.tenantId],
        userIds: [fixture.userId],
      });
    }
  });
});

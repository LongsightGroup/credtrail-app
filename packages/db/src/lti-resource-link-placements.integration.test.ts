import { expect, it } from "vitest";

import { createFixtureRule } from "./badge-issuance-rule-test-fixtures";
import {
  findLtiResourceLinkPlacement,
  listLtiResourceLinkPlacementsForContext,
  listLtiResourceLinkPlacementsForRule,
  retireLtiResourceLinkPlacement,
  upsertLtiResourceLinkPlacement,
} from "./lti-resource-link-placements";
import {
  cleanupTestResources,
  createBadgeRuleIntegrationFixture,
  describeDbIntegration,
  selectCount,
  uniqueTestId,
} from "./postgres-test-support";

const placementIdentity = () => ({
  issuer: "https://placements.example.test",
  clientId: uniqueTestId("client"),
  deploymentId: uniqueTestId("deployment"),
  contextId: uniqueTestId("context"),
  resourceLinkId: uniqueTestId("resource"),
});

describeDbIntegration("LTI resource-link placement lifecycle with Postgres", () => {
  it("filters retired rows by default and rejects contradictory lifecycle state", async () => {
    const fixture = await createBadgeRuleIntegrationFixture();

    try {
      const created = await createFixtureRule(fixture);
      const identity = placementIdentity();
      const placement = await upsertLtiResourceLinkPlacement(fixture.db, {
        tenantId: fixture.tenantId,
        ...identity,
        badgeTemplateId: fixture.badgeTemplateId,
        ruleId: created.rule.id,
        createdByUserId: fixture.userId,
      });

      expect(placement).toMatchObject({
        status: "active",
        retiredAt: null,
        retiredByUserId: null,
      });
      expect(placement.lastSeenAt).toBe(placement.updatedAt);

      await retireLtiResourceLinkPlacement(fixture.db, {
        tenantId: fixture.tenantId,
        ruleId: created.rule.id,
        placementId: placement.id,
        actorUserId: fixture.userId,
        actorRole: "admin",
      });

      await expect(
        fixture.db
          .prepare(
            "UPDATE lti_resource_link_placements SET status = 'active' WHERE tenant_id = ? AND id = ?",
          )
          .bind(fixture.tenantId, placement.id)
          .run(),
      ).rejects.toThrow(/lifecycle/i);

      const activeOnly = await listLtiResourceLinkPlacementsForContext(fixture.db, {
        tenantId: fixture.tenantId,
        ...identity,
      });
      const includingRetired = await listLtiResourceLinkPlacementsForContext(fixture.db, {
        tenantId: fixture.tenantId,
        ...identity,
        includeRetired: true,
      });

      expect(activeOnly).toEqual([]);
      expect(includingRetired).toHaveLength(1);
      expect(includingRetired[0]?.status).toBe("retired");
    } finally {
      await cleanupTestResources(fixture.db, {
        tenantIds: [fixture.tenantId],
        userIds: [fixture.userId],
      });
    }
  });

  it("retires once under concurrent requests and reactivates from verified placement evidence", async () => {
    const fixture = await createBadgeRuleIntegrationFixture();

    try {
      const created = await createFixtureRule(fixture);
      const identity = placementIdentity();
      const placement = await upsertLtiResourceLinkPlacement(fixture.db, {
        tenantId: fixture.tenantId,
        ...identity,
        badgeTemplateId: fixture.badgeTemplateId,
        ruleId: created.rule.id,
        createdByUserId: fixture.userId,
      });
      const [first, second] = await Promise.all([
        retireLtiResourceLinkPlacement(fixture.db, {
          tenantId: fixture.tenantId,
          ruleId: created.rule.id,
          placementId: placement.id,
          actorUserId: fixture.userId,
          actorRole: "admin",
        }),
        retireLtiResourceLinkPlacement(fixture.db, {
          tenantId: fixture.tenantId,
          ruleId: created.rule.id,
          placementId: placement.id,
          actorUserId: fixture.userId,
          actorRole: "admin",
        }),
      ]);

      expect([first.status, second.status].sort()).toEqual(["already_retired", "retired"]);
      expect(
        await selectCount(
          fixture.db,
          "SELECT COUNT(*) AS totalCount FROM audit_logs WHERE tenant_id = ? AND target_id = ? AND action = 'lti.resource_link_placement_retired'",
          [fixture.tenantId, placement.id],
        ),
      ).toBe(1);

      const reactivated = await upsertLtiResourceLinkPlacement(fixture.db, {
        tenantId: fixture.tenantId,
        ...identity,
        badgeTemplateId: fixture.badgeTemplateId,
        ruleId: created.rule.id,
        createdByUserId: fixture.userId,
      });

      expect(reactivated).toMatchObject({
        id: placement.id,
        status: "active",
        createdAt: placement.createdAt,
        retiredAt: null,
        retiredByUserId: null,
      });
      expect(
        await selectCount(
          fixture.db,
          "SELECT COUNT(*) AS totalCount FROM audit_logs WHERE tenant_id = ? AND target_id = ? AND action = 'lti.resource_link_placement_reactivated'",
          [fixture.tenantId, placement.id],
        ),
      ).toBe(1);
      expect(
        await listLtiResourceLinkPlacementsForRule(fixture.db, {
          tenantId: fixture.tenantId,
          ruleId: created.rule.id,
        }),
      ).toHaveLength(1);
    } finally {
      await cleanupTestResources(fixture.db, {
        tenantIds: [fixture.tenantId],
        userIds: [fixture.userId],
      });
    }
  });

  it("does not retire a placement through another tenant or rule", async () => {
    const fixture = await createBadgeRuleIntegrationFixture();
    const otherFixture = await createBadgeRuleIntegrationFixture();

    try {
      const created = await createFixtureRule(fixture);
      const otherRule = await createFixtureRule(otherFixture);
      const identity = placementIdentity();
      const placement = await upsertLtiResourceLinkPlacement(fixture.db, {
        tenantId: fixture.tenantId,
        ...identity,
        badgeTemplateId: fixture.badgeTemplateId,
        ruleId: created.rule.id,
        createdByUserId: fixture.userId,
      });

      await expect(
        upsertLtiResourceLinkPlacement(fixture.db, {
          tenantId: otherFixture.tenantId,
          ...identity,
          badgeTemplateId: otherFixture.badgeTemplateId,
          ruleId: otherRule.rule.id,
          createdByUserId: otherFixture.userId,
        }),
      ).rejects.toThrow("belongs to another tenant");

      const crossTenant = await retireLtiResourceLinkPlacement(fixture.db, {
        tenantId: otherFixture.tenantId,
        ruleId: otherRule.rule.id,
        placementId: placement.id,
        actorUserId: otherFixture.userId,
        actorRole: "admin",
      });
      const wrongRule = await retireLtiResourceLinkPlacement(fixture.db, {
        tenantId: fixture.tenantId,
        ruleId: uniqueTestId("brl_wrong"),
        placementId: placement.id,
        actorUserId: fixture.userId,
        actorRole: "admin",
      });
      const unchanged = await findLtiResourceLinkPlacement(fixture.db, identity);

      expect(crossTenant).toEqual({ status: "not_found" });
      expect(wrongRule).toEqual({ status: "not_found" });
      expect(unchanged?.status).toBe("active");
    } finally {
      await cleanupTestResources(fixture.db, {
        tenantIds: [fixture.tenantId, otherFixture.tenantId],
        userIds: [fixture.userId, otherFixture.userId],
      });
    }
  });
});

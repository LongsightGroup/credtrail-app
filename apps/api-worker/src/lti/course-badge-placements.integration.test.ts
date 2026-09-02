import {
  retireLtiResourceLinkPlacement,
  setBadgeTemplateArchivedState,
  upsertLtiResourceLinkPlacement,
} from "@credtrail/db";
import {
  LTI_CLAIM_DEPLOYMENT_ID,
  LTI_CLAIM_MESSAGE_TYPE,
  LTI_CLAIM_TARGET_LINK_URI,
  LTI_CLAIM_VERSION,
  LTI_MESSAGE_TYPE_RESOURCE_LINK_REQUEST,
  type LTI13JwtPayload as LtiLaunchClaims,
} from "@longsightgroup/lti-tool";
import { expect, it } from "vitest";
import { createFixtureRule } from "../../../../packages/db/src/badge-issuance-rule-test-fixtures";
import {
  cleanupTestResources,
  createBadgeRuleIntegrationFixture,
  describeDbIntegration,
  uniqueTestId,
} from "../../../../packages/db/src/postgres-test-support";
import { resolveOrderedCourseBadgeTemplatesForContext } from "./course-badge-placements";

const ISSUER = "https://course-placements.example.test";

const launchClaims = (clientId: string, deploymentId: string): LtiLaunchClaims => ({
  iss: ISSUER,
  sub: "instructor-001",
  aud: clientId,
  exp: 1_800_000_000,
  iat: 1_700_000_000,
  nonce: "nonce-123",
  [LTI_CLAIM_MESSAGE_TYPE]: LTI_MESSAGE_TYPE_RESOURCE_LINK_REQUEST,
  [LTI_CLAIM_VERSION]: "1.3.0",
  [LTI_CLAIM_DEPLOYMENT_ID]: deploymentId,
  [LTI_CLAIM_TARGET_LINK_URI]: "https://tool.example.test/v1/lti/launch",
});

const activateRule = async (
  fixture: Awaited<ReturnType<typeof createBadgeRuleIntegrationFixture>>,
  created: Awaited<ReturnType<typeof createFixtureRule>>,
): Promise<void> => {
  const activatedAt = "2026-09-02T12:00:00.000Z";

  await fixture.db
    .prepare(
      `
      UPDATE badge_issuance_rule_versions
      SET status = 'active',
          activated_by_user_id = ?,
          activated_at = ?,
          updated_at = ?
      WHERE tenant_id = ?
        AND rule_id = ?
        AND id = ?
    `,
    )
    .bind(
      fixture.userId,
      activatedAt,
      activatedAt,
      fixture.tenantId,
      created.rule.id,
      created.version.id,
    )
    .run();
  await fixture.db
    .prepare(
      `
      UPDATE badge_issuance_rules
      SET active_version_id = ?, updated_at = ?
      WHERE tenant_id = ?
        AND id = ?
    `,
    )
    .bind(created.version.id, activatedAt, fixture.tenantId, created.rule.id)
    .run();
};

describeDbIntegration("course badge placement resolution with Postgres", () => {
  it("reports historical placements but returns only placements backed by an active rule", async () => {
    const fixture = await createBadgeRuleIntegrationFixture();

    try {
      const rules = await Promise.all([
        createFixtureRule(fixture),
        createFixtureRule(fixture),
        createFixtureRule(fixture),
      ]);
      const clientId = uniqueTestId("client");
      const deploymentId = uniqueTestId("deployment");
      const contextId = uniqueTestId("context");
      const placements = await Promise.all(
        rules.map((created) =>
          upsertLtiResourceLinkPlacement(fixture.db, {
            tenantId: fixture.tenantId,
            issuer: ISSUER,
            clientId,
            deploymentId,
            contextId,
            resourceLinkId: uniqueTestId("resource"),
            badgeTemplateId: fixture.badgeTemplateId,
            ruleId: created.rule.id,
            createdByUserId: fixture.userId,
          }),
        ),
      );
      const claims = launchClaims(clientId, deploymentId);
      const historical = await resolveOrderedCourseBadgeTemplatesForContext({
        db: fixture.db,
        tenantId: fixture.tenantId,
        launchClaims: claims,
        issuerClientId: clientId,
        contextId,
      });

      expect(historical.placementGroups).toEqual([]);
      expect(historical.status).toEqual({
        kind: "empty",
        reason: "no_active_rules",
        counts: {
          queriedPlacements: 3,
          activePlacements: 3,
          retiredPlacements: 0,
          usablePlacements: 0,
          inactiveRulePlacements: 3,
          missingRulePlacements: 0,
          archivedTemplatePlacements: 0,
          missingTemplatePlacements: 0,
        },
      });

      const activeRule = rules[0];
      const activePlacement = placements[0];

      if (activeRule === undefined || activePlacement === undefined) {
        throw new Error("Expected active rule placement fixture");
      }

      await activateRule(fixture, activeRule);
      const active = await resolveOrderedCourseBadgeTemplatesForContext({
        db: fixture.db,
        tenantId: fixture.tenantId,
        launchClaims: claims,
        issuerClientId: clientId,
        contextId,
      });

      expect(active.placementGroups).toHaveLength(1);
      expect(active.placements).toHaveLength(1);
      expect(active.status).toMatchObject({
        kind: "usable",
        counts: { usablePlacements: 1, inactiveRulePlacements: 2 },
      });

      await retireLtiResourceLinkPlacement(fixture.db, {
        tenantId: fixture.tenantId,
        ruleId: activeRule.rule.id,
        placementId: activePlacement.id,
        actorUserId: fixture.userId,
        actorRole: "admin",
      });
      const retired = await resolveOrderedCourseBadgeTemplatesForContext({
        db: fixture.db,
        tenantId: fixture.tenantId,
        launchClaims: claims,
        issuerClientId: clientId,
        contextId,
      });

      expect(retired.placementGroups).toEqual([]);
      expect(retired.status).toMatchObject({
        kind: "empty",
        reason: "no_active_rules",
        counts: { retiredPlacements: 1, inactiveRulePlacements: 2 },
      });
    } finally {
      await cleanupTestResources(fixture.db, {
        tenantIds: [fixture.tenantId],
        userIds: [fixture.userId],
      });
    }
  });

  it("classifies unlinked rules and archived templates instead of presenting them as active", async () => {
    const fixture = await createBadgeRuleIntegrationFixture();

    try {
      const activeRule = await createFixtureRule(fixture);
      await activateRule(fixture, activeRule);
      const clientId = uniqueTestId("client");
      const deploymentId = uniqueTestId("deployment");
      const contextId = uniqueTestId("context");
      await Promise.all([
        upsertLtiResourceLinkPlacement(fixture.db, {
          tenantId: fixture.tenantId,
          issuer: ISSUER,
          clientId,
          deploymentId,
          contextId,
          resourceLinkId: uniqueTestId("resource"),
          badgeTemplateId: fixture.badgeTemplateId,
          ruleId: activeRule.rule.id,
          createdByUserId: fixture.userId,
        }),
        upsertLtiResourceLinkPlacement(fixture.db, {
          tenantId: fixture.tenantId,
          issuer: ISSUER,
          clientId,
          deploymentId,
          contextId,
          resourceLinkId: uniqueTestId("resource"),
          badgeTemplateId: fixture.badgeTemplateId,
          ruleId: null,
          createdByUserId: fixture.userId,
        }),
      ]);
      await setBadgeTemplateArchivedState(fixture.db, {
        tenantId: fixture.tenantId,
        id: fixture.badgeTemplateId,
        isArchived: true,
      });

      const result = await resolveOrderedCourseBadgeTemplatesForContext({
        db: fixture.db,
        tenantId: fixture.tenantId,
        launchClaims: launchClaims(clientId, deploymentId),
        issuerClientId: clientId,
        contextId,
      });

      expect(result.orderedTemplates).toEqual([]);
      expect(result.status).toEqual({
        kind: "empty",
        reason: "no_available_templates",
        counts: {
          queriedPlacements: 2,
          activePlacements: 2,
          retiredPlacements: 0,
          usablePlacements: 0,
          inactiveRulePlacements: 0,
          missingRulePlacements: 1,
          archivedTemplatePlacements: 1,
          missingTemplatePlacements: 0,
        },
      });
    } finally {
      await cleanupTestResources(fixture.db, {
        tenantIds: [fixture.tenantId],
        userIds: [fixture.userId],
      });
    }
  });
});

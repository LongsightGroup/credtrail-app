import { expect, it } from "vitest";

import * as dbModule from "./index";
import { createAuditLog } from "./audit-logs";
import { createFixtureRule } from "./badge-issuance-rule-test-fixtures";
import {
  cleanupTestResources,
  createBadgeRuleIntegrationFixture,
  describeDbIntegration,
  seedAssertion,
  uniqueTestId,
} from "./postgres-test-support";

describeDbIntegration("assertion evidence DB helpers with Postgres", () => {
  it("finds rule evaluations by assertion id", async () => {
    const fixture = await createBadgeRuleIntegrationFixture();

    try {
      const createdRule = await createFixtureRule(fixture);
      const version = createdRule.version;

      const assertionId = await seedAssertion(fixture.db, {
        tenantId: fixture.tenantId,
        badgeTemplateId: fixture.badgeTemplateId,
        recipientIdentity: "learner@example.edu",
        issuedAt: "2026-03-24T15:00:00.000Z",
        issuedByUserId: fixture.userId,
      });

      await dbModule.createBadgeIssuanceRuleEvaluation(fixture.db, {
        tenantId: fixture.tenantId,
        ruleId: createdRule.rule.id,
        versionId: version.id,
        learnerId: "learner-001",
        recipientIdentity: "learner@example.edu",
        recipientIdentityType: "email",
        matched: true,
        issuanceStatus: "issued",
        assertionId,
        evaluationJson: JSON.stringify({ outcome: "matched" }),
      });

      const loaded = await dbModule.findBadgeIssuanceRuleEvaluationByAssertionId(fixture.db, {
        tenantId: fixture.tenantId,
        assertionId,
      });

      expect(loaded?.assertionId).toBe(assertionId);
      expect(loaded?.ruleId).toBe(createdRule.rule.id);
    } finally {
      await cleanupTestResources(fixture.db, {
        tenantIds: [fixture.tenantId],
        userIds: [fixture.userId],
      });
    }
  });

  it("persists and reads assertion issuance provenance snapshots", async () => {
    const fixture = await createBadgeRuleIntegrationFixture();

    try {
      const createdRule = await createFixtureRule(fixture);
      const version = createdRule.version;

      const assertionId = uniqueTestId("assertion");
      const finalized = await dbModule.finalizeAssertionIssuance(fixture.db, {
        assertion: {
          id: assertionId,
          tenantId: fixture.tenantId,
          recipientIdentity: "learner-two@example.edu",
          recipientIdentityType: "email",
          vcR2Key: `tenants/${fixture.tenantId}/assertions/${assertionId}.jsonld`,
          statusListIndex: 7,
          idempotencyKey: uniqueTestId("idem"),
          issuedAt: "2026-03-24T16:00:00.000Z",
          issuedByUserId: fixture.userId,
        },
        achievementSource: {
          kind: "rule_version",
          provenance: {
            source: "lti_roster",
            ruleId: createdRule.rule.id,
            versionId: version.id,
            provenanceJson: JSON.stringify({ outcome: "matched" }),
          },
        },
        buildAuditLog: (assertion) => ({
          tenantId: fixture.tenantId,
          actorUserId: fixture.userId,
          action: "assertion.issued",
          targetType: "assertion",
          targetId: assertion.id,
        }),
      });

      const loaded = await dbModule.findAssertionIssuanceProvenanceByAssertionId(fixture.db, {
        tenantId: fixture.tenantId,
        assertionId,
      });

      expect(loaded?.source).toBe("lti_roster");
      expect(loaded?.ruleId).toBe(createdRule.rule.id);
      expect(loaded?.versionId).toBe(version.id);
      expect(finalized.status).toBe("issued");
    } finally {
      await cleanupTestResources(fixture.db, {
        tenantIds: [fixture.tenantId],
        userIds: [fixture.userId],
      });
    }
  });

  it("rolls back assertion issuance when the selected pathway handoff is not eligible", async () => {
    const fixture = await createBadgeRuleIntegrationFixture();

    try {
      const createdRule = await createFixtureRule(fixture);
      const learner = await dbModule.createLearnerProfile(fixture.db, {
        tenantId: fixture.tenantId,
        primaryIdentityType: "email",
        primaryIdentityValue: "pathway-handoff@example.edu",
      });
      const assertionId = uniqueTestId("assertion_handoff_conflict");
      const finalized = await dbModule.finalizeAssertionIssuance(fixture.db, {
        assertion: {
          id: assertionId,
          tenantId: fixture.tenantId,
          learnerProfileId: learner.id,
          recipientIdentity: "pathway-handoff@example.edu",
          recipientIdentityType: "email",
          vcR2Key: `tenants/${fixture.tenantId}/assertions/${assertionId}.jsonld`,
          statusListIndex: 17,
          idempotencyKey: uniqueTestId("idem_handoff_conflict"),
          issuedAt: "2026-03-24T16:30:00.000Z",
          issuedByUserId: fixture.userId,
        },
        achievementSource: {
          kind: "rule_version",
          provenance: {
            source: "lti_roster",
            ruleId: createdRule.rule.id,
            versionId: createdRule.version.id,
            provenanceJson: "{}",
          },
        },
        learnerPathwayCompletionHandoffId: uniqueTestId("missing_handoff"),
        buildAuditLog: (assertion) => ({
          tenantId: fixture.tenantId,
          actorUserId: fixture.userId,
          action: "assertion.issued",
          targetType: "assertion",
          targetId: assertion.id,
        }),
      });
      const assertion = await dbModule.findAssertionById(fixture.db, fixture.tenantId, assertionId);

      expect(finalized).toEqual({ status: "learner_pathway_handoff_conflict" });
      expect(assertion).toBeNull();
    } finally {
      await cleanupTestResources(fixture.db, {
        tenantIds: [fixture.tenantId],
        userIds: [fixture.userId],
      });
    }
  });

  it("lists assertion-targeted audit logs and rule evaluation metadata", async () => {
    const fixture = await createBadgeRuleIntegrationFixture();

    try {
      const assertionId = await seedAssertion(fixture.db, {
        tenantId: fixture.tenantId,
        badgeTemplateId: fixture.badgeTemplateId,
        recipientIdentity: "learner-three@example.edu",
        issuedAt: "2026-03-24T17:00:00.000Z",
      });

      await createAuditLog(fixture.db, {
        tenantId: fixture.tenantId,
        actorUserId: fixture.userId,
        action: "assertion.issued",
        targetType: "assertion",
        targetId: assertionId,
        metadata: { assertionId },
      });
      await createAuditLog(fixture.db, {
        tenantId: fixture.tenantId,
        actorUserId: fixture.userId,
        action: "badge_rule.evaluated",
        targetType: "badge_rule",
        targetId: "brl_evaluated",
        metadata: { assertionId },
      });

      const logs = await dbModule.listAuditLogsForAssertion(fixture.db, {
        tenantId: fixture.tenantId,
        assertionId,
      });

      expect(logs.map((log) => log.action).sort()).toEqual(
        ["assertion.issued", "badge_rule.evaluated"].sort(),
      );
    } finally {
      await cleanupTestResources(fixture.db, {
        tenantIds: [fixture.tenantId],
        userIds: [fixture.userId],
      });
    }
  });
});

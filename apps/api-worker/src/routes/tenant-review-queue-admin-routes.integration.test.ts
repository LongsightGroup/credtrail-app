import { Hono } from "hono";
import { expect, it } from "vitest";
import {
  createBadgeIssuanceRuleEvaluation,
  findBadgeIssuanceRuleEvaluationById,
} from "@credtrail/db";
import { createFixtureRule } from "../../../../packages/db/src/badge-issuance-rule-test-fixtures";
import {
  cleanupTestResources,
  createBadgeRuleIntegrationFixture,
  describeDbIntegration,
} from "../../../../packages/db/src/postgres-test-support";
import { registerTenantReviewQueueAdminRoutes } from "./tenant-review-queue-admin-routes";
import { loadBadgeRuleReviewQueueEntries } from "../badge-rule-review-queue-workspace";
import type { AppEnv } from "../app/types";

describeDbIntegration("review queue decisions", () => {
  it("shows persisted missing information and saves the administrator's own decision note", async () => {
    const fixture = await createBadgeRuleIntegrationFixture();
    try {
      const rule = await createFixtureRule(fixture);
      const evaluation = await createBadgeIssuanceRuleEvaluation(fixture.db, {
        tenantId: fixture.tenantId,
        ruleId: rule.rule.id,
        versionId: rule.version.id,
        learnerId: "learner",
        recipientIdentity: "review@example.edu",
        recipientIdentityType: "email",
        matched: false,
        issuanceStatus: "review_required",
        reviewStatus: "pending",
        evaluationJson: JSON.stringify({
          evaluation: {
            matched: false,
            tree: {
              matched: false,
              detail: "Course completion is missing",
              resultKind: "missing_data",
            },
          },
        }),
      });
      const entries = await loadBadgeRuleReviewQueueEntries(fixture.db, fixture.tenantId);
      expect(entries[0]?.missingInformation).toEqual(["Course completion is missing"]);
      expect(entries[0]?.badgeTitle).toBe(rule.version.snapshot.badgeTemplateTitle);
      const app = new Hono<AppEnv>();
      registerTenantReviewQueueAdminRoutes({
        app,
        resolveDatabase: () => fixture.db,
        resolveInstitutionAdminAdminRole: async () => ({
          principal: {
            userId: fixture.userId,
            authSessionId: "test-session",
            authMethod: "better_auth",
            expiresAt: "2027-01-01T00:00:00.000Z",
          },
          membershipRole: "admin",
        }),
        issueBadgeForTenant: async () => {
          throw new Error("Dismiss must not issue a badge");
        },
      });
      const response = await app.request(
        `/tenants/${fixture.tenantId}/admin/operations/review-queue/resolve`,
        {
          method: "POST",
          body: new URLSearchParams({
            evaluationId: evaluation.id,
            decision: "dismiss",
            comment: "Registrar confirmed the course is incomplete.",
          }),
        },
        { BETTER_AUTH_SECRET: "review-integration-test-secret" },
      );
      expect(response.status).toBe(303);
      const stored = await findBadgeIssuanceRuleEvaluationById(fixture.db, {
        tenantId: fixture.tenantId,
        evaluationId: evaluation.id,
      });
      expect(stored?.reviewComment).toBe("Registrar confirmed the course is incomplete.");
      expect(stored?.reviewStatus).toBe("resolved");
      expect(stored?.assertionId).toBeNull();
      expect(await loadBadgeRuleReviewQueueEntries(fixture.db, fixture.tenantId)).toEqual([]);
      const history = await loadBadgeRuleReviewQueueEntries(fixture.db, fixture.tenantId, {
        reviewStatus: "resolved",
      });
      expect(history).toHaveLength(1);
      expect(history[0]).toMatchObject({
        evaluationId: evaluation.id,
        decision: "dismiss",
        decisionNote: "Registrar confirmed the course is incomplete.",
        reviewedAt: stored?.reviewedAt,
      });
      expect(history[0]?.reviewerEmail).toContain("@");
      expect(
        await loadBadgeRuleReviewQueueEntries(fixture.db, "different-tenant", {
          reviewStatus: "resolved",
        }),
      ).toEqual([]);
    } finally {
      await cleanupTestResources(fixture.db, {
        tenantIds: [fixture.tenantId],
        userIds: [fixture.userId],
      });
    }
  });
});

import { expect, it } from "vitest";
import { createLearnerProfile, recordAssertionLifecycleTransition } from "@credtrail/db";
import {
  cleanupTestResources,
  createBadgeRuleIntegrationFixture,
  describeDbIntegration,
  seedAssertion,
} from "../../../../packages/db/src/postgres-test-support";
import { loadLearnerRecordExportBundle } from "./learner-record-export";

describeDbIntegration("learner record lifecycle", () => {
  it("exports suspended, restored, expired, and revoked status from the latest lifecycle state", async () => {
    const f = await createBadgeRuleIntegrationFixture();
    try {
      const profile = await createLearnerProfile(f.db, {
        tenantId: f.tenantId,
        primaryIdentityType: "email",
        primaryIdentityValue: "lifecycle@example.edu",
        primaryIdentityVerified: true,
      });
      const assertionId = await seedAssertion(f.db, {
        tenantId: f.tenantId,
        badgeTemplateId: f.badgeTemplateId,
        recipientIdentity: "lifecycle@example.edu",
        learnerProfileId: profile.id,
        issuedAt: "2026-09-01T00:00:00.000Z",
      });
      let day = 2;
      for (const state of ["active", "suspended", "active", "expired", "revoked"] as const) {
        if (day > 2)
          await recordAssertionLifecycleTransition(f.db, {
            tenantId: f.tenantId,
            assertionId,
            toState: state,
            reasonCode: "other",
            reason: "Lifecycle test",
            transitionSource: "manual",
            actorUserId: f.userId,
            transitionedAt: `2026-09-${String(day).padStart(2, "0")}T00:00:00.000Z`,
          });
        const bundle = await loadLearnerRecordExportBundle(f.db, {
          tenantId: f.tenantId,
          learnerProfileId: profile.id,
        });
        expect(bundle?.items[0]?.status).toBe(state);
        day += 1;
      }
    } finally {
      await cleanupTestResources(f.db, { tenantIds: [f.tenantId], userIds: [f.userId] });
    }
  });
});

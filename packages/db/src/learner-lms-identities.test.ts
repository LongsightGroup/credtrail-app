import { expect, it } from "vitest";

import {
  createLearnerProfile,
  finalizeAssertionIssuance,
  findAssertionById,
  listLearnerProfilesForRecordLookup,
  upsertTenantLmsConnection,
} from "./index";
import {
  cleanupTestResources,
  createBadgeRuleIntegrationFixture,
  describeDbIntegration,
  type BadgeRuleIntegrationFixture,
  uniqueTestId,
} from "./postgres-test-support";

const ISSUED_AT = "2026-08-04T10:00:00.000Z";

const finalizeTestIssuance = (
  fixture: BadgeRuleIntegrationFixture,
  input: {
    readonly assertionId: string;
    readonly learnerProfileId: string;
    readonly recipientEmail: string;
    readonly connectionId: string;
    readonly lmsLearnerId: string;
    readonly statusListIndex: number;
    readonly badgeTemplateId?: string;
  },
) =>
  finalizeAssertionIssuance(fixture.db, {
    assertion: {
      id: input.assertionId,
      tenantId: fixture.tenantId,
      learnerProfileId: input.learnerProfileId,
      badgeTemplateId: input.badgeTemplateId ?? fixture.badgeTemplateId,
      recipientIdentity: input.recipientEmail,
      recipientIdentityType: "email",
      vcR2Key: `test/${input.assertionId}.json`,
      statusListIndex: input.statusListIndex,
      idempotencyKey: uniqueTestId(`idem_${input.assertionId}`),
      issuedAt: ISSUED_AT,
    },
    provenance: { source: "rule_evaluate" },
    lmsLearnerIdentity: {
      connectionId: input.connectionId,
      learnerId: input.lmsLearnerId,
    },
    buildAuditLog: (assertion) => ({
      tenantId: fixture.tenantId,
      actorUserId: fixture.userId,
      action: "assertion.issued",
      targetType: "assertion",
      targetId: assertion.id,
    }),
  });

describeDbIntegration("connection-scoped LMS learner identities", () => {
  it("links issuance atomically and reports cross-profile conflicts", async () => {
    const fixture = await createBadgeRuleIntegrationFixture();

    try {
      const firstProfile = await createLearnerProfile(fixture.db, {
        tenantId: fixture.tenantId,
        primaryIdentityType: "email",
        primaryIdentityValue: "first@example.edu",
      });
      const secondProfile = await createLearnerProfile(fixture.db, {
        tenantId: fixture.tenantId,
        primaryIdentityType: "email",
        primaryIdentityValue: "second@example.edu",
      });
      const firstAssertionId = uniqueTestId("assertion_lms_first");
      const conflictingAssertionId = uniqueTestId("assertion_lms_conflict");
      const first = await finalizeTestIssuance(fixture, {
        assertionId: firstAssertionId,
        learnerProfileId: firstProfile.id,
        recipientEmail: "first@example.edu",
        connectionId: fixture.lmsConnectionId,
        lmsLearnerId: "provider-user-123",
        statusListIndex: 100,
      });

      expect(first.status).toBe("issued");
      expect(
        await listLearnerProfilesForRecordLookup(fixture.db, {
          tenantId: fixture.tenantId,
          lookupValue: "provider-user-123",
        }),
      ).toEqual([firstProfile]);
      expect(
        await listLearnerProfilesForRecordLookup(fixture.db, {
          tenantId: fixture.tenantId,
          lookupValue: " FIRST@EXAMPLE.EDU ",
        }),
      ).toEqual([firstProfile]);

      const conflict = await finalizeTestIssuance(fixture, {
        assertionId: conflictingAssertionId,
        learnerProfileId: secondProfile.id,
        recipientEmail: "second@example.edu",
        connectionId: fixture.lmsConnectionId,
        lmsLearnerId: "provider-user-123",
        statusListIndex: 101,
      });

      expect(conflict).toEqual({
        status: "lms_identity_conflict",
        reason: "lms_learner_id_in_use",
      });
      expect(
        await findAssertionById(fixture.db, fixture.tenantId, conflictingAssertionId),
      ).toBeNull();

      const profileConflictAssertionId = uniqueTestId("assertion_profile_conflict");
      const profileConflict = await finalizeTestIssuance(fixture, {
        assertionId: profileConflictAssertionId,
        learnerProfileId: firstProfile.id,
        recipientEmail: "first@example.edu",
        connectionId: fixture.lmsConnectionId,
        lmsLearnerId: "different-provider-user",
        statusListIndex: 102,
      });

      expect(profileConflict).toEqual({
        status: "lms_identity_conflict",
        reason: "learner_profile_in_use",
      });
      expect(
        await findAssertionById(fixture.db, fixture.tenantId, profileConflictAssertionId),
      ).toBeNull();
    } finally {
      await cleanupTestResources(fixture.db, {
        tenantIds: [fixture.tenantId],
        userIds: [fixture.userId],
      });
    }
  });

  it("keeps equal provider IDs separate across connections and rolls links back on failure", async () => {
    const fixture = await createBadgeRuleIntegrationFixture();

    try {
      const firstProfile = await createLearnerProfile(fixture.db, {
        tenantId: fixture.tenantId,
        primaryIdentityType: "email",
        primaryIdentityValue: "one@example.edu",
      });
      const secondProfile = await createLearnerProfile(fixture.db, {
        tenantId: fixture.tenantId,
        primaryIdentityType: "email",
        primaryIdentityValue: "two@example.edu",
      });
      const secondConnection = await upsertTenantLmsConnection(fixture.db, {
        id: uniqueTestId("lms_second"),
        tenantId: fixture.tenantId,
        displayName: "Second LMS",
        providerKind: "sakai",
        apiBaseUrl: "https://sakai.example.test",
      });

      for (const [index, connectionAndProfile] of [
        { connectionId: fixture.lmsConnectionId, profile: firstProfile },
        { connectionId: secondConnection.id, profile: secondProfile },
      ].entries()) {
        const assertionId = uniqueTestId(`assertion_scoped_${String(index)}`);
        const result = await finalizeTestIssuance(fixture, {
          assertionId,
          learnerProfileId: connectionAndProfile.profile.id,
          recipientEmail: `${String(index)}@example.edu`,
          connectionId: connectionAndProfile.connectionId,
          lmsLearnerId: "shared-provider-id",
          statusListIndex: 110 + index,
        });

        expect(result.status).toBe("issued");
      }

      expect(
        await listLearnerProfilesForRecordLookup(fixture.db, {
          tenantId: fixture.tenantId,
          lookupValue: "shared-provider-id",
        }),
      ).toEqual(
        [firstProfile, secondProfile].sort((left, right) => left.id.localeCompare(right.id)),
      );

      const rollbackProfile = await createLearnerProfile(fixture.db, {
        tenantId: fixture.tenantId,
        primaryIdentityType: "email",
        primaryIdentityValue: "rollback@example.edu",
      });
      const failedAssertionId = uniqueTestId("assertion_rollback");

      await expect(
        finalizeTestIssuance(fixture, {
          assertionId: failedAssertionId,
          learnerProfileId: rollbackProfile.id,
          recipientEmail: "rollback@example.edu",
          connectionId: fixture.lmsConnectionId,
          lmsLearnerId: "rolled-back-provider-id",
          statusListIndex: 120,
          badgeTemplateId: uniqueTestId("missing_template"),
        }),
      ).rejects.toThrow(/assertions.*foreign key/i);

      expect(
        await listLearnerProfilesForRecordLookup(fixture.db, {
          tenantId: fixture.tenantId,
          lookupValue: "rolled-back-provider-id",
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

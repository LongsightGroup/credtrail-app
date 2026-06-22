import { expect, it } from "vitest";

import {
  listAssertionsByBadgeTemplatesAndRecipientEmails,
  listAssertionsByIdempotencyKeys,
} from "./assertions";
import {
  cleanupTestResources,
  createTestTenantFixture,
  describeDbIntegration,
  seedAssertion,
  seedBadgeTemplate,
  uniqueTestId,
} from "./postgres-test-support";

describeDbIntegration("assertion batch lookups", () => {
  it("lists assertions by idempotency keys within the tenant", async () => {
    const fixture = await createTestTenantFixture({
      displayName: "CredTrail University",
    });
    const otherFixture = await createTestTenantFixture({
      displayName: "Other University",
    });

    try {
      const badgeTemplateId = await seedBadgeTemplate(fixture.db, {
        tenantId: fixture.tenantId,
      });
      const otherBadgeTemplateId = await seedBadgeTemplate(otherFixture.db, {
        tenantId: otherFixture.tenantId,
      });
      const matchingKey = uniqueTestId("idem_match");
      const secondMatchingKey = uniqueTestId("idem_second");
      const otherTenantKey = uniqueTestId("idem_other_tenant");
      const matchingAssertionId = await seedAssertion(fixture.db, {
        tenantId: fixture.tenantId,
        badgeTemplateId,
        recipientIdentity: "learner.one@example.edu",
        idempotencyKey: matchingKey,
        issuedAt: "2026-02-11T14:00:00.000Z",
      });
      const secondMatchingAssertionId = await seedAssertion(fixture.db, {
        tenantId: fixture.tenantId,
        badgeTemplateId,
        recipientIdentity: "learner.two@example.edu",
        idempotencyKey: secondMatchingKey,
        issuedAt: "2026-02-12T14:00:00.000Z",
      });
      await seedAssertion(otherFixture.db, {
        tenantId: otherFixture.tenantId,
        badgeTemplateId: otherBadgeTemplateId,
        recipientIdentity: "learner.one@example.edu",
        idempotencyKey: otherTenantKey,
        issuedAt: "2026-02-13T14:00:00.000Z",
      });

      const assertions = await listAssertionsByIdempotencyKeys(fixture.db, {
        tenantId: fixture.tenantId,
        idempotencyKeys: [matchingKey, matchingKey, secondMatchingKey, otherTenantKey, ""],
      });

      expect(assertions.map((assertion) => assertion.id).sort()).toEqual(
        [matchingAssertionId, secondMatchingAssertionId].sort(),
      );
    } finally {
      await cleanupTestResources(fixture.db, {
        tenantIds: [fixture.tenantId, otherFixture.tenantId],
      });
    }
  });

  it("lists email recipient assertions by badge template with normalized emails", async () => {
    const fixture = await createTestTenantFixture({
      displayName: "CredTrail University",
    });

    try {
      const badgeTemplateId = await seedBadgeTemplate(fixture.db, {
        tenantId: fixture.tenantId,
      });
      const otherBadgeTemplateId = await seedBadgeTemplate(fixture.db, {
        tenantId: fixture.tenantId,
      });
      const olderAssertionId = await seedAssertion(fixture.db, {
        tenantId: fixture.tenantId,
        badgeTemplateId,
        recipientIdentity: "Learner.One@Example.edu",
        idempotencyKey: uniqueTestId("idem_older"),
        issuedAt: "2026-02-11T14:00:00.000Z",
      });
      const newestAssertionId = await seedAssertion(fixture.db, {
        tenantId: fixture.tenantId,
        badgeTemplateId,
        recipientIdentity: "learner.one@example.edu",
        idempotencyKey: uniqueTestId("idem_newer"),
        issuedAt: "2026-02-12T14:00:00.000Z",
      });
      await seedAssertion(fixture.db, {
        tenantId: fixture.tenantId,
        badgeTemplateId: otherBadgeTemplateId,
        recipientIdentity: "learner.one@example.edu",
        idempotencyKey: uniqueTestId("idem_other_badge"),
        issuedAt: "2026-02-13T14:00:00.000Z",
      });
      await seedAssertion(fixture.db, {
        tenantId: fixture.tenantId,
        badgeTemplateId,
        recipientIdentity: "learner.two@example.edu",
        idempotencyKey: uniqueTestId("idem_other_email"),
        issuedAt: "2026-02-14T14:00:00.000Z",
      });
      await seedAssertion(fixture.db, {
        tenantId: fixture.tenantId,
        badgeTemplateId,
        recipientIdentity: "learner.one@example.edu",
        recipientIdentityType: "email_sha256",
        idempotencyKey: uniqueTestId("idem_hashed_email"),
        issuedAt: "2026-02-15T14:00:00.000Z",
      });

      const assertions = await listAssertionsByBadgeTemplatesAndRecipientEmails(fixture.db, {
        tenantId: fixture.tenantId,
        badgeTemplateIds: [badgeTemplateId],
        recipientEmails: [" LEARNER.ONE@example.edu ", "learner.one@example.edu"],
      });

      expect(assertions.map((assertion) => assertion.id)).toEqual([
        newestAssertionId,
        olderAssertionId,
      ]);
    } finally {
      await cleanupTestResources(fixture.db, {
        tenantIds: [fixture.tenantId],
      });
    }
  });
});

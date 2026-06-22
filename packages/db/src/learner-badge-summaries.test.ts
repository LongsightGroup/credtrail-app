import { describe, expect, it } from "vitest";

import {
  addLearnerIdentityAlias,
  createLearnerProfile,
  findClaimableLearnerBadgeSummary,
  listLearnerBadgeSummaries,
  upsertUserByEmail,
} from "./index";
import {
  cleanupTestResources,
  createTestTenantFixture,
  describeDbIntegration,
  seedAssertion,
  seedBadgeTemplate,
  uniqueTestId,
} from "./postgres-test-support";

describeDbIntegration("learner badge summaries", () => {
  it("returns empty results when the user does not exist", async () => {
    const fixture = await createTestTenantFixture();

    try {
      const summaries = await listLearnerBadgeSummaries(fixture.db, {
        tenantId: fixture.tenantId,
        userId: uniqueTestId("missing_user"),
      });
      const claimable = await findClaimableLearnerBadgeSummary(fixture.db, {
        tenantId: fixture.tenantId,
        userId: uniqueTestId("missing_user"),
        assertionId: uniqueTestId("assertion"),
      });

      expect(summaries).toEqual([]);
      expect(claimable).toBeNull();
    } finally {
      await cleanupTestResources(fixture.db, {
        tenantIds: [fixture.tenantId],
      });
    }
  });

  it("lists legacy email-only badges when the user has no learner profile", async () => {
    const fixture = await createTestTenantFixture();
    const user = await upsertUserByEmail(fixture.db, "legacy.learner@umich.edu");
    const badgeTemplateId = await seedBadgeTemplate(fixture.db, {
      tenantId: fixture.tenantId,
      title: "Legacy Badge",
    });
    const matchingAssertionId = uniqueTestId("assertion_legacy_match");
    const otherAssertionId = uniqueTestId("assertion_legacy_other");

    try {
      await seedAssertion(fixture.db, {
        id: matchingAssertionId,
        tenantId: fixture.tenantId,
        badgeTemplateId,
        recipientIdentity: "Legacy.Learner@Umich.edu",
        issuedAt: "2026-03-20T12:00:00.000Z",
      });
      await seedAssertion(fixture.db, {
        id: otherAssertionId,
        tenantId: fixture.tenantId,
        badgeTemplateId,
        recipientIdentity: "someone-else@umich.edu",
        issuedAt: "2026-03-21T12:00:00.000Z",
      });

      const summaries = await listLearnerBadgeSummaries(fixture.db, {
        tenantId: fixture.tenantId,
        userId: user.id,
      });

      expect(summaries).toHaveLength(1);
      expect(summaries[0]).toMatchObject({
        assertionId: matchingAssertionId,
        tenantId: fixture.tenantId,
        badgeTemplateId,
        badgeTitle: "Legacy Badge",
      });
    } finally {
      await cleanupTestResources(fixture.db, {
        tenantIds: [fixture.tenantId],
        userIds: [user.id],
      });
    }
  });

  it("lists badges linked to a learner profile or matching email aliases", async () => {
    const fixture = await createTestTenantFixture();
    const user = await upsertUserByEmail(fixture.db, "student@umich.edu");
    const profile = await createLearnerProfile(fixture.db, {
      tenantId: fixture.tenantId,
      primaryIdentityType: "email",
      primaryIdentityValue: "student@umich.edu",
      primaryIdentityVerified: true,
    });
    await addLearnerIdentityAlias(fixture.db, {
      tenantId: fixture.tenantId,
      learnerProfileId: profile.id,
      identityType: "email",
      identityValue: "student.alias@umich.edu",
      isVerified: true,
    });

    const badgeTemplateId = await seedBadgeTemplate(fixture.db, {
      tenantId: fixture.tenantId,
      title: "Profile Badge",
    });
    const profileLinkedAssertionId = uniqueTestId("assertion_profile");
    const aliasAssertionId = uniqueTestId("assertion_alias");
    const otherAssertionId = uniqueTestId("assertion_other");

    try {
      await seedAssertion(fixture.db, {
        id: profileLinkedAssertionId,
        tenantId: fixture.tenantId,
        learnerProfileId: profile.id,
        badgeTemplateId,
        recipientIdentity: "student@umich.edu",
        issuedAt: "2026-03-22T12:00:00.000Z",
      });
      await seedAssertion(fixture.db, {
        id: aliasAssertionId,
        tenantId: fixture.tenantId,
        badgeTemplateId,
        recipientIdentity: "student.alias@umich.edu",
        issuedAt: "2026-03-24T12:00:00.000Z",
      });
      await seedAssertion(fixture.db, {
        id: otherAssertionId,
        tenantId: fixture.tenantId,
        badgeTemplateId,
        recipientIdentity: "someone-else@umich.edu",
        issuedAt: "2026-03-25T12:00:00.000Z",
      });

      const summaries = await listLearnerBadgeSummaries(fixture.db, {
        tenantId: fixture.tenantId,
        userId: user.id,
      });

      expect(summaries.map((summary) => summary.assertionId)).toEqual([
        aliasAssertionId,
        profileLinkedAssertionId,
      ]);
    } finally {
      await cleanupTestResources(fixture.db, {
        tenantIds: [fixture.tenantId],
        userIds: [user.id],
      });
    }
  });

  it("includes revoked badges in list results but not in claimable lookup", async () => {
    const fixture = await createTestTenantFixture();
    const user = await upsertUserByEmail(fixture.db, "revoked-list@umich.edu");
    const badgeTemplateId = await seedBadgeTemplate(fixture.db, {
      tenantId: fixture.tenantId,
      title: "Revoked List Badge",
    });
    const activeAssertionId = uniqueTestId("assertion_active");
    const revokedAssertionId = uniqueTestId("assertion_revoked_list");

    try {
      await seedAssertion(fixture.db, {
        id: activeAssertionId,
        tenantId: fixture.tenantId,
        badgeTemplateId,
        recipientIdentity: "revoked-list@umich.edu",
        issuedAt: "2026-03-20T12:00:00.000Z",
      });
      await seedAssertion(fixture.db, {
        id: revokedAssertionId,
        tenantId: fixture.tenantId,
        badgeTemplateId,
        recipientIdentity: "revoked-list@umich.edu",
        issuedAt: "2026-03-21T12:00:00.000Z",
        revokedAt: "2026-03-22T12:00:00.000Z",
      });

      const summaries = await listLearnerBadgeSummaries(fixture.db, {
        tenantId: fixture.tenantId,
        userId: user.id,
      });
      const claimableActive = await findClaimableLearnerBadgeSummary(fixture.db, {
        tenantId: fixture.tenantId,
        userId: user.id,
        assertionId: activeAssertionId,
      });
      const claimableRevoked = await findClaimableLearnerBadgeSummary(fixture.db, {
        tenantId: fixture.tenantId,
        userId: user.id,
        assertionId: revokedAssertionId,
      });

      expect(summaries.map((summary) => summary.assertionId)).toEqual([
        revokedAssertionId,
        activeAssertionId,
      ]);
      expect(claimableActive?.assertionId).toBe(activeAssertionId);
      expect(claimableRevoked).toBeNull();
    } finally {
      await cleanupTestResources(fixture.db, {
        tenantIds: [fixture.tenantId],
        userIds: [user.id],
      });
    }
  });

  it("finds claimable profile-linked badges", async () => {
    const fixture = await createTestTenantFixture();
    const user = await upsertUserByEmail(fixture.db, "profile-claim@umich.edu");
    const profile = await createLearnerProfile(fixture.db, {
      tenantId: fixture.tenantId,
      primaryIdentityType: "email",
      primaryIdentityValue: "profile-claim@umich.edu",
      primaryIdentityVerified: true,
    });
    const badgeTemplateId = await seedBadgeTemplate(fixture.db, {
      tenantId: fixture.tenantId,
      title: "Profile Claim Badge",
    });
    const claimableAssertionId = uniqueTestId("assertion_profile_claimable");

    try {
      await seedAssertion(fixture.db, {
        id: claimableAssertionId,
        tenantId: fixture.tenantId,
        learnerProfileId: profile.id,
        badgeTemplateId,
        recipientIdentity: "profile-claim@umich.edu",
        issuedAt: "2026-03-20T12:00:00.000Z",
      });

      const claimable = await findClaimableLearnerBadgeSummary(fixture.db, {
        tenantId: fixture.tenantId,
        userId: user.id,
        assertionId: claimableAssertionId,
      });

      expect(claimable).toMatchObject({
        assertionId: claimableAssertionId,
        badgeTitle: "Profile Claim Badge",
        revokedAt: null,
      });
    } finally {
      await cleanupTestResources(fixture.db, {
        tenantIds: [fixture.tenantId],
        userIds: [user.id],
      });
    }
  });

  it("finds only claimable badges and ignores revoked or inaccessible assertions", async () => {
    const fixture = await createTestTenantFixture();
    const user = await upsertUserByEmail(fixture.db, "claimable@umich.edu");
    const badgeTemplateId = await seedBadgeTemplate(fixture.db, {
      tenantId: fixture.tenantId,
      title: "Claimable Badge",
    });
    const claimableAssertionId = uniqueTestId("assertion_claimable");
    const revokedAssertionId = uniqueTestId("assertion_revoked");
    const inaccessibleAssertionId = uniqueTestId("assertion_inaccessible");

    try {
      await seedAssertion(fixture.db, {
        id: claimableAssertionId,
        tenantId: fixture.tenantId,
        badgeTemplateId,
        recipientIdentity: "claimable@umich.edu",
        issuedAt: "2026-03-20T12:00:00.000Z",
      });
      await seedAssertion(fixture.db, {
        id: revokedAssertionId,
        tenantId: fixture.tenantId,
        badgeTemplateId,
        recipientIdentity: "claimable@umich.edu",
        issuedAt: "2026-03-21T12:00:00.000Z",
        revokedAt: "2026-03-22T12:00:00.000Z",
      });
      await seedAssertion(fixture.db, {
        id: inaccessibleAssertionId,
        tenantId: fixture.tenantId,
        badgeTemplateId,
        recipientIdentity: "other-person@umich.edu",
        issuedAt: "2026-03-23T12:00:00.000Z",
      });

      const claimable = await findClaimableLearnerBadgeSummary(fixture.db, {
        tenantId: fixture.tenantId,
        userId: user.id,
        assertionId: claimableAssertionId,
      });
      const revoked = await findClaimableLearnerBadgeSummary(fixture.db, {
        tenantId: fixture.tenantId,
        userId: user.id,
        assertionId: revokedAssertionId,
      });
      const inaccessible = await findClaimableLearnerBadgeSummary(fixture.db, {
        tenantId: fixture.tenantId,
        userId: user.id,
        assertionId: inaccessibleAssertionId,
      });

      expect(claimable).toMatchObject({
        assertionId: claimableAssertionId,
        badgeTitle: "Claimable Badge",
        revokedAt: null,
      });
      expect(revoked).toBeNull();
      expect(inaccessible).toBeNull();
    } finally {
      await cleanupTestResources(fixture.db, {
        tenantIds: [fixture.tenantId],
        userIds: [user.id],
      });
    }
  });

  it("does not return assertions from another tenant", async () => {
    const homeFixture = await createTestTenantFixture();
    const otherFixture = await createTestTenantFixture();
    const user = await upsertUserByEmail(homeFixture.db, "tenant-boundary@umich.edu");
    const homeBadgeTemplateId = await seedBadgeTemplate(homeFixture.db, {
      tenantId: homeFixture.tenantId,
      title: "Home Tenant Badge",
    });
    const otherBadgeTemplateId = await seedBadgeTemplate(otherFixture.db, {
      tenantId: otherFixture.tenantId,
      title: "Other Tenant Badge",
    });
    const homeAssertionId = uniqueTestId("assertion_home");
    const otherAssertionId = uniqueTestId("assertion_other_tenant");

    try {
      await seedAssertion(homeFixture.db, {
        id: homeAssertionId,
        tenantId: homeFixture.tenantId,
        badgeTemplateId: homeBadgeTemplateId,
        recipientIdentity: "tenant-boundary@umich.edu",
        issuedAt: "2026-03-20T12:00:00.000Z",
      });
      await seedAssertion(otherFixture.db, {
        id: otherAssertionId,
        tenantId: otherFixture.tenantId,
        badgeTemplateId: otherBadgeTemplateId,
        recipientIdentity: "tenant-boundary@umich.edu",
        issuedAt: "2026-03-21T12:00:00.000Z",
      });

      const summaries = await listLearnerBadgeSummaries(homeFixture.db, {
        tenantId: homeFixture.tenantId,
        userId: user.id,
      });
      const crossTenantClaimable = await findClaimableLearnerBadgeSummary(homeFixture.db, {
        tenantId: homeFixture.tenantId,
        userId: user.id,
        assertionId: otherAssertionId,
      });

      expect(summaries.map((summary) => summary.assertionId)).toEqual([homeAssertionId]);
      expect(crossTenantClaimable).toBeNull();
    } finally {
      await cleanupTestResources(homeFixture.db, {
        tenantIds: [homeFixture.tenantId, otherFixture.tenantId],
        userIds: [user.id],
      });
    }
  });
});

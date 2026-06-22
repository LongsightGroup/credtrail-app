import { describe, expect, it } from "vitest";

import {
  addLearnerIdentityAlias,
  createLearnerProfile,
  findLearnerProfileById,
  findLearnerProfileByIdentity,
  listAuditLogs,
  listLearnerIdentitiesByProfile,
  moveLearnerIdentityAliasToProfile,
  normalizeLearnerIdentityValue,
  resolveLearnerProfileForIdentity,
  resolveLearnerProfileFromSaml,
} from "./index";
import {
  cleanupTestResources,
  createTestTenantFixture,
  describeDbIntegration,
  seedAssertion,
  seedBadgeTemplate,
} from "./postgres-test-support";

describe("normalizeLearnerIdentityValue", () => {
  it("normalizes email and email_sha256 identity values", () => {
    expect(normalizeLearnerIdentityValue("email", "  Student@Umich.edu ")).toBe(
      "student@umich.edu",
    );
    expect(normalizeLearnerIdentityValue("email_sha256", " AABBCC ")).toBe("aabbcc");
  });
});

describeDbIntegration("learner profiles and identity aliases", () => {
  it("creates a learner profile and resolves it by normalized primary identity", async () => {
    const fixture = await createTestTenantFixture();

    try {
      const profile = await createLearnerProfile(fixture.db, {
        tenantId: fixture.tenantId,
        displayName: "Jane Doe",
        primaryIdentityType: "email",
        primaryIdentityValue: " Jane.Doe@Umich.edu ",
        primaryIdentityVerified: true,
      });

      expect(profile.tenantId).toBe(fixture.tenantId);
      expect(profile.displayName).toBe("Jane Doe");
      expect(profile.subjectId.startsWith(`urn:credtrail:learner:${fixture.tenantId}:`)).toBe(true);

      const resolved = await findLearnerProfileByIdentity(fixture.db, {
        tenantId: fixture.tenantId,
        identityType: "email",
        identityValue: "jane.doe@umich.edu",
      });

      expect(resolved?.id).toBe(profile.id);

      const identities = await listLearnerIdentitiesByProfile(
        fixture.db,
        fixture.tenantId,
        profile.id,
      );
      expect(identities).toHaveLength(1);
      expect(identities[0]?.isPrimary).toBe(true);
      expect(identities[0]?.isVerified).toBe(true);
      expect(identities[0]?.identityValue).toBe("jane.doe@umich.edu");
    } finally {
      await cleanupTestResources(fixture.db, {
        tenantIds: [fixture.tenantId],
      });
    }
  });

  it("links new aliases to the same learner and switches primary identity when requested", async () => {
    const fixture = await createTestTenantFixture();

    try {
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
        identityValue: "student@gmail.com",
        isPrimary: true,
        isVerified: true,
      });

      const oldIdentityResolved = await findLearnerProfileByIdentity(fixture.db, {
        tenantId: fixture.tenantId,
        identityType: "email",
        identityValue: "student@umich.edu",
      });
      const newIdentityResolved = await findLearnerProfileByIdentity(fixture.db, {
        tenantId: fixture.tenantId,
        identityType: "email",
        identityValue: "student@gmail.com",
      });

      expect(oldIdentityResolved?.id).toBe(profile.id);
      expect(newIdentityResolved?.id).toBe(profile.id);

      const identities = await listLearnerIdentitiesByProfile(
        fixture.db,
        fixture.tenantId,
        profile.id,
      );
      expect(identities).toHaveLength(2);
      expect(identities[0]?.identityValue).toBe("student@gmail.com");
      expect(identities[0]?.isPrimary).toBe(true);
      expect(identities[1]?.identityValue).toBe("student@umich.edu");
      expect(identities[1]?.isPrimary).toBe(false);
    } finally {
      await cleanupTestResources(fixture.db, {
        tenantIds: [fixture.tenantId],
      });
    }
  });

  it("prevents duplicate identity aliases within a tenant", async () => {
    const fixture = await createTestTenantFixture();

    try {
      const firstProfile = await createLearnerProfile(fixture.db, {
        tenantId: fixture.tenantId,
        primaryIdentityType: "email",
        primaryIdentityValue: "first@umich.edu",
      });
      const secondProfile = await createLearnerProfile(fixture.db, {
        tenantId: fixture.tenantId,
        primaryIdentityType: "email",
        primaryIdentityValue: "second@umich.edu",
      });

      expect(firstProfile.id).not.toBe(secondProfile.id);

      await expect(
        addLearnerIdentityAlias(fixture.db, {
          tenantId: fixture.tenantId,
          learnerProfileId: secondProfile.id,
          identityType: "email",
          identityValue: "first@umich.edu",
        }),
      ).rejects.toThrow("duplicate key value violates unique constraint");
    } finally {
      await cleanupTestResources(fixture.db, {
        tenantIds: [fixture.tenantId],
      });
    }
  });

  it("resolves to existing learner profile for repeated identity values", async () => {
    const fixture = await createTestTenantFixture();

    try {
      const first = await resolveLearnerProfileForIdentity(fixture.db, {
        tenantId: fixture.tenantId,
        identityType: "email",
        identityValue: "student@umich.edu",
      });
      const second = await resolveLearnerProfileForIdentity(fixture.db, {
        tenantId: fixture.tenantId,
        identityType: "email",
        identityValue: "student@umich.edu",
      });

      expect(second.id).toBe(first.id);
      const identities = await listLearnerIdentitiesByProfile(
        fixture.db,
        fixture.tenantId,
        first.id,
      );
      expect(identities).toHaveLength(1);
    } finally {
      await cleanupTestResources(fixture.db, {
        tenantIds: [fixture.tenantId],
      });
    }
  });

  it("moves an identity alias from a stale learner profile to the selected profile", async () => {
    const fixture = await createTestTenantFixture();

    try {
      const selectedProfile = await createLearnerProfile(fixture.db, {
        tenantId: fixture.tenantId,
        primaryIdentityType: "email",
        primaryIdentityValue: "student@umich.edu",
        primaryIdentityVerified: true,
      });
      const staleProfile = await createLearnerProfile(fixture.db, {
        tenantId: fixture.tenantId,
        primaryIdentityType: "saml_subject",
        primaryIdentityValue: "canvas-subject-123",
        primaryIdentityVerified: true,
      });
      const staleProfileId = staleProfile.id;

      const movedIdentity = await moveLearnerIdentityAliasToProfile(fixture.db, {
        tenantId: fixture.tenantId,
        learnerProfileId: selectedProfile.id,
        identityType: "saml_subject",
        identityValue: "canvas-subject-123",
        isPrimary: false,
        isVerified: true,
      });

      expect(movedIdentity.learnerProfileId).toBe(selectedProfile.id);

      const resolvedBySubject = await findLearnerProfileByIdentity(fixture.db, {
        tenantId: fixture.tenantId,
        identityType: "saml_subject",
        identityValue: "canvas-subject-123",
      });
      expect(resolvedBySubject?.id).toBe(selectedProfile.id);

      const staleIdentities = await listLearnerIdentitiesByProfile(
        fixture.db,
        fixture.tenantId,
        staleProfileId,
      );
      expect(staleIdentities).toHaveLength(0);

      const deletedStaleProfile = await findLearnerProfileById(
        fixture.db,
        fixture.tenantId,
        staleProfileId,
      );
      expect(deletedStaleProfile).toBeNull();

      const selectedIdentities = await listLearnerIdentitiesByProfile(
        fixture.db,
        fixture.tenantId,
        selectedProfile.id,
      );
      expect(selectedIdentities.map((identity) => identity.identityType)).toEqual([
        "email",
        "saml_subject",
      ]);
    } finally {
      await cleanupTestResources(fixture.db, {
        tenantIds: [fixture.tenantId],
      });
    }
  });

  it("returns the existing identity when move is called on the same profile", async () => {
    const fixture = await createTestTenantFixture();

    try {
      const profile = await createLearnerProfile(fixture.db, {
        tenantId: fixture.tenantId,
        primaryIdentityType: "email",
        primaryIdentityValue: "student@umich.edu",
        primaryIdentityVerified: true,
      });

      const first = await moveLearnerIdentityAliasToProfile(fixture.db, {
        tenantId: fixture.tenantId,
        learnerProfileId: profile.id,
        identityType: "email",
        identityValue: "student@umich.edu",
        isPrimary: true,
        isVerified: true,
      });
      const second = await moveLearnerIdentityAliasToProfile(fixture.db, {
        tenantId: fixture.tenantId,
        learnerProfileId: profile.id,
        identityType: "email",
        identityValue: "student@umich.edu",
        isPrimary: true,
        isVerified: true,
      });

      expect(second.id).toBe(first.id);

      const identities = await listLearnerIdentitiesByProfile(
        fixture.db,
        fixture.tenantId,
        profile.id,
      );
      expect(identities).toHaveLength(1);
    } finally {
      await cleanupTestResources(fixture.db, {
        tenantIds: [fixture.tenantId],
      });
    }
  });

  it("updates primary and verified flags when move is called on the same profile", async () => {
    const fixture = await createTestTenantFixture();

    try {
      const profile = await createLearnerProfile(fixture.db, {
        tenantId: fixture.tenantId,
        primaryIdentityType: "email",
        primaryIdentityValue: "student@umich.edu",
        primaryIdentityVerified: false,
      });

      const updated = await moveLearnerIdentityAliasToProfile(fixture.db, {
        tenantId: fixture.tenantId,
        learnerProfileId: profile.id,
        identityType: "email",
        identityValue: "student@umich.edu",
        isPrimary: true,
        isVerified: true,
      });

      expect(updated.isPrimary).toBe(true);
      expect(updated.isVerified).toBe(true);

      const identities = await listLearnerIdentitiesByProfile(
        fixture.db,
        fixture.tenantId,
        profile.id,
      );
      expect(identities).toHaveLength(1);
      expect(identities[0]?.isPrimary).toBe(true);
      expect(identities[0]?.isVerified).toBe(true);
    } finally {
      await cleanupTestResources(fixture.db, {
        tenantIds: [fixture.tenantId],
      });
    }
  });

  it("attaches a new identity alias when none exists yet", async () => {
    const fixture = await createTestTenantFixture();

    try {
      const profile = await createLearnerProfile(fixture.db, {
        tenantId: fixture.tenantId,
        primaryIdentityType: "email",
        primaryIdentityValue: "student@umich.edu",
        primaryIdentityVerified: true,
      });

      const attached = await moveLearnerIdentityAliasToProfile(fixture.db, {
        tenantId: fixture.tenantId,
        learnerProfileId: profile.id,
        identityType: "saml_subject",
        identityValue: "canvas-subject-456",
        isPrimary: false,
        isVerified: true,
      });

      expect(attached.learnerProfileId).toBe(profile.id);
      expect(attached.identityType).toBe("saml_subject");

      const identities = await listLearnerIdentitiesByProfile(
        fixture.db,
        fixture.tenantId,
        profile.id,
      );
      expect(identities).toHaveLength(2);
    } finally {
      await cleanupTestResources(fixture.db, {
        tenantIds: [fixture.tenantId],
      });
    }
  });

  it("moves a primary identity and demotes other primaries on the target profile", async () => {
    const fixture = await createTestTenantFixture();

    try {
      const targetProfile = await createLearnerProfile(fixture.db, {
        tenantId: fixture.tenantId,
        primaryIdentityType: "email",
        primaryIdentityValue: "student@umich.edu",
        primaryIdentityVerified: true,
      });
      const staleProfile = await createLearnerProfile(fixture.db, {
        tenantId: fixture.tenantId,
        primaryIdentityType: "saml_subject",
        primaryIdentityValue: "canvas-primary-subject",
        primaryIdentityVerified: true,
      });

      await addLearnerIdentityAlias(fixture.db, {
        tenantId: fixture.tenantId,
        learnerProfileId: targetProfile.id,
        identityType: "sourced_id",
        identityValue: "sourced-123",
        isPrimary: true,
        isVerified: true,
      });

      await moveLearnerIdentityAliasToProfile(fixture.db, {
        tenantId: fixture.tenantId,
        learnerProfileId: targetProfile.id,
        identityType: "saml_subject",
        identityValue: "canvas-primary-subject",
        isPrimary: true,
        isVerified: true,
      });

      const identities = await listLearnerIdentitiesByProfile(
        fixture.db,
        fixture.tenantId,
        targetProfile.id,
      );
      const primaryIdentities = identities.filter((identity) => identity.isPrimary);

      expect(primaryIdentities).toHaveLength(1);
      expect(primaryIdentities[0]?.identityType).toBe("saml_subject");

      const deletedStaleProfile = await findLearnerProfileById(
        fixture.db,
        fixture.tenantId,
        staleProfile.id,
      );
      expect(deletedStaleProfile).toBeNull();
    } finally {
      await cleanupTestResources(fixture.db, {
        tenantIds: [fixture.tenantId],
      });
    }
  });

  it("writes an audit log when an identity is reparented", async () => {
    const fixture = await createTestTenantFixture();

    try {
      const selectedProfile = await createLearnerProfile(fixture.db, {
        tenantId: fixture.tenantId,
        primaryIdentityType: "email",
        primaryIdentityValue: "student@umich.edu",
        primaryIdentityVerified: true,
      });
      await createLearnerProfile(fixture.db, {
        tenantId: fixture.tenantId,
        primaryIdentityType: "saml_subject",
        primaryIdentityValue: "canvas-audit-subject",
        primaryIdentityVerified: true,
      });

      const movedIdentity = await moveLearnerIdentityAliasToProfile(fixture.db, {
        tenantId: fixture.tenantId,
        learnerProfileId: selectedProfile.id,
        identityType: "saml_subject",
        identityValue: "canvas-audit-subject",
        isPrimary: false,
        isVerified: true,
      });

      const auditLogs = await listAuditLogs(fixture.db, {
        tenantId: fixture.tenantId,
        action: "learner_identity.reparented",
        targetType: "learner_identity",
        targetId: movedIdentity.id,
        limit: 5,
      });

      expect(auditLogs).toHaveLength(1);
      expect(auditLogs[0]?.metadataJson).toContain(selectedProfile.id);
    } finally {
      await cleanupTestResources(fixture.db, {
        tenantIds: [fixture.tenantId],
      });
    }
  });

  it("does not delete a stale profile when it still has issued assertions", async () => {
    const fixture = await createTestTenantFixture();

    try {
      const selectedProfile = await createLearnerProfile(fixture.db, {
        tenantId: fixture.tenantId,
        primaryIdentityType: "email",
        primaryIdentityValue: "student@umich.edu",
        primaryIdentityVerified: true,
      });
      const staleProfile = await createLearnerProfile(fixture.db, {
        tenantId: fixture.tenantId,
        primaryIdentityType: "saml_subject",
        primaryIdentityValue: "canvas-assertion-subject",
        primaryIdentityVerified: true,
      });
      const badgeTemplateId = await seedBadgeTemplate(fixture.db, {
        tenantId: fixture.tenantId,
        title: "Follow-up badge",
      });

      await seedAssertion(fixture.db, {
        tenantId: fixture.tenantId,
        badgeTemplateId,
        learnerProfileId: staleProfile.id,
        recipientIdentity: "student@umich.edu",
        issuedAt: "2026-01-01T00:00:00.000Z",
      });

      await moveLearnerIdentityAliasToProfile(fixture.db, {
        tenantId: fixture.tenantId,
        learnerProfileId: selectedProfile.id,
        identityType: "saml_subject",
        identityValue: "canvas-assertion-subject",
        isPrimary: false,
        isVerified: true,
      });

      const retainedStaleProfile = await findLearnerProfileById(
        fixture.db,
        fixture.tenantId,
        staleProfile.id,
      );
      expect(retainedStaleProfile?.id).toBe(staleProfile.id);
    } finally {
      await cleanupTestResources(fixture.db, {
        tenantIds: [fixture.tenantId],
      });
    }
  });
});

describeDbIntegration("resolveLearnerProfileFromSaml", () => {
  it("falls back to verified email and links new SAML subject when subject changes", async () => {
    const fixture = await createTestTenantFixture();

    try {
      const profile = await createLearnerProfile(fixture.db, {
        tenantId: fixture.tenantId,
        primaryIdentityType: "email",
        primaryIdentityValue: "student@umich.edu",
        primaryIdentityVerified: true,
      });

      const resolvedFromFallback = await resolveLearnerProfileFromSaml(fixture.db, {
        tenantId: fixture.tenantId,
        samlSubject: "umich-subject-123",
        email: "student@umich.edu",
      });

      expect(resolvedFromFallback.strategy).toBe("verified_email");
      expect(resolvedFromFallback.profile.id).toBe(profile.id);

      const resolvedBySaml = await resolveLearnerProfileFromSaml(fixture.db, {
        tenantId: fixture.tenantId,
        samlSubject: "umich-subject-123",
        email: "another-email@umich.edu",
      });

      expect(resolvedBySaml.strategy).toBe("saml_subject");
      expect(resolvedBySaml.profile.id).toBe(profile.id);

      const identities = await listLearnerIdentitiesByProfile(
        fixture.db,
        fixture.tenantId,
        profile.id,
      );
      expect(identities.map((entry) => entry.identityType)).toEqual(["saml_subject", "email"]);
      expect(identities[0]?.isPrimary).toBe(true);
      expect(identities[1]?.isPrimary).toBe(false);
    } finally {
      await cleanupTestResources(fixture.db, {
        tenantIds: [fixture.tenantId],
      });
    }
  });

  it("creates a new profile when no existing SAML or verified email identity exists", async () => {
    const fixture = await createTestTenantFixture();

    try {
      const resolved = await resolveLearnerProfileFromSaml(fixture.db, {
        tenantId: fixture.tenantId,
        samlSubject: "umich-subject-999",
        email: "new.student@gmail.com",
        displayName: "New Student",
      });

      expect(resolved.strategy).toBe("created");
      expect(resolved.profile.displayName).toBe("New Student");

      const identities = await listLearnerIdentitiesByProfile(
        fixture.db,
        fixture.tenantId,
        resolved.profile.id,
      );
      expect(identities).toHaveLength(2);
      expect(identities[0]?.identityType).toBe("saml_subject");
      expect(identities[1]?.identityType).toBe("email");
      expect(identities[1]?.isVerified).toBe(true);
    } finally {
      await cleanupTestResources(fixture.db, {
        tenantIds: [fixture.tenantId],
      });
    }
  });

  it("fails when neither SAML subject nor email is provided", async () => {
    const fixture = await createTestTenantFixture();

    try {
      await expect(
        resolveLearnerProfileFromSaml(fixture.db, {
          tenantId: fixture.tenantId,
        }),
      ).rejects.toThrow("Cannot resolve learner profile without SAML subject or email");
    } finally {
      await cleanupTestResources(fixture.db, {
        tenantIds: [fixture.tenantId],
      });
    }
  });
});

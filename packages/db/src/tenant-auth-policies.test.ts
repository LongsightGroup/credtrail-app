import { expect, it } from "vitest";

import {
  countTenantMembershipsByRole,
  createTenantAuthProvider,
  findActiveTenantBreakGlassAccountByEmail,
  findTenantAuthPolicy,
  findTenantAuthProviderById,
  listAccessibleTenantContextsForUser,
  listTenantAuthProviders,
  listTenantBreakGlassAccounts,
  listTenantMembers,
  markTenantBreakGlassAccountUsed,
  markTenantBreakGlassEnrollmentEmailSent,
  removeTenantMembership,
  resolveTenantAuthPolicy,
  revokeTenantBreakGlassAccount,
  updateTenantAuthProvider,
  upsertTenant,
  upsertTenantAuthPolicy,
  upsertTenantBreakGlassAccount,
  upsertTenantMembershipRole,
  upsertTenantSsoSamlConfiguration,
  upsertUserByEmail,
  type SqlDatabase,
} from "./index";
import {
  cleanupTestResources,
  createTestTenantFixture,
  describeDbIntegration,
  seedBetterAuthCredentialUser,
  uniqueTestId,
} from "./postgres-test-support";

const createAdditionalTenant = async (
  db: SqlDatabase,
  input: {
    id: string;
    slug: string;
    displayName: string;
    planTier: "free" | "team" | "institution" | "enterprise";
    isActive?: boolean | undefined;
  },
): Promise<void> => {
  await upsertTenant(db, {
    id: input.id,
    slug: input.slug,
    displayName: input.displayName,
    planTier: input.planTier,
    issuerDomain: `${input.slug}.issuer.test`,
    didWeb: `did:web:${input.slug}.issuer.test`,
    isActive: input.isActive,
  });
};

describeDbIntegration("tenant auth policy and provider helpers", () => {
  it("resolves local auth policy defaults when no tenant auth policy exists", async () => {
    const fixture = await createTestTenantFixture();

    try {
      const policy = await resolveTenantAuthPolicy(fixture.db, fixture.tenantId);

      expect(policy).toEqual({
        tenantId: fixture.tenantId,
        loginMode: "local",
        breakGlassEnabled: false,
        localMfaRequired: false,
        defaultProviderId: null,
        enforceForRoles: "all_users",
        createdAt: expect.any(String),
        updatedAt: expect.any(String),
      });
    } finally {
      await cleanupTestResources(fixture.db, {
        tenantIds: [fixture.tenantId],
      });
    }
  });

  it("persists and updates tenant auth policy state", async () => {
    const fixture = await createTestTenantFixture();

    try {
      const created = await upsertTenantAuthPolicy(fixture.db, {
        tenantId: fixture.tenantId,
        loginMode: "hybrid",
        breakGlassEnabled: true,
        localMfaRequired: true,
        defaultProviderId: "tap_oidc",
        enforceForRoles: "admins_only",
      });
      const resolved = await findTenantAuthPolicy(fixture.db, fixture.tenantId);

      expect(created.loginMode).toBe("hybrid");
      expect(created.breakGlassEnabled).toBe(true);
      expect(created.localMfaRequired).toBe(true);
      expect(created.defaultProviderId).toBe("tap_oidc");
      expect(created.enforceForRoles).toBe("all_users");
      expect(resolved).toEqual(created);
    } finally {
      await cleanupTestResources(fixture.db, {
        tenantIds: [fixture.tenantId],
      });
    }
  });

  it("keeps exactly one default OIDC auth provider per tenant when providers are created or updated", async () => {
    const fixture = await createTestTenantFixture();
    const primaryProviderId = uniqueTestId("tap_oidc");
    const backupProviderId = uniqueTestId("tap_oidc_backup");

    try {
      await createTenantAuthProvider(fixture.db, {
        id: primaryProviderId,
        tenantId: fixture.tenantId,
        protocol: "oidc",
        label: "Campus OIDC",
        enabled: true,
        isDefault: true,
        configJson: '{"issuer":"https://idp.example.edu"}',
      });
      await createTenantAuthProvider(fixture.db, {
        id: backupProviderId,
        tenantId: fixture.tenantId,
        protocol: "oidc",
        label: "Campus OIDC Backup",
        enabled: true,
        isDefault: false,
        configJson: '{"issuer":"https://backup-idp.example.edu"}',
      });

      const updated = await updateTenantAuthProvider(fixture.db, {
        tenantId: fixture.tenantId,
        providerId: backupProviderId,
        protocol: "oidc",
        label: "Campus OIDC Backup",
        enabled: false,
        isDefault: true,
        configJson: '{"issuer":"https://backup-idp.example.edu"}',
      });
      const providers = await listTenantAuthProviders(fixture.db, fixture.tenantId);

      expect(updated?.isDefault).toBe(true);
      expect(updated?.enabled).toBe(false);
      expect(providers).toHaveLength(2);
      expect(providers.find((provider) => provider.id === backupProviderId)?.isDefault).toBe(true);
      expect(providers.find((provider) => provider.id === primaryProviderId)?.isDefault).toBe(
        false,
      );

      const backupProvider = await findTenantAuthProviderById(
        fixture.db,
        fixture.tenantId,
        backupProviderId,
      );
      expect(backupProvider?.enabled).toBe(false);
    } finally {
      await cleanupTestResources(fixture.db, {
        tenantIds: [fixture.tenantId],
      });
    }
  });

  it("rejects new hosted SAML provider writes while preserving legacy compatibility reads", async () => {
    const fixture = await createTestTenantFixture();
    const providerId = uniqueTestId("tap_oidc");

    try {
      await expect(
        createTenantAuthProvider(fixture.db, {
          id: uniqueTestId("tap_saml"),
          tenantId: fixture.tenantId,
          protocol: "saml",
          label: "Campus SAML",
          enabled: true,
          isDefault: true,
          configJson: '{"ssoLoginUrl":"https://idp.example.edu/sso"}',
        }),
      ).rejects.toThrow("Hosted enterprise sign-in currently supports OIDC providers only.");

      await createTenantAuthProvider(fixture.db, {
        id: providerId,
        tenantId: fixture.tenantId,
        protocol: "oidc",
        label: "Campus OIDC",
        enabled: true,
        isDefault: true,
        configJson: '{"issuer":"https://idp.example.edu"}',
      });

      await expect(
        updateTenantAuthProvider(fixture.db, {
          tenantId: fixture.tenantId,
          providerId,
          protocol: "saml",
          label: "Campus SAML",
          enabled: true,
          isDefault: true,
          configJson: '{"ssoLoginUrl":"https://idp.example.edu/sso"}',
        }),
      ).rejects.toThrow("Hosted enterprise sign-in currently supports OIDC providers only.");
    } finally {
      await cleanupTestResources(fixture.db, {
        tenantIds: [fixture.tenantId],
      });
    }
  });

  it("bridges legacy SAML configuration into the provider and policy model", async () => {
    const fixture = await createTestTenantFixture();

    try {
      await upsertTenantSsoSamlConfiguration(fixture.db, {
        tenantId: fixture.tenantId,
        idpEntityId: "https://idp.example.edu/entity",
        ssoLoginUrl: "https://idp.example.edu/sso/login",
        idpCertificatePem: "-----BEGIN CERTIFICATE-----\\nabc\\n-----END CERTIFICATE-----",
        idpMetadataUrl: "https://idp.example.edu/metadata",
        spEntityId: "https://credtrail.example.edu/saml/sp",
        assertionConsumerServiceUrl: "https://credtrail.example.edu/saml/acs",
        nameIdFormat: "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
        enforced: true,
      });

      const policy = await findTenantAuthPolicy(fixture.db, fixture.tenantId);
      const providers = await listTenantAuthProviders(fixture.db, fixture.tenantId);

      expect(policy?.loginMode).toBe("sso_required");
      expect(policy?.defaultProviderId).toBe(`${fixture.tenantId}:provider:saml-default`);
      expect(providers).toEqual([
        expect.objectContaining({
          id: `${fixture.tenantId}:provider:saml-default`,
          protocol: "saml",
          isDefault: true,
          enabled: true,
          label: "Legacy SAML (compatibility only)",
        }),
      ]);

      const configJson = providers[0]?.configJson ?? "{}";
      expect(configJson).toContain("idpEntityId");
      expect(configJson).toContain("idpCertificatePem");
    } finally {
      await cleanupTestResources(fixture.db, {
        tenantIds: [fixture.tenantId],
      });
    }
  });

  it("stores break-glass accounts with enrollment and usage status", async () => {
    const fixture = await createTestTenantFixture();
    const user = await upsertUserByEmail(fixture.db, `${uniqueTestId("admin")}@example.edu`);
    const authUserId = uniqueTestId("ba_usr_admin");

    try {
      await seedBetterAuthCredentialUser(fixture.db, {
        id: authUserId,
        email: user.email,
        twoFactorEnabled: true,
      });

      await upsertTenantBreakGlassAccount(fixture.db, {
        tenantId: fixture.tenantId,
        userId: user.id,
      });
      await markTenantBreakGlassEnrollmentEmailSent(fixture.db, {
        tenantId: fixture.tenantId,
        userId: user.id,
        sentAt: "2026-03-16T12:05:00.000Z",
      });
      await markTenantBreakGlassAccountUsed(fixture.db, {
        tenantId: fixture.tenantId,
        userId: user.id,
        usedAt: "2026-03-16T12:10:00.000Z",
      });

      const listed = await listTenantBreakGlassAccounts(fixture.db, fixture.tenantId);
      const resolved = await findActiveTenantBreakGlassAccountByEmail(
        fixture.db,
        fixture.tenantId,
        user.email,
      );

      expect(listed).toHaveLength(1);
      expect(listed[0]).toEqual(
        expect.objectContaining({
          tenantId: fixture.tenantId,
          userId: user.id,
          email: user.email,
          localCredentialEnabled: true,
          twoFactorEnabled: true,
        }),
      );
      expect(resolved?.lastEnrollmentEmailSentAt).toBe("2026-03-16T12:05:00.000Z");
      expect(resolved?.lastUsedAt).toBe("2026-03-16T12:10:00.000Z");

      const removed = await revokeTenantBreakGlassAccount(fixture.db, {
        tenantId: fixture.tenantId,
        userId: user.id,
        revokedAt: "2026-03-16T12:20:00.000Z",
      });
      const resolvedAfterRevoke = await findActiveTenantBreakGlassAccountByEmail(
        fixture.db,
        fixture.tenantId,
        user.email,
      );

      expect(removed).toBe(true);
      expect(resolvedAfterRevoke).toBeNull();
    } finally {
      await cleanupTestResources(fixture.db, {
        tenantIds: [fixture.tenantId],
        userIds: [user.id],
        betterAuthUserIds: [authUserId],
      });
    }
  });

  it("lists tenant members, counts roles, and removes only tenant membership", async () => {
    const fixture = await createTestTenantFixture();
    const otherTenantId = uniqueTestId("tenant_other");
    const otherTenantSlug = uniqueTestId("tenant-other").replace(/_/g, "-");
    const owner = await upsertUserByEmail(fixture.db, `${uniqueTestId("owner")}@example.edu`);
    const admin = await upsertUserByEmail(fixture.db, `${uniqueTestId("admin")}@example.edu`);
    const otherTenantUser = await upsertUserByEmail(
      fixture.db,
      `${uniqueTestId("other")}@example.edu`,
    );

    try {
      await createAdditionalTenant(fixture.db, {
        id: otherTenantId,
        slug: otherTenantSlug,
        displayName: "Other Tenant",
        planTier: "team",
      });
      await upsertTenantMembershipRole(fixture.db, {
        tenantId: fixture.tenantId,
        userId: owner.id,
        role: "owner",
      });
      await upsertTenantMembershipRole(fixture.db, {
        tenantId: fixture.tenantId,
        userId: admin.id,
        role: "admin",
      });
      await upsertTenantMembershipRole(fixture.db, {
        tenantId: otherTenantId,
        userId: otherTenantUser.id,
        role: "owner",
      });

      const listed = await listTenantMembers(fixture.db, fixture.tenantId);
      const counts = await countTenantMembershipsByRole(fixture.db, fixture.tenantId);
      const removed = await removeTenantMembership(fixture.db, fixture.tenantId, admin.id);
      const listedAfterRemoval = await listTenantMembers(fixture.db, fixture.tenantId);

      expect(listed).toEqual([
        expect.objectContaining({
          tenantId: fixture.tenantId,
          userId: owner.id,
          email: owner.email,
          role: "owner",
        }),
        expect.objectContaining({
          tenantId: fixture.tenantId,
          userId: admin.id,
          email: admin.email,
          role: "admin",
        }),
      ]);
      expect(counts).toEqual({
        owner: 1,
        admin: 1,
        issuer: 0,
        viewer: 0,
      });
      expect(removed).toBe(true);
      expect(listedAfterRemoval.map((member) => member.userId)).toEqual([owner.id]);
      await expect(
        listTenantMembers(fixture.db, otherTenantId).then((members) =>
          members.some((member) => member.userId === otherTenantUser.id),
        ),
      ).resolves.toBe(true);
    } finally {
      await cleanupTestResources(fixture.db, {
        tenantIds: [fixture.tenantId, otherTenantId],
        userIds: [owner.id, admin.id, otherTenantUser.id],
      });
    }
  });

  it("lists accessible tenant contexts for a user from active memberships", async () => {
    const fixture = await createTestTenantFixture();
    const user = await upsertUserByEmail(fixture.db, `${uniqueTestId("user")}@example.edu`);
    const adminTenantId = uniqueTestId("tenant_admin");
    const viewerTenantId = uniqueTestId("tenant_viewer");
    const inactiveTenantId = uniqueTestId("tenant_inactive");

    try {
      await createAdditionalTenant(fixture.db, {
        id: adminTenantId,
        slug: uniqueTestId("tenant-admin").replace(/_/g, "-"),
        displayName: "Admin Tenant",
        planTier: "enterprise",
      });
      await createAdditionalTenant(fixture.db, {
        id: viewerTenantId,
        slug: uniqueTestId("tenant-viewer").replace(/_/g, "-"),
        displayName: "Viewer Tenant",
        planTier: "team",
      });
      await createAdditionalTenant(fixture.db, {
        id: inactiveTenantId,
        slug: uniqueTestId("tenant-inactive").replace(/_/g, "-"),
        displayName: "Inactive Tenant",
        planTier: "institution",
        isActive: false,
      });

      await upsertTenantMembershipRole(fixture.db, {
        tenantId: viewerTenantId,
        userId: user.id,
        role: "viewer",
      });
      await upsertTenantMembershipRole(fixture.db, {
        tenantId: adminTenantId,
        userId: user.id,
        role: "admin",
      });
      await upsertTenantMembershipRole(fixture.db, {
        tenantId: inactiveTenantId,
        userId: user.id,
        role: "owner",
      });

      const contexts = await listAccessibleTenantContextsForUser(fixture.db, user.id);

      expect(contexts).toEqual([
        {
          tenantId: adminTenantId,
          tenantSlug: expect.any(String),
          tenantDisplayName: "Admin Tenant",
          tenantPlanTier: "enterprise",
          membershipRole: "admin",
        },
        {
          tenantId: viewerTenantId,
          tenantSlug: expect.any(String),
          tenantDisplayName: "Viewer Tenant",
          tenantPlanTier: "team",
          membershipRole: "viewer",
        },
      ]);
    } finally {
      await cleanupTestResources(fixture.db, {
        tenantIds: [fixture.tenantId, adminTenantId, viewerTenantId, inactiveTenantId],
        userIds: [user.id],
      });
    }
  });
});

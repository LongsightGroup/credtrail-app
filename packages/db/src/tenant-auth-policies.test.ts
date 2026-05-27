/* eslint-disable no-unused-vars */
import { readFileSync } from "node:fs";

import { describe, expect, it } from "vitest";
import * as dbModule from "./index";
import * as validationModule from "../../validation/src/index";

import {
  ASSERTION_ENGAGEMENT_EVENT_TYPES,
  addLearnerIdentityAlias,
  type AccessibleTenantContextRecord,
  countTenantMembershipsByRole,
  createLearnerRecordImportContext,
  createLearnerRecordEntry,
  createTenantAuthProvider,
  createAuthIdentityLink,
  createLearnerProfile,
  enqueueJobQueueMessageOnce,
  findActiveTenantBreakGlassAccountByEmail,
  findLearnerRecordImportContextByEntryId,
  listLearnerRecordEntries,
  listLearnerRecordAssertionExports,
  listImportLearnerRecordBatchQueueMessages,
  findTenantAuthPolicy,
  listAccessibleTenantContextsForUser,
  listTenantAuthProviders,
  listTenantMembers,
  findLearnerProfileByIdentity,
  findTenantAuthProviderById,
  findAuthIdentityLinkByAuthUserId,
  findAuthIdentityLinkByCredtrailUserId,
  findUserByEmail,
  listTenantBreakGlassAccounts,
  listLearnerIdentitiesByProfile,
  markLearnerRecordImportPreviewQueued,
  markTenantBreakGlassAccountUsed,
  markTenantBreakGlassEnrollmentEmailSent,
  normalizeLearnerIdentityValue,
  patchLearnerRecordEntry,
  removeTenantMembership,
  retryFailedImportLearnerRecordBatchQueueMessages,
  revokeTenantBreakGlassAccount,
  resolveTenantAuthPolicy,
  resolveLearnerProfileForIdentity,
  resolveLearnerProfileFromSaml,
  resolveAssertionReportingAttribution,
  summarizeTenantExecutiveRollup,
  summarizeTenantReportingComparisonRows,
  summarizeTenantReportingOverviewRows,
  summarizeTenantReportingTrendRows,
  updateTenantAuthProvider,
  upsertTenantMembershipRole,
  upsertTenantBreakGlassAccount,
  upsertTenantAuthPolicy,
  upsertUserByEmail,
  type LearnerIdentityType,
  type SqlDatabase,
  type SqlExecutionMeta,
  type SqlQueryResult,
  type SqlRunResult,
} from "./index";
import { REPORTING_METRIC_DEFINITIONS } from "../../../apps/api-worker/src/reporting/metric-definitions";

import {
  createFakeAuthIdentityDb,
  createFakeDb,
  createFakeTenantAuthDb,
  type FakeSqlDatabase,
  type FakeTenantAuthSqlDatabase,
} from "./test-support";

describe("tenant auth policy and provider helpers", () => {
  it("resolves local auth policy defaults when no tenant auth policy exists", async () => {
    const db = createFakeTenantAuthDb();

    const policy = await resolveTenantAuthPolicy(db, "tenant_123");

    expect(policy).toEqual({
      tenantId: "tenant_123",
      loginMode: "local",
      breakGlassEnabled: false,
      localMfaRequired: false,
      defaultProviderId: null,
      enforceForRoles: "all_users",
      createdAt: expect.any(String),
      updatedAt: expect.any(String),
    });
  });

  it("persists and updates tenant auth policy state", async () => {
    const db = createFakeTenantAuthDb();

    const created = await upsertTenantAuthPolicy(db, {
      tenantId: "tenant_123",
      loginMode: "hybrid",
      breakGlassEnabled: true,
      localMfaRequired: true,
      defaultProviderId: "tap_oidc",
      enforceForRoles: "admins_only",
    });
    const resolved = await findTenantAuthPolicy(db, "tenant_123");

    expect(created.loginMode).toBe("hybrid");
    expect(created.breakGlassEnabled).toBe(true);
    expect(created.localMfaRequired).toBe(true);
    expect(created.defaultProviderId).toBe("tap_oidc");
    expect(created.enforceForRoles).toBe("all_users");
    expect(resolved).toEqual(created);
  });

  it("keeps exactly one default OIDC auth provider per tenant when providers are created or updated", async () => {
    const db = createFakeTenantAuthDb();

    await createTenantAuthProvider(db, {
      id: "tap_oidc",
      tenantId: "tenant_123",
      protocol: "oidc",
      label: "Campus OIDC",
      enabled: true,
      isDefault: true,
      configJson: '{"issuer":"https://idp.example.edu"}',
    });
    await createTenantAuthProvider(db, {
      id: "tap_oidc_backup",
      tenantId: "tenant_123",
      protocol: "oidc",
      label: "Campus OIDC Backup",
      enabled: true,
      isDefault: false,
      configJson: '{"issuer":"https://backup-idp.example.edu"}',
    });

    const updated = await updateTenantAuthProvider(db, {
      tenantId: "tenant_123",
      providerId: "tap_oidc_backup",
      protocol: "oidc",
      label: "Campus OIDC Backup",
      enabled: false,
      isDefault: true,
      configJson: '{"issuer":"https://backup-idp.example.edu"}',
    });
    const providers = await listTenantAuthProviders(db, "tenant_123");

    expect(updated?.isDefault).toBe(true);
    expect(updated?.enabled).toBe(false);
    expect(providers).toHaveLength(2);
    expect(providers.find((provider) => provider.id === "tap_oidc_backup")?.isDefault).toBe(true);
    expect(providers.find((provider) => provider.id === "tap_oidc")?.isDefault).toBe(false);

    const backupProvider = await findTenantAuthProviderById(db, "tenant_123", "tap_oidc_backup");
    expect(backupProvider?.enabled).toBe(false);
  });

  it("rejects new hosted SAML provider writes while preserving legacy compatibility reads", async () => {
    const db = createFakeTenantAuthDb();

    await expect(
      createTenantAuthProvider(db, {
        id: "tap_saml",
        tenantId: "tenant_123",
        protocol: "saml",
        label: "Campus SAML",
        enabled: true,
        isDefault: true,
        configJson: '{"ssoLoginUrl":"https://idp.example.edu/sso"}',
      }),
    ).rejects.toThrow("Hosted enterprise sign-in currently supports OIDC providers only.");

    await createTenantAuthProvider(db, {
      id: "tap_oidc",
      tenantId: "tenant_123",
      protocol: "oidc",
      label: "Campus OIDC",
      enabled: true,
      isDefault: true,
      configJson: '{"issuer":"https://idp.example.edu"}',
    });

    await expect(
      updateTenantAuthProvider(db, {
        tenantId: "tenant_123",
        providerId: "tap_oidc",
        protocol: "saml",
        label: "Campus SAML",
        enabled: true,
        isDefault: true,
        configJson: '{"ssoLoginUrl":"https://idp.example.edu/sso"}',
      }),
    ).rejects.toThrow("Hosted enterprise sign-in currently supports OIDC providers only.");
  });

  it("bridges legacy SAML configuration into the provider and policy model", async () => {
    const db = createFakeTenantAuthDb();
    const tenantAuthDb = db as unknown as FakeTenantAuthSqlDatabase;

    tenantAuthDb.legacySamlConfigurations.push({
      tenant_id: "tenant_legacy",
      idp_entity_id: "https://idp.example.edu/entity",
      sso_login_url: "https://idp.example.edu/sso/login",
      idp_certificate_pem: "-----BEGIN CERTIFICATE-----\\nabc\\n-----END CERTIFICATE-----",
      idp_metadata_url: "https://idp.example.edu/metadata",
      sp_entity_id: "https://credtrail.example.edu/saml/sp",
      assertion_consumer_service_url: "https://credtrail.example.edu/saml/acs",
      name_id_format: "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
      enforced: 1,
      created_at: "2026-03-16T10:00:00.000Z",
      updated_at: "2026-03-16T10:00:00.000Z",
    });

    const policy = await findTenantAuthPolicy(db, "tenant_legacy");
    const providers = await listTenantAuthProviders(db, "tenant_legacy");

    expect(policy?.loginMode).toBe("sso_required");
    expect(policy?.defaultProviderId).toBe("tenant_legacy:provider:saml-default");
    expect(providers).toEqual([
      expect.objectContaining({
        id: "tenant_legacy:provider:saml-default",
        protocol: "saml",
        isDefault: true,
        enabled: true,
        label: "Legacy SAML (compatibility only)",
      }),
    ]);

    const configJson = providers[0]?.configJson ?? "{}";
    expect(configJson).toContain("idpEntityId");
    expect(configJson).toContain("idpCertificatePem");
  });

  it("stores break-glass accounts with enrollment and usage status", async () => {
    const db = createFakeTenantAuthDb();
    const tenantAuthDb = db as unknown as FakeTenantAuthSqlDatabase;
    const user = await upsertUserByEmail(db, "Admin@Example.edu");

    tenantAuthDb.betterAuthUsers.push({
      id: "ba_usr_admin",
      email: "admin@example.edu",
      two_factor_enabled: 1,
    });
    tenantAuthDb.betterAuthAccounts.push({
      user_id: "ba_usr_admin",
      provider_id: "credential",
      password: "hashed-password",
    });

    await upsertTenantBreakGlassAccount(db, {
      tenantId: "tenant_123",
      userId: user.id,
      createdByUserId: "usr_owner",
    });
    await markTenantBreakGlassEnrollmentEmailSent(db, {
      tenantId: "tenant_123",
      userId: user.id,
      sentAt: "2026-03-16T12:05:00.000Z",
    });
    await markTenantBreakGlassAccountUsed(db, {
      tenantId: "tenant_123",
      userId: user.id,
      usedAt: "2026-03-16T12:10:00.000Z",
    });

    const listed = await listTenantBreakGlassAccounts(db, "tenant_123");
    const resolved = await findActiveTenantBreakGlassAccountByEmail(
      db,
      "tenant_123",
      "admin@example.edu",
    );

    expect(listed).toHaveLength(1);
    expect(listed[0]).toEqual(
      expect.objectContaining({
        tenantId: "tenant_123",
        userId: user.id,
        email: "admin@example.edu",
        betterAuthUserId: "ba_usr_admin",
        localCredentialEnabled: true,
        twoFactorEnabled: true,
      }),
    );
    expect(resolved?.lastEnrollmentEmailSentAt).toBe("2026-03-16T12:05:00.000Z");
    expect(resolved?.lastUsedAt).toBe("2026-03-16T12:10:00.000Z");

    const removed = await revokeTenantBreakGlassAccount(db, {
      tenantId: "tenant_123",
      userId: user.id,
      revokedAt: "2026-03-16T12:20:00.000Z",
    });
    const resolvedAfterRevoke = await findActiveTenantBreakGlassAccountByEmail(
      db,
      "tenant_123",
      "admin@example.edu",
    );

    expect(removed).toBe(true);
    expect(resolvedAfterRevoke).toBeNull();
  });

  it("lists tenant members, counts roles, and removes only tenant membership", async () => {
    const db = createFakeTenantAuthDb();
    const tenantAuthDb = db as unknown as FakeTenantAuthSqlDatabase;
    const owner = await upsertUserByEmail(db, "Owner@Example.edu");
    const admin = await upsertUserByEmail(db, "Admin@Example.edu");
    const otherTenantUser = await upsertUserByEmail(db, "Other@Example.edu");

    await upsertTenantMembershipRole(db, {
      tenantId: "tenant_123",
      userId: owner.id,
      role: "owner",
    });
    await upsertTenantMembershipRole(db, {
      tenantId: "tenant_123",
      userId: admin.id,
      role: "admin",
    });
    await upsertTenantMembershipRole(db, {
      tenantId: "tenant_other",
      userId: otherTenantUser.id,
      role: "owner",
    });

    const listed = await listTenantMembers(db, "tenant_123");
    const counts = await countTenantMembershipsByRole(db, "tenant_123");
    const removed = await removeTenantMembership(db, "tenant_123", admin.id);
    const listedAfterRemoval = await listTenantMembers(db, "tenant_123");

    expect(listed).toEqual([
      expect.objectContaining({
        tenantId: "tenant_123",
        userId: owner.id,
        email: "owner@example.edu",
        role: "owner",
      }),
      expect.objectContaining({
        tenantId: "tenant_123",
        userId: admin.id,
        email: "admin@example.edu",
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
    expect(tenantAuthDb.users.some((user) => user.id === admin.id)).toBe(true);
    expect(tenantAuthDb.memberships.some((row) => row.user_id === otherTenantUser.id)).toBe(true);
  });

  it("lists accessible tenant contexts for a user from active memberships", async () => {
    const db = createFakeTenantAuthDb();
    const tenantAuthDb = db as unknown as FakeTenantAuthSqlDatabase;

    tenantAuthDb.tenants.push(
      {
        id: "tenant_admin",
        slug: "tenant-admin",
        display_name: "Admin Tenant",
        plan_tier: "enterprise",
        is_active: 1,
      },
      {
        id: "tenant_viewer",
        slug: "tenant-viewer",
        display_name: "Viewer Tenant",
        plan_tier: "team",
        is_active: 1,
      },
      {
        id: "tenant_inactive",
        slug: "tenant-inactive",
        display_name: "Inactive Tenant",
        plan_tier: "institution",
        is_active: 0,
      },
    );
    tenantAuthDb.memberships.push(
      {
        tenant_id: "tenant_viewer",
        user_id: "usr_123",
        role: "viewer",
      },
      {
        tenant_id: "tenant_admin",
        user_id: "usr_123",
        role: "admin",
      },
      {
        tenant_id: "tenant_inactive",
        user_id: "usr_123",
        role: "owner",
      },
    );

    const contexts = await listAccessibleTenantContextsForUser(db, "usr_123");

    expect(contexts).toEqual([
      {
        tenantId: "tenant_admin",
        tenantSlug: "tenant-admin",
        tenantDisplayName: "Admin Tenant",
        tenantPlanTier: "enterprise",
        membershipRole: "admin",
      },
      {
        tenantId: "tenant_viewer",
        tenantSlug: "tenant-viewer",
        tenantDisplayName: "Viewer Tenant",
        tenantPlanTier: "team",
        membershipRole: "viewer",
      },
    ]);
  });
});

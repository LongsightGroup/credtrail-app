/* oxlint-disable no-unused-vars */
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
} from "./test-support";

describe("normalizeLearnerIdentityValue", () => {
  it("normalizes email and email_sha256 identity values", () => {
    expect(normalizeLearnerIdentityValue("email", "  Student@Umich.edu ")).toBe(
      "student@umich.edu",
    );
    expect(normalizeLearnerIdentityValue("email_sha256", " AABBCC ")).toBe("aabbcc");
  });
});

describe("learner profiles and identity aliases", () => {
  it("creates a learner profile and resolves it by normalized primary identity", async () => {
    const db = createFakeDb();
    const profile = await createLearnerProfile(db, {
      tenantId: "tenant_umich",
      displayName: "Jane Doe",
      primaryIdentityType: "email",
      primaryIdentityValue: " Jane.Doe@Umich.edu ",
      primaryIdentityVerified: true,
    });

    expect(profile.tenantId).toBe("tenant_umich");
    expect(profile.displayName).toBe("Jane Doe");
    expect(profile.subjectId.startsWith("urn:credtrail:learner:tenant_umich:")).toBe(true);

    const resolved = await findLearnerProfileByIdentity(db, {
      tenantId: "tenant_umich",
      identityType: "email",
      identityValue: "jane.doe@umich.edu",
    });

    expect(resolved?.id).toBe(profile.id);

    const identities = await listLearnerIdentitiesByProfile(db, "tenant_umich", profile.id);
    expect(identities).toHaveLength(1);
    expect(identities[0]?.isPrimary).toBe(true);
    expect(identities[0]?.isVerified).toBe(true);
    expect(identities[0]?.identityValue).toBe("jane.doe@umich.edu");
  });

  it("links new aliases to the same learner and switches primary identity when requested", async () => {
    const db = createFakeDb();
    const profile = await createLearnerProfile(db, {
      tenantId: "tenant_umich",
      primaryIdentityType: "email",
      primaryIdentityValue: "student@umich.edu",
      primaryIdentityVerified: true,
    });

    await addLearnerIdentityAlias(db, {
      tenantId: "tenant_umich",
      learnerProfileId: profile.id,
      identityType: "email",
      identityValue: "student@gmail.com",
      isPrimary: true,
      isVerified: true,
    });

    const oldIdentityResolved = await findLearnerProfileByIdentity(db, {
      tenantId: "tenant_umich",
      identityType: "email",
      identityValue: "student@umich.edu",
    });
    const newIdentityResolved = await findLearnerProfileByIdentity(db, {
      tenantId: "tenant_umich",
      identityType: "email",
      identityValue: "student@gmail.com",
    });

    expect(oldIdentityResolved?.id).toBe(profile.id);
    expect(newIdentityResolved?.id).toBe(profile.id);

    const identities = await listLearnerIdentitiesByProfile(db, "tenant_umich", profile.id);
    expect(identities).toHaveLength(2);
    expect(identities[0]?.identityValue).toBe("student@gmail.com");
    expect(identities[0]?.isPrimary).toBe(true);
    expect(identities[1]?.identityValue).toBe("student@umich.edu");
    expect(identities[1]?.isPrimary).toBe(false);
  });

  it("prevents duplicate identity aliases within a tenant", async () => {
    const db = createFakeDb();
    const firstProfile = await createLearnerProfile(db, {
      tenantId: "tenant_umich",
      primaryIdentityType: "email",
      primaryIdentityValue: "first@umich.edu",
    });
    const secondProfile = await createLearnerProfile(db, {
      tenantId: "tenant_umich",
      primaryIdentityType: "email",
      primaryIdentityValue: "second@umich.edu",
    });

    expect(firstProfile.id).not.toBe(secondProfile.id);

    await expect(
      addLearnerIdentityAlias(db, {
        tenantId: "tenant_umich",
        learnerProfileId: secondProfile.id,
        identityType: "email",
        identityValue: "first@umich.edu",
      }),
    ).rejects.toThrow("duplicate key value violates unique constraint");
  });

  it("resolves to existing learner profile for repeated identity values", async () => {
    const db = createFakeDb();
    const first = await resolveLearnerProfileForIdentity(db, {
      tenantId: "tenant_umich",
      identityType: "email",
      identityValue: "student@umich.edu",
    });
    const second = await resolveLearnerProfileForIdentity(db, {
      tenantId: "tenant_umich",
      identityType: "email",
      identityValue: "student@umich.edu",
    });

    expect(second.id).toBe(first.id);
    const identities = await listLearnerIdentitiesByProfile(db, "tenant_umich", first.id);
    expect(identities).toHaveLength(1);
  });
});

describe("resolveLearnerProfileFromSaml", () => {
  it("falls back to verified email and links new SAML subject when subject changes", async () => {
    const db = createFakeDb();
    const profile = await createLearnerProfile(db, {
      tenantId: "tenant_umich",
      primaryIdentityType: "email",
      primaryIdentityValue: "student@umich.edu",
      primaryIdentityVerified: true,
    });

    const resolvedFromFallback = await resolveLearnerProfileFromSaml(db, {
      tenantId: "tenant_umich",
      samlSubject: "umich-subject-123",
      email: "student@umich.edu",
    });

    expect(resolvedFromFallback.strategy).toBe("verified_email");
    expect(resolvedFromFallback.profile.id).toBe(profile.id);

    const resolvedBySaml = await resolveLearnerProfileFromSaml(db, {
      tenantId: "tenant_umich",
      samlSubject: "umich-subject-123",
      email: "another-email@umich.edu",
    });

    expect(resolvedBySaml.strategy).toBe("saml_subject");
    expect(resolvedBySaml.profile.id).toBe(profile.id);

    const identities = await listLearnerIdentitiesByProfile(db, "tenant_umich", profile.id);
    expect(identities.map((entry) => entry.identityType)).toEqual(["saml_subject", "email"]);
    expect(identities[0]?.isPrimary).toBe(true);
    expect(identities[1]?.isPrimary).toBe(false);
  });

  it("creates a new profile when no existing SAML or verified email identity exists", async () => {
    const db = createFakeDb();
    const resolved = await resolveLearnerProfileFromSaml(db, {
      tenantId: "tenant_umich",
      samlSubject: "umich-subject-999",
      email: "new.student@gmail.com",
      displayName: "New Student",
    });

    expect(resolved.strategy).toBe("created");
    expect(resolved.profile.displayName).toBe("New Student");

    const identities = await listLearnerIdentitiesByProfile(
      db,
      "tenant_umich",
      resolved.profile.id,
    );
    expect(identities).toHaveLength(2);
    expect(identities[0]?.identityType).toBe("saml_subject");
    expect(identities[1]?.identityType).toBe("email");
    expect(identities[1]?.isVerified).toBe(true);
  });

  it("fails when neither SAML subject nor email is provided", async () => {
    const db = createFakeDb();

    await expect(
      resolveLearnerProfileFromSaml(db, {
        tenantId: "tenant_umich",
      }),
    ).rejects.toThrow("Cannot resolve learner profile without SAML subject or email");
  });
});

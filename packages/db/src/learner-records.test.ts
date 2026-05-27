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
} from "./test-support";

describe("learner-record entries", () => {
  it("creates and lists non-badge learner-record entries for a learner profile", async () => {
    const db = createFakeDb();
    const profile = await createLearnerProfile(db, {
      tenantId: "tenant_umich",
      primaryIdentityType: "email",
      primaryIdentityValue: "student@umich.edu",
      primaryIdentityVerified: true,
    });

    const createdEntry = await createLearnerRecordEntry(db, {
      tenantId: "tenant_umich",
      learnerProfileId: profile.id,
      trustLevel: "issuer_verified",
      recordType: "course",
      title: "Clinical Placement Seminar",
      description: "Completed with distinction.",
      issuerName: "University of Michigan",
      issuerUserId: "usr_admin",
      sourceSystem: "credtrail_admin",
      issuedAt: "2026-03-24T15:00:00.000Z",
      evidenceLinks: ["https://credtrail.example.edu/evidence/clinical-placement-seminar"],
      detailsJson: '{"grade":"A","credits":3}',
    });

    expect(createdEntry.id.startsWith("lre_")).toBe(true);
    expect(createdEntry.title).toBe("Clinical Placement Seminar");
    expect(createdEntry.evidenceLinksJson).toBe(
      '["https://credtrail.example.edu/evidence/clinical-placement-seminar"]',
    );

    const listedEntries = await listLearnerRecordEntries(db, {
      tenantId: "tenant_umich",
      learnerProfileId: profile.id,
    });

    expect(listedEntries).toEqual([createdEntry]);
  });

  it("filters learner-record entries by trust and status", async () => {
    const db = createFakeDb();
    const profile = await createLearnerProfile(db, {
      tenantId: "tenant_umich",
      primaryIdentityType: "email",
      primaryIdentityValue: "student@umich.edu",
      primaryIdentityVerified: true,
    });

    await createLearnerRecordEntry(db, {
      tenantId: "tenant_umich",
      learnerProfileId: profile.id,
      trustLevel: "issuer_verified",
      recordType: "course",
      title: "Applied Statistics",
      issuerName: "University of Michigan",
      sourceSystem: "credtrail_admin",
      issuedAt: "2026-03-20T15:00:00.000Z",
      evidenceLinks: [],
    });
    const supplemental = await createLearnerRecordEntry(db, {
      tenantId: "tenant_umich",
      learnerProfileId: profile.id,
      trustLevel: "learner_supplemental",
      recordType: "supplemental_artifact",
      title: "Portfolio Reflection",
      issuerName: "Learner Portfolio",
      sourceSystem: "learner_self_reported",
      issuedAt: "2026-03-25T15:00:00.000Z",
      evidenceLinks: [],
      status: "expired",
    });

    const filtered = await listLearnerRecordEntries(db, {
      tenantId: "tenant_umich",
      learnerProfileId: profile.id,
      trustLevel: "learner_supplemental",
      status: "expired",
    });

    expect(filtered).toEqual([supplemental]);
  });

  it("patches learner-record provenance and revoke state without mutating badge assertions", async () => {
    const db = createFakeDb();
    const profile = await createLearnerProfile(db, {
      tenantId: "tenant_umich",
      primaryIdentityType: "email",
      primaryIdentityValue: "student@umich.edu",
      primaryIdentityVerified: true,
    });
    const createdEntry = await createLearnerRecordEntry(db, {
      tenantId: "tenant_umich",
      learnerProfileId: profile.id,
      trustLevel: "issuer_verified",
      recordType: "certificate",
      title: "Instructional Design Certificate",
      issuerName: "University of Michigan",
      sourceSystem: "csv_import",
      sourceRecordId: "legacy-cert-123",
      issuedAt: "2026-03-18T15:00:00.000Z",
      evidenceLinks: ["https://credtrail.example.edu/evidence/instructional-design"],
    });

    const updatedEntry = await patchLearnerRecordEntry(db, {
      tenantId: "tenant_umich",
      entryId: createdEntry.id,
      description: "Revoked after academic integrity review.",
      status: "revoked",
      detailsJson: '{"reviewedBy":"Academic Affairs"}',
      revisedAt: "2026-03-25T12:00:00.000Z",
      revokedAt: "2026-03-25T15:00:00.000Z",
      issuerName: "University of Michigan Academic Affairs",
      sourceSystem: "api",
      sourceRecordId: "revocation-456",
      evidenceLinks: ["https://credtrail.example.edu/reviews/instructional-design"],
    });

    expect(updatedEntry).not.toBeNull();
    expect(updatedEntry).toMatchObject({
      id: createdEntry.id,
      status: "revoked",
      description: "Revoked after academic integrity review.",
      issuerName: "University of Michigan Academic Affairs",
      sourceSystem: "api",
      sourceRecordId: "revocation-456",
      revisedAt: "2026-03-25T12:00:00.000Z",
      revokedAt: "2026-03-25T15:00:00.000Z",
      detailsJson: '{"reviewedBy":"Academic Affairs"}',
      evidenceLinksJson: '["https://credtrail.example.edu/reviews/instructional-design"]',
    });
  });
});

describe("learner-record import context", () => {
  it("persists queryable smart-default context separately from learner-record details", async () => {
    const db = createFakeDb();
    const profile = await createLearnerProfile(db, {
      tenantId: "tenant_umich",
      primaryIdentityType: "email",
      primaryIdentityValue: "student@umich.edu",
      primaryIdentityVerified: true,
    });
    const entry = await createLearnerRecordEntry(db, {
      tenantId: "tenant_umich",
      learnerProfileId: profile.id,
      trustLevel: "issuer_verified",
      recordType: "course",
      title: "Clinical Placement Seminar",
      issuerName: "University of Michigan",
      sourceSystem: "csv_import",
      issuedAt: "2026-03-26T15:00:00.000Z",
      evidenceLinks: [],
    });

    const createdContext = await createLearnerRecordImportContext(db, {
      tenantId: "tenant_umich",
      entryId: entry.id,
      orgUnitId: "tenant_umich:org:department-health",
      badgeTemplateId: "badge_template_001",
      pathwayLabel: "Clinical readiness",
      inferredFrom: ["row", "badge_template"],
    });

    expect(createdContext).toMatchObject({
      entryId: entry.id,
      tenantId: "tenant_umich",
      orgUnitId: "tenant_umich:org:department-health",
      badgeTemplateId: "badge_template_001",
      pathwayLabel: "Clinical readiness",
      inferredFromJson: '["row","badge_template"]',
    });

    const loadedContext = await findLearnerRecordImportContextByEntryId(
      db,
      "tenant_umich",
      entry.id,
    );

    expect(loadedContext).toEqual(createdContext);
  });
});

describe("learner-record import queue helpers", () => {
  it("enqueues learner-record import jobs idempotently by tenant, type, and key", async () => {
    const db = createFakeDb() as unknown as FakeSqlDatabase;

    const firstInsert = await enqueueJobQueueMessageOnce(db, {
      tenantId: "tenant_umich",
      jobType: "import_learner_record_batch",
      payload: {
        batchId: "batch_123",
        rowNumber: 1,
      },
      idempotencyKey: "learner-record-import:batch_123:1",
      nowIso: "2026-03-26T15:00:00.000Z",
    });
    const duplicateInsert = await enqueueJobQueueMessageOnce(db, {
      tenantId: "tenant_umich",
      jobType: "import_learner_record_batch",
      payload: {
        batchId: "batch_123",
        rowNumber: 1,
      },
      idempotencyKey: "learner-record-import:batch_123:1",
      nowIso: "2026-03-26T15:01:00.000Z",
    });

    expect(firstInsert).toBe(true);
    expect(duplicateInsert).toBe(false);
    expect(db.jobQueueMessages).toHaveLength(1);
    expect(db.jobQueueMessages[0]).toMatchObject({
      tenant_id: "tenant_umich",
      job_type: "import_learner_record_batch",
      idempotency_key: "learner-record-import:batch_123:1",
      status: "pending",
    });
  });

  it("marks active learner-record import previews queued only once", async () => {
    const db = createFakeDb() as unknown as FakeSqlDatabase;
    db.learnerRecordImportPreviews.push({
      tenant_id: "tenant_umich",
      batch_id: "batch_123",
      file_name: "learner-records.csv",
      format: "csv",
      defaults_json: "{}",
      reports_json: "[]",
      queue_payloads_json: "[]",
      created_by_user_id: "usr_admin",
      created_at: "2026-03-26T15:00:00.000Z",
      expires_at: "2026-03-26T16:00:00.000Z",
      queued_at: null,
    });

    const firstMark = await markLearnerRecordImportPreviewQueued(db, {
      tenantId: "tenant_umich",
      batchId: "batch_123",
      queuedAt: "2026-03-26T15:10:00.000Z",
    });
    const secondMark = await markLearnerRecordImportPreviewQueued(db, {
      tenantId: "tenant_umich",
      batchId: "batch_123",
      queuedAt: "2026-03-26T15:11:00.000Z",
    });

    expect(firstMark).toBe(true);
    expect(secondMark).toBe(false);
    expect(db.learnerRecordImportPreviews[0]?.queued_at).toBe("2026-03-26T15:10:00.000Z");
  });

  it("lists and retries learner-record import queue messages by batch", async () => {
    const db = createFakeDb() as unknown as FakeSqlDatabase;

    db.jobQueueMessages.push(
      {
        id: "job_import_001",
        tenant_id: "tenant_umich",
        job_type: "import_learner_record_batch",
        payload_json: JSON.stringify({
          batchId: "batch_123",
          rowNumber: 1,
          fileName: "learner-records.csv",
          format: "csv",
          row: {
            effectiveTrustLevel: "issuer_verified",
          },
        }),
        idempotency_key: "idem_import_001",
        attempt_count: 3,
        max_attempts: 8,
        available_at: "2026-03-26T15:00:00.000Z",
        leased_until: null,
        lease_token: null,
        last_error: "Temporary downstream failure",
        completed_at: null,
        failed_at: "2026-03-26T15:05:00.000Z",
        status: "failed",
        created_at: "2026-03-26T15:00:00.000Z",
        updated_at: "2026-03-26T15:05:00.000Z",
      },
      {
        id: "job_import_002",
        tenant_id: "tenant_umich",
        job_type: "import_learner_record_batch",
        payload_json: JSON.stringify({
          batchId: "batch_123",
          rowNumber: 2,
          fileName: "learner-records.csv",
          format: "csv",
          row: {
            effectiveTrustLevel: "learner_supplemental",
          },
        }),
        idempotency_key: "idem_import_002",
        attempt_count: 1,
        max_attempts: 8,
        available_at: "2026-03-26T15:00:00.000Z",
        leased_until: null,
        lease_token: null,
        last_error: null,
        completed_at: "2026-03-26T15:04:00.000Z",
        failed_at: null,
        status: "completed",
        created_at: "2026-03-26T15:01:00.000Z",
        updated_at: "2026-03-26T15:04:00.000Z",
      },
    );

    const listed = await listImportLearnerRecordBatchQueueMessages(db, {
      tenantId: "tenant_umich",
    });

    expect(listed).toHaveLength(2);
    expect(listed[0]).toMatchObject({
      batchId: "batch_123",
      rowNumber: 2,
      defaultTrustLevel: "learner_supplemental",
    });

    const retry = await retryFailedImportLearnerRecordBatchQueueMessages(db, {
      tenantId: "tenant_umich",
      batchId: "batch_123",
      rowNumbers: [1],
      nowIso: "2026-03-26T15:10:00.000Z",
    });

    expect(retry).toEqual({
      matched: 1,
      retried: 1,
      skippedNotFailed: 0,
    });
    expect(db.jobQueueMessages[0]).toMatchObject({
      status: "pending",
      attempt_count: 0,
      last_error: null,
      failed_at: null,
      available_at: "2026-03-26T15:10:00.000Z",
    });
  });
});

describe("learner-record exports", () => {
  it("lists badge assertion exports for a learner profile with email alias fallback", async () => {
    const db = createFakeDb();
    const fakeDb = db as unknown as FakeSqlDatabase;
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
      identityValue: "student.alias@umich.edu",
      isVerified: true,
    });

    fakeDb.tenants.push({
      id: "tenant_umich",
      slug: "umich",
      display_name: "University of Michigan",
      plan_tier: "institution",
      is_active: 1,
    });
    fakeDb.badgeTemplates.push({
      id: "badge_template_001",
      tenant_id: "tenant_umich",
      title: "Clinical Hours Badge",
      description: "Awarded for completing clinical hours.",
      criteria_uri: "https://credtrail.example.edu/badges/clinical-hours/criteria",
      image_uri: "https://credtrail.example.edu/badges/clinical-hours/image.png",
    });
    fakeDb.assertions.push(
      {
        id: "assertion_primary",
        tenant_id: "tenant_umich",
        public_id: "public_primary",
        learner_profile_id: profile.id,
        badge_template_id: "badge_template_001",
        recipient_identity: "student@umich.edu",
        recipient_identity_type: "email",
        vc_r2_key: "tenants/tenant_umich/assertions/assertion_primary.jsonld",
        status_list_index: 1,
        idempotency_key: "idem_primary",
        issued_at: "2026-03-24T15:00:00.000Z",
        issued_by_user_id: "usr_admin",
        revoked_at: null,
        created_at: "2026-03-24T15:00:00.000Z",
        updated_at: "2026-03-24T15:00:00.000Z",
      },
      {
        id: "assertion_alias",
        tenant_id: "tenant_umich",
        public_id: "public_alias",
        learner_profile_id: null,
        badge_template_id: "badge_template_001",
        recipient_identity: "student.alias@umich.edu",
        recipient_identity_type: "email",
        vc_r2_key: "tenants/tenant_umich/assertions/assertion_alias.jsonld",
        status_list_index: 2,
        idempotency_key: "idem_alias",
        issued_at: "2026-03-25T15:00:00.000Z",
        issued_by_user_id: "usr_admin",
        revoked_at: null,
        created_at: "2026-03-25T15:00:00.000Z",
        updated_at: "2026-03-25T15:00:00.000Z",
      },
      {
        id: "assertion_other",
        tenant_id: "tenant_umich",
        public_id: "public_other",
        learner_profile_id: null,
        badge_template_id: "badge_template_001",
        recipient_identity: "someone-else@umich.edu",
        recipient_identity_type: "email",
        vc_r2_key: "tenants/tenant_umich/assertions/assertion_other.jsonld",
        status_list_index: 3,
        idempotency_key: "idem_other",
        issued_at: "2026-03-26T15:00:00.000Z",
        issued_by_user_id: "usr_admin",
        revoked_at: null,
        created_at: "2026-03-26T15:00:00.000Z",
        updated_at: "2026-03-26T15:00:00.000Z",
      },
    );

    const exported = await listLearnerRecordAssertionExports(db, {
      tenantId: "tenant_umich",
      learnerProfileId: profile.id,
    });

    expect(exported.map((row) => row.assertionId)).toEqual([
      "assertion_alias",
      "assertion_primary",
    ]);
    expect(exported[0]).toMatchObject({
      tenantId: "tenant_umich",
      learnerProfileId: null,
      badgeTemplateId: "badge_template_001",
      badgeTitle: "Clinical Hours Badge",
      badgeCriteriaUri: "https://credtrail.example.edu/badges/clinical-hours/criteria",
      issuerName: "University of Michigan",
      recipientIdentity: "student.alias@umich.edu",
    });
  });
});

describe("learner-record foundation", () => {
  it("adds a learner-record migration with provenance and tenant/profile indexes", () => {
    const sql = readFileSync(
      new URL("../migrations/0035_learner_record_entries.sql", import.meta.url),
      "utf8",
    );

    expect(sql).toContain("CREATE TABLE IF NOT EXISTS learner_record_entries");
    expect(sql).toContain("trust_level TEXT NOT NULL CHECK");
    expect(sql).toContain("source_system TEXT NOT NULL CHECK");
    expect(sql).toContain("evidence_links_json TEXT NOT NULL DEFAULT '[]'");
    expect(sql).toContain("FOREIGN KEY (tenant_id, learner_profile_id)");
    expect(sql).toContain("idx_learner_record_entries_tenant_profile_issued");
    expect(sql).toContain("idx_learner_record_entries_tenant_trust_status");
  });

  it("adds a learner-record import-context migration with queryable org-unit and badge-template indexes", () => {
    const sql = readFileSync(
      new URL("../migrations/0036_learner_record_import_context.sql", import.meta.url),
      "utf8",
    );

    expect(sql).toContain("CREATE TABLE IF NOT EXISTS learner_record_import_context");
    expect(sql).toContain("entry_id TEXT PRIMARY KEY");
    expect(sql).toContain("inferred_from_json TEXT NOT NULL DEFAULT '[\"none\"]'");
    expect(sql).toContain("idx_learner_record_import_context_tenant_org_unit");
    expect(sql).toContain("idx_learner_record_import_context_tenant_badge_template");
  });
});

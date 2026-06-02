import { readFileSync } from "node:fs";

import { describe, expect, it } from "vitest";

import {
  addLearnerIdentityAlias,
  createLearnerProfile,
  createLearnerRecordEntry,
  createLearnerRecordImportContext,
  createLearnerRecordImportPreview,
  enqueueJobQueueMessageOnce,
  findLearnerRecordImportContextByEntryId,
  listImportLearnerRecordBatchQueueMessages,
  listLearnerRecordAssertionExports,
  listLearnerRecordEntries,
  markLearnerRecordImportPreviewQueued,
  patchLearnerRecordEntry,
  retryFailedImportLearnerRecordBatchQueueMessages,
  type SqlDatabase,
} from "./index";
import {
  cleanupTestResources,
  countRows,
  createTestTenantFixture,
  describeDbIntegration,
  seedAssertion,
  seedBadgeTemplate,
  uniqueTestId,
} from "./postgres-test-support";

const createProfile = async (db: SqlDatabase, tenantId: string) => {
  return createLearnerProfile(db, {
    tenantId,
    primaryIdentityType: "email",
    primaryIdentityValue: `${uniqueTestId("student")}@umich.edu`,
    primaryIdentityVerified: true,
  });
};

describeDbIntegration("learner-record entries", () => {
  it("creates and lists non-badge learner-record entries for a learner profile", async () => {
    const fixture = await createTestTenantFixture({
      displayName: "University of Michigan",
    });

    try {
      const profile = await createProfile(fixture.db, fixture.tenantId);
      const createdEntry = await createLearnerRecordEntry(fixture.db, {
        tenantId: fixture.tenantId,
        learnerProfileId: profile.id,
        trustLevel: "issuer_verified",
        recordType: "course",
        title: "Clinical Placement Seminar",
        description: "Completed with distinction.",
        issuerName: "University of Michigan",
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

      const listedEntries = await listLearnerRecordEntries(fixture.db, {
        tenantId: fixture.tenantId,
        learnerProfileId: profile.id,
      });

      expect(listedEntries).toEqual([createdEntry]);
    } finally {
      await cleanupTestResources(fixture.db, {
        tenantIds: [fixture.tenantId],
      });
    }
  });

  it("filters learner-record entries by trust and status", async () => {
    const fixture = await createTestTenantFixture({
      displayName: "University of Michigan",
    });

    try {
      const profile = await createProfile(fixture.db, fixture.tenantId);
      await createLearnerRecordEntry(fixture.db, {
        tenantId: fixture.tenantId,
        learnerProfileId: profile.id,
        trustLevel: "issuer_verified",
        recordType: "course",
        title: "Applied Statistics",
        issuerName: "University of Michigan",
        sourceSystem: "credtrail_admin",
        issuedAt: "2026-03-20T15:00:00.000Z",
        evidenceLinks: [],
      });
      const supplemental = await createLearnerRecordEntry(fixture.db, {
        tenantId: fixture.tenantId,
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

      const filtered = await listLearnerRecordEntries(fixture.db, {
        tenantId: fixture.tenantId,
        learnerProfileId: profile.id,
        trustLevel: "learner_supplemental",
        status: "expired",
      });

      expect(filtered).toEqual([supplemental]);
    } finally {
      await cleanupTestResources(fixture.db, {
        tenantIds: [fixture.tenantId],
      });
    }
  });

  it("patches learner-record provenance and revoke state without mutating badge assertions", async () => {
    const fixture = await createTestTenantFixture({
      displayName: "University of Michigan",
    });

    try {
      const profile = await createProfile(fixture.db, fixture.tenantId);
      const createdEntry = await createLearnerRecordEntry(fixture.db, {
        tenantId: fixture.tenantId,
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

      const updatedEntry = await patchLearnerRecordEntry(fixture.db, {
        tenantId: fixture.tenantId,
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
    } finally {
      await cleanupTestResources(fixture.db, {
        tenantIds: [fixture.tenantId],
      });
    }
  });
});

describeDbIntegration("learner-record import context", () => {
  it("persists queryable smart-default context separately from learner-record details", async () => {
    const fixture = await createTestTenantFixture({
      displayName: "University of Michigan",
    });

    try {
      const profile = await createProfile(fixture.db, fixture.tenantId);
      const entry = await createLearnerRecordEntry(fixture.db, {
        tenantId: fixture.tenantId,
        learnerProfileId: profile.id,
        trustLevel: "issuer_verified",
        recordType: "course",
        title: "Clinical Placement Seminar",
        issuerName: "University of Michigan",
        sourceSystem: "csv_import",
        issuedAt: "2026-03-26T15:00:00.000Z",
        evidenceLinks: [],
      });

      const createdContext = await createLearnerRecordImportContext(fixture.db, {
        tenantId: fixture.tenantId,
        entryId: entry.id,
        orgUnitId: `${fixture.tenantId}:org:department-health`,
        badgeTemplateId: "badge_template_001",
        pathwayLabel: "Clinical readiness",
        inferredFrom: ["row", "badge_template"],
      });

      expect(createdContext).toMatchObject({
        entryId: entry.id,
        tenantId: fixture.tenantId,
        orgUnitId: `${fixture.tenantId}:org:department-health`,
        badgeTemplateId: "badge_template_001",
        pathwayLabel: "Clinical readiness",
        inferredFromJson: '["row","badge_template"]',
      });

      const loadedContext = await findLearnerRecordImportContextByEntryId(
        fixture.db,
        fixture.tenantId,
        entry.id,
      );

      expect(loadedContext).toEqual(createdContext);
    } finally {
      await cleanupTestResources(fixture.db, {
        tenantIds: [fixture.tenantId],
      });
    }
  });
});

describeDbIntegration("learner-record import queue helpers", () => {
  it("enqueues learner-record import jobs idempotently by tenant, type, and key", async () => {
    const fixture = await createTestTenantFixture({
      displayName: "University of Michigan",
    });
    const idempotencyKey = uniqueTestId("learner-record-import");

    try {
      const firstInsert = await enqueueJobQueueMessageOnce(fixture.db, {
        tenantId: fixture.tenantId,
        jobType: "import_learner_record_batch",
        payload: {
          batchId: "batch_123",
          rowNumber: 1,
        },
        idempotencyKey,
        nowIso: "2026-03-26T15:00:00.000Z",
      });
      const duplicateInsert = await enqueueJobQueueMessageOnce(fixture.db, {
        tenantId: fixture.tenantId,
        jobType: "import_learner_record_batch",
        payload: {
          batchId: "batch_123",
          rowNumber: 1,
        },
        idempotencyKey,
        nowIso: "2026-03-26T15:01:00.000Z",
      });

      expect(firstInsert).toBe(true);
      expect(duplicateInsert).toBe(false);
      await expect(
        countRows(fixture.db, "job_queue_messages", "tenant_id = ?", [fixture.tenantId]),
      ).resolves.toBe(1);
    } finally {
      await cleanupTestResources(fixture.db, {
        tenantIds: [fixture.tenantId],
      });
    }
  });

  it("marks active learner-record import previews queued only once", async () => {
    const fixture = await createTestTenantFixture({
      displayName: "University of Michigan",
    });

    try {
      await createLearnerRecordImportPreview(fixture.db, {
        tenantId: fixture.tenantId,
        batchId: "batch_123",
        fileName: "learner-records.csv",
        format: "csv",
        defaultsJson: "{}",
        reportsJson: "[]",
        queuePayloadsJson: "[]",
        createdByUserId: null,
        createdAt: "2026-03-26T15:00:00.000Z",
        expiresAt: "2026-03-26T16:00:00.000Z",
      });

      const firstMark = await markLearnerRecordImportPreviewQueued(fixture.db, {
        tenantId: fixture.tenantId,
        batchId: "batch_123",
        queuedAt: "2026-03-26T15:10:00.000Z",
      });
      const secondMark = await markLearnerRecordImportPreviewQueued(fixture.db, {
        tenantId: fixture.tenantId,
        batchId: "batch_123",
        queuedAt: "2026-03-26T15:11:00.000Z",
      });

      expect(firstMark).toBe(true);
      expect(secondMark).toBe(false);
    } finally {
      await cleanupTestResources(fixture.db, {
        tenantIds: [fixture.tenantId],
      });
    }
  });

  it("lists and retries learner-record import queue messages by batch", async () => {
    const fixture = await createTestTenantFixture({
      displayName: "University of Michigan",
    });

    try {
      await fixture.db
        .prepare(
          `
          INSERT INTO job_queue_messages (
            id,
            tenant_id,
            job_type,
            payload_json,
            idempotency_key,
            attempt_count,
            max_attempts,
            available_at,
            leased_until,
            lease_token,
            last_error,
            completed_at,
            failed_at,
            status,
            created_at,
            updated_at
          )
          VALUES
            (?, ?, 'import_learner_record_batch', ?, ?, 3, 8, ?, NULL, NULL, ?, NULL, ?, 'failed', ?, ?),
            (?, ?, 'import_learner_record_batch', ?, ?, 1, 8, ?, NULL, NULL, NULL, ?, NULL, 'completed', ?, ?)
        `,
        )
        .bind(
          uniqueTestId("job"),
          fixture.tenantId,
          JSON.stringify({
            batchId: "batch_123",
            rowNumber: 1,
            fileName: "learner-records.csv",
            format: "csv",
            row: {
              effectiveTrustLevel: "issuer_verified",
            },
          }),
          uniqueTestId("idem"),
          "2026-03-26T15:00:00.000Z",
          "Temporary downstream failure",
          "2026-03-26T15:05:00.000Z",
          "2026-03-26T15:00:00.000Z",
          "2026-03-26T15:05:00.000Z",
          uniqueTestId("job"),
          fixture.tenantId,
          JSON.stringify({
            batchId: "batch_123",
            rowNumber: 2,
            fileName: "learner-records.csv",
            format: "csv",
            row: {
              effectiveTrustLevel: "learner_supplemental",
            },
          }),
          uniqueTestId("idem"),
          "2026-03-26T15:00:00.000Z",
          "2026-03-26T15:04:00.000Z",
          "2026-03-26T15:01:00.000Z",
          "2026-03-26T15:04:00.000Z",
        )
        .run();

      const listed = await listImportLearnerRecordBatchQueueMessages(fixture.db, {
        tenantId: fixture.tenantId,
      });

      expect(listed).toHaveLength(2);
      expect(listed[0]).toMatchObject({
        batchId: "batch_123",
        rowNumber: 2,
        defaultTrustLevel: "learner_supplemental",
      });

      const retry = await retryFailedImportLearnerRecordBatchQueueMessages(fixture.db, {
        tenantId: fixture.tenantId,
        batchId: "batch_123",
        rowNumbers: [1],
        nowIso: "2026-03-26T15:10:00.000Z",
      });

      expect(retry).toEqual({
        matched: 1,
        retried: 1,
        skippedNotFailed: 0,
      });
    } finally {
      await cleanupTestResources(fixture.db, {
        tenantIds: [fixture.tenantId],
      });
    }
  });
});

describeDbIntegration("learner-record exports", () => {
  it("lists badge assertion exports for a learner profile with email alias fallback", async () => {
    const fixture = await createTestTenantFixture({
      displayName: "University of Michigan",
    });

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
        identityValue: "student.alias@umich.edu",
        isVerified: true,
      });

      const badgeTemplateId = await seedBadgeTemplate(fixture.db, {
        id: uniqueTestId("badge_template"),
        tenantId: fixture.tenantId,
        title: "Clinical Hours Badge",
        description: "Awarded for completing clinical hours.",
        criteriaUri: "https://credtrail.example.edu/badges/clinical-hours/criteria",
        imageUri: "https://credtrail.example.edu/badges/clinical-hours/image.png",
      });

      const primaryAssertionId = uniqueTestId("assertion_primary");
      const aliasAssertionId = uniqueTestId("assertion_alias");
      const otherAssertionId = uniqueTestId("assertion_other");

      await seedAssertion(fixture.db, {
        id: primaryAssertionId,
        tenantId: fixture.tenantId,
        publicId: uniqueTestId("public_primary"),
        learnerProfileId: profile.id,
        badgeTemplateId,
        recipientIdentity: "student@umich.edu",
        statusListIndex: 1,
        idempotencyKey: uniqueTestId("idem_primary"),
        issuedAt: "2026-03-24T15:00:00.000Z",
      });
      await seedAssertion(fixture.db, {
        id: aliasAssertionId,
        tenantId: fixture.tenantId,
        publicId: uniqueTestId("public_alias"),
        badgeTemplateId,
        recipientIdentity: "student.alias@umich.edu",
        statusListIndex: 2,
        idempotencyKey: uniqueTestId("idem_alias"),
        issuedAt: "2026-03-25T15:00:00.000Z",
      });
      await seedAssertion(fixture.db, {
        id: otherAssertionId,
        tenantId: fixture.tenantId,
        publicId: uniqueTestId("public_other"),
        badgeTemplateId,
        recipientIdentity: "someone-else@umich.edu",
        statusListIndex: 3,
        idempotencyKey: uniqueTestId("idem_other"),
        issuedAt: "2026-03-26T15:00:00.000Z",
      });

      const exported = await listLearnerRecordAssertionExports(fixture.db, {
        tenantId: fixture.tenantId,
        learnerProfileId: profile.id,
      });

      expect(exported.map((row) => row.assertionId)).toEqual([
        aliasAssertionId,
        primaryAssertionId,
      ]);
      expect(exported[0]).toMatchObject({
        tenantId: fixture.tenantId,
        learnerProfileId: null,
        badgeTemplateId,
        badgeTitle: "Clinical Hours Badge",
        badgeCriteriaUri: "https://credtrail.example.edu/badges/clinical-hours/criteria",
        issuerName: "University of Michigan",
        recipientIdentity: "student.alias@umich.edu",
      });
    } finally {
      await cleanupTestResources(fixture.db, {
        tenantIds: [fixture.tenantId],
      });
    }
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

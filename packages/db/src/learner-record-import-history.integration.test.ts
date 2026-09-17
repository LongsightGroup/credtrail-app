import { expect, it } from "vitest";
import {
  applyLearnerRecordImport,
  listImportedLearners,
  listLearnerRecordImportHistory,
  retryFailedImportLearnerRecordBatchQueueMessages,
} from "./index";
import {
  cleanupTestResources,
  createTestTenantFixture,
  describeDbIntegration,
  uniqueTestId,
} from "./postgres-test-support";

describeDbIntegration("learner import history", () => {
  it("counts and retries every row in large batches with tenant isolation", async () => {
    const f = await createTestTenantFixture({ displayName: "Import history" });
    const other = await createTestTenantFixture({ displayName: "Other imports" });
    try {
      for (const tenant of [f.tenantId, other.tenantId]) {
        await f.db
          .prepare(`INSERT INTO job_queue_messages (id, tenant_id, job_type, payload_json, idempotency_key, attempt_count, max_attempts, available_at, status, created_at, updated_at)
          SELECT ? || n::text, ?, 'import_learner_record_batch', json_build_object('batchId','large','rowNumber',n,'fileName','records.csv')::text, ? || n::text, 1, 8, '2026-09-17T00:00:00.000Z', CASE WHEN n <= 1100 THEN 'failed' ELSE 'completed' END, '2026-09-17T00:00:00.000Z', '2026-09-17T00:00:00.000Z' FROM generate_series(1,1200) n`)
          .bind(uniqueTestId("job"), tenant, uniqueTestId("key"))
          .run();
      }
      expect(await listLearnerRecordImportHistory(f.db, f.tenantId)).toMatchObject([
        { batchId: "large", totalRows: 1200, failedRows: 1100, completedRows: 100 },
      ]);
      expect(
        await retryFailedImportLearnerRecordBatchQueueMessages(f.db, {
          tenantId: f.tenantId,
          batchId: "large",
        }),
      ).toEqual({ matched: 1200, retried: 1100, skippedNotFailed: 100 });
      expect(await listLearnerRecordImportHistory(f.db, f.tenantId)).toMatchObject([
        { pendingRows: 1100, failedRows: 0, completedRows: 100 },
      ]);
      expect(await listLearnerRecordImportHistory(f.db, other.tenantId)).toMatchObject([
        { failedRows: 1100 },
      ]);
      expect(await listImportedLearners(f.db, { tenantId: f.tenantId, batchId: "large" })).toEqual(
        [],
      );
    } finally {
      await cleanupTestResources(f.db, { tenantIds: [f.tenantId, other.tenantId] });
    }
  });
  it("lists only applied records, groups learners, and respects the page cursor and tenant", async () => {
    const f = await createTestTenantFixture({ displayName: "Imported learners" });
    try {
      const email = `${uniqueTestId("learner")}@example.edu`;
      const input = {
        tenantId: f.tenantId,
        batchId: "batch",
        rowNumber: 1,
        learnerEmail: email,
        learnerDisplayName: "Imported learner",
        entry: {
          trustLevel: "issuer_verified" as const,
          recordType: "course" as const,
          title: "Course",
          issuerName: "University",
          sourceSystem: "csv_import" as const,
          issuedAt: "2026-09-17T00:00:00.000Z",
          evidenceLinks: [],
        },
        context: { inferredFrom: ["none" as const] },
      };
      const applied = await applyLearnerRecordImport(f.db, input);
      await applyLearnerRecordImport(f.db, { ...input, rowNumber: 2 });
      await applyLearnerRecordImport(f.db, input);
      expect(await listImportedLearners(f.db, { tenantId: f.tenantId, batchId: "batch" })).toEqual([
        { profileId: applied.learnerProfileId, displayName: "Imported learner", email, records: 2 },
      ]);
      expect(
        await listImportedLearners(f.db, {
          tenantId: f.tenantId,
          batchId: "batch",
          after: applied.learnerProfileId,
        }),
      ).toEqual([]);
      expect(await listImportedLearners(f.db, { tenantId: "other", batchId: "batch" })).toEqual([]);
    } finally {
      await cleanupTestResources(f.db, { tenantIds: [f.tenantId] });
    }
  });
});

import { expect, it } from "vitest";
import {
  cleanupTestResources,
  countRows,
  createTestTenantFixture,
  describeDbIntegration,
  uniqueTestId,
} from "./postgres-test-support";
import { applyLearnerRecordImport, type ApplyLearnerRecordImportInput } from "./index";

const importInput = (
  tenantId: string,
  batchId: string,
  learnerEmail: string,
): ApplyLearnerRecordImportInput => ({
  tenantId,
  batchId,
  rowNumber: 1,
  learnerEmail,
  learnerDisplayName: "Learner Example",
  entry: {
    trustLevel: "issuer_verified",
    recordType: "course",
    title: "Clinical Placement Seminar",
    issuerName: "CredTrail University",
    sourceSystem: "csv_import",
    issuedAt: "2026-08-17T12:00:00.000Z",
    evidenceLinks: [],
  },
  context: {
    pathwayLabel: "Clinical readiness",
    inferredFrom: ["none"],
  },
});

describeDbIntegration("atomic learner-record imports", () => {
  it("applies concurrent retries exactly once and returns the original result", async () => {
    const fixture = await createTestTenantFixture({ displayName: "CredTrail University" });
    const batchId = uniqueTestId("batch");
    const input = importInput(fixture.tenantId, batchId, `${uniqueTestId("learner")}@example.edu`);

    try {
      const results = await Promise.all([
        applyLearnerRecordImport(fixture.db, input),
        applyLearnerRecordImport(fixture.db, input),
      ]);

      expect(results.map((result) => result.status).sort()).toEqual(["already_applied", "applied"]);
      expect(results[0]?.learnerProfileId).toBe(results[1]?.learnerProfileId);
      expect(results[0]?.learnerRecordEntryId).toBe(results[1]?.learnerRecordEntryId);
      await expect(
        countRows(fixture.db, "learner_record_import_applications", "tenant_id = ?", [
          fixture.tenantId,
        ]),
      ).resolves.toBe(1);
      await expect(
        countRows(fixture.db, "learner_record_entries", "tenant_id = ?", [fixture.tenantId]),
      ).resolves.toBe(1);
      await expect(
        countRows(fixture.db, "learner_record_import_context", "tenant_id = ?", [fixture.tenantId]),
      ).resolves.toBe(1);
      await expect(
        countRows(fixture.db, "job_queue_messages", "tenant_id = ? AND job_type = ?", [
          fixture.tenantId,
          "process_learner_evidence_change",
        ]),
      ).resolves.toBe(1);
    } finally {
      await cleanupTestResources(fixture.db, { tenantIds: [fixture.tenantId] });
    }
  });

  it("rolls back every write when applying the import context fails", async () => {
    const fixture = await createTestTenantFixture({ displayName: "CredTrail University" });
    const batchId = uniqueTestId("batch");
    const input = importInput(fixture.tenantId, batchId, `${uniqueTestId("learner")}@example.edu`);

    try {
      await expect(
        applyLearnerRecordImport(fixture.db, {
          ...input,
          context: { inferredFrom: [] },
        }),
      ).rejects.toThrow("must include at least one inference source");
      await expect(
        countRows(fixture.db, "learner_record_import_applications", "tenant_id = ?", [
          fixture.tenantId,
        ]),
      ).resolves.toBe(0);
      await expect(
        countRows(fixture.db, "learner_record_entries", "tenant_id = ?", [fixture.tenantId]),
      ).resolves.toBe(0);
      await expect(
        countRows(fixture.db, "learner_profiles", "tenant_id = ?", [fixture.tenantId]),
      ).resolves.toBe(0);

      await expect(applyLearnerRecordImport(fixture.db, input)).resolves.toMatchObject({
        status: "applied",
      });
    } finally {
      await cleanupTestResources(fixture.db, { tenantIds: [fixture.tenantId] });
    }
  });

  it("returns the original result when a retry reuses the row identity", async () => {
    const fixture = await createTestTenantFixture({ displayName: "CredTrail University" });
    const batchId = uniqueTestId("batch");
    const input = importInput(fixture.tenantId, batchId, `${uniqueTestId("learner")}@example.edu`);

    try {
      const first = await applyLearnerRecordImport(fixture.db, input);
      const retry = await applyLearnerRecordImport(fixture.db, {
        ...input,
        learnerEmail: `${uniqueTestId("different")}@example.edu`,
        entry: { ...input.entry, title: "Different row" },
      });

      expect(retry).toEqual({ ...first, status: "already_applied" });
      await expect(
        countRows(fixture.db, "learner_record_entries", "tenant_id = ?", [fixture.tenantId]),
      ).resolves.toBe(1);
    } finally {
      await cleanupTestResources(fixture.db, { tenantIds: [fixture.tenantId] });
    }
  });
});

import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { seededDemoLearnerRecordFixture } from "../test-support/seeded-demo-learner-record-fixture";

const learnerRecordDir = dirname(fileURLToPath(import.meta.url));

const readRuntimeSource = (relativePath: string): string => {
  return readFileSync(resolve(learnerRecordDir, relativePath), "utf8");
};

describe("seeded demo learner record fixture", () => {
  it("exports a believable unified learner-record story on normal product routes", () => {
    expect(seededDemoLearnerRecordFixture.tenantId).toBe("tenant_123");
    expect(seededDemoLearnerRecordFixture.routeFamily.learnerRecord).toBe(
      "/tenants/tenant_123/learner/record",
    );
    expect(seededDemoLearnerRecordFixture.routeFamily.adminReview).toBe(
      "/tenants/tenant_123/admin/operations/learner-records?learner=learner%40example.edu",
    );
    expect(seededDemoLearnerRecordFixture.routeFamily.nativeExport).toContain(
      "profile=native_portable_json",
    );
    expect(seededDemoLearnerRecordFixture.routeFamily.standardsMapping).toContain(
      "profile=clr_alignment_json",
    );
    expect(
      seededDemoLearnerRecordFixture.presentation.sections.map((section) => section.key),
    ).toEqual(["issuerVerifiedActive", "supplementalActive", "historical"]);
    expect(seededDemoLearnerRecordFixture.nativePortableExport.counts).toEqual({
      totalItems: 4,
      badgeAssertions: 1,
      recordEntries: 3,
      issuerVerified: 3,
      learnerSupplemental: 1,
    });
    expect(
      seededDemoLearnerRecordFixture.clrAlignedExport.records.map((record) => record.title),
    ).toEqual(
      expect.arrayContaining([
        "Applied Analytics Badge",
        "Clinical Placement Seminar",
        "Portfolio Reflection",
        "Leadership Society Membership",
      ]),
    );
  });

  it("stays test-only verification data and is not imported by runtime learner-record code", () => {
    const runtimeSources = [
      "../learner/learner-record-page.tsx",
      "../routes/learner-routes.ts",
      "../routes/tenant-governance-routes.tsx",
      "../routes/learner-record-export-routes.ts",
    ].map(readRuntimeSource);

    for (const source of runtimeSources) {
      expect(source).not.toContain("seeded-demo-learner-record-fixture");
    }
  });

  it("keeps seeded values route-faithful, portable, and trust-explicit", () => {
    for (const path of Object.values(seededDemoLearnerRecordFixture.routeFamily)) {
      expect(path).toContain("/tenants/tenant_123");
      expect(path).not.toContain("demo=");
      expect(path).not.toContain("/showcase");
    }

    expect(
      seededDemoLearnerRecordFixture.exportBundle.items.map((item) => item.trustLevel),
    ).toEqual(["issuer_verified", "issuer_verified", "learner_supplemental", "issuer_verified"]);
    expect(
      seededDemoLearnerRecordFixture.exportBundle.items.map((item) => item.provenance.sourceSystem),
    ).toEqual(
      expect.arrayContaining([
        "badge_assertion",
        "credtrail_admin",
        "learner_self_reported",
        "csv_import",
      ]),
    );
    expect(seededDemoLearnerRecordFixture.standardsMappingResponse.itemCounts).toEqual(
      seededDemoLearnerRecordFixture.nativePortableExport.counts,
    );
    expect(
      seededDemoLearnerRecordFixture.clrAlignedExport.records.every(
        (record) => record.alignment.clr === "mapped",
      ),
    ).toBe(true);
  });
});

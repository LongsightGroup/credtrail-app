import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const reportDir = dirname(fileURLToPath(import.meta.url));

const loadFixtureModule = async () => import("./seeded-demo-reporting-fixture");

const readRuntimeSource = (relativePath: string): string => {
  return readFileSync(resolve(reportDir, relativePath), "utf8");
};

describe("seeded demo reporting fixture", () => {
  it("exports a canonical seeded-demo slice with the contract minimums", async () => {
    const { seededDemoReportingFixture } = await loadFixtureModule();

    expect(seededDemoReportingFixture.tenantId).toBe("tenant_123");
    expect(seededDemoReportingFixture.routePath).toBe("/tenants/tenant_123/admin/reporting");
    expect(seededDemoReportingFixture.overview.counts.issued).toBeGreaterThan(0);
    expect(seededDemoReportingFixture.engagementCounts.issuedCount).toBe(
      seededDemoReportingFixture.overview.counts.issued,
    );
    expect(seededDemoReportingFixture.trends.series.length).toBeGreaterThanOrEqual(3);
    expect(seededDemoReportingFixture.templateComparisons.length).toBeGreaterThanOrEqual(3);
    expect(seededDemoReportingFixture.orgUnitComparisons.length).toBeGreaterThanOrEqual(3);
    expect(seededDemoReportingFixture.hierarchy.focusOrgUnitId).toBe("tenant_123:org:college-eng");
    expect(seededDemoReportingFixture.hierarchy.rows.length).toBeGreaterThanOrEqual(2);
    expect(seededDemoReportingFixture.hierarchy.orgUnitLineageIds).toEqual([
      "tenant_123:org:institution",
      "tenant_123:org:college-eng",
      "tenant_123:org:department-cs",
      "tenant_123:org:program-cs",
    ]);
    expect(seededDemoReportingFixture.scopedOrgContext.rootOrgUnitId).toBe(
      "tenant_123:org:college-eng",
    );
    expect(seededDemoReportingFixture.scopedOrgContext.visibleOrgUnitIds).toContain(
      seededDemoReportingFixture.scopedOrgContext.orgUnitId,
    );
  });

  it("stays test-only verification data and is not imported by runtime reporting code", async () => {
    await loadFixtureModule();

    const runtimeSources = [
      "../admin/institution-admin-page.tsx",
      "../routes/reporting-routes.ts",
      "../routes/tenant-governance-routes.tsx",
    ].map(readRuntimeSource);

    for (const source of runtimeSources) {
      expect(source).not.toContain("seeded-demo-reporting-fixture");
    }
  });

  it("keeps seeded values plausible enough for the shipped visuals without inventing metrics", async () => {
    const { seededDemoReportingFixture } = await loadFixtureModule();
    const supportedComparisonKeys = [
      "claimRate",
      "groupBy",
      "groupId",
      "issuedCount",
      "learnerClaimCount",
      "publicBadgeViewCount",
      "shareClickCount",
      "shareRate",
      "verificationViewCount",
      "walletAcceptCount",
    ];
    const trendIssuedTotal = seededDemoReportingFixture.trends.series.reduce((sum, row) => {
      return sum + row.issuedCount;
    }, 0);

    expect(trendIssuedTotal).toBe(seededDemoReportingFixture.overview.counts.issued);
    expect(seededDemoReportingFixture.templateComparisons.some((row) => row.issuedCount >= 5)).toBe(
      true,
    );
    expect(seededDemoReportingFixture.orgUnitComparisons.some((row) => row.issuedCount >= 5)).toBe(
      true,
    );

    for (const row of [
      ...seededDemoReportingFixture.templateComparisons,
      ...seededDemoReportingFixture.orgUnitComparisons,
      ...seededDemoReportingFixture.hierarchy.rows,
    ]) {
      expect(Object.keys(row).sort()).toEqual(supportedComparisonKeys);
      expect(row.claimRate).toBeGreaterThanOrEqual(0);
      expect(row.claimRate).toBeLessThanOrEqual(100);
      expect(row.shareRate).toBeGreaterThanOrEqual(0);
      expect(row.shareRate).toBeLessThanOrEqual(100);
    }
  });
});

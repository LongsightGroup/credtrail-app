import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { seededDemoExecutiveFixture } from "../test-support/seeded-demo-executive-fixture";

const executiveDir = dirname(fileURLToPath(import.meta.url));

const readRuntimeSource = (relativePath: string): string => {
  return readFileSync(resolve(executiveDir, relativePath), "utf8");
};

describe("seeded demo executive fixture", () => {
  it("exports believable system, focused, and scoped executive slices", () => {
    const moduleKinds = seededDemoExecutiveFixture.slices.system.kpiCatalog.modules.map(
      (module) => module.kind,
    );

    expect(seededDemoExecutiveFixture.tenantId).toBe("tenant_123");
    expect(seededDemoExecutiveFixture.routeFamily.landing).toBe("/tenants/tenant_123/executive");
    expect(seededDemoExecutiveFixture.slices.system.defaults.audience).toBe("system");
    expect(seededDemoExecutiveFixture.slices.system.rollup.rows.length).toBeGreaterThanOrEqual(2);
    expect(seededDemoExecutiveFixture.slices.system.trends.series.length).toBeGreaterThanOrEqual(3);
    expect(moduleKinds).toEqual(
      expect.arrayContaining(["comparison_summary", "top_movers", "laggards", "drilldown"]),
    );
    expect(seededDemoExecutiveFixture.slices.focused.defaults.focusOrgUnitId).toBe(
      "tenant_123:org:college-eng",
    );
    expect(seededDemoExecutiveFixture.slices.focused.navigation.breadcrumbs).toHaveLength(2);
    expect(seededDemoExecutiveFixture.slices.scoped.access.visibility).toBe("scoped");
    expect(seededDemoExecutiveFixture.slices.scoped.access.scopedOrgUnitIds).toContain(
      "tenant_123:org:college-eng",
    );
    expect(seededDemoExecutiveFixture.slices.scoped.navigation.breadcrumbs).toMatchObject([
      {
        label: "College of Engineering",
        focusOrgUnitId: "tenant_123:org:college-eng",
        comparisonLevel: "department",
      },
    ]);
    expect(seededDemoExecutiveFixture.slices.scoped.navigation.parent).toBeNull();
    expect(seededDemoExecutiveFixture.slices.scoped.navigation.back).toBeNull();
  });

  it("stays test-only verification data and is not imported by runtime executive code", () => {
    const runtimeSources = [
      "./executive-rollup-loader.ts",
      "./executive-dashboard-page.tsx",
      "../routes/executive-routes.ts",
    ].map(readRuntimeSource);

    for (const source of runtimeSources) {
      expect(source).not.toContain("seeded-demo-executive-fixture");
    }
  });

  it("keeps values route-faithful without introducing demo-only behavior", () => {
    const trendIssuedTotal = seededDemoExecutiveFixture.slices.system.trends.series.reduce(
      (sum, row) => sum + row.issuedCount,
      0,
    );

    expect(trendIssuedTotal).toBe(seededDemoExecutiveFixture.slices.system.overview.counts.issued);

    for (const path of Object.values(seededDemoExecutiveFixture.routeFamily)) {
      expect(path).toContain("/tenants/tenant_123/executive");
      expect(path).not.toContain("/admin/reporting");
      expect(path).not.toContain("demo=");
    }

    for (const row of [
      ...seededDemoExecutiveFixture.slices.system.rollup.rows,
      ...seededDemoExecutiveFixture.slices.focused.rollup.rows,
    ]) {
      expect(row.issuedCount).toBeGreaterThan(0);
      expect(row.claimRate).toBeGreaterThanOrEqual(0);
      expect(row.claimRate).toBeLessThanOrEqual(100);
      expect(row.shareRate).toBeGreaterThanOrEqual(0);
      expect(row.shareRate).toBeLessThanOrEqual(100);
    }
  });
});

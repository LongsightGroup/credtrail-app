import { describe, expect, it } from "vitest";

import type { ExecutiveDashboardDefaults } from "./executive-dashboard-contract";
import { REPORTING_METRIC_DEFINITIONS } from "../reporting/metric-definitions";
import { buildExecutiveKpiCatalog } from "./executive-kpi-catalog";

const sampleDefaults = (
  overrides: Partial<ExecutiveDashboardDefaults> = {},
): ExecutiveDashboardDefaults => {
  return {
    audience: "system",
    window: "last-90-days",
    focusOrgUnitId: "tenant_123:org:institution",
    focusUnitType: "institution",
    comparisonLevel: "college",
    comparisonGroupBy: "orgUnit",
    reportingFilters: {
      issuedFrom: "2025-12-23",
      issuedTo: "2026-03-22",
    },
    hierarchyFilters: {
      issuedFrom: "2025-12-23",
      issuedTo: "2026-03-22",
      focusOrgUnitId: "tenant_123:org:institution",
      level: "college",
    },
    pathState: {
      audience: "system",
      window: "last-90-days",
      focusOrgUnitId: "tenant_123:org:institution",
      comparisonLevel: "college",
    },
    ...overrides,
  };
};

describe("buildExecutiveKpiCatalog", () => {
  it("builds the KPI strip from the existing reporting metric catalog", () => {
    const catalog = buildExecutiveKpiCatalog({
      defaults: sampleDefaults(),
    });

    expect(catalog.kpis.map((metric) => metric.key)).toEqual([
      "issued",
      "active",
      "claimRate",
      "shareRate",
    ]);
    expect(
      catalog.kpis.every((metric) =>
        REPORTING_METRIC_DEFINITIONS.some((definition) => definition.key === metric.key),
      ),
    ).toBe(true);
  });

  it("chooses a consistent first-screen module set for system and scoped executive audiences", () => {
    const systemCatalog = buildExecutiveKpiCatalog({
      defaults: sampleDefaults(),
    });
    const scopedCatalog = buildExecutiveKpiCatalog({
      defaults: sampleDefaults({
        audience: "college",
        focusOrgUnitId: "tenant_123:org:college-eng",
        focusUnitType: "college",
        comparisonLevel: "department",
        hierarchyFilters: {
          issuedFrom: "2025-12-23",
          issuedTo: "2026-03-22",
          focusOrgUnitId: "tenant_123:org:college-eng",
          level: "department",
        },
      }),
    });

    expect(systemCatalog.modules.map((module) => module.id)).toEqual([
      "comparison-summary",
      "top-movers-issued",
      "top-movers-claim-rate",
      "lagging-share-rate",
      "drilldown",
    ]);
    expect(scopedCatalog.modules.map((module) => module.id)).toEqual([
      "comparison-summary",
      "top-movers-issued",
      "top-movers-claim-rate",
      "lagging-share-rate",
      "drilldown",
    ]);
    expect(systemCatalog.modules[0]).toMatchObject({
      kind: "comparison_summary",
      comparisonLevel: "college",
      groupBy: "orgUnit",
    });
    expect(scopedCatalog.modules[0]).toMatchObject({
      kind: "comparison_summary",
      comparisonLevel: "department",
      groupBy: "orgUnit",
    });
  });

  it("keeps top-mover and laggard modules explainable as count and engagement comparisons", () => {
    const catalog = buildExecutiveKpiCatalog({
      defaults: sampleDefaults(),
    });

    expect(catalog.modules.filter((module) => module.kind === "top_movers")).toEqual([
      expect.objectContaining({
        id: "top-movers-issued",
        metricKey: "issued",
        ranking: "top",
      }),
      expect.objectContaining({
        id: "top-movers-claim-rate",
        metricKey: "claimRate",
        ranking: "top",
      }),
    ]);
    expect(catalog.modules.filter((module) => module.kind === "laggards")).toEqual([
      expect.objectContaining({
        id: "lagging-share-rate",
        metricKey: "shareRate",
        ranking: "bottom",
      }),
    ]);
  });

  it("falls back to a focus summary when the current executive slice has no deeper comparison level", () => {
    const catalog = buildExecutiveKpiCatalog({
      defaults: sampleDefaults({
        audience: "program",
        focusOrgUnitId: "tenant_123:org:program-cs",
        focusUnitType: "program",
        comparisonLevel: "program",
        hierarchyFilters: {
          issuedFrom: "2025-12-23",
          issuedTo: "2026-03-22",
          focusOrgUnitId: "tenant_123:org:program-cs",
          level: "program",
        },
      }),
    });

    expect(catalog.modules.map((module) => module.id)).toEqual(["focus-summary", "drilldown"]);
    expect(catalog.modules[0]).toMatchObject({
      kind: "focus_summary",
      comparisonLevel: "program",
    });
    expect(
      catalog.modules.some((module) => module.kind === "top_movers" || module.kind === "laggards"),
    ).toBe(false);
  });
});

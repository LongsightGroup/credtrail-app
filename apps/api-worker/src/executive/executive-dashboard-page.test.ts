import { describe, expect, it } from "vitest";

import { pageAssetPath } from "../ui/page-assets";
import {
  renderExecutiveDashboardPage,
  renderExecutiveUnavailablePage,
} from "./executive-dashboard-page";
import { createSeededDemoExecutiveDashboardSlice } from "./seeded-demo-executive-fixture";

describe("renderExecutiveDashboardPage", () => {
  it("renders a dedicated executive shell with linked assets instead of inline route-local styles", () => {
    const html = renderExecutiveDashboardPage(createSeededDemoExecutiveDashboardSlice("scoped"));

    expect(html).toContain("Executive Dashboard</p>");
    expect(html).toContain("College of Engineering credential momentum");
    expect(html).toContain("Executive snapshot");
    expect(html).toContain('data-reporting-visual-kind="trend-series"');
    expect(html).toContain('data-reporting-visual-kind="comparison-ranked"');
    expect(html).toContain(pageAssetPath("foundationCss"));
    expect(html).toContain(pageAssetPath("executiveDashboardCss"));
    expect(html).not.toContain(".executive-hero {");
    expect(html).toContain('body data-variant="open"');
  });

  it("keeps the first screen KPI-first and preserves the executive JSON handoff", () => {
    const html = renderExecutiveDashboardPage(createSeededDemoExecutiveDashboardSlice("scoped"));

    expect(html).toContain('data-executive-audience="college"');
    expect(html).toContain("College executive view");
    expect(html).toContain("College of Engineering credential momentum");
    expect(html).toContain("Issued badges");
    expect(html).toContain("18");
    expect(html).toContain("Compare departments");
    expect(html).toContain(
      "/v1/tenants/tenant_123/executive?window=last-90-days&amp;audience=college&amp;state=active&amp;focusOrgUnitId=tenant_123%3Aorg%3Acollege-eng&amp;comparisonLevel=department",
    );
    expect(html).not.toContain("issuedFrom=2025-12-23");
    expect(html).not.toContain("issuedTo=2026-03-22");
    expect(html.indexOf('aria-label="Executive KPI summary"')).toBeLessThan(
      html.indexOf('data-reporting-visual-kind="trend-series"'),
    );
    expect(html.indexOf('data-reporting-visual-kind="trend-series"')).toBeLessThan(
      html.indexOf('data-reporting-visual-kind="comparison-ranked"'),
    );
  });

  it("changes hero framing for system slices and keeps sparse slices intentional", () => {
    const systemDashboard = createSeededDemoExecutiveDashboardSlice("scoped");
    systemDashboard.defaults.audience = "system";
    systemDashboard.defaults.focusUnitType = "institution";
    systemDashboard.rollup.focusUnitType = "institution";
    systemDashboard.rollup.focusDisplayName = "Tenant 123 Institution";
    systemDashboard.rollup.comparisonLevel = "college";

    const sparseDashboard = createSeededDemoExecutiveDashboardSlice("scoped");
    sparseDashboard.rollup.rows = [];
    sparseDashboard.kpiCatalog.modules = [
      {
        id: "focus-summary",
        kind: "focus_summary",
        title: "Current college summary",
        description: "Keep the executive story centered on this college.",
        audience: "college",
        focusOrgUnitId: "tenant_123:org:college-eng",
        comparisonLevel: "college",
      },
    ];

    const systemHtml = renderExecutiveDashboardPage(systemDashboard);
    const sparseHtml = renderExecutiveDashboardPage(sparseDashboard);

    expect(systemHtml).toContain("System-level executive view");
    expect(systemHtml).toContain("System credential momentum");
    expect(sparseHtml).toContain("Focused slice");
    expect(sparseHtml).toContain("Summary-first view");
    expect(sparseHtml).toContain(
      "This view stays intentionally narrow so leaders can trust the current slice instead of reading invented rankings.",
    );
  });

  it("renders breadcrumbed drilldown links that stay on the executive route family", () => {
    const html = renderExecutiveDashboardPage(createSeededDemoExecutiveDashboardSlice("focused"));

    expect(html).toContain('aria-label="Executive drilldown path"');
    expect(html).toContain(">Tenant 123 Institution<");
    expect(html).toContain(">College of Engineering<");
    expect(html).toContain(">Back to Tenant 123 Institution<");
    expect(html).toContain(">Computer Science<");
    expect(html).toContain(">Mathematics<");
    expect(html).toContain(
      "/tenants/tenant_123/executive?window=last-90-days&amp;audience=system&amp;badgeTemplateId=badge_template_science&amp;state=active&amp;focusOrgUnitId=tenant_123%3Aorg%3Adepartment-cs&amp;comparisonLevel=program",
    );
    expect(html).not.toContain("/admin/reporting");
    expect(html).not.toContain("Phase 23 will extend the executive route family");
  });

  it("keeps scoped executive breadcrumbs rooted in the visible subtree", () => {
    const html = renderExecutiveDashboardPage(createSeededDemoExecutiveDashboardSlice("scoped"));

    expect(html).toContain('aria-label="Executive drilldown path"');
    expect(html).toContain(">College of Engineering<");
    expect(html).not.toContain(">Tenant 123 Institution<");
    expect(html).not.toContain(">Back to Tenant 123 Institution<");
    expect(html).toContain(">Computer Science<");
    expect(html).toContain(">Mathematics<");
    expect(html).not.toContain("/admin/reporting");
  });

  it("keeps sparse executive drilldown states summary-first and honest", () => {
    const sparseDashboard = createSeededDemoExecutiveDashboardSlice("scoped");
    sparseDashboard.rollup.rows = [];
    sparseDashboard.navigation.drilldowns = [];
    sparseDashboard.kpiCatalog.modules = [
      {
        id: "focus-summary",
        kind: "focus_summary",
        title: "Current college summary",
        description: "Keep the executive story centered on this college.",
        audience: "college",
        focusOrgUnitId: "tenant_123:org:college-eng",
        comparisonLevel: "department",
      },
      {
        id: "drilldown",
        kind: "drilldown",
        title: "Review college detail",
        description:
          "Stay with the current executive slice when there is no deeper visible comparison to open.",
        audience: "college",
        focusOrgUnitId: "tenant_123:org:college-eng",
        comparisonLevel: "department",
      },
    ];

    const html = renderExecutiveDashboardPage(sparseDashboard);

    expect(html).toContain("This slice stays centered on College of Engineering");
    expect(html).toContain("Visible rows");
    expect(html).toContain(">0<");
    expect(html).not.toContain(">Back to Tenant 123 Institution<");
    expect(html).not.toContain(">Computer Science<");
    expect(html).not.toContain(">Mathematics<");
  });

  it("renders the unavailable state through the same dedicated executive asset shell", () => {
    const html = renderExecutiveUnavailablePage();

    expect(html).toContain("Executive dashboard unavailable");
    expect(html).toContain(pageAssetPath("executiveDashboardCss"));
    expect(html).not.toContain("Institution Admin");
  });
});

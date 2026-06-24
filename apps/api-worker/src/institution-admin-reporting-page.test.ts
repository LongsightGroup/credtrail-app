import { describe, expect, it, vi } from "vitest";
import {
  createEnv,
  fakeDb,
  getReportingPanelArticleMarkup,
  getReportingPanelMarkup,
  mockedFindTenantMembership,
  mockedGetTenantReportingComparisonsDb,
  mockedGetTenantReportingEngagementCountsDb,
  mockedGetTenantReportingOverviewDb,
  mockedGetTenantReportingTrendsDb,
  mockedListBadgeTemplates,
  mockedListTenantMembershipOrgUnitScopes,
  mockedListTenantOrgUnits,
  sampleMembership,
} from "./institution-admin-page-test-utils";
import { app } from "./index";
import { getSeededDemoReportingRouteFixture } from "./reporting/seeded-demo-reporting-fixture";
import { INSTITUTION_ADMIN_CSS } from "./ui/page-assets/content/institution-admin-css";
import { INSTITUTION_ADMIN_JS } from "./ui/page-assets/content/institution-admin-js";
import { pageAssetPath } from "./ui/page-assets";

describe("GET /tenants/:tenantId/admin/reporting", () => {
  it("returns a normalized 403 page when reporting access is missing", async () => {
    const env = createEnv();
    mockedFindTenantMembership.mockResolvedValue(sampleMembership("viewer"));

    const response = await app.request(
      "/tenants/tenant_123/admin/reporting",
      {
        headers: {
          Cookie: "better-auth.session_token=session-token",
        },
      },
      env,
    );
    const body = await response.text();

    expect(response.status).toBe(403);
    expect(response.headers.get("content-type")).toContain("text/html");
    expect(body).toContain("Reporting access required");
    expect(body).toContain(pageAssetPath("institutionAdminCss"));
    expect(body).toContain('class="ct-admin-content"');
    expect(body).toContain('class="ct-admin-page-header"');
    expect(body).toContain('class="ct-admin__panel ct-stack"');
    expect(body).not.toContain('style="');
  });

  it("renders a distilled reporting home before deeper reporting sections", async () => {
    const env = createEnv();

    const response = await app.request(
      "/tenants/tenant_123/admin/reporting?issuedFrom=2026-03-01&issuedTo=2026-03-31",
      {
        headers: {
          Cookie: "better-auth.session_token=session-token",
        },
      },
      env,
    );
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(body).toContain(">Reporting<");
    expect(body).not.toContain("Reporting Highlights");
    expect(body).toContain("At a glance");
    expect(body).toContain("ct-admin__reporting-summary-band");
    expect(body).toContain(
      'class="ct-admin__reporting-presentation-shell ct-admin__reporting-presentation-shell--highlights',
    );
    expect(body).toContain('data-reporting-summary-metric="issued"');
    expect(body).toContain('data-reporting-summary-metric="claim-rate"');
    expect(body).toContain('data-reporting-summary-metric="share-rate"');
    expect(body).toContain('data-reporting-summary-metric="public-badge-views"');
    expect(body).not.toContain("90-day issuance momentum");
    expect(body).not.toContain('data-reporting-visual-kind="trend-area"');
    expect(body).not.toContain("What happens after issuance");
    expect(body).not.toContain('data-reporting-visual-kind="journey-funnel"');
    expect(body).not.toContain('class="ct-admin__reporting-insight-grid"');
    expect(body).not.toContain("Smart defaults active.");
    expect(body).toContain("Ranked charts");
    expect(body).toContain("Top badge templates");
    expect(body).toContain("Top org units");
    expect(body).toContain("Where to look next");
    expect(body).toContain("Focus areas");
    expect(body).toContain("Open in Explore");
    expect(body).toContain("Explore");
    expect(body).toContain("Reports");
    expect(body).toContain("Public badge views");
    expect(body).toContain("35.7");
    expect(body).toContain('href="/tenants/tenant_123/admin/reporting"');
    expect(body).toContain('href="/tenants/tenant_123/admin/reporting/explore');
    expect(body).toContain('href="/tenants/tenant_123/admin/reporting/trends');
    expect(body).toContain('href="/tenants/tenant_123/admin/reporting/reports');
    expect(body).not.toContain('href="/tenants/tenant_123/admin/reporting/saved');
    expect(body).not.toContain('href="/tenants/tenant_123/admin/reporting/custom');
    expect(body).not.toContain('href="/tenants/tenant_123/admin/reporting/exports');
    expect(body).toContain("14");
    expect(body.indexOf('data-reporting-summary-metric="issued"')).toBeLessThan(
      body.indexOf("Where to look next"),
    );
    expect(body).not.toContain("Reporting Overview");
    expect(body).not.toContain("Engagement Counts");
    expect(body).not.toContain("Trend lines");
    expect(body).not.toContain("Metric Definitions");
    expect(body).not.toContain("<h2>Export CSV</h2>");
    expect(body).not.toContain("Phase 11 Scope");
    expect(body).not.toContain("Manual Issue Badge");
    expect(body).not.toContain('id="issued-badges-filter-form"');
    expect(mockedGetTenantReportingOverviewDb).toHaveBeenCalledWith(fakeDb, {
      tenantId: "tenant_123",
      issuedFrom: "2026-03-01",
      issuedTo: "2026-03-31",
      badgeTemplateId: undefined,
      orgUnitId: undefined,
      state: undefined,
    });
    expect(mockedGetTenantReportingEngagementCountsDb).toHaveBeenCalledWith(fakeDb, {
      tenantId: "tenant_123",
      from: "2026-03-01",
      to: "2026-03-31",
      badgeTemplateId: undefined,
      orgUnitId: undefined,
    });
    expect(mockedGetTenantReportingTrendsDb).toHaveBeenCalledWith(fakeDb, {
      tenantId: "tenant_123",
      from: "2026-03-01",
      to: "2026-03-31",
      badgeTemplateId: undefined,
      orgUnitId: undefined,
      bucket: "day",
    });
    expect(mockedGetTenantReportingComparisonsDb).toHaveBeenNthCalledWith(1, fakeDb, {
      tenantId: "tenant_123",
      from: "2026-03-01",
      to: "2026-03-31",
      badgeTemplateId: undefined,
      orgUnitId: undefined,
      groupBy: "badgeTemplate",
    });
    expect(mockedGetTenantReportingComparisonsDb).toHaveBeenNthCalledWith(2, fakeDb, {
      tenantId: "tenant_123",
      from: "2026-03-01",
      to: "2026-03-31",
      badgeTemplateId: undefined,
      orgUnitId: undefined,
      groupBy: "orgUnit",
    });
  });

  it("keeps the current view and generated-at context visible at the top of reporting", async () => {
    const env = createEnv();
    mockedGetTenantReportingOverviewDb.mockImplementationOnce(async (_db, input) => {
      return {
        tenantId: "tenant_123",
        filters: {
          issuedFrom: input.issuedFrom ?? null,
          issuedTo: input.issuedTo ?? null,
          badgeTemplateId: input.badgeTemplateId ?? null,
          orgUnitId: input.orgUnitId ?? null,
          state: input.state ?? null,
        },
        counts: {
          issued: 14,
          active: 12,
          suspended: 1,
          revoked: 1,
          pendingReview: 1,
        },
        generatedAt: "2026-03-21T12:00:00.000Z",
      };
    });

    const response = await app.request(
      "/tenants/tenant_123/admin/reporting?issuedFrom=2026-03-01&issuedTo=2026-03-31&badgeTemplateId=badge_template_001&orgUnitId=tenant_123%3Aorg%3Adepartment-cs&state=active",
      {
        headers: {
          Cookie: "better-auth.session_token=session-token",
        },
      },
      env,
    );
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(body).toContain('class="ct-admin__reporting-summary-context"');
    expect(body).toContain("Current view");
    expect(body).toContain("Mar 1");
    expect(body).toContain("Mar 31");
    expect(body).toContain("TypeScript Foundations");
    expect(body).toContain("Computer Science");
    expect(body).toContain("active");
    expect(body).toContain("Generated Mar 21, 2026, 12:00 PM");
  });

  it("applies smart last-90-day and scoped-root defaults when reporting query params are absent", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-05-10T12:00:00.000Z"));

    try {
      const env = createEnv();
      mockedFindTenantMembership.mockResolvedValue(sampleMembership("issuer"));
      mockedListTenantMembershipOrgUnitScopes.mockResolvedValue([
        {
          tenantId: "tenant_123",
          userId: "usr_admin",
          orgUnitId: "tenant_123:org:college-eng",
          role: "issuer",
          createdByUserId: "usr_admin",
          createdAt: "2026-02-18T12:00:00.000Z",
          updatedAt: "2026-02-18T12:30:00.000Z",
        },
      ]);
      mockedGetTenantReportingOverviewDb.mockImplementationOnce(async (_db, input) => {
        return {
          tenantId: "tenant_123",
          filters: {
            issuedFrom: input.issuedFrom ?? null,
            issuedTo: input.issuedTo ?? null,
            badgeTemplateId: input.badgeTemplateId ?? null,
            orgUnitId: input.orgUnitId ?? null,
            state: input.state ?? null,
          },
          counts: {
            issued: 14,
            active: 12,
            suspended: 1,
            revoked: 1,
            pendingReview: 1,
          },
          generatedAt: "2026-03-21T12:00:00.000Z",
        };
      });

      const response = await app.request(
        "/tenants/tenant_123/admin/reporting",
        {
          headers: {
            Cookie: "better-auth.session_token=session-token",
          },
        },
        env,
      );
      const body = await response.text();

      expect(response.status).toBe(200);
      expect(body).toContain("Feb 10 to May 10");
      expect(body).toContain("College of Engineering");
      expect(mockedGetTenantReportingOverviewDb).toHaveBeenCalledWith(fakeDb, {
        tenantId: "tenant_123",
        issuedFrom: "2026-02-10",
        issuedTo: "2026-05-10",
        badgeTemplateId: undefined,
        orgUnitId: "tenant_123:org:college-eng",
        state: undefined,
      });
      expect(mockedGetTenantReportingEngagementCountsDb).toHaveBeenCalledWith(fakeDb, {
        tenantId: "tenant_123",
        from: "2026-02-10",
        to: "2026-05-10",
        badgeTemplateId: undefined,
        orgUnitId: "tenant_123:org:college-eng",
      });
    } finally {
      vi.useRealTimers();
    }
  });

  it("renders aggregate export links that preserve the current reporting filters", async () => {
    const env = createEnv();
    mockedGetTenantReportingOverviewDb.mockImplementationOnce(async (_db, input) => {
      return {
        tenantId: "tenant_123",
        filters: {
          issuedFrom: input.issuedFrom ?? null,
          issuedTo: input.issuedTo ?? null,
          badgeTemplateId: input.badgeTemplateId ?? null,
          orgUnitId: input.orgUnitId ?? null,
          state: input.state ?? null,
        },
        counts: {
          issued: 14,
          active: 12,
          suspended: 1,
          revoked: 1,
          pendingReview: 1,
        },
        generatedAt: "2026-03-21T12:00:00.000Z",
      };
    });

    const response = await app.request(
      "/tenants/tenant_123/admin/reporting/reports?issuedFrom=2026-03-01&issuedTo=2026-03-31&badgeTemplateId=badge_template_001&orgUnitId=tenant_123%3Aorg%3Adepartment-cs&state=active",
      {
        headers: {
          Cookie: "better-auth.session_token=session-token",
        },
      },
      env,
    );
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(body).toContain("Report Library");
    expect(body).toContain("Saved reports");
    expect(body).toContain("Custom reports");
    expect(body).toContain("Export filters");
    expect(body).toContain('method="get" action="/tenants/tenant_123/admin/reporting/reports"');
    expect(body).toContain("Export CSV");
    expect(body).not.toContain("Executive Summary");
    expect(body).toContain(
      'href="/v1/tenants/tenant_123/reporting/overview/export.csv?issuedFrom=2026-03-01&amp;issuedTo=2026-03-31&amp;badgeTemplateId=badge_template_001&amp;orgUnitId=tenant_123%3Aorg%3Adepartment-cs&amp;state=active"',
    );
    expect(body).toContain(
      'href="/v1/tenants/tenant_123/reporting/engagement/export.csv?issuedFrom=2026-03-01&amp;issuedTo=2026-03-31&amp;badgeTemplateId=badge_template_001&amp;orgUnitId=tenant_123%3Aorg%3Adepartment-cs&amp;state=active"',
    );
    expect(body).toContain(
      'href="/v1/tenants/tenant_123/reporting/trends/export.csv?issuedFrom=2026-03-01&amp;issuedTo=2026-03-31&amp;badgeTemplateId=badge_template_001&amp;orgUnitId=tenant_123%3Aorg%3Adepartment-cs&amp;state=active&amp;bucket=day"',
    );
    expect(body).toContain(
      'href="/v1/tenants/tenant_123/reporting/comparisons/export.csv?issuedFrom=2026-03-01&amp;issuedTo=2026-03-31&amp;badgeTemplateId=badge_template_001&amp;orgUnitId=tenant_123%3Aorg%3Adepartment-cs&amp;state=active&amp;groupBy=badgeTemplate"',
    );
    expect(body).toContain(
      'href="/v1/tenants/tenant_123/reporting/comparisons/export.csv?issuedFrom=2026-03-01&amp;issuedTo=2026-03-31&amp;badgeTemplateId=badge_template_001&amp;orgUnitId=tenant_123%3Aorg%3Adepartment-cs&amp;state=active&amp;groupBy=orgUnit"',
    );
    expect(body).not.toContain('href="/v1/tenants/tenant_123/assertions/ledger-export.csv"');
  });

  it("renders one reports screen and keeps legacy reporting utility routes compatible", async () => {
    const env = createEnv();

    const reportsResponse = await app.request(
      "/tenants/tenant_123/admin/reporting/reports?issuedFrom=2026-03-01&issuedTo=2026-03-31",
      {
        headers: {
          Cookie: "better-auth.session_token=session-token",
        },
      },
      env,
    );
    const reportsBody = await reportsResponse.text();
    const savedResponse = await app.request(
      "/tenants/tenant_123/admin/reporting/saved?issuedFrom=2026-03-01&issuedTo=2026-03-31",
      {
        headers: {
          Cookie: "better-auth.session_token=session-token",
        },
      },
      env,
    );
    const savedBody = await savedResponse.text();
    const customResponse = await app.request(
      "/tenants/tenant_123/admin/reporting/custom?issuedFrom=2026-03-01&issuedTo=2026-03-31",
      {
        headers: {
          Cookie: "better-auth.session_token=session-token",
        },
      },
      env,
    );
    const customBody = await customResponse.text();
    const exportsResponse = await app.request(
      "/tenants/tenant_123/admin/reporting/exports?issuedFrom=2026-03-01&issuedTo=2026-03-31",
      {
        headers: {
          Cookie: "better-auth.session_token=session-token",
        },
      },
      env,
    );
    const exportsBody = await exportsResponse.text();

    expect(reportsResponse.status).toBe(200);
    expect(reportsBody).toContain("Report Library");
    expect(reportsBody).toContain('id="reporting-reports-saved"');
    expect(reportsBody).toContain('id="reporting-reports-custom"');
    expect(reportsBody).toContain('id="reporting-reports-exports"');
    expect(savedResponse.status).toBe(200);
    expect(savedBody).toContain("Report Library");
    expect(savedBody).toContain("Saved report shortcuts will live here.");
    expect(savedBody).toContain("Custom report setup will live here.");
    expect(savedBody).toContain("Export CSV");
    expect(savedBody).toContain("Planned");
    expect(savedBody).toContain('href="/tenants/tenant_123/admin/reporting/explore');
    expect(savedBody).not.toContain("Reporting Overview");
    expect(customResponse.status).toBe(200);
    expect(customBody).toContain("Report Library");
    expect(customBody).toContain("Custom report setup will live here.");
    expect(customBody).toContain("Planned");
    expect(customBody).toContain('href="/tenants/tenant_123/admin/reporting/reports');
    expect(customBody).not.toContain("Reporting Overview");
    expect(exportsResponse.status).toBe(200);
    expect(exportsBody).toContain("Report Library");
    expect(exportsBody).toContain("Export CSV");
    expect(exportsBody).toMatch(/class="[^"]*ct-admin__actions[^"]*ct-action-group/);
    expect(exportsBody).toContain("Overview CSV");
    expect(exportsBody).toMatch(/class="[^"]*ct-admin__button[^"]*ct-action--secondary/);
    expect(exportsBody).not.toContain("Reporting Overview");
  });

  it("keeps the reporting home distilled with ranked charts behind disclosure", async () => {
    const env = createEnv();

    const response = await app.request(
      "/tenants/tenant_123/admin/reporting?issuedFrom=2026-03-01&issuedTo=2026-03-31",
      {
        headers: {
          Cookie: "better-auth.session_token=session-token",
        },
      },
      env,
    );
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(body).toContain('class="ct-admin__reporting-presentation-shell');
    expect(body).toContain("ct-admin__reporting-presentation-shell--highlights");
    expect(body).not.toContain('class="ct-admin__reporting-presentation-note');
    expect(body).not.toContain('class="ct-admin__reporting-summary-feature"');
    expect(body).not.toContain("ct-admin__reporting-journey-panel");
    expect(body).not.toContain("Smart defaults active.");
    expect(body).toContain("At a glance");
    expect(body).toContain(
      '<details class="ct-admin__reporting-inline-disclosure ct-admin__reporting-inline-disclosure--ranked">',
    );
    expect(body).toContain('class="ct-admin__reporting-primary-story');
    expect(body).toContain('class="ct-admin__reporting-first-screen');
    expect(body).toContain('class="ct-admin__reporting-highlight-grid');
    expect(body).toContain('class="ct-admin__reporting-deep-links');
    expect(body).toContain('class="ct-admin__reporting-deep-link');
    expect(body).toContain("Top badge templates");
    expect(body).toContain("Top org units");
    expect(body).toContain("Where to look next");
    expect(body).not.toContain("Scoped drilldowns");
    expect(body).not.toContain("Open a visible reporting path");
    expect(body.indexOf('class="ct-admin__reporting-first-screen')).toBeLessThan(
      body.indexOf("Where to look next"),
    );
    expect(body).not.toContain("demo mode");
    expect(body).not.toContain("presentation-only");
  });

  it("renders shared reporting visuals without losing filter and export affordances", async () => {
    const env = createEnv();

    const response = await app.request(
      "/tenants/tenant_123/admin/reporting/explore?issuedFrom=2026-03-01&issuedTo=2026-03-31",
      {
        headers: {
          Cookie: "better-auth.session_token=session-token",
        },
      },
      env,
    );
    const body = await response.text();
    const trendPanel = getReportingPanelArticleMarkup(body, "Trend lines");

    expect(response.status).toBe(200);
    expect(body).toContain('class="ct-reporting-visual"');
    expect(body).toContain('data-reporting-visual-kind="comparison-bars"');
    expect(body).toContain('data-reporting-visual-kind="trend-series"');
    expect(body).toContain('class="ct-reporting-visual__legend"');
    expect(body).toContain("Legend");
    expect(body).toContain('class="ct-admin__reporting-slice-strip"');
    expect(body).toContain('data-reporting-slice-metric="issued"');
    expect(body).toContain('class="ct-admin__reporting-state-summary"');
    expect(body).toContain("Current badge state mix");
    expect(body).toContain("Public badge views");
    expect(body).toContain("Claim rate");
    expect(body).toContain('id="reporting-filters-form"');
    expect(body).toContain('method="get" action="/tenants/tenant_123/admin/reporting/explore"');
    expect(body).toContain('href="/tenants/tenant_123/admin/reporting/reports');
    expect(body).not.toContain("Overview CSV");
    expect(trendPanel).toContain('data-reporting-visual-kind="trend-series"');
    expect(trendPanel).toContain('data-reporting-visual-density="compact"');
    expect(trendPanel).toContain('class="ct-reporting-visual__chart-key"');
    expect(trendPanel).toContain("Issued badges");
    expect(trendPanel).toContain('class="ct-reporting-visual__axis ct-reporting-visual__axis--x');
    expect(trendPanel).toContain("Need exact daily counts?");
    expect(trendPanel).toContain("Open trend detail");
    expect(trendPanel).not.toContain('class="ct-reporting-visual__trend-axis"');
    expect(trendPanel).not.toContain('class="ct-reporting-visual__trend-callouts"');
    expect(trendPanel).not.toContain('class="ct-reporting-visual__legend"');
    expect(trendPanel).not.toContain("The table below preserves every visible count");
    expect(body).not.toContain('data-reporting-visual-kind="stacked-summary"');
    expect(body).not.toContain("Executive Summary");
  });

  it("ships a mid-width reporting breakpoint for walkthrough layouts", () => {
    expect(INSTITUTION_ADMIN_CSS).toContain("@media (max-width: 900px)");
    expect(INSTITUTION_ADMIN_CSS).toContain(
      ".ct-admin__reporting-presentation-shell,\n  .ct-admin__reporting-secondary-story {\n    gap: 0.9rem;",
    );
    expect(INSTITUTION_ADMIN_CSS).toContain(
      ".ct-admin__reporting-supporting-grid,\n  .ct-admin__reporting-highlight-grid,\n  .ct-admin__reporting-panel-media,\n  .ct-admin__reporting-focus-summary-grid {\n    grid-template-columns: minmax(0, 1fr);",
    );
    expect(INSTITUTION_ADMIN_CSS).toContain(".ct-admin__reporting-summary-metrics");
    expect(INSTITUTION_ADMIN_CSS).toContain(".ct-admin__reporting-deep-link");
    expect(INSTITUTION_ADMIN_CSS).toContain(
      ".ct-admin__reporting-presentation-note {\n    gap: 0.6rem;",
    );
    expect(INSTITUTION_ADMIN_CSS).toContain(".ct-admin__reporting-advanced-drilldowns");
  });

  it("moves trend detail out of the reporting home and keeps a compact route link", async () => {
    const env = createEnv();

    const response = await app.request(
      "/tenants/tenant_123/admin/reporting?issuedFrom=2026-03-01&issuedTo=2026-03-31",
      {
        headers: {
          Cookie: "better-auth.session_token=session-token",
        },
      },
      env,
    );
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(body).toContain("At a glance");
    expect(body).not.toContain("90-day issuance momentum");
    expect(body).not.toContain('data-reporting-visual-kind="trend-area"');
    expect(body).toContain("Trend detail");
    expect(body).not.toContain("Chart-first read");
    expect(body).not.toContain("Read issued badge momentum first");
    expect(body).not.toContain("Peak day");
    expect(body).not.toContain("Latest day");
    expect(body).toContain('href="/tenants/tenant_123/admin/reporting/trends');
    expect(body).not.toContain('class="ct-admin__reporting-trend-hero"');
    expect(body).not.toContain("Open trend detail for exact engagement counts.");
    expect(body).not.toContain("Detailed trend table");
    expect(body).toContain("Public badge views");
    expect(body).not.toContain("wallet accepts");
    expect(body).toContain('href="/tenants/tenant_123/admin/reporting/reports');
    expect(body).not.toContain("<h2>Export CSV</h2>");
  });

  it("renders the detailed trend table on the trend detail sub-page", async () => {
    const env = createEnv();

    const response = await app.request(
      "/tenants/tenant_123/admin/reporting/trends?issuedFrom=2026-03-01&issuedTo=2026-03-31",
      {
        headers: {
          Cookie: "better-auth.session_token=session-token",
        },
      },
      env,
    );
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(body).toContain("Trend Detail");
    expect(body).toContain(
      '<details id="reporting-trend-filters-panel" class="ct-admin__panel ct-admin__add-disclosure">',
    );
    expect(body).not.toContain('<details id="reporting-trend-filters-panel" open');
    expect(body).toContain("Filter trend data");
    expect(body).toContain("Show filters");
    expect(body).not.toContain("<h2>Trend filters</h2>");
    expect(body).toContain('method="get" action="/tenants/tenant_123/admin/reporting/trends"');
    expect(body).toContain("Trend lines");
    expect(body).toContain(
      "Daily issued badge counts for the selected filters, with exact engagement counts in the table below.",
    );
    expect(body).toContain("The table below lists the exact engagement counts for each day.");
    expect(body).toContain("Detailed trend table");
    expect(body).not.toContain("Executive Summary");
    expect(body).not.toContain("Selected reporting view");
    expect(body).not.toContain("Back to overview");
    expect(body).not.toContain("Export CSV");
    expect(body).toContain('href="/tenants/tenant_123/admin/reporting"');
  });

  it("renders deliberate empty shells for trend, comparison, hierarchy, and performer panels", async () => {
    const env = createEnv();
    mockedGetTenantReportingOverviewDb.mockResolvedValueOnce({
      tenantId: "tenant_123",
      filters: {
        issuedFrom: null,
        issuedTo: null,
        badgeTemplateId: null,
        orgUnitId: null,
        state: null,
      },
      counts: {
        issued: 0,
        active: 0,
        suspended: 0,
        revoked: 0,
        pendingReview: 0,
      },
      generatedAt: "2026-03-21T12:00:00.000Z",
    });
    mockedGetTenantReportingEngagementCountsDb.mockResolvedValueOnce({
      issuedCount: 0,
      publicBadgeViewCount: 0,
      verificationViewCount: 0,
      shareClickCount: 0,
      learnerClaimCount: 0,
      walletAcceptCount: 0,
      claimRate: 0,
      shareRate: 0,
    });
    mockedGetTenantReportingTrendsDb.mockResolvedValueOnce({
      tenantId: "tenant_123",
      filters: {
        from: "2026-03-01",
        to: "2026-03-31",
        badgeTemplateId: null,
        orgUnitId: null,
        state: null,
      },
      bucket: "day",
      series: [],
      generatedAt: "2026-03-21T12:00:00.000Z",
    });
    mockedGetTenantReportingComparisonsDb.mockResolvedValueOnce([]);
    mockedGetTenantReportingComparisonsDb.mockResolvedValueOnce([]);

    const response = await app.request(
      "/tenants/tenant_123/admin/reporting/explore?issuedFrom=2026-03-01&issuedTo=2026-03-31",
      {
        headers: {
          Cookie: "better-auth.session_token=session-token",
        },
      },
      env,
    );
    const body = await response.text();
    const trendPanel = getReportingPanelArticleMarkup(body, "Trend lines");
    const templatePanel = getReportingPanelArticleMarkup(body, "Compare by badge template");
    const orgUnitPanel = getReportingPanelArticleMarkup(body, "Compare by org unit");
    const hierarchyPanel = getReportingPanelArticleMarkup(body, "Hierarchy drilldown");
    const performerPanel = getReportingPanelArticleMarkup(body, "Performer panels");

    expect(response.status).toBe(200);
    expect(trendPanel).toContain('data-reporting-state="empty"');
    expect(trendPanel).toContain("The selected filters do not have enough activity to chart yet.");
    expect(templatePanel).toContain('data-reporting-state="empty"');
    expect(templatePanel).toContain("No badge-template rows are visible for this view yet.");
    expect(orgUnitPanel).toContain('data-reporting-state="empty"');
    expect(orgUnitPanel).toContain("No org-unit rows are visible for this view yet.");
    expect(hierarchyPanel).toContain('data-reporting-state="empty"');
    expect(hierarchyPanel).toContain(
      "Hierarchy drilldowns appear here once visible org-unit rows exist for this view.",
    );
    expect(performerPanel).toContain('data-reporting-state="empty"');
    expect(performerPanel).toContain(
      "Performer rankings appear once this view includes comparable hierarchy rows.",
    );
  });

  it("marks limited reporting views as sparse and drops momentum or ranking language", async () => {
    const env = createEnv();
    mockedGetTenantReportingOverviewDb.mockResolvedValueOnce({
      tenantId: "tenant_123",
      filters: {
        issuedFrom: null,
        issuedTo: null,
        badgeTemplateId: null,
        orgUnitId: null,
        state: null,
      },
      counts: {
        issued: 5,
        active: 5,
        suspended: 0,
        revoked: 0,
        pendingReview: 0,
      },
      generatedAt: "2026-03-21T12:00:00.000Z",
    });
    mockedGetTenantReportingEngagementCountsDb.mockResolvedValueOnce({
      issuedCount: 5,
      publicBadgeViewCount: 14,
      verificationViewCount: 5,
      shareClickCount: 2,
      learnerClaimCount: 2,
      walletAcceptCount: 1,
      claimRate: 40,
      shareRate: 20,
    });
    mockedGetTenantReportingTrendsDb.mockResolvedValueOnce({
      tenantId: "tenant_123",
      filters: {
        from: "2026-03-01",
        to: "2026-03-31",
        badgeTemplateId: null,
        orgUnitId: null,
        state: null,
      },
      bucket: "day",
      series: [
        {
          bucketStart: "2026-03-01",
          issuedCount: 5,
          publicBadgeViewCount: 14,
          verificationViewCount: 5,
          shareClickCount: 2,
          learnerClaimCount: 2,
          walletAcceptCount: 1,
        },
      ],
      generatedAt: "2026-03-21T12:00:00.000Z",
    });
    mockedGetTenantReportingComparisonsDb.mockImplementationOnce(async () => {
      return [
        {
          groupBy: "badgeTemplate",
          groupId: "badge_template_001",
          issuedCount: 5,
          publicBadgeViewCount: 14,
          verificationViewCount: 5,
          shareClickCount: 2,
          learnerClaimCount: 2,
          walletAcceptCount: 1,
          claimRate: 40,
          shareRate: 20,
        },
      ];
    });
    mockedGetTenantReportingComparisonsDb.mockImplementationOnce(async () => {
      return [
        {
          groupBy: "orgUnit",
          groupId: "tenant_123:org:program-cs",
          issuedCount: 5,
          publicBadgeViewCount: 14,
          verificationViewCount: 5,
          shareClickCount: 2,
          learnerClaimCount: 2,
          walletAcceptCount: 1,
          claimRate: 40,
          shareRate: 20,
        },
      ];
    });

    const response = await app.request(
      "/tenants/tenant_123/admin/reporting/explore?issuedFrom=2026-03-01&issuedTo=2026-03-31",
      {
        headers: {
          Cookie: "better-auth.session_token=session-token",
        },
      },
      env,
    );
    const body = await response.text();
    const trendPanel = getReportingPanelArticleMarkup(body, "Trend lines");
    const templatePanel = getReportingPanelArticleMarkup(body, "Compare by badge template");
    const orgUnitPanel = getReportingPanelArticleMarkup(body, "Compare by org unit");
    const hierarchyPanel = getReportingPanelArticleMarkup(body, "Hierarchy drilldown");
    const performerPanel = getReportingPanelArticleMarkup(body, "Performer panels");

    expect(response.status).toBe(200);
    expect(trendPanel).toContain('data-reporting-state="sparse"');
    expect(trendPanel).toContain("Only one day matches the selected filters.");
    expect(trendPanel).toContain("Open trend detail to review the exact counts for that day.");
    expect(trendPanel).not.toContain("momentum read");
    expect(trendPanel).not.toContain("Read issued badge momentum first");
    expect(templatePanel).toContain('data-reporting-state="sparse"');
    expect(templatePanel).toContain(
      "One badge template matches these filters. Open the exact row only when you need every event column.",
    );
    expect(templatePanel).toContain("Exact badge-template row");
    expect(templatePanel).toContain("Show all event columns");
    expect(templatePanel).not.toContain("Start with the ranked visual");
    expect(orgUnitPanel).toContain('data-reporting-state="sparse"');
    expect(orgUnitPanel).toContain(
      "One org unit matches these filters. Open the exact row only when you need every event column.",
    );
    expect(orgUnitPanel).toContain("Exact org-unit row");
    expect(orgUnitPanel).toContain("Show all event columns");
    expect(orgUnitPanel).not.toContain("Start with the ranked visual");
    expect(hierarchyPanel).toContain('data-reporting-state="sparse"');
    expect(hierarchyPanel).toContain("Your filters currently show one visible reporting path.");
    expect(performerPanel).toContain('data-reporting-state="sparse"');
    expect(performerPanel).toContain(
      "Rankings stay paused until this view has more than one comparable hierarchy row.",
    );
  });

  it("renders an SSR-honest pending hook on the reporting filter form", async () => {
    const env = createEnv();

    const response = await app.request(
      "/tenants/tenant_123/admin/reporting/explore",
      {
        headers: {
          Cookie: "better-auth.session_token=session-token",
        },
      },
      env,
    );
    const body = await response.text();
    const overviewPanel = getReportingPanelArticleMarkup(body, "Reporting Overview");

    expect(response.status).toBe(200);
    expect(overviewPanel).toContain('id="reporting-filters-form"');
    expect(overviewPanel).toContain('data-reporting-submit-state="idle"');
    expect(overviewPanel).toContain('id="reporting-filters-status"');
    expect(overviewPanel).toContain("data-reporting-submit-status");
    expect(overviewPanel).toContain(
      "Applying filters refreshes this page with your current selection.",
    );
    expect(INSTITUTION_ADMIN_JS).toContain("reporting-filters-form");
    expect(INSTITUTION_ADMIN_JS).toContain(
      "reportingFiltersForm.dataset.reportingSubmitState = 'pending'",
    );
    expect(INSTITUTION_ADMIN_JS).toContain("Refreshing this page with your current filters...");
    expect(overviewPanel).not.toContain("Loading dashboard");
  });

  it("renders reporting chart markup directly in the server response", async () => {
    const env = createEnv();

    const response = await app.request(
      "/tenants/tenant_123/admin/reporting/explore",
      {
        headers: {
          Cookie: "better-auth.session_token=session-token",
        },
      },
      env,
    );
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(body).toContain('<svg class="ct-reporting-visual__graphic"');
    expect(body).toContain('role="img"');
    expect(body).toContain("Visible labels and numeric values are listed in the legend below.");
    expect(body).toContain('class="ct-admin__reporting-state-meter"');
    expect(body).toContain("Current badge state mix");
    expect(body).toContain("12 active; 3 need attention.");
  });

  it("can verify a seeded-demo reporting view on the normal reporting route from the canonical fixture", async () => {
    const env = createEnv();
    const seededDemo = getSeededDemoReportingRouteFixture();

    mockedListTenantOrgUnits.mockResolvedValueOnce([...seededDemo.orgUnits]);
    mockedListBadgeTemplates.mockResolvedValueOnce([...seededDemo.badgeTemplates]);
    mockedGetTenantReportingOverviewDb.mockResolvedValueOnce(seededDemo.overview);
    mockedGetTenantReportingEngagementCountsDb.mockResolvedValueOnce(seededDemo.engagementCounts);
    mockedGetTenantReportingTrendsDb.mockResolvedValueOnce(seededDemo.trends);
    mockedGetTenantReportingComparisonsDb.mockImplementationOnce(async (_db, input) => {
      expect(input.groupBy).toBe("badgeTemplate");
      return [...seededDemo.templateComparisons];
    });
    mockedGetTenantReportingComparisonsDb.mockImplementationOnce(async (_db, input) => {
      expect(input.groupBy).toBe("orgUnit");
      return [...seededDemo.orgUnitComparisons];
    });

    const response = await app.request(
      seededDemo.routePath,
      {
        headers: {
          Cookie: "better-auth.session_token=session-token",
        },
      },
      env,
    );
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(body).toContain('href="/tenants/tenant_123/admin/reporting"');
    expect(body).toContain("TypeScript Foundations");
    expect(body).toContain("Applied Analytics");
    expect(body).toContain("Design Systems");
    expect(body).toContain("Computer Science");
    expect(body).toContain("Mathematics");
    expect(body).toContain("History");
    expect(body).toContain('data-reporting-visual-kind="comparison-ranked"');
  });

  it("renders Explore comparison panels as direct exact tables", async () => {
    const env = createEnv();
    mockedListBadgeTemplates.mockResolvedValue([
      {
        id: "badge_template_alpha",
        tenantId: "tenant_123",
        slug: "applied-analytics",
        title: "Applied Analytics",
        description: "Awarded for applied analytics coursework.",
        criteriaUri: "https://example.edu/criteria/applied-analytics",
        imageUri: "https://example.edu/badges/applied-analytics.png",
        createdByUserId: "usr_admin",
        ownerOrgUnitId: "tenant_123:org:institution",
        governanceMetadataJson: null,
        isArchived: false,
        createdAt: "2026-02-18T12:00:00.000Z",
        updatedAt: "2026-02-18T12:00:00.000Z",
      },
      {
        id: "badge_template_beta",
        tenantId: "tenant_123",
        slug: "biotech-lab",
        title: "Biotech Lab",
        description: "Awarded for biotech lab completion.",
        criteriaUri: "https://example.edu/criteria/biotech-lab",
        imageUri: "https://example.edu/badges/biotech-lab.png",
        createdByUserId: "usr_admin",
        ownerOrgUnitId: "tenant_123:org:institution",
        governanceMetadataJson: null,
        isArchived: false,
        createdAt: "2026-02-18T12:00:00.000Z",
        updatedAt: "2026-02-18T12:00:00.000Z",
      },
      {
        id: "badge_template_gamma",
        tenantId: "tenant_123",
        slug: "civic-history",
        title: "Civic History",
        description: "Awarded for civic history work.",
        criteriaUri: "https://example.edu/criteria/civic-history",
        imageUri: "https://example.edu/badges/civic-history.png",
        createdByUserId: "usr_admin",
        ownerOrgUnitId: "tenant_123:org:institution",
        governanceMetadataJson: null,
        isArchived: false,
        createdAt: "2026-02-18T12:00:00.000Z",
        updatedAt: "2026-02-18T12:00:00.000Z",
      },
      {
        id: "badge_template_delta",
        tenantId: "tenant_123",
        slug: "digital-design",
        title: "Digital Design",
        description: "Awarded for digital design work.",
        criteriaUri: "https://example.edu/criteria/digital-design",
        imageUri: "https://example.edu/badges/digital-design.png",
        createdByUserId: "usr_admin",
        ownerOrgUnitId: "tenant_123:org:institution",
        governanceMetadataJson: null,
        isArchived: false,
        createdAt: "2026-02-18T12:00:00.000Z",
        updatedAt: "2026-02-18T12:00:00.000Z",
      },
      {
        id: "badge_template_epsilon",
        tenantId: "tenant_123",
        slug: "ethics-capstone",
        title: "Ethics Capstone",
        description: "Awarded for ethics capstone completion.",
        criteriaUri: "https://example.edu/criteria/ethics-capstone",
        imageUri: "https://example.edu/badges/ethics-capstone.png",
        createdByUserId: "usr_admin",
        ownerOrgUnitId: "tenant_123:org:institution",
        governanceMetadataJson: null,
        isArchived: false,
        createdAt: "2026-02-18T12:00:00.000Z",
        updatedAt: "2026-02-18T12:00:00.000Z",
      },
      {
        id: "badge_template_zeta",
        tenantId: "tenant_123",
        slug: "zoology-fieldwork",
        title: "Zoology Fieldwork",
        description: "Awarded for zoology fieldwork.",
        criteriaUri: "https://example.edu/criteria/zoology-fieldwork",
        imageUri: "https://example.edu/badges/zoology-fieldwork.png",
        createdByUserId: "usr_admin",
        ownerOrgUnitId: "tenant_123:org:institution",
        governanceMetadataJson: null,
        isArchived: false,
        createdAt: "2026-02-18T12:00:00.000Z",
        updatedAt: "2026-02-18T12:00:00.000Z",
      },
    ]);
    mockedGetTenantReportingComparisonsDb.mockImplementation(
      async (_db, input: { groupBy: "badgeTemplate" | "orgUnit" }) => {
        if (input.groupBy === "badgeTemplate") {
          return [
            {
              groupBy: "badgeTemplate",
              groupId: "badge_template_beta",
              issuedCount: 19,
              publicBadgeViewCount: 40,
              verificationViewCount: 14,
              shareClickCount: 6,
              learnerClaimCount: 8,
              walletAcceptCount: 4,
              claimRate: 42.1,
              shareRate: 31.6,
            },
            {
              groupBy: "badgeTemplate",
              groupId: "badge_template_alpha",
              issuedCount: 24,
              publicBadgeViewCount: 51,
              verificationViewCount: 18,
              shareClickCount: 8,
              learnerClaimCount: 11,
              walletAcceptCount: 6,
              claimRate: 45.8,
              shareRate: 33.3,
            },
            {
              groupBy: "badgeTemplate",
              groupId: "badge_template_zeta",
              issuedCount: 5,
              publicBadgeViewCount: 11,
              verificationViewCount: 4,
              shareClickCount: 1,
              learnerClaimCount: 1,
              walletAcceptCount: 0,
              claimRate: 20,
              shareRate: 10,
            },
            {
              groupBy: "badgeTemplate",
              groupId: "badge_template_epsilon",
              issuedCount: 12,
              publicBadgeViewCount: 25,
              verificationViewCount: 10,
              shareClickCount: 4,
              learnerClaimCount: 5,
              walletAcceptCount: 2,
              claimRate: 41.7,
              shareRate: 33.3,
            },
            {
              groupBy: "badgeTemplate",
              groupId: "badge_template_delta",
              issuedCount: 9,
              publicBadgeViewCount: 18,
              verificationViewCount: 7,
              shareClickCount: 2,
              learnerClaimCount: 3,
              walletAcceptCount: 1,
              claimRate: 33.3,
              shareRate: 22.2,
            },
            {
              groupBy: "badgeTemplate",
              groupId: "badge_template_gamma",
              issuedCount: 24,
              publicBadgeViewCount: 47,
              verificationViewCount: 15,
              shareClickCount: 7,
              learnerClaimCount: 10,
              walletAcceptCount: 5,
              claimRate: 41.7,
              shareRate: 29.2,
            },
          ];
        }

        return [
          {
            groupBy: "orgUnit",
            groupId: "tenant_123:org:department-cs",
            issuedCount: 14,
            publicBadgeViewCount: 30,
            verificationViewCount: 11,
            shareClickCount: 5,
            learnerClaimCount: 6,
            walletAcceptCount: 3,
            claimRate: 42.9,
            shareRate: 35.7,
          },
          {
            groupBy: "orgUnit",
            groupId: "tenant_123:org:college-arts",
            issuedCount: 17,
            publicBadgeViewCount: 39,
            verificationViewCount: 13,
            shareClickCount: 6,
            learnerClaimCount: 7,
            walletAcceptCount: 4,
            claimRate: 41.2,
            shareRate: 35.3,
          },
          {
            groupBy: "orgUnit",
            groupId: "tenant_123:org:department-history",
            issuedCount: 11,
            publicBadgeViewCount: 22,
            verificationViewCount: 8,
            shareClickCount: 3,
            learnerClaimCount: 4,
            walletAcceptCount: 1,
            claimRate: 36.4,
            shareRate: 27.3,
          },
          {
            groupBy: "orgUnit",
            groupId: "tenant_123:org:program-design",
            issuedCount: 4,
            publicBadgeViewCount: 10,
            verificationViewCount: 3,
            shareClickCount: 1,
            learnerClaimCount: 1,
            walletAcceptCount: 0,
            claimRate: 25,
            shareRate: 25,
          },
          {
            groupBy: "orgUnit",
            groupId: "tenant_123:org:college-eng",
            issuedCount: 17,
            publicBadgeViewCount: 42,
            verificationViewCount: 15,
            shareClickCount: 7,
            learnerClaimCount: 8,
            walletAcceptCount: 4,
            claimRate: 47.1,
            shareRate: 41.2,
          },
          {
            groupBy: "orgUnit",
            groupId: "tenant_123:org:department-math",
            issuedCount: 8,
            publicBadgeViewCount: 16,
            verificationViewCount: 6,
            shareClickCount: 2,
            learnerClaimCount: 2,
            walletAcceptCount: 1,
            claimRate: 25,
            shareRate: 25,
          },
        ];
      },
    );

    const response = await app.request(
      "/tenants/tenant_123/admin/reporting/explore?issuedFrom=2026-03-01&issuedTo=2026-03-31",
      {
        headers: {
          Cookie: "better-auth.session_token=session-token",
        },
      },
      env,
    );
    const body = await response.text();
    const templatePanel = getReportingPanelMarkup(body, "Compare by badge template");
    const orgUnitPanel = getReportingPanelMarkup(body, "Compare by org unit");

    expect(response.status).toBe(200);
    expect(templatePanel).not.toContain('data-reporting-visual-kind="comparison-ranked"');
    expect(orgUnitPanel).not.toContain('data-reporting-visual-kind="comparison-ranked"');
    expect(templatePanel).not.toContain("Issued ranking by badge template");
    expect(orgUnitPanel).not.toContain("Issued ranking by org unit");
    expect(templatePanel).toContain(
      "Exact badge-template rows for the current filters. Use Highlights for the ranked visual summary.",
    );
    expect(orgUnitPanel).toContain(
      "Exact org-unit rows for the current filters. Advanced hierarchy drilldowns stay collapsed below until needed.",
    );
    expect(templatePanel).not.toContain("Top 5 shown here.");
    expect(orgUnitPanel).not.toContain("Top 5 shown here.");
    expect(templatePanel).toContain("51");
    expect(orgUnitPanel).toContain("42");
    expect(templatePanel).toContain("Applied Analytics");
    expect(templatePanel).toContain("Civic History");
    expect(templatePanel).toContain("Zoology Fieldwork");
    expect(orgUnitPanel).toContain("College of Arts");
    expect(orgUnitPanel).toContain("College of Engineering");
    expect(orgUnitPanel).toContain("Design Foundations");
  });

  it("renders hierarchy drilldown sections with breadcrumb context and reporting-local drill links", async () => {
    const env = createEnv();
    mockedGetTenantReportingOverviewDb.mockImplementationOnce(async (_db, input) => {
      return {
        tenantId: "tenant_123",
        filters: {
          issuedFrom: input.issuedFrom ?? null,
          issuedTo: input.issuedTo ?? null,
          badgeTemplateId: input.badgeTemplateId ?? null,
          orgUnitId: input.orgUnitId ?? null,
          state: input.state ?? null,
        },
        counts: {
          issued: 14,
          active: 12,
          suspended: 1,
          revoked: 1,
          pendingReview: 1,
        },
        generatedAt: "2026-03-21T12:00:00.000Z",
      };
    });

    const response = await app.request(
      "/tenants/tenant_123/admin/reporting/explore?issuedFrom=2026-03-01&issuedTo=2026-03-31",
      {
        headers: {
          Cookie: "better-auth.session_token=session-token",
        },
      },
      env,
    );
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(body).toContain("Hierarchy drilldown");
    expect(body).toContain('id="reporting-advanced-drilldowns"');
    expect(body).toContain("Advanced hierarchy drilldowns");
    expect(body).toContain(
      "Open org-unit drilldowns and performer rankings when you need structural detail.",
    );
    expect(body).toContain("Visible roots stay inside the reporting workspace.");
    expect(body).toContain("Institution");
    expect(body).toContain("College of Engineering");
    expect(body).toContain("Computer Science");
    expect(body).toContain("Computer Science Program");
    expect(body).toContain("Breadcrumb");
    expect(body).toContain('aria-label="Reporting hierarchy breadcrumb"');
    expect(body).toContain('class="ct-admin__reporting-breadcrumb-list"');
    expect(body).toContain(
      'href="/tenants/tenant_123/admin/reporting/explore#reporting-hierarchy-focus-tenant_123%3Aorg%3Ainstitution"',
    );
    expect(body).toContain('aria-current="page">College of Engineering</span>');
    expect(body).toContain('aria-current="page">Computer Science</span>');
    expect(body).toContain("ct-admin__reporting-focus-summary");
    expect(body).toContain("Current focus");
    expect(body).toContain("Current hierarchy level");
    expect(body).toContain("Next child level");
    expect(body).toContain("Reporting workspace");
    expect(body).toContain("Keeps this drilldown inside reporting");
    expect(body).toContain("data-reporting-root-link");
    expect(body).toContain(
      'data-reporting-focus-target="reporting-hierarchy-focus-tenant_123%3Aorg%3Acollege-eng"',
    );
    expect(body).toContain(
      'data-reporting-focus-root="reporting-hierarchy-focus-tenant_123%3Aorg%3Ainstitution"',
    );
    expect(body).not.toContain("Institution / College of Engineering");
    expect(body).toContain(
      'href="/tenants/tenant_123/admin/reporting/explore#reporting-hierarchy-focus-tenant_123%3Aorg%3Acollege-eng"',
    );
    expect(body).toContain(
      'href="/tenants/tenant_123/admin/reporting/explore#reporting-hierarchy-focus-tenant_123%3Aorg%3Adepartment-cs"',
    );
    expect(body).toContain(
      'href="/v1/tenants/tenant_123/reporting/hierarchy/export.csv?issuedFrom=2026-03-01&amp;issuedTo=2026-03-31&amp;focusOrgUnitId=tenant_123%3Aorg%3Acollege-eng&amp;level=department"',
    );
    expect(body).not.toContain(
      'href="/tenants/tenant_123/admin/access/org-units" data-reporting-drill-link',
    );
  });

  it("renders honest performer panels with separate volume and rate rankings", async () => {
    const env = createEnv();

    const response = await app.request(
      "/tenants/tenant_123/admin/reporting/explore",
      {
        headers: {
          Cookie: "better-auth.session_token=session-token",
        },
      },
      env,
    );
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(body).toContain("Performer panels");
    expect(body).toContain('class="ct-admin__reporting-performer-groups"');
    expect(body).toContain("Volume rankings");
    expect(body).toContain("Rate rankings");
    expect(body).toContain("Compare level: department rows in the current visible hierarchy.");
    expect(body).toContain(
      "Rate rankings require at least 5 issued badges so issued totals stay visible beside every rate callout.",
    );
    expect(body).toContain("Highest issuance volume");
    expect(body).toContain("Lowest issuance volume");
    expect(body).toContain("Highest claim rate");
    expect(body).toContain("Lowest share rate");
    expect(body).toContain("Comparing department rows by claim rate.");
    expect(body).toContain("Issued totals stay visible beside each ranked rate row.");
    expect(body).toContain("Computer Science");
    expect(body).toContain("History");
    expect(body).not.toContain(
      'Design Foundations</strong><div class="ct-admin__meta">Below the minimum sample',
    );
    expect(body).toContain('class="ct-admin__reporting-lower-story"');
    expect(body.indexOf("Compare by badge template")).toBeLessThan(
      body.indexOf("Compare by org unit"),
    );
    expect(body.indexOf("Compare by org unit")).toBeLessThan(
      body.indexOf("Advanced hierarchy drilldowns"),
    );
    expect(body.indexOf("Advanced hierarchy drilldowns")).toBeLessThan(
      body.indexOf("Hierarchy drilldown"),
    );
    expect(body.indexOf("Hierarchy drilldown")).toBeLessThan(body.indexOf("Performer panels"));
  });
});

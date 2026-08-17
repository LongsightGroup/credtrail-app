import type { HtmlEscapedString } from "hono/utils/html";
import { buildReportingPageQueryEntries } from "../../reporting/reporting-page-filters";
import { AdminActions, AdminButtonLink, AdminPanel, AdminStatusPill } from "../components";
import type { InstitutionAdminPageInput } from "./page-types";
import {
  renderInstitutionAdminReportingFiltersForm,
  reportingFilterValuesFromPage,
} from "./reporting-filter-form";
import { buildPathWithQuery } from "./reporting-helpers";
import { createReportingRenderHelpers } from "./reporting-render-helpers";
import { renderInstitutionAdminReportingTrendSections } from "./reporting-trend-sections";

type HonoElement = HtmlEscapedString | Promise<HtmlEscapedString>;

interface FocusedReportingViewInput {
  readonly page: InstitutionAdminPageInput;
  readonly reportingExplorePath: string;
}

interface RenderReportingTrendsViewInput extends FocusedReportingViewInput {
  readonly reportingTrendsPath: string;
}

interface RenderReportingReportsViewInput extends FocusedReportingViewInput {
  readonly reportingPath: string;
  readonly reportingReportsPath: string;
}

const reportingQueryEntries = (page: InstitutionAdminPageInput) => {
  const filters = reportingFilterValuesFromPage(page);
  return buildReportingPageQueryEntries({
    issuedFrom: filters.issuedFrom,
    issuedTo: filters.issuedTo,
    badgeTemplateId: filters.badgeTemplateId,
    orgUnitId: filters.orgUnitId,
    state: filters.state ?? undefined,
  });
};

/** Renders the trend-detail reporting page without constructing unrelated report sections. */
export const renderInstitutionAdminReportingTrendsView = (
  input: RenderReportingTrendsViewInput,
): HonoElement => {
  const templateById = new Map(
    input.page.badgeTemplates.map((template) => [template.id, template]),
  );
  const orgUnitById = new Map(input.page.orgUnits.map((orgUnit) => [orgUnit.id, orgUnit]));
  const helpers = createReportingRenderHelpers({
    templateById,
    orgUnitById,
    reportingExplorePath: input.reportingExplorePath,
    renderOrgUnitSummary: (orgUnitId) => {
      const orgUnit = orgUnitById.get(orgUnitId);
      return orgUnit === undefined ? (
        <strong>{orgUnitId}</strong>
      ) : (
        <strong>{orgUnit.displayName}</strong>
      );
    },
  });
  const reportingTrendSeries = input.page.reportingTrends?.series ?? [];
  const reportingTrendState = helpers.classifyReportingPanelState(
    reportingTrendSeries.filter((row) => helpers.hasReportingActivity(row)).length,
  );
  const reportingTrendsHref = buildPathWithQuery(
    input.reportingTrendsPath,
    reportingQueryEntries(input.page),
  );
  const { renderReportingTrendPanelMarkup } = renderInstitutionAdminReportingTrendSections({
    reportingTrendSeries,
    reportingTrendState,
    reportingTrendsHref,
    helpers,
  });

  return (
    <>
      <details id="reporting-trend-filters-panel" class="ct-admin__panel ct-admin__add-disclosure">
        <summary class="ct-admin__add-disclosure-summary">
          <span>
            <strong>Filter trend data</strong>
            <small>
              Change date, badge, org unit, or state only when you need a narrower view.
            </small>
          </span>
        </summary>
        {renderInstitutionAdminReportingFiltersForm({
          page: input.page,
          actionPath: input.reportingTrendsPath,
          formClass: "ct-admin__form ct-admin__add-disclosure-form ct-grid",
        })}
      </details>
      {renderReportingTrendPanelMarkup({ includeDetailedTable: true })}
    </>
  );
};

/** Renders the reports and exports page without loading reporting metric datasets. */
export const renderInstitutionAdminReportingReportsView = (
  input: RenderReportingReportsViewInput,
): HonoElement => {
  const queryEntries = reportingQueryEntries(input.page);
  const aggregateExportEntries = [...queryEntries] as const;
  const reportingExploreHref = buildPathWithQuery(input.reportingExplorePath, queryEntries);
  const reportingReportsHref = buildPathWithQuery(input.reportingReportsPath, queryEntries);
  const reportingReportsExportsHref = `${reportingReportsHref}#reporting-reports-exports`;
  const exportHref = (
    resource: string,
    extra: readonly (readonly [string, string])[] = [],
  ): string => {
    return buildPathWithQuery(
      `/v1/tenants/${encodeURIComponent(input.page.tenant.id)}/reporting/${resource}`,
      [...aggregateExportEntries, ...extra],
    );
  };

  return (
    <>
      <section class="ct-admin__reporting-highlight-grid">
        <AdminPanel id="reporting-reports-saved" className="ct-admin__reporting-placeholder-panel">
          <div class="ct-cluster">
            <div class="ct-stack">
              <p class="ct-admin__eyebrow">Saved reports</p>
              <h2>Saved report shortcuts will live here.</h2>
            </div>
            <AdminStatusPill>Planned</AdminStatusPill>
          </div>
          <p>
            Reserved for named reports that preserve filters, audience, and export intent. For now,
            use Highlights for the default read and Explore for the exact table workspace.
          </p>
          <AdminActions>
            <AdminButtonLink href={input.reportingPath} variant="secondary">
              Open Highlights
            </AdminButtonLink>
            <AdminButtonLink href={reportingExploreHref} variant="quiet">
              Open Explore
            </AdminButtonLink>
          </AdminActions>
        </AdminPanel>
        <AdminPanel id="reporting-reports-custom" className="ct-admin__reporting-placeholder-panel">
          <div class="ct-cluster">
            <div class="ct-stack">
              <p class="ct-admin__eyebrow">Custom reports</p>
              <h2>Custom report setup will live here.</h2>
            </div>
            <AdminStatusPill>Planned</AdminStatusPill>
          </div>
          <p>
            Custom report builders and reusable export profiles are planned. Current filters still
            travel through Explore, Trends, and Reports.
          </p>
          <AdminActions>
            <AdminButtonLink href={reportingExploreHref} variant="secondary">
              Build from Explore
            </AdminButtonLink>
            <AdminButtonLink href={reportingReportsExportsHref} variant="quiet">
              Export current view
            </AdminButtonLink>
          </AdminActions>
        </AdminPanel>
      </section>
      <AdminPanel id="reporting-export-filters-panel">
        <div class="ct-cluster">
          <h2>Export filters</h2>
        </div>
        <p>Choose filters before downloading CSV files.</p>
        {renderInstitutionAdminReportingFiltersForm({
          page: input.page,
          actionPath: input.reportingReportsPath,
        })}
      </AdminPanel>
      <article id="reporting-reports-exports" class="ct-admin__panel ct-stack">
        <div class="ct-cluster">
          <h2>Export CSV</h2>
          <span class="ct-admin__status-pill">Supporting operations</span>
        </div>
        <p>
          Download CSV files for the selected filters. These links preserve issue date, badge,
          organization, and lifecycle state selections.
        </p>
        <AdminActions>
          <AdminButtonLink href={exportHref("overview/export.csv")} variant="secondary">
            Overview CSV
          </AdminButtonLink>
          <AdminButtonLink href={exportHref("engagement/export.csv")} variant="secondary">
            Engagement CSV
          </AdminButtonLink>
          <AdminButtonLink
            href={exportHref("trends/export.csv", [["bucket", "day"]])}
            variant="secondary"
          >
            Trends CSV
          </AdminButtonLink>
          <AdminButtonLink
            href={exportHref("comparisons/export.csv", [["groupBy", "badgeTemplate"]])}
            variant="secondary"
          >
            Template comparisons CSV
          </AdminButtonLink>
          <AdminButtonLink
            href={exportHref("comparisons/export.csv", [["groupBy", "orgUnit"]])}
            variant="secondary"
          >
            Org-unit comparisons CSV
          </AdminButtonLink>
        </AdminActions>
        <p class="ct-admin__hint">
          Recipient-level ledger export stays in Operations for owner/admin users and does not
          appear in the reporting workspace.
        </p>
      </article>
    </>
  );
};

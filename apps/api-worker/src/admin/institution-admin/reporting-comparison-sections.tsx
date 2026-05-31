import type { TenantReportingComparisonRowRecord } from "@credtrail/db";
import type { HtmlEscapedString } from "hono/utils/html";
import { AdminEmptyTableRow, AdminPanel, AdminTable } from "../components";
import { formatReportingCount, formatReportingRate } from "./reporting-helpers";
import { createReportingRenderHelpers } from "./reporting-render-helpers";

type HonoElement = HtmlEscapedString | Promise<HtmlEscapedString>;
type ReportingRenderHelpers = ReturnType<typeof createReportingRenderHelpers>;

interface RenderInstitutionAdminReportingComparisonSectionsInput {
  reportingTemplateComparisons: readonly TenantReportingComparisonRowRecord[];
  reportingOrgUnitComparisons: readonly TenantReportingComparisonRowRecord[];
  helpers: ReportingRenderHelpers;
}

interface InstitutionAdminReportingComparisonSections {
  reportingTemplateComparisonPanelMarkup: HonoElement;
  reportingOrgUnitComparisonPanelMarkup: HonoElement;
}

export const renderInstitutionAdminReportingComparisonSections = (
  source: RenderInstitutionAdminReportingComparisonSectionsInput,
): InstitutionAdminReportingComparisonSections => {
  const { reportingTemplateComparisons, reportingOrgUnitComparisons, helpers } = source;
  const {
    classifyReportingPanelState,
    hasReportingActivity,
    renderReportingComparisonGroupLabel,
    renderReportingCountCell,
  } = helpers;

  const renderReportingComparisonRows = (
    rows: readonly TenantReportingComparisonRowRecord[],
    emptyLabel: string,
  ): HonoElement => {
    if (rows.length === 0) {
      return <AdminEmptyTableRow colSpan={9}>{emptyLabel}</AdminEmptyTableRow>;
    }

    return (
      <>
        {rows.map((row) => (
          <tr>
            <td>{renderReportingComparisonGroupLabel(row)}</td>
            <td>
              <span class="ct-admin__reporting-table-number">
                {renderReportingCountCell(row.issuedCount)}
              </span>
            </td>
            <td>
              <span class="ct-admin__reporting-table-number">
                {renderReportingCountCell(row.publicBadgeViewCount)}
              </span>
            </td>
            <td>
              <span class="ct-admin__reporting-table-number">
                {renderReportingCountCell(row.verificationViewCount)}
              </span>
            </td>
            <td>
              <span class="ct-admin__reporting-table-number">
                {renderReportingCountCell(row.shareClickCount)}
              </span>
            </td>
            <td>
              <span class="ct-admin__reporting-table-number">
                {renderReportingCountCell(row.learnerClaimCount)}
              </span>
            </td>
            <td>
              <span class="ct-admin__reporting-table-number">
                {renderReportingCountCell(row.walletAcceptCount)}
              </span>
            </td>
            <td>{formatReportingRate(row.claimRate)}</td>
            <td>{formatReportingRate(row.shareRate)}</td>
          </tr>
        ))}
      </>
    );
  };
  const reportingTemplateComparisonRowsMarkup = renderReportingComparisonRows(
    reportingTemplateComparisons,
    "No badge-template comparisons available for the selected filters.",
  );
  const reportingTemplateComparisonState = classifyReportingPanelState(
    reportingTemplateComparisons.filter((row) => hasReportingActivity(row)).length,
  );
  const reportingOrgUnitComparisonRowsMarkup = renderReportingComparisonRows(
    reportingOrgUnitComparisons,
    "No org-unit comparisons available for the selected filters.",
  );
  const reportingOrgUnitComparisonState = classifyReportingPanelState(
    reportingOrgUnitComparisons.filter((row) => hasReportingActivity(row)).length,
  );
  const selectSparseReportingComparisonRow = (
    rows: readonly TenantReportingComparisonRowRecord[],
  ): TenantReportingComparisonRowRecord | null => {
    const activeRows = rows.filter((row) => hasReportingActivity(row));

    return activeRows.length === 1 ? (activeRows[0] ?? null) : null;
  };
  const reportingSparseTemplateComparisonRow = selectSparseReportingComparisonRow(
    reportingTemplateComparisons,
  );
  const reportingSparseOrgUnitComparisonRow = selectSparseReportingComparisonRow(
    reportingOrgUnitComparisons,
  );

  const renderReportingComparisonSummary = (
    row: TenantReportingComparisonRowRecord,
  ): HonoElement => (
    <section class="ct-admin__reporting-comparison-summary">
      <div class="ct-admin__reporting-comparison-identity">
        {renderReportingComparisonGroupLabel(row)}
      </div>
      <dl class="ct-admin__reporting-comparison-metrics">
        <div>
          <dt>Issued</dt>
          <dd>{formatReportingCount(row.issuedCount)}</dd>
        </div>
        <div>
          <dt>Public views</dt>
          <dd>{formatReportingCount(row.publicBadgeViewCount)}</dd>
        </div>
        <div>
          <dt>Claim rate</dt>
          <dd>{formatReportingRate(row.claimRate)}</dd>
        </div>
        <div>
          <dt>Share rate</dt>
          <dd>{formatReportingRate(row.shareRate)}</dd>
        </div>
      </dl>
    </section>
  );
  const reportingComparisonTableHeaders = [
    "Issued",
    "Public badge views",
    "Verification views",
    "Share clicks",
    "Claim actions",
    "Wallet accepts",
    "Claim rate",
    "Share rate",
  ];
  const renderReportingComparisonTable = (input: {
    groupHeader: string;
    rows: HonoElement;
    rowGroup: "org-comparisons" | "template-comparisons";
  }): HonoElement => (
    <AdminTable
      headers={[input.groupHeader, ...reportingComparisonTableHeaders]}
      tbodyDataAttributes={{ "data-reporting-bar-group": input.rowGroup }}
    >
      {input.rows}
    </AdminTable>
  );

  const reportingTemplateComparisonPanelMarkup = (
    <AdminPanel
      variant="table"
      dataAttributes={{ "data-reporting-state": reportingTemplateComparisonState }}
    >
      <h2>Compare by badge template</h2>
      <p>
        {reportingTemplateComparisonState === "rich"
          ? "Exact badge-template rows for the current filters. Use Highlights for the ranked visual summary."
          : reportingTemplateComparisonState === "sparse"
            ? "One badge template matches these filters. Open the exact row only when you need every event column."
            : "No badge-template rows are visible for this view yet. Widen the date range or remove a filter to compare templates."}
      </p>
      {reportingSparseTemplateComparisonRow === null
        ? null
        : renderReportingComparisonSummary(reportingSparseTemplateComparisonRow)}
      {reportingTemplateComparisonState === "sparse" &&
      reportingSparseTemplateComparisonRow !== null ? (
        <details class="ct-admin__reporting-inline-disclosure">
          <summary class="ct-admin__reporting-inline-summary">
            <span>Exact badge-template row</span>
            <small>Show all event columns</small>
          </summary>
          <div class="ct-admin__reporting-inline-body">
            {renderReportingComparisonTable({
              groupHeader: "Badge template",
              rows: reportingTemplateComparisonRowsMarkup,
              rowGroup: "template-comparisons",
            })}
          </div>
        </details>
      ) : (
        renderReportingComparisonTable({
          groupHeader: "Badge template",
          rows: reportingTemplateComparisonRowsMarkup,
          rowGroup: "template-comparisons",
        })
      )}
    </AdminPanel>
  );

  const reportingOrgUnitComparisonPanelMarkup = (
    <AdminPanel
      variant="table"
      dataAttributes={{ "data-reporting-state": reportingOrgUnitComparisonState }}
    >
      <h2>Compare by org unit</h2>
      <p>
        {reportingOrgUnitComparisonState === "rich"
          ? "Exact org-unit rows for the current filters. Advanced hierarchy drilldowns stay collapsed below until needed."
          : reportingOrgUnitComparisonState === "sparse"
            ? "One org unit matches these filters. Open the exact row only when you need every event column."
            : "No org-unit rows are visible for this view yet. Widen the date range or remove a filter to compare org units."}
      </p>
      {reportingSparseOrgUnitComparisonRow === null
        ? null
        : renderReportingComparisonSummary(reportingSparseOrgUnitComparisonRow)}
      {reportingOrgUnitComparisonState === "sparse" &&
      reportingSparseOrgUnitComparisonRow !== null ? (
        <details class="ct-admin__reporting-inline-disclosure">
          <summary class="ct-admin__reporting-inline-summary">
            <span>Exact org-unit row</span>
            <small>Show all event columns</small>
          </summary>
          <div class="ct-admin__reporting-inline-body">
            {renderReportingComparisonTable({
              groupHeader: "Org unit",
              rows: reportingOrgUnitComparisonRowsMarkup,
              rowGroup: "org-comparisons",
            })}
          </div>
        </details>
      ) : (
        renderReportingComparisonTable({
          groupHeader: "Org unit",
          rows: reportingOrgUnitComparisonRowsMarkup,
          rowGroup: "org-comparisons",
        })
      )}
    </AdminPanel>
  );

  return {
    reportingTemplateComparisonPanelMarkup,
    reportingOrgUnitComparisonPanelMarkup,
  };
};

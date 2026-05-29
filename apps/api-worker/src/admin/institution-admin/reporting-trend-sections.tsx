import type { TenantReportingTrendBucketRecord } from "@credtrail/db";
import type { HtmlEscapedString } from "hono/utils/html";
import { AdminEmptyTableRow, AdminPanel, AdminTable } from "../components";
import {
  formatReportingCount,
  formatReportingDateLabel,
  type ReportingPanelState,
} from "./reporting-helpers";
import { createReportingRenderHelpers } from "./reporting-render-helpers";

type HonoElement = HtmlEscapedString | Promise<HtmlEscapedString>;
type ReportingRenderHelpers = ReturnType<typeof createReportingRenderHelpers>;

interface RenderInstitutionAdminReportingTrendSectionsInput {
  reportingTrendSeries: readonly TenantReportingTrendBucketRecord[];
  reportingTrendState: ReportingPanelState;
  reportingTrendsHref: string;
  helpers: ReportingRenderHelpers;
}

interface InstitutionAdminReportingTrendSections {
  renderReportingTrendPanelMarkup: (input: { includeDetailedTable: boolean }) => HonoElement;
}

export const renderInstitutionAdminReportingTrendSections = (
  source: RenderInstitutionAdminReportingTrendSectionsInput,
): InstitutionAdminReportingTrendSections => {
  const { reportingTrendSeries, reportingTrendState, reportingTrendsHref, helpers } = source;
  const {
    renderReportingCountCell,
    renderReportingStateShell,
    renderReportingTrendCallout,
    renderReportingVisualModule,
  } = helpers;

  const renderReportingTrendVisualMarkup = (includeDetailedContext: boolean): HonoElement => {
    if (reportingTrendSeries.length === 0) {
      return <></>;
    }

    return renderReportingVisualModule({
      kind: "trend-series",
      title: "Issued over time",
      description: includeDetailedContext
        ? "Tracks issued badge volume over the selected dates. The table below keeps the exact daily engagement counts."
        : "Tracks issued badge volume over the selected dates.",
      density: includeDetailedContext ? "regular" : "compact",
      showLegend: false,
      showTrendContext: includeDetailedContext,
      series: reportingTrendSeries.map((row) => ({
        label: formatReportingDateLabel(row.bucketStart),
        value: row.issuedCount,
        detail: `${formatReportingCount(row.publicBadgeViewCount)} public views · ${formatReportingCount(row.shareClickCount)} shares`,
      })),
      ...(includeDetailedContext
        ? {
            note: "The table below preserves every visible count so the chart remains a summary, not a second interpretation layer.",
          }
        : {}),
    });
  };
  const reportingTrendRowsMarkup =
    reportingTrendSeries.length === 0 ? (
      <AdminEmptyTableRow colSpan={7}>
        No trend data available for the selected filters.
      </AdminEmptyTableRow>
    ) : (
      reportingTrendSeries.map((row) => (
        <tr>
          <td>
            <strong>{formatReportingDateLabel(row.bucketStart)}</strong>
          </td>
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
        </tr>
      ))
    );
  const getReportingTrendIntroCopy = (includeDetailedTable: boolean): string => {
    if (reportingTrendState === "rich") {
      return includeDetailedTable
        ? "Daily issued badge counts for the selected filters, with exact engagement counts in the table below."
        : "Daily issued badge counts for the selected filters. Open trend detail for exact engagement counts.";
    }

    if (reportingTrendState === "sparse") {
      return "The selected filters return one day of trend data.";
    }

    return "No trend data is available for the selected filters yet.";
  };
  const renderReportingTrendHeroMarkup = (includeDetailedTable: boolean): HonoElement =>
    reportingTrendState === "empty"
      ? renderReportingStateShell({
          state: "empty",
          eyebrow: "No trend line yet",
          title: "The selected filters do not have enough activity to chart yet.",
          description:
            "Expand the date range or remove a filter to see how issuance changes over time.",
        })
      : reportingTrendState === "sparse"
        ? renderReportingStateShell({
            state: "sparse",
            eyebrow: "Limited trend data",
            title: "Only one day matches the selected filters.",
            description: includeDetailedTable
              ? "Use the table below for the exact counts for that day."
              : "Open trend detail to review the exact counts for that day.",
          })
        : (() => {
            const startRow = reportingTrendSeries[0];

            if (startRow === undefined) {
              return (
                <div class="ct-admin__empty">No trend data available for the selected filters.</div>
              );
            }

            const latestRow = reportingTrendSeries[reportingTrendSeries.length - 1] ?? startRow;
            const peakRow = reportingTrendSeries.reduce((highestRow, row) => {
              return row.issuedCount > highestRow.issuedCount ? row : highestRow;
            }, startRow);

            return (
              <div class="ct-admin__reporting-trend-hero">
                <div class="ct-admin__reporting-trend-intro ct-stack">
                  <p class="ct-admin__eyebrow">Issued badges</p>
                  <h3>Issuance over time</h3>
                  <p>
                    Use the chart to compare daily issued badge counts for the selected filters.{" "}
                    {includeDetailedTable
                      ? "The table below lists the exact engagement counts for each day."
                      : "Open trend detail for the exact engagement counts behind each day."}
                  </p>
                  <div class="ct-admin__reporting-trend-callouts">
                    {renderReportingTrendCallout({
                      kind: "peak",
                      label: "Peak day",
                      row: peakRow,
                    })}
                    {renderReportingTrendCallout({
                      kind: "latest",
                      label: "Latest day",
                      row: latestRow,
                    })}
                  </div>
                </div>
                {renderReportingTrendVisualMarkup(true)}
              </div>
            );
          })();

  const renderReportingTrendPanelMarkup = (input: {
    includeDetailedTable: boolean;
  }): HonoElement => (
    <AdminPanel variant="table" dataAttributes={{ "data-reporting-state": reportingTrendState }}>
      <h2>Trend lines</h2>
      <p>{getReportingTrendIntroCopy(input.includeDetailedTable)}</p>
      {input.includeDetailedTable || reportingTrendState !== "rich"
        ? renderReportingTrendHeroMarkup(input.includeDetailedTable)
        : renderReportingTrendVisualMarkup(false)}
      {input.includeDetailedTable ? (
        <div>
          <h3>Detailed trend table</h3>
          <AdminTable
            headers={[
              "Day",
              "Issued",
              "Public badge views",
              "Verification views",
              "Share clicks",
              "Claim actions",
              "Wallet accepts",
            ]}
            tbodyDataAttributes={{ "data-reporting-bar-group": "trends" }}
          >
            {reportingTrendRowsMarkup}
          </AdminTable>
        </div>
      ) : (
        <p class="ct-admin__hint">
          Need exact daily counts? <a href={reportingTrendsHref}>Open trend detail</a>.
        </p>
      )}
    </AdminPanel>
  );

  return { renderReportingTrendPanelMarkup };
};

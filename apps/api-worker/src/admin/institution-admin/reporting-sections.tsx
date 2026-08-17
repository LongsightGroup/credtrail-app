import type { TenantReportingComparisonRowRecord } from "@credtrail/db";
import type { HtmlEscapedString } from "hono/utils/html";
import { selectReportingHighlightRows } from "../../reporting/reporting-highlights";
import {
  buildReportingHierarchyQueryEntries,
  buildReportingPageQueryEntries,
} from "../../reporting/reporting-page-filters";
import { formatIsoTimestamp } from "../../utils/display-format";
import {
  AdminActions,
  AdminButtonLink,
  AdminEmptyTableRow,
  AdminPanel,
  AdminStatusPill,
  AdminTable,
} from "../components";
import type { InstitutionAdminPageInput } from "./page-types";
import {
  renderInstitutionAdminReportingFiltersForm,
  reportingFilterValuesFromPage,
} from "./reporting-filter-form";
import {
  REPORTING_RATE_MIN_ISSUED,
  buildPathWithQuery,
  formatReportingCount,
  formatReportingDateLabel,
  formatReportingRate,
  formatReportingStateLabel,
  type ReportingHierarchyLevel,
} from "./reporting-helpers";
import { renderInstitutionAdminReportingComparisonSections } from "./reporting-comparison-sections";
import { renderInstitutionAdminReportingHierarchySections } from "./reporting-hierarchy-sections";
import { createReportingRenderHelpers } from "./reporting-render-helpers";
import { renderInstitutionAdminReportingTrendSections } from "./reporting-trend-sections";

type HonoElement = HtmlEscapedString | Promise<HtmlEscapedString>;

interface RenderInstitutionAdminReportingSectionsInput {
  input: InstitutionAdminPageInput;
  reportingExplorePath: string;
  reportingTrendsPath: string;
  reportingReportsPath: string;
}

interface InstitutionAdminReportingSections {
  reportingExecutiveSummaryMarkup: HonoElement;
  reportingFocusAreaPanelMarkup: HonoElement;
  reportingRankedChartsMarkup: HonoElement;
  reportingDeepLinksMarkup: HonoElement;
  reportingExploreSliceSummaryMarkup: HonoElement;
  reportingOverviewPanelMarkup: HonoElement;
  renderReportingTrendPanelMarkup: (input: { includeDetailedTable: boolean }) => HonoElement;
  reportingEngagementPanelMarkup: HonoElement;
  reportingLowerStoryMarkup: HonoElement;
  reportingDefinitionsPanelMarkup: HonoElement;
  reportingDeferredPanelMarkup: HonoElement | null;
}

export const renderInstitutionAdminReportingSections = (
  source: RenderInstitutionAdminReportingSectionsInput,
): InstitutionAdminReportingSections => {
  const { input, reportingExplorePath, reportingTrendsPath, reportingReportsPath } = source;
  const templateById = new Map(input.badgeTemplates.map((template) => [template.id, template]));
  const orgUnitById = new Map(input.orgUnits.map((orgUnit) => [orgUnit.id, orgUnit]));
  const reportingEngagementCounts = input.reportingEngagementCounts ?? null;
  const reportingOverview = input.reportingOverview ?? null;
  const reportingMetrics = input.reportingMetrics ?? [];
  const reportingOrgUnitComparisons = input.reportingOrgUnitComparisons ?? [];
  const reportingTemplateComparisons = input.reportingTemplateComparisons ?? [];
  const reportingTrends = input.reportingTrends ?? null;
  const renderOrgUnitSummary = (orgUnitId: string): HonoElement => {
    const orgUnit = orgUnitById.get(orgUnitId);

    if (orgUnit === undefined) {
      return <strong>{orgUnitId}</strong>;
    }

    return (
      <>
        <strong>{orgUnit.displayName}</strong>
        <div class="ct-admin__meta">{`${orgUnit.id} · ${orgUnit.unitType}`}</div>
      </>
    );
  };
  const reportingRenderHelpers = createReportingRenderHelpers({
    templateById,
    orgUnitById,
    reportingExplorePath,
    renderOrgUnitSummary,
  });
  const {
    buildReportingComparisonSeries,
    classifyReportingPanelState,
    getReportingComparisonLabel,
    getReportingOrgUnitLabel,
    hasReportingActivity,
    renderReportingStateShell,
    renderReportingVisualModule,
  } = reportingRenderHelpers;

  const reportingFilters = reportingFilterValuesFromPage(input);
  const reportingState = reportingFilters.state;
  const reportingIssuedFromValue = reportingFilters.issuedFrom;
  const reportingIssuedToValue = reportingFilters.issuedTo;
  const reportingBadgeTemplateIdValue = reportingFilters.badgeTemplateId;
  const reportingOrgUnitIdValue = reportingFilters.orgUnitId;
  const reportingPageQueryEntries = buildReportingPageQueryEntries({
    issuedFrom: reportingIssuedFromValue,
    issuedTo: reportingIssuedToValue,
    badgeTemplateId: reportingBadgeTemplateIdValue,
    orgUnitId: reportingOrgUnitIdValue,
    state: reportingState ?? undefined,
  });
  const reportingAggregateExportEntries = [...reportingPageQueryEntries] as const;
  const reportingExploreHref = buildPathWithQuery(reportingExplorePath, reportingPageQueryEntries);
  const reportingTrendsHref = buildPathWithQuery(reportingTrendsPath, reportingPageQueryEntries);
  const reportingReportsHref = buildPathWithQuery(reportingReportsPath, reportingPageQueryEntries);
  const reportingReportsExportsHref = `${reportingReportsHref}#reporting-reports-exports`;
  const reportingTemplateComparisonExportHref = buildPathWithQuery(
    `/v1/tenants/${encodeURIComponent(input.tenant.id)}/reporting/comparisons/export.csv`,
    [...reportingAggregateExportEntries, ["groupBy", "badgeTemplate"]] as const,
  );
  const reportingOrgUnitComparisonExportHref = buildPathWithQuery(
    `/v1/tenants/${encodeURIComponent(input.tenant.id)}/reporting/comparisons/export.csv`,
    [...reportingAggregateExportEntries, ["groupBy", "orgUnit"]] as const,
  );
  const buildReportingHierarchyExportHref = (focus: {
    focusOrgUnitId: string;
    level: ReportingHierarchyLevel;
  }): string => {
    return buildPathWithQuery(
      `/v1/tenants/${encodeURIComponent(input.tenant.id)}/reporting/hierarchy/export.csv`,
      buildReportingHierarchyQueryEntries({
        issuedFrom: reportingIssuedFromValue,
        issuedTo: reportingIssuedToValue,
        badgeTemplateId: reportingBadgeTemplateIdValue,
        orgUnitId: reportingOrgUnitIdValue,
        state: reportingState ?? undefined,
        focusOrgUnitId: focus.focusOrgUnitId,
        level: focus.level,
      }),
    );
  };
  const reportingGeneratedAtLabel =
    reportingOverview === null
      ? "Generated just now"
      : `Generated ${formatIsoTimestamp(reportingOverview.generatedAt)}`;
  const reportingTrendSeries = reportingTrends?.series ?? [];
  const reportingTrendActivityRowCount = reportingTrendSeries.filter((row) =>
    hasReportingActivity(row),
  ).length;
  const reportingTrendState = classifyReportingPanelState(reportingTrendActivityRowCount);
  const selectTopReportingComparisonRow = (
    rows: readonly TenantReportingComparisonRowRecord[],
  ): TenantReportingComparisonRowRecord | null => {
    return (
      rows
        .filter((row) => hasReportingActivity(row))
        .sort((left, right) => {
          if (right.issuedCount !== left.issuedCount) {
            return right.issuedCount - left.issuedCount;
          }

          return getReportingComparisonLabel(left).localeCompare(
            getReportingComparisonLabel(right),
          );
        })[0] ?? null
    );
  };
  const reportingTopTemplateRow = selectTopReportingComparisonRow(reportingTemplateComparisons);
  const reportingTopOrgUnitRow = selectTopReportingComparisonRow(reportingOrgUnitComparisons);
  const buildReportingExploreHrefForComparisonRow = (
    row: TenantReportingComparisonRowRecord,
  ): string => {
    return buildPathWithQuery(
      reportingExplorePath,
      buildReportingPageQueryEntries({
        issuedFrom: reportingIssuedFromValue,
        issuedTo: reportingIssuedToValue,
        badgeTemplateId:
          row.groupBy === "badgeTemplate" ? row.groupId : reportingBadgeTemplateIdValue,
        orgUnitId: row.groupBy === "orgUnit" ? row.groupId : reportingOrgUnitIdValue,
        state: reportingState ?? undefined,
      }),
    );
  };
  const reportingClaimRateLeader =
    [...reportingTemplateComparisons, ...reportingOrgUnitComparisons]
      .filter((row) => row.issuedCount >= REPORTING_RATE_MIN_ISSUED)
      .sort((left, right) => {
        if (right.claimRate !== left.claimRate) {
          return right.claimRate - left.claimRate;
        }

        if (right.issuedCount !== left.issuedCount) {
          return right.issuedCount - left.issuedCount;
        }

        return getReportingComparisonLabel(left).localeCompare(getReportingComparisonLabel(right));
      })[0] ?? null;
  const reportingSummaryContextItems = [
    {
      label: "Issued window",
      value:
        reportingIssuedFromValue.length > 0 && reportingIssuedToValue.length > 0
          ? `${formatReportingDateLabel(reportingIssuedFromValue)} to ${formatReportingDateLabel(reportingIssuedToValue)}`
          : reportingIssuedFromValue.length > 0
            ? `From ${formatReportingDateLabel(reportingIssuedFromValue)}`
            : reportingIssuedToValue.length > 0
              ? `Through ${formatReportingDateLabel(reportingIssuedToValue)}`
              : "All issue dates",
    },
    {
      label: "Badge template",
      value:
        reportingBadgeTemplateIdValue.length > 0
          ? (templateById.get(reportingBadgeTemplateIdValue)?.title ??
            reportingBadgeTemplateIdValue)
          : "All templates",
    },
    {
      label: "Org scope",
      value:
        reportingOrgUnitIdValue.length > 0
          ? getReportingOrgUnitLabel(reportingOrgUnitIdValue)
          : "All visible org units",
    },
    {
      label: "Lifecycle state",
      value: formatReportingStateLabel(reportingState),
    },
  ] as const;
  const reportingExploreSliceMetrics = [
    {
      key: "issued",
      label: "Issued",
      value: formatReportingCount(
        reportingOverview?.counts.issued ?? reportingEngagementCounts?.issuedCount ?? 0,
      ),
    },
    {
      key: "claim-rate",
      label: "Claim rate",
      value: formatReportingRate(reportingEngagementCounts?.claimRate ?? 0),
    },
    {
      key: "share-rate",
      label: "Share rate",
      value: formatReportingRate(reportingEngagementCounts?.shareRate ?? 0),
    },
    {
      key: "public-views",
      label: "Public views",
      value: formatReportingCount(reportingEngagementCounts?.publicBadgeViewCount ?? 0),
    },
  ] as const;
  const reportingExploreSliceSummaryMarkup = (
    <section class="ct-admin__reporting-slice-strip" aria-label="Current report view">
      <div class="ct-admin__reporting-slice-main">
        <div class="ct-cluster">
          <p class="ct-admin__eyebrow">Current view</p>
          <span class="ct-admin__status-pill">{reportingGeneratedAtLabel}</span>
        </div>
        <div class="ct-admin__reporting-slice-tags">
          {reportingSummaryContextItems.map((item) => (
            <span class="ct-admin__reporting-slice-tag">
              <strong>{item.label}</strong>
              {item.value}
            </span>
          ))}
        </div>
      </div>
      <dl class="ct-admin__reporting-slice-metrics">
        {reportingExploreSliceMetrics.map((metric) => (
          <div data-reporting-slice-metric={metric.key}>
            <dt>{metric.label}</dt>
            <dd>{metric.value}</dd>
          </div>
        ))}
      </dl>
    </section>
  );
  const reportingHierarchyScopeSummary = reportingSummaryContextItems
    .map((item) => `${item.label}: ${item.value}`)
    .join(" · ");
  const reportingExecutiveSummaryMetrics = [
    {
      key: "issued",
      label: "Issued badges",
      value: formatReportingCount(
        reportingOverview?.counts.issued ?? reportingEngagementCounts?.issuedCount ?? 0,
      ),
      detail: "Current issued volume for the active filters.",
    },
    {
      key: "claim-rate",
      label: "Claim rate",
      value: formatReportingRate(reportingEngagementCounts?.claimRate ?? 0),
      detail: "Distinct claimed or accepted assertions over issued badges.",
    },
    {
      key: "share-rate",
      label: "Share rate",
      value: formatReportingRate(reportingEngagementCounts?.shareRate ?? 0),
      detail: "Distinct shared assertions over issued badges in the same view.",
    },
    {
      key: "public-badge-views",
      label: "Public badge views",
      value: formatReportingCount(reportingEngagementCounts?.publicBadgeViewCount ?? 0),
      detail: "CredTrail-owned public badge page loads for the current view.",
    },
  ] as const;
  const reportingExecutiveSummaryMarkup = (
    <article class="ct-admin__panel ct-admin__reporting-summary-band ct-stack">
      <div class="ct-admin__reporting-readout-head">
        <div class="ct-stack">
          <p class="ct-admin__eyebrow">Current view</p>
          <h2>At a glance</h2>
          <p class="ct-admin__reporting-summary-copy">
            {formatReportingCount(
              reportingOverview?.counts.issued ?? reportingEngagementCounts?.issuedCount ?? 0,
            )}{" "}
            issued badges, {formatReportingRate(reportingEngagementCounts?.claimRate ?? 0)} claim
            rate, {formatReportingRate(reportingEngagementCounts?.shareRate ?? 0)} share rate.
          </p>
        </div>
        <span class="ct-admin__status-pill">{reportingGeneratedAtLabel}</span>
      </div>
      <dl class="ct-admin__reporting-summary-metrics">
        {reportingExecutiveSummaryMetrics.map((metric) => (
          <div data-reporting-summary-metric={metric.key}>
            <dt>{metric.label}</dt>
            <dd>{metric.value}</dd>
            <span>{metric.detail}</span>
          </div>
        ))}
      </dl>
      <section class="ct-admin__reporting-summary-context" aria-label="Current view">
        <div class="ct-stack">
          <div class="ct-cluster">
            <p class="ct-admin__eyebrow">Filters</p>
          </div>
          <div class="ct-cluster">
            {reportingSummaryContextItems.map((item) => (
              <span class="ct-admin__status-pill">
                <strong>{item.label}:</strong> {item.value}
              </span>
            ))}
          </div>
        </div>
      </section>
    </article>
  );
  const reportingDeferredMetrics = reportingMetrics.filter((metric) => !metric.available);
  const reportingDeferredMetricsMarkup = reportingDeferredMetrics.map((metric) => {
    return (
      <article class="ct-admin__panel ct-admin__panel--nested ct-stack">
        <div class="ct-cluster">
          <strong>{metric.label}</strong>
          <span class="ct-admin__status-pill">Deferred</span>
        </div>
        <p>{metric.description}</p>
        <p class="ct-admin__hint">{metric.availabilityNote ?? "Not available yet."}</p>
      </article>
    );
  });
  const reportingDefinitionRows =
    reportingMetrics.length === 0 ? (
      <AdminEmptyTableRow colSpan={4}>
        No reporting metric definitions available.
      </AdminEmptyTableRow>
    ) : (
      reportingMetrics.map((metric) => {
        return (
          <tr>
            <td>
              <strong>{metric.label}</strong>
            </td>
            <td>{metric.source}</td>
            <td>{metric.available ? "Available" : "Deferred"}</td>
            <td>{metric.availabilityNote ?? metric.description}</td>
          </tr>
        );
      })
    );
  const reportingEngagementCardsMarkup =
    reportingEngagementCounts === null ? (
      <p class="ct-admin__empty">Engagement counts are not available yet.</p>
    ) : (
      [
        {
          label: "Public badge views",
          description: "Successful public badge page loads captured on CredTrail-owned routes.",
          value: reportingEngagementCounts.publicBadgeViewCount,
        },
        {
          label: "Verification views",
          description: "Successful credential verification responses served by CredTrail.",
          value: reportingEngagementCounts.verificationViewCount,
        },
        {
          label: "Share clicks",
          description: "Outbound share actions routed through CredTrail before handoff.",
          value: reportingEngagementCounts.shareClickCount,
        },
        {
          label: "Claim actions",
          description: "Explicit learner claim actions captured in the dashboard.",
          value: reportingEngagementCounts.learnerClaimCount,
        },
        {
          label: "Wallet accepts",
          description: "Successful OID4VCI credential retrievals recorded as acceptance.",
          value: reportingEngagementCounts.walletAcceptCount,
        },
      ].map((metric) => (
        <article class="ct-admin__metric-card ct-stack">
          <p class="ct-admin__eyebrow">{metric.label}</p>
          <strong class="ct-admin__metric-value">{formatReportingCount(metric.value)}</strong>
          <p class="ct-admin__hint">{metric.description}</p>
        </article>
      ))
    );
  const reportingRateCardsMarkup =
    reportingEngagementCounts === null
      ? []
      : [
          {
            label: "Claim rate",
            description:
              "Distinct claimed or accepted assertions over issued badges in the same window.",
            value: reportingEngagementCounts.claimRate,
          },
          {
            label: "Share rate",
            description: "Distinct shared assertions over issued badges, not raw repeat clicks.",
            value: reportingEngagementCounts.shareRate,
          },
        ].map((metric) => (
          <article class="ct-admin__metric-card ct-stack ct-admin__metric-card--rate">
            <p class="ct-admin__eyebrow">{metric.label}</p>
            <strong class="ct-admin__metric-value">{formatReportingRate(metric.value)}</strong>
            <p class="ct-admin__hint">{metric.description}</p>
          </article>
        ));
  const reportingRawEngagementTotal =
    reportingEngagementCounts === null
      ? 0
      : reportingEngagementCounts.publicBadgeViewCount +
        reportingEngagementCounts.verificationViewCount +
        reportingEngagementCounts.shareClickCount +
        reportingEngagementCounts.learnerClaimCount +
        reportingEngagementCounts.walletAcceptCount;
  const reportingHasRawEngagementEvents = reportingRawEngagementTotal > 0;
  const reportingEngagementVisualsMarkup =
    reportingEngagementCounts === null ? null : (
      <div class="ct-admin__reporting-visual-grid">
        {renderReportingVisualModule({
          kind: "comparison-bars",
          title: "Supported engagement signals",
          description:
            "Raw event totals for public views, verification, sharing, claims, and wallet accepts.",
          series: [
            {
              label: "Public badge views",
              value: reportingEngagementCounts.publicBadgeViewCount,
              detail: "Product-owned page-load events.",
            },
            {
              label: "Verification views",
              value: reportingEngagementCounts.verificationViewCount,
              detail: "Successful verification responses.",
            },
            {
              label: "Share clicks",
              value: reportingEngagementCounts.shareClickCount,
              detail: "CredTrail-owned outbound share actions.",
            },
            {
              label: "Claim actions",
              value: reportingEngagementCounts.learnerClaimCount,
              detail: "Explicit learner claim events.",
            },
            {
              label: "Wallet accepts",
              value: reportingEngagementCounts.walletAcceptCount,
              detail: "Successful credential retrievals.",
            },
          ] as const,
          note: "Use these event totals for export checks; rates stay distinct-assertion metrics.",
        })}
        {renderReportingVisualModule({
          kind: "comparison-bars",
          title: "Rate context",
          description:
            "Claim and share rates stay derived from distinct engaged assertions over the same issued-badge window.",
          series: [
            {
              label: "Claim rate",
              value: reportingEngagementCounts.claimRate,
              detail: `${formatReportingCount(reportingEngagementCounts.learnerClaimCount)} claim actions over ${formatReportingCount(reportingEngagementCounts.issuedCount)} issued badges.`,
            },
            {
              label: "Share rate",
              value: reportingEngagementCounts.shareRate,
              detail: `${formatReportingCount(reportingEngagementCounts.shareClickCount)} share clicks over ${formatReportingCount(reportingEngagementCounts.issuedCount)} issued badges.`,
            },
          ] as const,
          note: "Claim and share rates use distinct assertions, not repeat clicks.",
        })}
      </div>
    );
  const reportingStateMixItems =
    reportingOverview === null
      ? []
      : [
          {
            key: "active",
            label: "Active",
            value: reportingOverview.counts.active,
          },
          {
            key: "suspended",
            label: "Suspended",
            value: reportingOverview.counts.suspended,
          },
          {
            key: "revoked",
            label: "Revoked",
            value: reportingOverview.counts.revoked,
          },
          {
            key: "pending-review",
            label: "Pending review",
            value: reportingOverview.counts.pendingReview,
          },
        ];
  const reportingStateMixTotal = reportingStateMixItems.reduce(
    (total, item) => total + item.value,
    0,
  );
  const reportingActiveStateCount =
    reportingOverview === null ? 0 : reportingOverview.counts.active;
  const reportingAttentionStateCount = Math.max(
    reportingStateMixTotal - reportingActiveStateCount,
    0,
  );
  const reportingStateMixSummary =
    reportingOverview === null || reportingStateMixTotal === 0
      ? "No badges match the current filters yet."
      : reportingActiveStateCount === reportingStateMixTotal
        ? `All ${formatReportingCount(reportingStateMixTotal)} badges are active.`
        : `${formatReportingCount(reportingActiveStateCount)} active; ${formatReportingCount(
            reportingAttentionStateCount,
          )} ${reportingAttentionStateCount === 1 ? "needs" : "need"} attention.`;
  const reportingStateMixMarkup =
    reportingOverview === null ? (
      renderReportingStateShell({
        state: "empty",
        eyebrow: "Current badge state mix",
        title: "No badge state counts are available yet.",
        description: "Widen the date range or remove filters to check badge lifecycle state.",
      })
    ) : (
      <section class="ct-admin__reporting-state-summary" aria-label="Current badge state mix">
        <div class="ct-admin__reporting-state-summary-head">
          <h3>Current badge state mix</h3>
          <p>{reportingStateMixSummary}</p>
        </div>
        <div
          class="ct-admin__reporting-state-meter"
          role="img"
          aria-label={reportingStateMixItems
            .map((item) => `${item.label}: ${formatReportingCount(item.value)}`)
            .join(", ")}
        >
          {reportingStateMixItems.filter((item) => item.value > 0).length === 0 ? (
            <span class="ct-admin__reporting-state-meter-empty"></span>
          ) : (
            reportingStateMixItems
              .filter((item) => item.value > 0)
              .map((item) => {
                const width =
                  reportingStateMixTotal === 0 ? 0 : (item.value / reportingStateMixTotal) * 100;

                return (
                  <span
                    class={`ct-admin__reporting-state-segment ct-admin__reporting-state-segment--${item.key}`}
                    style={`flex-basis:${width.toFixed(2)}%`}
                    aria-label={`${item.label}: ${formatReportingCount(item.value)}`}
                  ></span>
                );
              })
          )}
        </div>
        <dl class="ct-admin__reporting-state-list">
          {reportingStateMixItems.map((item) => (
            <div
              class={`ct-admin__reporting-state-item ct-admin__reporting-state-item--${item.key}`}
            >
              <dt>{item.label}</dt>
              <dd>{formatReportingCount(item.value)}</dd>
            </div>
          ))}
        </dl>
      </section>
    );
  const reportingTemplateHighlightRows = selectReportingHighlightRows(reportingTemplateComparisons);
  const reportingOrgUnitHighlightRows = selectReportingHighlightRows(reportingOrgUnitComparisons);
  const renderReportingHighlightComparisonPanel = (input: {
    actionHref: string;
    exportHref: string;
    emptyDescription: string;
    emptyTitle: string;
    eyebrow: string;
    rows: readonly TenantReportingComparisonRowRecord[];
    title: string;
    totalRowCount: number;
    visualDescription: string;
    visualId: string;
  }): HonoElement => {
    const activeRowCount = input.rows.filter((row) => hasReportingActivity(row)).length;
    const state = classifyReportingPanelState(activeRowCount);
    const visualMarkup =
      state === "empty"
        ? renderReportingStateShell({
            state: "empty",
            eyebrow: input.eyebrow,
            title: input.emptyTitle,
            description: input.emptyDescription,
          })
        : renderReportingVisualModule({
            kind: "comparison-ranked",
            id: input.visualId,
            title: input.title,
            description: input.visualDescription,
            series: buildReportingComparisonSeries(input.rows),
            seriesOrder: "input",
            note: `Top ${formatReportingCount(input.rows.length)} of ${formatReportingCount(
              input.totalRowCount,
            )} visible rows shown. Open Explore for the complete table and hierarchy context.`,
          });

    return (
      <AdminPanel
        className="ct-admin__reporting-highlight-panel"
        dataAttributes={{ "data-reporting-state": state }}
      >
        <div class="ct-cluster">
          <div class="ct-stack">
            <p class="ct-admin__eyebrow">{input.eyebrow}</p>
            <h2>{input.title}</h2>
          </div>
          <AdminStatusPill>{state === "rich" ? "Top rows" : "Current view"}</AdminStatusPill>
        </div>
        {visualMarkup}
        <AdminActions>
          <AdminButtonLink href={input.actionHref} variant="secondary">
            Open Explore
          </AdminButtonLink>
          <AdminButtonLink href={input.exportHref} variant="quiet">
            Export CSV
          </AdminButtonLink>
        </AdminActions>
      </AdminPanel>
    );
  };
  const { reportingHierarchyPanelMarkup, reportingPerformerPanelsMarkup } =
    renderInstitutionAdminReportingHierarchySections({
      input,
      orgUnitById,
      reportingOrgUnitComparisons,
      reportingHierarchyScopeSummary,
      buildReportingHierarchyExportHref,
      renderOrgUnitSummary,
      helpers: reportingRenderHelpers,
    });
  const reportingOverviewPanelMarkup = (
    <AdminPanel id="reporting-overview-panel" className="ct-admin__reporting-overview-panel">
      <div class="ct-cluster">
        <h2>Reporting Overview</h2>
        <AdminStatusPill>Filters</AdminStatusPill>
      </div>
      {renderInstitutionAdminReportingFiltersForm({
        page: input,
        actionPath: reportingExplorePath,
      })}
      <p class="ct-admin__hint">
        Need CSV downloads for this view?{" "}
        <a href={reportingReportsExportsHref}>Open export options</a>.
      </p>
      {reportingStateMixMarkup}
      <p class="ct-admin__hint">
        Generated{" "}
        {reportingOverview === null
          ? "just now"
          : formatIsoTimestamp(reportingOverview.generatedAt)}
      </p>
    </AdminPanel>
  );

  const reportingEngagementPanelMarkup = (
    <AdminPanel className="ct-admin__reporting-engagement-panel">
      <div class="ct-cluster">
        <h2>Engagement Counts</h2>
        <AdminStatusPill>Rates first</AdminStatusPill>
      </div>
      <p>
        Claim and share rates stay visible here; raw event totals are available when you need export
        parity checks.
      </p>
      {reportingRateCardsMarkup.length === 0 ? null : (
        <div class="ct-admin__metric-grid ct-admin__metric-grid--rates">
          {reportingRateCardsMarkup}
        </div>
      )}
      {reportingEngagementCounts === null ? (
        <p class="ct-admin__empty">Engagement counts are not available yet.</p>
      ) : (
        <details class="ct-admin__reporting-inline-disclosure">
          <summary class="ct-admin__reporting-inline-summary">
            <span>Engagement event counts</span>
            <small>
              {reportingHasRawEngagementEvents
                ? `${formatReportingCount(reportingRawEngagementTotal)} raw events in this view`
                : "No raw engagement events yet for this view"}
            </small>
          </summary>
          <div class="ct-admin__reporting-inline-body">
            {reportingHasRawEngagementEvents ? (
              <>
                {reportingEngagementVisualsMarkup}
                <div class="ct-admin__metric-grid">{reportingEngagementCardsMarkup}</div>
              </>
            ) : (
              <p class="ct-admin__empty">No engagement events yet for this view.</p>
            )}
          </div>
        </details>
      )}
    </AdminPanel>
  );

  const { renderReportingTrendPanelMarkup } = renderInstitutionAdminReportingTrendSections({
    reportingTrendSeries,
    reportingTrendState,
    reportingTrendsHref,
    helpers: reportingRenderHelpers,
  });
  const { reportingTemplateComparisonPanelMarkup, reportingOrgUnitComparisonPanelMarkup } =
    renderInstitutionAdminReportingComparisonSections({
      reportingTemplateComparisons,
      reportingOrgUnitComparisons,
      helpers: reportingRenderHelpers,
    });
  const reportingDefinitionsPanelMarkup = (
    <details class="ct-admin__reporting-inline-disclosure ct-admin__reporting-inline-disclosure--definitions">
      <summary class="ct-admin__reporting-inline-summary">
        <span>Metric Definitions</span>
        <small>Show sources and rate definitions</small>
      </summary>
      <div class="ct-admin__reporting-inline-body">
        <AdminTable headers={["Metric", "Source", "Status", "Notes"]}>
          {reportingDefinitionRows}
        </AdminTable>
      </div>
    </details>
  );

  const reportingDeferredPanelMarkup =
    reportingDeferredMetricsMarkup.length === 0 ? null : (
      <section class="ct-admin__grid ct-stack">{reportingDeferredMetricsMarkup}</section>
    );
  const reportingTemplateHighlightsPanelMarkup = renderReportingHighlightComparisonPanel({
    eyebrow: "Template performance",
    title: "Top badge templates",
    visualId: "reporting-highlights-templates",
    visualDescription:
      "Top issued badge templates for the current filters, with public views plus claim and share context carried beside each row.",
    rows: reportingTemplateHighlightRows,
    totalRowCount: reportingTemplateComparisons.length,
    emptyTitle: "No template highlights are available for this view yet.",
    emptyDescription:
      "Widen the date window or remove a filter in Explore to review badge-template performance.",
    actionHref: reportingExploreHref,
    exportHref: reportingTemplateComparisonExportHref,
  });
  const reportingOrgUnitHighlightsPanelMarkup = renderReportingHighlightComparisonPanel({
    eyebrow: "Org performance",
    title: "Top org units",
    visualId: "reporting-highlights-org-units",
    visualDescription:
      "Top issued organization units for the current filters, scoped to the rows this user can see.",
    rows: reportingOrgUnitHighlightRows,
    totalRowCount: reportingOrgUnitComparisons.length,
    emptyTitle: "No org-unit highlights are available for this view yet.",
    emptyDescription:
      "Widen the date window or remove a filter in Explore to review org-unit performance.",
    actionHref: reportingExploreHref,
    exportHref: reportingOrgUnitComparisonExportHref,
  });
  const reportingRankedChartsMarkup = (
    <details class="ct-admin__reporting-inline-disclosure ct-admin__reporting-inline-disclosure--ranked">
      <summary class="ct-admin__reporting-inline-summary">
        <span>Ranked charts</span>
        <small>Top badge templates and org units for this view</small>
      </summary>
      <div class="ct-admin__reporting-inline-body">
        <section class="ct-admin__reporting-highlight-grid">
          {reportingTemplateHighlightsPanelMarkup}
          {reportingOrgUnitHighlightsPanelMarkup}
        </section>
      </div>
    </details>
  );
  const reportingLifecycleAttentionCount =
    reportingOverview === null
      ? 0
      : reportingOverview.counts.suspended +
        reportingOverview.counts.revoked +
        reportingOverview.counts.pendingReview;
  const reportingLifecycleAttentionState =
    reportingOverview === null
      ? undefined
      : reportingOverview.counts.pendingReview > 0
        ? "pending_review"
        : reportingOverview.counts.suspended > 0
          ? "suspended"
          : reportingOverview.counts.revoked > 0
            ? "revoked"
            : undefined;
  const reportingLifecycleAttentionHref = buildPathWithQuery(
    reportingExplorePath,
    buildReportingPageQueryEntries({
      issuedFrom: reportingIssuedFromValue,
      issuedTo: reportingIssuedToValue,
      badgeTemplateId: reportingBadgeTemplateIdValue,
      orgUnitId: reportingOrgUnitIdValue,
      state: reportingLifecycleAttentionState ?? reportingState ?? undefined,
    }),
  );
  const reportingFocusAreaItems: Array<{
    actionLabel: string;
    detail: string;
    eyebrow: string;
    href: string;
    metric: string;
    title: string;
  }> = [];

  if (reportingLifecycleAttentionCount > 0) {
    reportingFocusAreaItems.push({
      eyebrow: "Lifecycle attention",
      metric: formatReportingCount(reportingLifecycleAttentionCount),
      title: "Badges need review",
      detail: "Suspended, revoked, or pending-review badges are present in this view.",
      href: reportingLifecycleAttentionHref,
      actionLabel: "Review in Explore",
    });
  }

  if (reportingTopOrgUnitRow !== null) {
    reportingFocusAreaItems.push({
      eyebrow: "Org unit to notice",
      metric: `${formatReportingCount(reportingTopOrgUnitRow.issuedCount)} issued`,
      title: getReportingComparisonLabel(reportingTopOrgUnitRow),
      detail: "Highest visible org-unit volume in the current view.",
      href: buildReportingExploreHrefForComparisonRow(reportingTopOrgUnitRow),
      actionLabel: "Open in Explore",
    });
  }

  if (reportingTopTemplateRow !== null) {
    reportingFocusAreaItems.push({
      eyebrow: "Template to notice",
      metric: `${formatReportingCount(reportingTopTemplateRow.issuedCount)} issued`,
      title: getReportingComparisonLabel(reportingTopTemplateRow),
      detail: "Highest visible badge-template volume in the current view.",
      href: buildReportingExploreHrefForComparisonRow(reportingTopTemplateRow),
      actionLabel: "Open in Explore",
    });
  } else if (reportingClaimRateLeader !== null) {
    reportingFocusAreaItems.push({
      eyebrow: "Engagement to notice",
      metric: formatReportingRate(reportingClaimRateLeader.claimRate),
      title: getReportingComparisonLabel(reportingClaimRateLeader),
      detail: "Strongest claim-rate signal above the minimum sample threshold.",
      href: buildReportingExploreHrefForComparisonRow(reportingClaimRateLeader),
      actionLabel: "Open in Explore",
    });
  }
  const reportingFocusAreaState = classifyReportingPanelState(reportingFocusAreaItems.length);
  const visibleReportingFocusAreaItems = reportingFocusAreaItems.slice(0, 2);

  const reportingFocusAreaPanelMarkup = (
    <AdminPanel
      className="ct-admin__reporting-highlight-panel"
      dataAttributes={{ "data-reporting-state": reportingFocusAreaState }}
    >
      <div class="ct-cluster">
        <div class="ct-stack">
          <p class="ct-admin__eyebrow">Focus areas</p>
          <h2>Where to look next</h2>
        </div>
        <AdminStatusPill>
          {formatReportingCount(visibleReportingFocusAreaItems.length)}{" "}
          {visibleReportingFocusAreaItems.length === 1 ? "signal" : "signals"}
        </AdminStatusPill>
      </div>
      <p>Start here. Open Explore only when you need exact rows or custom filters.</p>
      {visibleReportingFocusAreaItems.length === 0 ? (
        renderReportingStateShell({
          state: "empty",
          eyebrow: "No focus areas yet",
          title: "Highlights will suggest focus areas once this view has activity.",
          description:
            "Widen the date window or remove a filter in Explore to review more reporting signals.",
        })
      ) : (
        <div class="ct-admin__reporting-focus-area-list">
          {visibleReportingFocusAreaItems.map((item) => (
            <article class="ct-admin__reporting-focus-area-item">
              <div class="ct-admin__reporting-focus-area-metric">{item.metric}</div>
              <div class="ct-admin__reporting-focus-area-copy">
                <p class="ct-admin__eyebrow">{item.eyebrow}</p>
                <h3>{item.title}</h3>
                <p class="ct-admin__hint">{item.detail}</p>
              </div>
              <AdminButtonLink href={item.href} variant="quiet">
                {item.actionLabel}
              </AdminButtonLink>
            </article>
          ))}
        </div>
      )}
      <AdminActions>
        <AdminButtonLink href={reportingExploreHref} variant="secondary">
          Open Explore
        </AdminButtonLink>
      </AdminActions>
    </AdminPanel>
  );
  const reportingDeepLinksMarkup = (
    <section class="ct-admin__reporting-deep-links" aria-label="Advanced reporting links">
      <a
        class="ct-admin__reporting-deep-link ct-admin__reporting-deep-link--primary"
        href={reportingExploreHref}
      >
        Explore
      </a>
      <a class="ct-admin__reporting-deep-link" href={reportingTrendsHref}>
        Trend detail
      </a>
      <a class="ct-admin__reporting-deep-link" href={reportingReportsHref}>
        Reports
      </a>
    </section>
  );
  const reportingAdvancedDrilldownsMarkup = (
    <details id="reporting-advanced-drilldowns" class="ct-admin__reporting-advanced-drilldowns">
      <summary class="ct-admin__reporting-advanced-summary">
        <span>Advanced hierarchy drilldowns</span>
        <small>
          Open org-unit drilldowns and performer rankings when you need structural detail.
        </small>
      </summary>
      <div class="ct-admin__reporting-advanced-body">
        {reportingHierarchyPanelMarkup}
        {reportingPerformerPanelsMarkup}
      </div>
    </details>
  );
  const reportingLowerStoryMarkup = (
    <section class="ct-admin__reporting-lower-story" aria-label="Reporting comparison tables">
      {reportingTemplateComparisonPanelMarkup}
      {reportingOrgUnitComparisonPanelMarkup}
      {reportingAdvancedDrilldownsMarkup}
    </section>
  );

  return {
    reportingExecutiveSummaryMarkup,
    reportingFocusAreaPanelMarkup,
    reportingRankedChartsMarkup,
    reportingDeepLinksMarkup,
    reportingExploreSliceSummaryMarkup,
    reportingOverviewPanelMarkup,
    renderReportingTrendPanelMarkup,
    reportingEngagementPanelMarkup,
    reportingLowerStoryMarkup,
    reportingDefinitionsPanelMarkup,
    reportingDeferredPanelMarkup,
  };
};

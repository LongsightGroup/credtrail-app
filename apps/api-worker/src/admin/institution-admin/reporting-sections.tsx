import type { TenantOrgUnitRecord, TenantReportingComparisonRowRecord } from "@credtrail/db";
import type { HtmlEscapedString } from "hono/utils/html";
import { selectReportingHighlightRows } from "../../reporting/reporting-highlights";
import {
  buildReportingHierarchyQueryEntries,
  buildReportingPageQueryEntries,
} from "../../reporting/reporting-page-filters";
import { formatIsoTimestamp } from "../../utils/display-format";
import {
  AdminButton,
  AdminButtonLink,
  AdminEmptyTableRow,
  AdminField,
  AdminForm,
  AdminPanel,
  AdminStatusPill,
  AdminTable,
} from "../components";
import type { InstitutionAdminPageInput } from "./page-types";
import {
  REPORTING_HIERARCHY_DEPTH,
  REPORTING_HIERARCHY_LEVELS,
  REPORTING_PERFORMER_ROW_LIMIT,
  REPORTING_RATE_MIN_ISSUED,
  buildPathWithQuery,
  buildReportingHierarchyFocusId,
  formatReportingCount,
  formatReportingDateLabel,
  formatReportingHierarchyLevelLabel,
  formatReportingRate,
  formatReportingStateLabel,
  getNextReportingHierarchyLevel,
  isReportingHierarchyLevel,
  type ReportingHierarchyLevel,
  type ReportingHierarchyRow,
} from "./reporting-helpers";
import { createReportingRenderHelpers } from "./reporting-render-helpers";

type HonoElement = HtmlEscapedString | Promise<HtmlEscapedString>;

interface RenderInstitutionAdminReportingSectionsInput {
  input: InstitutionAdminPageInput;
  reportingPath: string;
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
  reportingTrendFiltersPanelMarkup: HonoElement;
  reportingReportsLibraryMarkup: HonoElement;
  reportingExportFiltersPanelMarkup: HonoElement;
  reportingExportsPanelMarkup: HonoElement;
}

export const renderInstitutionAdminReportingSections = (
  source: RenderInstitutionAdminReportingSectionsInput,
): InstitutionAdminReportingSections => {
  const { input, reportingPath, reportingExplorePath, reportingTrendsPath, reportingReportsPath } =
    source;
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
  const {
    aggregateReportingHierarchyRows,
    buildReportingComparisonSeries,
    buildReportingHierarchyDrillHref,
    buildReportingLegendDetail,
    classifyReportingPanelState,
    getReportingComparisonLabel,
    getReportingOrgUnitLabel,
    hasReportingActivity,
    renderReportingComparisonGroupLabel,
    renderReportingCountCell,
    renderReportingHierarchyRows,
    renderReportingStateShell,
    renderReportingTrendCallout,
    renderReportingVisualModule,
  } = createReportingRenderHelpers({
    templateById,
    orgUnitById,
    reportingExplorePath,
    renderOrgUnitSummary,
  });

  const reportingState = reportingOverview?.filters.state ?? null;
  const reportingIssuedFromValue = reportingOverview?.filters.issuedFrom ?? "";
  const reportingIssuedToValue = reportingOverview?.filters.issuedTo ?? "";
  const reportingBadgeTemplateIdValue = reportingOverview?.filters.badgeTemplateId ?? "";
  const reportingOrgUnitIdValue = reportingOverview?.filters.orgUnitId ?? "";
  const reportingTemplateFilterOptions = input.badgeTemplates.map((template) => {
    return (
      <option value={template.id} selected={reportingBadgeTemplateIdValue === template.id}>
        {template.title}
      </option>
    );
  });
  const reportingOrgUnitOptions = input.orgUnits
    .filter((orgUnit) => orgUnit.isActive)
    .map((orgUnit) => {
      return (
        <option value={orgUnit.id} selected={reportingOrgUnitIdValue === orgUnit.id}>
          {`${orgUnit.displayName} (${orgUnit.unitType})`}
        </option>
      );
    });
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
  const reportingOverviewExportHref = buildPathWithQuery(
    `/v1/tenants/${encodeURIComponent(input.tenant.id)}/reporting/overview/export.csv`,
    reportingAggregateExportEntries,
  );
  const reportingEngagementExportHref = buildPathWithQuery(
    `/v1/tenants/${encodeURIComponent(input.tenant.id)}/reporting/engagement/export.csv`,
    reportingAggregateExportEntries,
  );
  const reportingTrendsExportHref = buildPathWithQuery(
    `/v1/tenants/${encodeURIComponent(input.tenant.id)}/reporting/trends/export.csv`,
    [...reportingAggregateExportEntries, ["bucket", "day"]] as const,
  );
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
  const reportingExportsPanelMarkup = (
    <article id="reporting-reports-exports" class="ct-admin__panel ct-stack">
      <div class="ct-cluster">
        <h2>Export CSV</h2>
        <span class="ct-admin__status-pill">Supporting operations</span>
      </div>
      <p>
        Download CSV files for the selected filters. These links preserve issue date, badge,
        organization, and lifecycle state selections.
      </p>
      <div class="ct-cluster">
        <AdminButtonLink href={reportingOverviewExportHref} variant="secondary">
          Overview CSV
        </AdminButtonLink>
        <AdminButtonLink href={reportingEngagementExportHref} variant="secondary">
          Engagement CSV
        </AdminButtonLink>
        <AdminButtonLink href={reportingTrendsExportHref} variant="secondary">
          Trends CSV
        </AdminButtonLink>
        <AdminButtonLink href={reportingTemplateComparisonExportHref} variant="secondary">
          Template comparisons CSV
        </AdminButtonLink>
        <AdminButtonLink href={reportingOrgUnitComparisonExportHref} variant="secondary">
          Org-unit comparisons CSV
        </AdminButtonLink>
      </div>
      <p class="ct-admin__hint">
        Recipient-level ledger export stays in Operations for owner/admin users and does not appear
        in the reporting workspace.
      </p>
    </article>
  );
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
    <section class="ct-admin__reporting-slice-strip" aria-label="Current reporting slice">
      <div class="ct-admin__reporting-slice-main">
        <div class="ct-cluster">
          <p class="ct-admin__eyebrow">Current slice</p>
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
      detail: "Current issued volume for the selected reporting slice.",
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
      detail: "Distinct shared assertions over issued badges in the same slice.",
    },
    {
      key: "public-badge-views",
      label: "Public badge views",
      value: formatReportingCount(reportingEngagementCounts?.publicBadgeViewCount ?? 0),
      detail: "CredTrail-owned public badge page loads for the current slice.",
    },
  ] as const;
  const reportingExecutiveSummaryMarkup = (
    <article class="ct-admin__panel ct-admin__reporting-summary-band ct-stack">
      <div class="ct-admin__reporting-readout-head">
        <div class="ct-stack">
          <p class="ct-admin__eyebrow">Current slice</p>
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
      <section class="ct-admin__reporting-summary-context" aria-label="Current slice">
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
      <AdminEmptyTableRow colSpan={4}>No reporting definitions loaded yet.</AdminEmptyTableRow>
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
      ? "No badges are in this slice yet."
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
        description: "Widen the reporting slice or remove filters to check badge lifecycle state.",
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
          <AdminStatusPill>{state === "rich" ? "Top rows" : "Current slice"}</AdminStatusPill>
        </div>
        {visualMarkup}
        <div class="ct-admin__reporting-highlight-actions">
          <AdminButtonLink href={input.actionHref} variant="secondary">
            Open Explore
          </AdminButtonLink>
          <AdminButtonLink href={input.exportHref} variant="ghost">
            Export CSV
          </AdminButtonLink>
        </div>
      </AdminPanel>
    );
  };
  const reportingHierarchyRowsByLevel = new Map(
    REPORTING_HIERARCHY_LEVELS.map((level) => [
      level,
      aggregateReportingHierarchyRows({
        comparisonRows: reportingOrgUnitComparisons,
        level,
      }),
    ]),
  );
  const reportingHierarchyComparableRowCount = Math.max(
    0,
    ...REPORTING_HIERARCHY_LEVELS.map(
      (level) =>
        reportingHierarchyRowsByLevel.get(level)?.filter((row) => hasReportingActivity(row))
          .length ?? 0,
    ),
  );
  const reportingHierarchyState = classifyReportingPanelState(reportingHierarchyComparableRowCount);
  const reportingVisibleRoots = input.orgUnits
    .filter(
      (orgUnit) =>
        isReportingHierarchyLevel(orgUnit.unitType) &&
        (orgUnit.parentOrgUnitId === null || !orgUnitById.has(orgUnit.parentOrgUnitId)) &&
        (reportingHierarchyRowsByLevel
          .get(orgUnit.unitType)
          ?.some((row) => row.orgUnitId === orgUnit.id) ??
          false),
    )
    .sort((left, right) => left.displayName.localeCompare(right.displayName));
  const renderReportingHierarchyFocusSection = (
    focusOrgUnit: TenantOrgUnitRecord,
    breadcrumb: readonly TenantOrgUnitRecord[],
  ): HonoElement => {
    if (!isReportingHierarchyLevel(focusOrgUnit.unitType)) {
      return <></>;
    }

    const childLevel = getNextReportingHierarchyLevel(focusOrgUnit.unitType);
    const sectionId = buildReportingHierarchyFocusId(focusOrgUnit.id);
    const rootSectionId = buildReportingHierarchyFocusId((breadcrumb[0] ?? focusOrgUnit).id);
    const currentLevelLabel = formatReportingHierarchyLevelLabel(focusOrgUnit.unitType);
    const childLevelLabel =
      childLevel === null
        ? "Deepest reporting level"
        : formatReportingHierarchyLevelLabel(childLevel);
    const rows =
      childLevel === null
        ? []
        : aggregateReportingHierarchyRows({
            comparisonRows: reportingOrgUnitComparisons,
            focusOrgUnitId: focusOrgUnit.id,
            level: childLevel,
          });
    const breadcrumbMarkup = (
      <nav class="ct-admin__reporting-breadcrumb-nav" aria-label="Reporting hierarchy breadcrumb">
        <ol class="ct-admin__reporting-breadcrumb-list">
          {breadcrumb.map((orgUnit, index) => {
            const isCurrent = index === breadcrumb.length - 1;

            return (
              <li class="ct-admin__reporting-breadcrumb-item">
                {isCurrent ? (
                  <span class="ct-admin__reporting-breadcrumb-current" aria-current="page">
                    {orgUnit.displayName}
                  </span>
                ) : (
                  <a
                    class="ct-admin__reporting-breadcrumb-link"
                    href={buildReportingHierarchyDrillHref(orgUnit.id)}
                    data-reporting-focus-link
                    data-reporting-focus-target={buildReportingHierarchyFocusId(orgUnit.id)}
                  >
                    {orgUnit.displayName}
                  </a>
                )}
              </li>
            );
          })}
        </ol>
      </nav>
    );
    const focusSummaryCopy =
      childLevel === null
        ? "Keeps this drilldown inside reporting while marking the deepest visible reporting leaf for the current workspace slice."
        : `Keeps this drilldown inside reporting while the exact ${childLevelLabel.toLowerCase()} table and export link stay adjacent to the shared visual.`;
    const focusSummaryMarkup = (
      <section
        class="ct-admin__reporting-focus-summary ct-stack"
        aria-label="Hierarchy focus summary"
      >
        <div class="ct-stack">
          <p class="ct-admin__eyebrow">Current focus</p>
          <p class="ct-admin__reporting-focus-summary-title">{focusOrgUnit.displayName}</p>
          <p class="ct-admin__hint">{focusSummaryCopy}</p>
        </div>
        <dl class="ct-admin__reporting-focus-summary-grid">
          <div class="ct-admin__reporting-focus-summary-item">
            <dt>Current hierarchy level</dt>
            <dd>{currentLevelLabel}</dd>
          </div>
          <div class="ct-admin__reporting-focus-summary-item">
            <dt>Next child level</dt>
            <dd>{childLevelLabel}</dd>
          </div>
          <div class="ct-admin__reporting-focus-summary-item">
            <dt>Reporting workspace</dt>
            <dd>{reportingHierarchyScopeSummary}</dd>
          </div>
        </dl>
      </section>
    );
    const visualMarkup =
      childLevel === null || rows.length === 0
        ? null
        : renderReportingVisualModule({
            kind: "comparison-ranked",
            headingLevel: "h4",
            id: `${sectionId}-visual`,
            title: `${focusOrgUnit.displayName} ${childLevelLabel} ranking`,
            description:
              "Volume-first hierarchy summary ranks the visible child rows by issued count while keeping public views plus claim/share detail adjacent to each ranked row.",
            series: rows.map((row) => ({
              label: getReportingOrgUnitLabel(row.orgUnitId),
              value: row.issuedCount,
              detail: buildReportingLegendDetail({
                publicBadgeViewCount: row.publicBadgeViewCount,
                claimRate: row.claimRate,
                shareRate: row.shareRate,
              }),
            })),
            note: `The exact ${childLevelLabel.toLowerCase()} table below keeps every visible row, drill target, and export context intact.`,
          });
    const childMarkup =
      childLevel === null ? (
        <p class="ct-admin__hint">Program is the deepest reporting level in this workspace.</p>
      ) : (
        <div class="ct-admin__reporting-panel-media">
          {visualMarkup}
          <AdminTable
            headers={[
              formatReportingHierarchyLevelLabel(childLevel),
              "Issued",
              "Public badge views",
              "Verification views",
              "Share clicks",
              "Claim actions",
              "Wallet accepts",
              "Claim rate",
              "Share rate",
            ]}
            tbodyDataAttributes={{ "data-reporting-bar-group": sectionId }}
          >
            {renderReportingHierarchyRows(
              rows,
              `No ${formatReportingHierarchyLevelLabel(childLevel).toLowerCase()} rows available for this focus.`,
            )}
          </AdminTable>
        </div>
      );
    const descendantMarkup = rows.map((row) => {
      const childOrgUnit = orgUnitById.get(row.orgUnitId);

      if (childOrgUnit === undefined || !isReportingHierarchyLevel(childOrgUnit.unitType)) {
        return null;
      }

      return renderReportingHierarchyFocusSection(childOrgUnit, [...breadcrumb, childOrgUnit]);
    });

    return (
      <section
        id={sectionId}
        class="ct-admin__reporting-focus-section ct-stack"
        data-reporting-focus-root={rootSectionId}
        data-reporting-focus-section
        tabindex={-1}
      >
        <div class="ct-cluster">
          <h3>{focusOrgUnit.displayName}</h3>
          <div class="ct-cluster">
            <span class="ct-admin__status-pill">
              {childLevel === null
                ? "Program leaf"
                : `Shows ${formatReportingHierarchyLevelLabel(childLevel).toLowerCase()} rows`}
            </span>
            {childLevel === null ? null : (
              <AdminButtonLink
                variant="secondary"
                href={buildReportingHierarchyExportHref({
                  focusOrgUnitId: focusOrgUnit.id,
                  level: childLevel,
                })}
              >
                Export CSV
              </AdminButtonLink>
            )}
          </div>
        </div>
        <p class="ct-admin__eyebrow">Breadcrumb</p>
        {breadcrumbMarkup}
        {focusSummaryMarkup}
        {childMarkup}
        {descendantMarkup}
      </section>
    );
  };
  const reportingHierarchyStateShellMarkup =
    reportingHierarchyState === "rich"
      ? null
      : reportingHierarchyState === "sparse"
        ? renderReportingStateShell({
            state: "sparse",
            eyebrow: "Thin-data slice",
            title: "This slice currently resolves to one visible reporting path.",
            description:
              "Use the current focus summary and exact hierarchy table below to review the visible path without implying a fuller tree.",
          })
        : renderReportingStateShell({
            state: "empty",
            eyebrow: "No hierarchy rows yet",
            title:
              "Hierarchy drilldowns appear here once visible org-unit rows exist for this slice.",
            description:
              "The reporting route stays the same; this panel fills in as soon as the current slice exposes hierarchy rows.",
          });
  const reportingHierarchyPanelMarkup = (
    <article class="ct-admin__panel ct-stack" data-reporting-state={reportingHierarchyState}>
      <div class="ct-cluster">
        <h2>Hierarchy drilldown</h2>
        <span class="ct-admin__status-pill">Workspace-local</span>
      </div>
      <p>
        Use these tables to move between institution, college, department, and program views without
        leaving reporting. The overview filters above stay exact-match; hierarchy drilldowns stay
        explicit here.
      </p>
      {reportingHierarchyStateShellMarkup}
      {reportingHierarchyState === "empty" ? null : (
        <>
          <p class="ct-admin__hint">Visible roots stay inside the reporting workspace.</p>
          <div class="ct-admin__reporting-root-links">
            {reportingVisibleRoots.map((rootOrgUnit) => (
              <a
                class="ct-admin__reporting-root-link"
                href={buildReportingHierarchyDrillHref(rootOrgUnit.id)}
                data-reporting-focus-link
                data-reporting-root-link
                data-reporting-focus-target={buildReportingHierarchyFocusId(rootOrgUnit.id)}
              >
                {rootOrgUnit.displayName}
              </a>
            ))}
          </div>
          {reportingVisibleRoots.map((rootOrgUnit) =>
            renderReportingHierarchyFocusSection(rootOrgUnit, [rootOrgUnit]),
          )}
        </>
      )}
    </article>
  );
  const reportingPerformerLevel =
    REPORTING_HIERARCHY_LEVELS.filter(
      (level) => (reportingHierarchyRowsByLevel.get(level)?.length ?? 0) > 1,
    ).sort((left, right) => {
      const countDifference =
        (reportingHierarchyRowsByLevel.get(right)?.length ?? 0) -
        (reportingHierarchyRowsByLevel.get(left)?.length ?? 0);

      if (countDifference !== 0) {
        return countDifference;
      }

      return REPORTING_HIERARCHY_DEPTH[right] - REPORTING_HIERARCHY_DEPTH[left];
    })[0] ?? null;
  const reportingPerformerRows =
    reportingPerformerLevel === null
      ? []
      : (reportingHierarchyRowsByLevel.get(reportingPerformerLevel) ?? []);
  const reportingPerformerCompareLevelLabel =
    reportingPerformerLevel === null
      ? null
      : formatReportingHierarchyLevelLabel(reportingPerformerLevel).toLowerCase();
  const reportingPerformerState = classifyReportingPanelState(reportingHierarchyComparableRowCount);
  const reportingRateEligibleRows = reportingPerformerRows.filter(
    (row) => row.issuedCount >= REPORTING_RATE_MIN_ISSUED,
  );
  const buildPerformerSummaryOverride = (input: {
    metricLabel: "claim rate" | "issued volume" | "share rate";
    rankingIntent: "highest" | "lowest";
    summaryKind: "rate" | "volume";
  }): string => {
    const compareLevelLabel = reportingPerformerCompareLevelLabel ?? "visible";
    const rankingCopy =
      input.rankingIntent === "highest"
        ? "Highest values appear first."
        : "Lowest values appear first.";

    if (input.summaryKind === "rate") {
      return `Comparing ${compareLevelLabel} rows by ${input.metricLabel}. Issued totals stay visible beside each ranked rate row. ${rankingCopy}`;
    }

    return `Comparing ${compareLevelLabel} rows by ${input.metricLabel}. Claim and share rates stay visible beside each ranked row. ${rankingCopy}`;
  };
  const renderPerformerTableRows = (
    rows: readonly ReportingHierarchyRow[],
    emptyLabel: string,
  ): HonoElement => {
    if (rows.length === 0) {
      return <AdminEmptyTableRow colSpan={4}>{emptyLabel}</AdminEmptyTableRow>;
    }

    return (
      <>
        {rows.map((row) => (
          <tr>
            <td>{renderOrgUnitSummary(row.orgUnitId)}</td>
            <td>
              <span class="ct-admin__reporting-table-number">
                {renderReportingCountCell(row.issuedCount)}
              </span>
            </td>
            <td>{formatReportingRate(row.claimRate)}</td>
            <td>{formatReportingRate(row.shareRate)}</td>
          </tr>
        ))}
      </>
    );
  };
  const renderPerformerPanel = (input: {
    description: string;
    title: string;
    rows: readonly ReportingHierarchyRow[];
    emptyLabel: string;
    barGroup: string;
    rankingIntent: "highest" | "lowest";
    metric: "claimRate" | "issuedCount" | "shareRate";
  }): HonoElement => {
    const summaryOverride =
      input.metric === "issuedCount"
        ? buildPerformerSummaryOverride({
            metricLabel: "issued volume",
            rankingIntent: input.rankingIntent,
            summaryKind: "volume",
          })
        : buildPerformerSummaryOverride({
            metricLabel: input.metric === "claimRate" ? "claim rate" : "share rate",
            rankingIntent: input.rankingIntent,
            summaryKind: "rate",
          });
    const visualMarkup =
      input.rows.length === 0
        ? null
        : renderReportingVisualModule({
            kind: "comparison-ranked",
            headingLevel: "h4",
            id: `performer-${input.barGroup}`,
            title: input.title,
            description: input.description,
            seriesOrder: "input",
            summaryOverride,
            series: input.rows.map((row) => ({
              label: getReportingOrgUnitLabel(row.orgUnitId),
              value:
                input.metric === "issuedCount"
                  ? row.issuedCount
                  : input.metric === "claimRate"
                    ? row.claimRate
                    : row.shareRate,
              detail:
                input.metric === "issuedCount"
                  ? `${formatReportingRate(row.claimRate)} claim · ${formatReportingRate(row.shareRate)} share`
                  : `${formatReportingCount(row.issuedCount)} issued · ${
                      input.metric === "claimRate"
                        ? `${formatReportingRate(row.shareRate)} share`
                        : `${formatReportingRate(row.claimRate)} claim`
                    }`,
            })),
            note: "The exact table below preserves the same rows, issued totals, and rate semantics for detailed comparison.",
          });

    return (
      <article class="ct-admin__panel ct-admin__panel--nested ct-stack">
        <h3>{input.title}</h3>
        {visualMarkup}
        <AdminTable
          headers={["Org unit", "Issued", "Claim rate", "Share rate"]}
          compact={true}
          tbodyDataAttributes={{ "data-reporting-bar-group": input.barGroup }}
        >
          {renderPerformerTableRows(input.rows, input.emptyLabel)}
        </AdminTable>
      </article>
    );
  };
  const reportingHighestVolumeRows = [...reportingPerformerRows]
    .sort((left, right) => {
      if (right.issuedCount !== left.issuedCount) {
        return right.issuedCount - left.issuedCount;
      }

      return left.orgUnitId.localeCompare(right.orgUnitId);
    })
    .slice(0, REPORTING_PERFORMER_ROW_LIMIT);
  const reportingLowestVolumeRows = [...reportingPerformerRows]
    .sort((left, right) => {
      if (left.issuedCount !== right.issuedCount) {
        return left.issuedCount - right.issuedCount;
      }

      return left.orgUnitId.localeCompare(right.orgUnitId);
    })
    .slice(0, REPORTING_PERFORMER_ROW_LIMIT);
  const reportingHighestClaimRateRows = [...reportingRateEligibleRows]
    .sort((left, right) => {
      if (right.claimRate !== left.claimRate) {
        return right.claimRate - left.claimRate;
      }

      if (right.issuedCount !== left.issuedCount) {
        return right.issuedCount - left.issuedCount;
      }

      return left.orgUnitId.localeCompare(right.orgUnitId);
    })
    .slice(0, REPORTING_PERFORMER_ROW_LIMIT);
  const reportingLowestClaimRateRows = [...reportingRateEligibleRows]
    .sort((left, right) => {
      if (left.claimRate !== right.claimRate) {
        return left.claimRate - right.claimRate;
      }

      if (left.issuedCount !== right.issuedCount) {
        return left.issuedCount - right.issuedCount;
      }

      return left.orgUnitId.localeCompare(right.orgUnitId);
    })
    .slice(0, REPORTING_PERFORMER_ROW_LIMIT);
  const reportingHighestShareRateRows = [...reportingRateEligibleRows]
    .sort((left, right) => {
      if (right.shareRate !== left.shareRate) {
        return right.shareRate - left.shareRate;
      }

      if (right.issuedCount !== left.issuedCount) {
        return right.issuedCount - left.issuedCount;
      }

      return left.orgUnitId.localeCompare(right.orgUnitId);
    })
    .slice(0, REPORTING_PERFORMER_ROW_LIMIT);
  const reportingLowestShareRateRows = [...reportingRateEligibleRows]
    .sort((left, right) => {
      if (left.shareRate !== right.shareRate) {
        return left.shareRate - right.shareRate;
      }

      if (left.issuedCount !== right.issuedCount) {
        return left.issuedCount - right.issuedCount;
      }

      return left.orgUnitId.localeCompare(right.orgUnitId);
    })
    .slice(0, REPORTING_PERFORMER_ROW_LIMIT);
  const renderPerformerGroup = (input: {
    title: string;
    description: string;
    panels: readonly HonoElement[];
  }): HonoElement => {
    return (
      <section class="ct-admin__reporting-performer-group ct-stack">
        <div class="ct-stack">
          <p class="ct-admin__eyebrow">{input.title}</p>
          <p class="ct-admin__hint">{input.description}</p>
        </div>
        <div class="ct-admin__reporting-performer-grid">{input.panels}</div>
      </section>
    );
  };
  const reportingPerformerPanelsMarkup =
    reportingPerformerState !== "rich" || reportingPerformerLevel === null ? (
      <article class="ct-admin__panel ct-stack" data-reporting-state={reportingPerformerState}>
        <h2>Performer panels</h2>
        {renderReportingStateShell({
          state: reportingPerformerState === "empty" ? "empty" : "sparse",
          eyebrow: reportingPerformerState === "empty" ? "No rankings yet" : "Thin-data slice",
          title:
            reportingPerformerState === "empty"
              ? "Performer rankings appear once this slice includes comparable hierarchy rows."
              : "Rankings stay paused until this slice has more than one comparable hierarchy row.",
          description:
            reportingPerformerState === "empty"
              ? "This section reuses the same visible hierarchy rows shown above, so it stays honest when the current slice has nothing comparable to rank."
              : "The current slice still shows real hierarchy data above, but performer rankings wait until more than one visible row can be compared honestly.",
        })}
      </article>
    ) : (
      <article class="ct-admin__panel ct-stack" data-reporting-state="rich">
        <div class="ct-cluster">
          <h2>Performer panels</h2>
          <span class="ct-admin__status-pill">
            {`${formatReportingHierarchyLevelLabel(reportingPerformerLevel)} rows`}
          </span>
        </div>
        <p>These rankings keep issued volume separate from claim and share rates.</p>
        <p class="ct-admin__hint">
          Compare level:{" "}
          {`${reportingPerformerCompareLevelLabel} rows in the current visible hierarchy.`}
        </p>
        <div class="ct-admin__reporting-performer-groups">
          {renderPerformerGroup({
            title: "Volume rankings",
            description:
              "Issued volume stays primary while claim and share rates remain visible beside each ranked row.",
            panels: [
              renderPerformerPanel({
                title: "Highest issuance volume",
                description:
                  "Highlights the org units issuing the most badges while keeping exact totals and rates visible.",
                rows: reportingHighestVolumeRows,
                emptyLabel: "No org units available for volume rankings.",
                barGroup: "performer-high-volume",
                rankingIntent: "highest",
                metric: "issuedCount",
              }),
              renderPerformerPanel({
                title: "Lowest issuance volume",
                description:
                  "Highlights lower-volume org units without separating the ranking from its exact table rows.",
                rows: reportingLowestVolumeRows,
                emptyLabel: "No org units available for volume rankings.",
                barGroup: "performer-low-volume",
                rankingIntent: "lowest",
                metric: "issuedCount",
              }),
            ],
          })}
          {renderPerformerGroup({
            title: "Rate rankings",
            description: `Rate rankings require at least ${formatReportingCount(
              REPORTING_RATE_MIN_ISSUED,
            )} issued badges so issued totals stay visible beside every rate callout.`,
            panels: [
              renderPerformerPanel({
                title: "Highest claim rate",
                description:
                  "Ranks claim-rate leaders that meet the minimum issued-badge threshold.",
                rows: reportingHighestClaimRateRows,
                emptyLabel: `No ${formatReportingHierarchyLevelLabel(reportingPerformerLevel).toLowerCase()} rows meet the minimum rate sample.`,
                barGroup: "performer-high-claim-rate",
                rankingIntent: "highest",
                metric: "claimRate",
              }),
              renderPerformerPanel({
                title: "Lowest claim rate",
                description: "Ranks lower claim-rate rows using the same minimum-sample rule.",
                rows: reportingLowestClaimRateRows,
                emptyLabel: `No ${formatReportingHierarchyLevelLabel(reportingPerformerLevel).toLowerCase()} rows meet the minimum rate sample.`,
                barGroup: "performer-low-claim-rate",
                rankingIntent: "lowest",
                metric: "claimRate",
              }),
              renderPerformerPanel({
                title: "Highest share rate",
                description:
                  "Ranks share-rate leaders while keeping issued totals visible in the adjacent table.",
                rows: reportingHighestShareRateRows,
                emptyLabel: `No ${formatReportingHierarchyLevelLabel(reportingPerformerLevel).toLowerCase()} rows meet the minimum rate sample.`,
                barGroup: "performer-high-share-rate",
                rankingIntent: "highest",
                metric: "shareRate",
              }),
              renderPerformerPanel({
                title: "Lowest share rate",
                description:
                  "Ranks lower share-rate rows with the same volume threshold used by the table below.",
                rows: reportingLowestShareRateRows,
                emptyLabel: `No ${formatReportingHierarchyLevelLabel(reportingPerformerLevel).toLowerCase()} rows meet the minimum rate sample.`,
                barGroup: "performer-low-share-rate",
                rankingIntent: "lowest",
                metric: "shareRate",
              }),
            ],
          })}
        </div>
      </article>
    );

  const renderReportingFiltersForm = (
    actionPath: string,
    formClass = "ct-admin__form ct-admin__form--inline ct-grid",
    resetPath = actionPath,
  ): HonoElement => (
    <>
      <AdminForm
        id="reporting-filters-form"
        method="get"
        action={actionPath}
        className={formClass}
        dataAttributes={{
          "data-reporting-submit-state": "idle",
        }}
      >
        <AdminField label="Issued from">
          <input name="issuedFrom" type="date" value={reportingIssuedFromValue} />
        </AdminField>
        <AdminField label="Issued to">
          <input name="issuedTo" type="date" value={reportingIssuedToValue} />
        </AdminField>
        <AdminField label="Badge template">
          <select name="badgeTemplateId">
            <option value="">All templates</option>
            {reportingTemplateFilterOptions}
          </select>
        </AdminField>
        <AdminField label="Org unit">
          <select name="orgUnitId">
            <option value="">All org units</option>
            {reportingOrgUnitOptions}
          </select>
        </AdminField>
        <AdminField label="Lifecycle state">
          <select name="state">
            <option value="">All current states</option>
            <option value="active" selected={reportingState === "active"}>
              active
            </option>
            <option value="suspended" selected={reportingState === "suspended"}>
              suspended
            </option>
            <option value="revoked" selected={reportingState === "revoked"}>
              revoked
            </option>
            <option value="expired" selected={reportingState === "expired"}>
              expired
            </option>
            <option value="pending_review" selected={reportingState === "pending_review"}>
              pending review
            </option>
          </select>
        </AdminField>
        <div class="ct-cluster">
          <AdminButton type="submit">Apply filters</AdminButton>
          <AdminButtonLink href={resetPath} variant="secondary">
            Reset
          </AdminButtonLink>
        </div>
      </AdminForm>
      <p
        id="reporting-filters-status"
        class="ct-admin__hint"
        data-reporting-submit-status
        aria-live="polite"
      >
        Applying filters refreshes this page with the selected reporting slice.
      </p>
    </>
  );

  const reportingOverviewPanelMarkup = (
    <AdminPanel id="reporting-overview-panel" className="ct-admin__reporting-overview-panel">
      <div class="ct-cluster">
        <h2>Reporting Overview</h2>
        <AdminStatusPill>Filters</AdminStatusPill>
      </div>
      {renderReportingFiltersForm(reportingExplorePath)}
      <p class="ct-admin__hint">
        Need CSV downloads for this slice?{" "}
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

  const reportingTrendFiltersPanelMarkup = (
    <details id="reporting-trend-filters-panel" class="ct-admin__panel ct-admin__add-disclosure">
      <summary class="ct-admin__add-disclosure-summary">
        <span>
          <strong>Filter trend data</strong>
          <small>Change date, badge, org unit, or state only when you need a narrower view.</small>
        </span>
        <span class="ct-admin__add-disclosure-control">
          <span class="ct-admin__add-disclosure-control-open">Show filters</span>
          <span class="ct-admin__add-disclosure-control-close">Hide filters</span>
        </span>
      </summary>
      {renderReportingFiltersForm(
        reportingTrendsPath,
        "ct-admin__form ct-admin__add-disclosure-form ct-grid",
      )}
    </details>
  );

  const reportingExportFiltersPanelMarkup = (
    <AdminPanel id="reporting-export-filters-panel">
      <div class="ct-cluster">
        <h2>Export filters</h2>
      </div>
      <p>Choose filters before downloading CSV files.</p>
      {renderReportingFiltersForm(reportingReportsPath)}
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
                ? `${formatReportingCount(reportingRawEngagementTotal)} raw events in this slice`
                : "No raw engagement events yet for this slice"}
            </small>
          </summary>
          <div class="ct-admin__reporting-inline-body">
            {reportingHasRawEngagementEvents ? (
              <>
                {reportingEngagementVisualsMarkup}
                <div class="ct-admin__metric-grid">{reportingEngagementCardsMarkup}</div>
              </>
            ) : (
              <p class="ct-admin__empty">No engagement events yet for this slice.</p>
            )}
          </div>
        </details>
      )}
    </AdminPanel>
  );

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
          ? "Exact badge-template rows for the selected slice. Use Highlights for the ranked visual summary."
          : reportingTemplateComparisonState === "sparse"
            ? "One badge template matches this slice. Open the exact row only when you need every event column."
            : "No badge-template rows are visible for this slice yet. Widen the date range or remove a filter to compare templates."}
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
          ? "Exact org-unit rows for the selected slice. Advanced hierarchy drilldowns stay collapsed below until needed."
          : reportingOrgUnitComparisonState === "sparse"
            ? "One org unit matches this slice. Open the exact row only when you need every event column."
            : "No org-unit rows are visible for this slice yet. Widen the date range or remove a filter to compare org units."}
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
      "Top issued badge templates for the selected reporting slice, with public views plus claim and share context carried beside each row.",
    rows: reportingTemplateHighlightRows,
    totalRowCount: reportingTemplateComparisons.length,
    emptyTitle: "No template highlights are available for this slice yet.",
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
      "Top issued organization units for the selected reporting slice, scoped to the rows this user can see.",
    rows: reportingOrgUnitHighlightRows,
    totalRowCount: reportingOrgUnitComparisons.length,
    emptyTitle: "No org-unit highlights are available for this slice yet.",
    emptyDescription:
      "Widen the date window or remove a filter in Explore to review org-unit performance.",
    actionHref: reportingExploreHref,
    exportHref: reportingOrgUnitComparisonExportHref,
  });
  const reportingRankedChartsMarkup = (
    <details class="ct-admin__reporting-inline-disclosure ct-admin__reporting-inline-disclosure--ranked">
      <summary class="ct-admin__reporting-inline-summary">
        <span>Ranked charts</span>
        <small>Top badge templates and org units for this slice</small>
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
      detail: "Suspended, revoked, or pending-review badges are present in this slice.",
      href: reportingLifecycleAttentionHref,
      actionLabel: "Review in Explore",
    });
  }

  if (reportingTopOrgUnitRow !== null) {
    reportingFocusAreaItems.push({
      eyebrow: "Org unit to notice",
      metric: `${formatReportingCount(reportingTopOrgUnitRow.issuedCount)} issued`,
      title: getReportingComparisonLabel(reportingTopOrgUnitRow),
      detail: "Highest visible org-unit volume in the current slice.",
      href: buildReportingExploreHrefForComparisonRow(reportingTopOrgUnitRow),
      actionLabel: "Explore this slice",
    });
  }

  if (reportingTopTemplateRow !== null) {
    reportingFocusAreaItems.push({
      eyebrow: "Template to notice",
      metric: `${formatReportingCount(reportingTopTemplateRow.issuedCount)} issued`,
      title: getReportingComparisonLabel(reportingTopTemplateRow),
      detail: "Highest visible badge-template volume in the current slice.",
      href: buildReportingExploreHrefForComparisonRow(reportingTopTemplateRow),
      actionLabel: "Explore this slice",
    });
  } else if (reportingClaimRateLeader !== null) {
    reportingFocusAreaItems.push({
      eyebrow: "Engagement to notice",
      metric: formatReportingRate(reportingClaimRateLeader.claimRate),
      title: getReportingComparisonLabel(reportingClaimRateLeader),
      detail: "Strongest claim-rate signal above the minimum sample threshold.",
      href: buildReportingExploreHrefForComparisonRow(reportingClaimRateLeader),
      actionLabel: "Explore this slice",
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
          title: "Highlights will suggest focus areas once this slice has activity.",
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
              <AdminButtonLink href={item.href} variant="ghost">
                {item.actionLabel}
              </AdminButtonLink>
            </article>
          ))}
        </div>
      )}
      <div class="ct-admin__reporting-highlight-actions">
        <AdminButtonLink href={reportingExploreHref} variant="secondary">
          Open Explore
        </AdminButtonLink>
      </div>
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
  const reportingSavedReportsPanelMarkup = (
    <AdminPanel id="reporting-reports-saved" className="ct-admin__reporting-placeholder-panel">
      <div class="ct-cluster">
        <div class="ct-stack">
          <p class="ct-admin__eyebrow">Saved reports</p>
          <h2>Saved report shortcuts will live here.</h2>
        </div>
        <AdminStatusPill>Planned</AdminStatusPill>
      </div>
      <p>
        Reserved for named reports that preserve a reporting slice, audience, and export intent. For
        now, use Highlights for the default read and Explore for the exact table workspace.
      </p>
      <div class="ct-admin__reporting-highlight-actions">
        <AdminButtonLink href={reportingPath} variant="secondary">
          Open Highlights
        </AdminButtonLink>
        <AdminButtonLink href={reportingExploreHref} variant="ghost">
          Open Explore
        </AdminButtonLink>
      </div>
    </AdminPanel>
  );
  const reportingCustomReportsPanelMarkup = (
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
      <div class="ct-admin__reporting-highlight-actions">
        <AdminButtonLink href={reportingExploreHref} variant="secondary">
          Build from Explore
        </AdminButtonLink>
        <AdminButtonLink href={reportingReportsExportsHref} variant="ghost">
          Export current slice
        </AdminButtonLink>
      </div>
    </AdminPanel>
  );
  const reportingReportsLibraryMarkup = (
    <section class="ct-admin__reporting-highlight-grid">
      {reportingSavedReportsPanelMarkup}
      {reportingCustomReportsPanelMarkup}
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
    reportingTrendFiltersPanelMarkup,
    reportingReportsLibraryMarkup,
    reportingExportFiltersPanelMarkup,
    reportingExportsPanelMarkup,
  };
};

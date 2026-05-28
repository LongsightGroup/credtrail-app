import type {
  BadgeTemplateRecord,
  TenantOrgUnitRecord,
  TenantReportingComparisonRowRecord,
  TenantReportingTrendRecord,
} from "@credtrail/db";
import type { HtmlEscapedString } from "hono/utils/html";
import { renderReporting, type ReportingVisualSeriesPoint } from "../../reporting/reporting-visuals";
import { AdminEmptyTableRow } from "../components";
import {
  buildReportingHierarchyFocusId,
  formatReportingCount,
  formatReportingDateLabel,
  formatReportingHierarchyLevelLabel,
  formatReportingRate,
  getNextReportingHierarchyLevel,
  isReportingHierarchyLevel,
  type ReportingActivityCounts,
  type ReportingHierarchyLevel,
  type ReportingHierarchyRow,
  type ReportingPanelState,
} from "./reporting-helpers";

type HonoElement = HtmlEscapedString | Promise<HtmlEscapedString>;

interface CreateReportingRenderHelpersInput {
  templateById: ReadonlyMap<string, BadgeTemplateRecord>;
  orgUnitById: ReadonlyMap<string, TenantOrgUnitRecord>;
  reportingExplorePath: string;
  renderOrgUnitSummary: (orgUnitId: string) => HonoElement;
}

export const createReportingRenderHelpers = (input: CreateReportingRenderHelpersInput) => {
  const { templateById, orgUnitById, reportingExplorePath, renderOrgUnitSummary } = input;

  const getReportingOrgUnitLabel = (orgUnitId: string): string => {
    return orgUnitById.get(orgUnitId)?.displayName ?? orgUnitId;
  };
  const getReportingComparisonLabel = (row: TenantReportingComparisonRowRecord): string => {
    if (row.groupBy === "badgeTemplate") {
      return templateById.get(row.groupId)?.title ?? row.groupId;
    }

    return getReportingOrgUnitLabel(row.groupId);
  };
  const renderReportingComparisonGroupLabel = (
    row: TenantReportingComparisonRowRecord,
  ): HonoElement => {
    if (row.groupBy === "badgeTemplate") {
      const template = templateById.get(row.groupId);

      if (template === undefined) {
        return <strong>{row.groupId}</strong>;
      }

      return (
        <>
          <strong>{template.title}</strong>
          <div class="ct-admin__meta">{template.id}</div>
        </>
      );
    }

    return renderOrgUnitSummary(row.groupId);
  };
  const buildReportingLegendDetail = (input: {
    publicBadgeViewCount: number;
    claimRate: number;
    shareRate: number;
  }): string => {
    return `${formatReportingCount(input.publicBadgeViewCount)} public views · ${formatReportingRate(
      input.claimRate,
    )} claim · ${formatReportingRate(input.shareRate)} share`;
  };
  const buildReportingComparisonSeries = (
    rows: readonly TenantReportingComparisonRowRecord[],
  ): ReportingVisualSeriesPoint[] => {
    return rows
      .map((row) => ({
        label: getReportingComparisonLabel(row),
        value: row.issuedCount,
        detail: buildReportingLegendDetail({
          publicBadgeViewCount: row.publicBadgeViewCount,
          claimRate: row.claimRate,
          shareRate: row.shareRate,
        }),
      }))
      .sort((left, right) => {
        if (right.value !== left.value) {
          return right.value - left.value;
        }

        return left.label.localeCompare(right.label);
      });
  };
  const hasReportingActivity = (input: ReportingActivityCounts): boolean => {
    return (
      input.issuedCount > 0 ||
      input.publicBadgeViewCount > 0 ||
      input.verificationViewCount > 0 ||
      input.shareClickCount > 0 ||
      input.learnerClaimCount > 0 ||
      input.walletAcceptCount > 0
    );
  };
  const classifyReportingPanelState = (activeRowCount: number): ReportingPanelState => {
    if (activeRowCount === 0) {
      return "empty";
    }

    return activeRowCount === 1 ? "sparse" : "rich";
  };
  const renderReportingStateShell = (input: {
    description: string;
    eyebrow: string;
    state: Exclude<ReportingPanelState, "rich">;
    title: string;
  }): HonoElement => {
    return (
      <section
        class="ct-admin__reporting-state-shell ct-stack"
        data-reporting-panel-state={input.state}
      >
        <p class="ct-admin__eyebrow">{input.eyebrow}</p>
        <h3>{input.title}</h3>
        <p class="ct-admin__hint">{input.description}</p>
      </section>
    );
  };
  const renderReportingVisualModule = (input: {
    description: string;
    density?: "regular" | "compact";
    emptyMessage?: string;
    headingLevel?: "h3" | "h4";
    id?: string;
    kind:
      | "comparison-bars"
      | "comparison-ranked"
      | "journey-funnel"
      | "stacked-summary"
      | "trend-area"
      | "trend-series";
    note?: string;
    series: readonly ReportingVisualSeriesPoint[];
    seriesOrder?: "input" | "value-desc";
    showLegend?: boolean;
    showTrendContext?: boolean;
    sparseMessage?: string;
    summaryOverride?: string;
    title: string;
  }): HonoElement => {
    return (
      <div class="ct-admin__reporting-visual-shell">
        {renderReporting(input)}
        {input.note === undefined || input.note.trim().length === 0 ? null : (
          <p class="ct-admin__reporting-visual-note">{input.note}</p>
        )}
      </div>
    );
  };
  const renderReportingTrendCallout = (input: {
    kind: "peak" | "latest";
    label: string;
    row: TenantReportingTrendRecord["series"][number];
  }): HonoElement => {
    return (
      <article class="ct-admin__reporting-trend-callout" data-reporting-trend-callout={input.kind}>
        <p class="ct-admin__eyebrow">{input.label}</p>
        <h3>{formatReportingDateLabel(input.row.bucketStart)}</h3>
        <p class="ct-admin__meta">{`${formatReportingCount(input.row.issuedCount)} issued badges`}</p>
        <p class="ct-admin__meta">
          {`${formatReportingCount(input.row.publicBadgeViewCount)} public views · ${formatReportingCount(input.row.shareClickCount)} share clicks · ${formatReportingCount(input.row.walletAcceptCount)} wallet accepts`}
        </p>
      </article>
    );
  };
  const renderReportingCountCell = (value: number): string => {
    return formatReportingCount(value);
  };
  const buildVisibleOrgUnitLineage = (orgUnitId: string): TenantOrgUnitRecord[] => {
    const lineage: TenantOrgUnitRecord[] = [];
    const visited = new Set<string>();
    let currentOrgUnitId: string | null = orgUnitId;

    while (currentOrgUnitId !== null) {
      if (visited.has(currentOrgUnitId)) {
        break;
      }

      visited.add(currentOrgUnitId);
      const orgUnit = orgUnitById.get(currentOrgUnitId);

      if (orgUnit === undefined) {
        break;
      }

      if (!isReportingHierarchyLevel(orgUnit.unitType)) {
        break;
      }

      lineage.push(orgUnit);
      currentOrgUnitId = orgUnit.parentOrgUnitId;
    }

    return lineage;
  };
  const aggregateReportingHierarchyRows = (input: {
    comparisonRows: readonly TenantReportingComparisonRowRecord[];
    focusOrgUnitId?: string | undefined;
    level: ReportingHierarchyLevel;
  }): ReportingHierarchyRow[] => {
    const focusOrgUnit =
      input.focusOrgUnitId === undefined ? null : (orgUnitById.get(input.focusOrgUnitId) ?? null);

    if (focusOrgUnit !== null && !isReportingHierarchyLevel(focusOrgUnit.unitType)) {
      return [];
    }

    const groups = new Map<
      string,
      {
        orgUnit: TenantOrgUnitRecord;
        issuedCount: number;
        publicBadgeViewCount: number;
        verificationViewCount: number;
        shareClickCount: number;
        learnerClaimCount: number;
        walletAcceptCount: number;
        weightedClaimRateTotal: number;
        weightedShareRateTotal: number;
      }
    >();

    for (const row of input.comparisonRows) {
      const lineage = buildVisibleOrgUnitLineage(row.groupId);

      if (lineage.length === 0) {
        continue;
      }

      if (focusOrgUnit !== null && !lineage.some((orgUnit) => orgUnit.id === focusOrgUnit.id)) {
        continue;
      }

      const targetOrgUnit = lineage.find((orgUnit) => orgUnit.unitType === input.level);

      if (targetOrgUnit === undefined) {
        continue;
      }

      const group =
        groups.get(targetOrgUnit.id) ??
        (() => {
          const created = {
            orgUnit: targetOrgUnit,
            issuedCount: 0,
            publicBadgeViewCount: 0,
            verificationViewCount: 0,
            shareClickCount: 0,
            learnerClaimCount: 0,
            walletAcceptCount: 0,
            weightedClaimRateTotal: 0,
            weightedShareRateTotal: 0,
          };
          groups.set(targetOrgUnit.id, created);
          return created;
        })();

      group.issuedCount += row.issuedCount;
      group.publicBadgeViewCount += row.publicBadgeViewCount;
      group.verificationViewCount += row.verificationViewCount;
      group.shareClickCount += row.shareClickCount;
      group.learnerClaimCount += row.learnerClaimCount;
      group.walletAcceptCount += row.walletAcceptCount;
      group.weightedClaimRateTotal += row.claimRate * row.issuedCount;
      group.weightedShareRateTotal += row.shareRate * row.issuedCount;
    }

    return Array.from(groups.values())
      .map((group) => {
        const issuedCount = group.issuedCount;

        return {
          orgUnitId: group.orgUnit.id,
          level: input.level,
          issuedCount,
          publicBadgeViewCount: group.publicBadgeViewCount,
          verificationViewCount: group.verificationViewCount,
          shareClickCount: group.shareClickCount,
          learnerClaimCount: group.learnerClaimCount,
          walletAcceptCount: group.walletAcceptCount,
          claimRate: issuedCount === 0 ? 0 : group.weightedClaimRateTotal / issuedCount,
          shareRate: issuedCount === 0 ? 0 : group.weightedShareRateTotal / issuedCount,
        };
      })
      .sort((left, right) => {
        if (right.issuedCount !== left.issuedCount) {
          return right.issuedCount - left.issuedCount;
        }

        return left.orgUnitId.localeCompare(right.orgUnitId);
      });
  };
  const buildReportingHierarchyDrillHref = (orgUnitId: string): string => {
    return `${reportingExplorePath}#${buildReportingHierarchyFocusId(orgUnitId)}`;
  };
  const renderReportingHierarchyRowLabel = (row: ReportingHierarchyRow): HonoElement => {
    const orgUnit = orgUnitById.get(row.orgUnitId);

    if (orgUnit === undefined || !isReportingHierarchyLevel(orgUnit.unitType)) {
      return renderOrgUnitSummary(row.orgUnitId);
    }

    const nextLevel = getNextReportingHierarchyLevel(orgUnit.unitType);

    if (nextLevel === null) {
      return (
        <>
          {renderOrgUnitSummary(row.orgUnitId)}
          <div class="ct-admin__meta">Deepest reporting level</div>
        </>
      );
    }

    return (
      <>
        {renderOrgUnitSummary(row.orgUnitId)}
        <div class="ct-admin__meta">
          <a data-reporting-drill-link href={buildReportingHierarchyDrillHref(row.orgUnitId)}>
            View {formatReportingHierarchyLevelLabel(nextLevel).toLowerCase()} drilldown
          </a>
        </div>
      </>
    );
  };
  const renderReportingHierarchyRows = (
    rows: readonly ReportingHierarchyRow[],
    emptyLabel: string,
  ): HonoElement => {
    if (rows.length === 0) {
      return <AdminEmptyTableRow colSpan={9}>{emptyLabel}</AdminEmptyTableRow>;
    }

    return (
      <>
        {rows.map((row) => (
          <tr>
            <td>{renderReportingHierarchyRowLabel(row)}</td>
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

  return {
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
  };
};

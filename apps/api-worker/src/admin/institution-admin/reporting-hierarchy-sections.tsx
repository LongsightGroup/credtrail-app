import type { TenantOrgUnitRecord, TenantReportingComparisonRowRecord } from "@credtrail/db";
import type { HtmlEscapedString } from "hono/utils/html";
import { AdminButtonLink, AdminEmptyTableRow, AdminTable } from "../components";
import type { InstitutionAdminPageInput } from "./page-types";
import {
  REPORTING_HIERARCHY_DEPTH,
  REPORTING_HIERARCHY_LEVELS,
  REPORTING_PERFORMER_ROW_LIMIT,
  REPORTING_RATE_MIN_ISSUED,
  buildReportingHierarchyFocusId,
  formatReportingCount,
  formatReportingHierarchyLevelLabel,
  formatReportingRate,
  getNextReportingHierarchyLevel,
  isReportingHierarchyLevel,
  type ReportingHierarchyLevel,
  type ReportingHierarchyRow,
} from "./reporting-helpers";
import { createReportingRenderHelpers } from "./reporting-render-helpers";

type HonoElement = HtmlEscapedString | Promise<HtmlEscapedString>;
type ReportingRenderHelpers = ReturnType<typeof createReportingRenderHelpers>;

interface RenderInstitutionAdminReportingHierarchySectionsInput {
  input: InstitutionAdminPageInput;
  orgUnitById: ReadonlyMap<string, TenantOrgUnitRecord>;
  reportingOrgUnitComparisons: readonly TenantReportingComparisonRowRecord[];
  reportingHierarchyScopeSummary: string;
  buildReportingHierarchyExportHref: (focus: {
    focusOrgUnitId: string;
    level: ReportingHierarchyLevel;
  }) => string;
  renderOrgUnitSummary: (orgUnitId: string) => HonoElement;
  helpers: ReportingRenderHelpers;
}

interface InstitutionAdminReportingHierarchySections {
  reportingHierarchyPanelMarkup: HonoElement;
  reportingPerformerPanelsMarkup: HonoElement;
}

export const renderInstitutionAdminReportingHierarchySections = (
  source: RenderInstitutionAdminReportingHierarchySectionsInput,
): InstitutionAdminReportingHierarchySections => {
  const {
    input,
    orgUnitById,
    reportingOrgUnitComparisons,
    reportingHierarchyScopeSummary,
    buildReportingHierarchyExportHref,
    renderOrgUnitSummary,
    helpers,
  } = source;
  const {
    aggregateReportingHierarchyRows,
    buildReportingHierarchyDrillHref,
    buildReportingLegendDetail,
    classifyReportingPanelState,
    getReportingOrgUnitLabel,
    hasReportingActivity,
    renderReportingCountCell,
    renderReportingHierarchyRows,
    renderReportingStateShell,
    renderReportingVisualModule,
  } = helpers;

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

  return {
    reportingHierarchyPanelMarkup,
    reportingPerformerPanelsMarkup,
  };
};

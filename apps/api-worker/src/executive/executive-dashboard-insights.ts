import type { ExecutiveDashboardModuleDescriptor } from "./executive-kpi-catalog";
import type { TenantExecutiveDashboardRecord } from "./executive-rollup-loader";
import type { ReportingVisualProps } from "../reporting/reporting-visuals";

const MIN_ISSUED_FOR_RATE_COMPARISON = 5;

export interface ExecutiveDashboardInsightSummaryItem {
  label: string;
  value: string;
}

export interface ExecutiveDashboardInsightLink {
  label: string;
  href: string;
}

export interface ExecutiveDashboardInsight {
  id: string;
  kicker: string;
  title: string;
  description: string;
  note?: string;
  visual?: ReportingVisualProps;
  summaryItems?: readonly ExecutiveDashboardInsightSummaryItem[];
  links?: readonly ExecutiveDashboardInsightLink[];
}

export interface ExecutiveDashboardInsights {
  trend: ExecutiveDashboardInsight;
  modules: readonly ExecutiveDashboardInsight[];
}

const formatCount = (value: number): string => {
  return new Intl.NumberFormat("en-US", {
    maximumFractionDigits: 0,
  }).format(value);
};

const formatPercent = (value: number): string => {
  return new Intl.NumberFormat("en-US", {
    minimumFractionDigits: 1,
    maximumFractionDigits: 1,
  }).format(value);
};

const titleCase = (value: string): string => {
  return value
    .split("-")
    .map((segment) => segment.charAt(0).toUpperCase() + segment.slice(1))
    .join(" ");
};

const formatBucketLabel = (value: string): string => {
  const parsed = new Date(`${value}T00:00:00.000Z`);

  if (Number.isNaN(parsed.getTime())) {
    return value;
  }

  return new Intl.DateTimeFormat("en-US", {
    month: "short",
    day: "numeric",
  }).format(parsed);
};

const buildIssuedDetail = (
  row: TenantExecutiveDashboardRecord["rollup"]["rows"][number],
): string => {
  return `${formatCount(row.publicBadgeViewCount)} public views · ${formatPercent(
    row.claimRate,
  )}% claim · ${formatPercent(row.shareRate)}% share`;
};

const buildRateDetail = (
  row: TenantExecutiveDashboardRecord["rollup"]["rows"][number],
  companionMetric: "claimRate" | "shareRate",
): string => {
  const companionLabel = companionMetric === "claimRate" ? "claim" : "share";
  const companionValue = companionMetric === "claimRate" ? row.claimRate : row.shareRate;

  return `${formatCount(row.issuedCount)} issued · ${formatPercent(companionValue)}% ${companionLabel}`;
};

const buildTrendInsight = (
  dashboard: TenantExecutiveDashboardRecord,
): ExecutiveDashboardInsight => {
  const latestBucket = dashboard.trends.series.at(-1) ?? null;
  const previousBucket = dashboard.trends.series.at(-2) ?? null;
  const deltaIssued =
    latestBucket === null || previousBucket === null
      ? null
      : latestBucket.issuedCount - previousBucket.issuedCount;
  const deltaLabel =
    deltaIssued === null
      ? null
      : deltaIssued === 0
        ? "holding steady versus the prior bucket"
        : `${formatCount(Math.abs(deltaIssued))} ${
            deltaIssued > 0 ? "more" : "fewer"
          } issued than the prior bucket`;

  return {
    id: "trend",
    kicker: "Trend",
    title: "Issued badges over time",
    description:
      "Issued volume stays primary while claim and share activity travels with the same executive slice.",
    note:
      latestBucket === null
        ? "Trend buckets will appear once the current executive slice has enough reporting activity."
        : `${formatBucketLabel(latestBucket.bucketStart)} closed with ${formatCount(
            latestBucket.issuedCount,
          )} issued, ${formatCount(latestBucket.learnerClaimCount)} claims, and ${formatCount(
            latestBucket.shareClickCount,
          )} shares${deltaLabel === null ? "" : `, ${deltaLabel}`}.`,
    visual: {
      kind: "trend-series",
      title: "Issued badges by time bucket",
      description:
        "The executive dashboard keeps exact values visible while the chart shows overall movement.",
      series: dashboard.trends.series.map((bucket) => {
        return {
          label: formatBucketLabel(bucket.bucketStart),
          value: bucket.issuedCount,
          detail: `${formatCount(bucket.learnerClaimCount)} claims · ${formatCount(
            bucket.shareClickCount,
          )} shares`,
        };
      }),
      emptyMessage: "No trend buckets are available for this executive slice yet.",
      ...(dashboard.trends.series.length <= 1
        ? {
            sparseMessage:
              "Only one trend bucket is visible, so treat this as a starting point rather than a movement story.",
          }
        : {}),
    },
  };
};

const buildComparisonSummaryInsight = (
  dashboard: TenantExecutiveDashboardRecord,
  module: ExecutiveDashboardModuleDescriptor,
): ExecutiveDashboardInsight => {
  return {
    id: module.id,
    kicker: "Compare",
    title: module.title,
    description: module.description,
    note: `${formatCount(
      dashboard.rollup.rows.length,
    )} visible ${titleCase(dashboard.rollup.comparisonLevel).toLowerCase()} rows are included in this slice.`,
    visual: {
      kind: "comparison-ranked",
      title: module.title,
      description: module.description,
      series: dashboard.rollup.rows.map((row) => {
        return {
          label: row.displayName,
          value: row.issuedCount,
          detail: buildIssuedDetail(row),
        };
      }),
      summaryOverride: `Comparing ${titleCase(
        dashboard.rollup.comparisonLevel,
      ).toLowerCase()} rows by issued badges. Claim and share rates stay visible beside each row.`,
      ...(dashboard.rollup.rows.length <= 1
        ? {
            sparseMessage:
              "Only one visible comparison row is available, so use the exact row values below as the current executive truth.",
          }
        : {}),
    },
    ...(dashboard.navigation.drilldowns.length > 0
      ? {
          links: dashboard.navigation.drilldowns.map((link) => {
            return {
              label: link.label,
              href: link.href,
            };
          }),
        }
      : {}),
  };
};

const buildRateSummaryFallback = (
  module: ExecutiveDashboardModuleDescriptor,
  qualifyingRowCount: number,
): ExecutiveDashboardInsight => {
  return {
    id: module.id,
    kicker: module.kind === "laggards" ? "Lagging signal" : "Rate signal",
    title: module.title,
    description: module.description,
    note: `CredTrail requires at least two visible rows with ${formatCount(
      MIN_ISSUED_FOR_RATE_COMPARISON,
    )} or more issued badges before it will rank engagement rates.`,
    summaryItems: [
      {
        label: "Qualifying rows",
        value: formatCount(qualifyingRowCount),
      },
      {
        label: "Threshold",
        value: `${formatCount(MIN_ISSUED_FOR_RATE_COMPARISON)} issued`,
      },
    ],
  };
};

const buildRateInsight = (
  dashboard: TenantExecutiveDashboardRecord,
  module: ExecutiveDashboardModuleDescriptor,
): ExecutiveDashboardInsight => {
  const metricKey = module.metricKey;

  if (metricKey !== "claimRate" && metricKey !== "shareRate") {
    return buildComparisonSummaryInsight(dashboard, module);
  }

  const qualifyingRows = dashboard.rollup.rows.filter(
    (row) => row.issuedCount >= MIN_ISSUED_FOR_RATE_COMPARISON,
  );

  if (qualifyingRows.length < 2) {
    return buildRateSummaryFallback(module, qualifyingRows.length);
  }

  const sortedRows = [...qualifyingRows].sort((left, right) => {
    const leftValue = metricKey === "claimRate" ? left.claimRate : left.shareRate;
    const rightValue = metricKey === "claimRate" ? right.claimRate : right.shareRate;

    if (module.ranking === "bottom") {
      if (leftValue !== rightValue) {
        return leftValue - rightValue;
      }
    } else if (rightValue !== leftValue) {
      return rightValue - leftValue;
    }

    return left.displayName.localeCompare(right.displayName);
  });

  const companionMetric = metricKey === "claimRate" ? "shareRate" : "claimRate";
  const summaryVerb = module.ranking === "bottom" ? "lowest" : "highest";

  return {
    id: module.id,
    kicker: module.ranking === "bottom" ? "Laggard" : "Leader",
    title: module.title,
    description: module.description,
    note: `Ranking the ${summaryVerb} ${metricKey === "claimRate" ? "claim" : "share"} rates across rows that meet the minimum issued threshold.`,
    visual: {
      kind: "comparison-ranked",
      title: module.title,
      description: module.description,
      series: sortedRows.map((row) => {
        return {
          label: row.displayName,
          value: metricKey === "claimRate" ? row.claimRate : row.shareRate,
          detail: buildRateDetail(row, companionMetric),
        };
      }),
      seriesOrder: "input",
      summaryOverride: `Comparing ${titleCase(
        dashboard.rollup.comparisonLevel,
      ).toLowerCase()} rows by ${metricKey === "claimRate" ? "claim" : "share"} rate. Issued totals stay visible so the ranking does not hide volume.`,
    },
  };
};

const buildFocusSummaryInsight = (
  dashboard: TenantExecutiveDashboardRecord,
  module: ExecutiveDashboardModuleDescriptor,
): ExecutiveDashboardInsight => {
  return {
    id: module.id,
    kicker: "Current focus",
    title: module.title,
    description: module.description,
    summaryItems: [
      {
        label: "Focus",
        value: dashboard.rollup.focusDisplayName,
      },
      {
        label: "Audience",
        value: titleCase(dashboard.defaults.audience),
      },
      {
        label: "Compare next",
        value: titleCase(dashboard.rollup.comparisonLevel),
      },
    ],
  };
};

const buildDrilldownSummaryInsight = (
  dashboard: TenantExecutiveDashboardRecord,
  module: ExecutiveDashboardModuleDescriptor,
): ExecutiveDashboardInsight => {
  const links =
    dashboard.navigation.drilldowns.length > 0
      ? dashboard.navigation.drilldowns.map((link) => {
          return {
            label: link.label,
            href: link.href,
          };
        })
      : dashboard.navigation.back === null
        ? []
        : [
            {
              label: `Back to ${dashboard.navigation.back.label}`,
              href: dashboard.navigation.back.href,
            },
          ];

  return {
    id: module.id,
    kicker: "Drilldown",
    title: module.title,
    description: module.description,
    note:
      links.length === 0
        ? "No deeper visible slice is available right now, so this route stays anchored to the current executive summary."
        : "Stay inside the executive route family while moving into the next visible slice.",
    summaryItems: [
      {
        label: "Route family",
        value: "/executive",
      },
      {
        label: "Focus",
        value: dashboard.rollup.focusDisplayName,
      },
      {
        label: "Visible rows",
        value: formatCount(dashboard.rollup.rows.length),
      },
    ],
    ...(links.length > 0 ? { links } : {}),
  };
};

const buildInsightFromModule = (
  dashboard: TenantExecutiveDashboardRecord,
  module: ExecutiveDashboardModuleDescriptor,
): ExecutiveDashboardInsight => {
  switch (module.kind) {
    case "comparison_summary":
      return buildComparisonSummaryInsight(dashboard, module);
    case "top_movers":
    case "laggards":
      if (module.metricKey === "issued") {
        return buildComparisonSummaryInsight(dashboard, module);
      }

      return buildRateInsight(dashboard, module);
    case "focus_summary":
      return buildFocusSummaryInsight(dashboard, module);
    case "drilldown":
      return buildDrilldownSummaryInsight(dashboard, module);
    default:
      return buildFocusSummaryInsight(dashboard, module);
  }
};

export const buildExecutiveDashboardInsights = (
  dashboard: TenantExecutiveDashboardRecord,
): ExecutiveDashboardInsights => {
  return {
    trend: buildTrendInsight(dashboard),
    modules: dashboard.kpiCatalog.modules.map((module) =>
      buildInsightFromModule(dashboard, module),
    ),
  };
};

import { escapeHtml } from "../utils/display-format";

export type ReportingVisualKind =
  | "comparison-bars"
  | "comparison-ranked"
  | "stacked-summary"
  | "trend-series";
export type ReportingVisualHeadingLevel = "h3" | "h4";

export interface ReportingVisualSeriesPoint {
  label: string;
  value: number;
  detail?: string;
}

export interface ReportingVisualProps {
  kind: ReportingVisualKind;
  title: string;
  description?: string;
  series: readonly ReportingVisualSeriesPoint[];
  id?: string;
  emptyMessage?: string;
  sparseMessage?: string;
  headingLevel?: ReportingVisualHeadingLevel;
  summaryOverride?: string;
  seriesOrder?: "input" | "value-desc";
}

const REPORTING_VISUAL_EMPTY_MESSAGE = "No reporting data available for this view yet.";
const REPORTING_COMPARISON_RANKED_LIMIT = 5;
const REPORTING_VISUAL_WIDTH = 360;
const REPORTING_VISUAL_PADDING = 16;

const formatValue = (value: number): string => {
  const normalizedValue = Number.isFinite(value) ? value : 0;

  if (Number.isInteger(normalizedValue)) {
    return new Intl.NumberFormat("en-US", {
      maximumFractionDigits: 0,
    }).format(normalizedValue);
  }

  return new Intl.NumberFormat("en-US", {
    minimumFractionDigits: 1,
    maximumFractionDigits: 1,
  }).format(normalizedValue);
};

const slugify = (value: string): string => {
  const collapsed = value
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "");

  return collapsed.length > 0 ? collapsed : "reporting-visual";
};

const normalizeValue = (value: number): number => {
  if (!Number.isFinite(value) || value <= 0) {
    return 0;
  }

  return value;
};

const hasRenderableData = (series: readonly ReportingVisualSeriesPoint[]): boolean => {
  return series.some((point) => normalizeValue(point.value) > 0);
};

const sortComparisonRankedSeries = (
  input: ReportingVisualProps,
  series: readonly ReportingVisualSeriesPoint[],
): ReportingVisualSeriesPoint[] => {
  if (input.seriesOrder === "input") {
    return [...series];
  }

  return [...series].sort((left, right) => {
    if (right.value !== left.value) {
      return right.value - left.value;
    }

    return left.label.localeCompare(right.label);
  });
};

const buildVisualId = (input: ReportingVisualProps): string => {
  const explicitId = input.id?.trim();

  if (explicitId !== undefined && explicitId.length > 0) {
    return slugify(explicitId);
  }

  return `${input.kind}-${slugify(input.title)}`;
};

const buildLegendDetail = (
  input: ReportingVisualProps,
  point: ReportingVisualSeriesPoint,
  maxValue: number,
  totalValue: number,
): string | null => {
  if (point.detail !== undefined && point.detail.trim().length > 0) {
    return point.detail.trim();
  }

  if (input.kind === "stacked-summary" && totalValue > 0) {
    return `${((normalizeValue(point.value) / totalValue) * 100).toFixed(1)}% of total`;
  }

  if (input.kind === "comparison-bars" && maxValue > 0) {
    return `${((normalizeValue(point.value) / maxValue) * 100).toFixed(1)}% of max`;
  }

  return null;
};

const buildSummaryText = (
  input: ReportingVisualProps,
  normalizedSeries: readonly ReportingVisualSeriesPoint[],
  totalValue: number,
): string => {
  if (input.kind === "stacked-summary") {
    return `Total ${formatValue(totalValue)} across ${normalizedSeries.length} segments.`;
  }

  const sortedSeries = [...normalizedSeries].sort((left, right) => right.value - left.value);
  const highestPoint = sortedSeries[0];

  if (highestPoint === undefined) {
    return "No reporting data available for this view yet.";
  }

  if (input.kind === "trend-series") {
    const lowestPoint = sortedSeries[sortedSeries.length - 1] ?? highestPoint;

    return `${highestPoint.label} peaks at ${formatValue(highestPoint.value)} while ${lowestPoint.label} sits at ${formatValue(lowestPoint.value)}.`;
  }

  if (input.kind === "comparison-ranked") {
    const highestRankedPoint =
      sortComparisonRankedSeries(input, normalizedSeries)[0] ?? highestPoint;

    return `${highestRankedPoint.label} leads at ${formatValue(highestRankedPoint.value)} across ${normalizedSeries.length} comparison rows.`;
  }

  return `${highestPoint.label} leads at ${formatValue(highestPoint.value)} across ${normalizedSeries.length} comparison points.`;
};

const renderLegend = (
  input: ReportingVisualProps,
  normalizedSeries: readonly ReportingVisualSeriesPoint[],
  totalValue: number,
  maxValue: number,
): string => {
  if (input.kind === "comparison-ranked") {
    return "";
  }

  const items = normalizedSeries
    .map((point, index) => {
      const detail = buildLegendDetail(input, point, maxValue, totalValue);
      const detailMarkup =
        detail === null
          ? ""
          : `<span class="ct-reporting-visual__legend-detail">${escapeHtml(detail)}</span>`;

      return `<li class="ct-reporting-visual__legend-item" data-reporting-visual-index="${String(index)}">
        <span class="ct-reporting-visual__swatch ct-reporting-visual__swatch--${String(index % 4)}" aria-hidden="true"></span>
        <span class="ct-reporting-visual__legend-label">${escapeHtml(point.label)}</span>
        <strong class="ct-reporting-visual__legend-value">${escapeHtml(formatValue(point.value))}</strong>
        ${detailMarkup}
      </li>`;
    })
    .join("");

  return `<div class="ct-reporting-visual__legend-block">
    <p class="ct-reporting-visual__legend-title">Legend</p>
    <ol class="ct-reporting-visual__legend">${items}</ol>
  </div>`;
};

const renderComparisonRankedGraphic = (
  input: ReportingVisualProps,
  normalizedSeries: readonly ReportingVisualSeriesPoint[],
  titleId: string,
  descriptionIds: string,
): string => {
  const sortedSeries = sortComparisonRankedSeries(input, normalizedSeries);
  const emphasizedSeries = sortedSeries.slice(0, REPORTING_COMPARISON_RANKED_LIMIT);
  const maxValue = Math.max(...emphasizedSeries.map((point) => point.value), 1);
  const items = emphasizedSeries
    .map((point, index) => {
      const width = Math.max((point.value / maxValue) * 100, 12);
      const detailMarkup =
        point.detail === undefined || point.detail.trim().length === 0
          ? ""
          : `<span class="ct-reporting-visual__comparison-ranked-detail">${escapeHtml(point.detail)}</span>`;

      return `<li class="ct-reporting-visual__comparison-ranked-item" data-reporting-visual-index="${String(index)}">
        <div class="ct-reporting-visual__comparison-ranked-head">
          <span class="ct-reporting-visual__comparison-ranked-label">${escapeHtml(point.label)}</span>
          <strong class="ct-reporting-visual__comparison-ranked-value">${escapeHtml(formatValue(point.value))}</strong>
        </div>
        <div class="ct-reporting-visual__comparison-ranked-bar-track" aria-hidden="true">
          <span class="ct-reporting-visual__comparison-ranked-bar ct-reporting-visual__comparison-ranked-bar--${String(
            index % 4,
          )}" style="width:${width.toFixed(2)}%"></span>
        </div>
        ${detailMarkup}
      </li>`;
    })
    .join("");
  const overflowMarkup =
    sortedSeries.length > REPORTING_COMPARISON_RANKED_LIMIT
      ? `<p class="ct-reporting-visual__comparison-ranked-overflow">Top ${String(
          REPORTING_COMPARISON_RANKED_LIMIT,
        )} shown here. The exact table below keeps all ${String(sortedSeries.length)} visible rows.</p>`
      : "";

  return `<div class="ct-reporting-visual__comparison-ranked" role="img" aria-labelledby="${titleId}" aria-describedby="${descriptionIds}" data-reporting-visual-emphasis-count="${String(Math.min(sortedSeries.length, REPORTING_COMPARISON_RANKED_LIMIT))}">
    <ol class="ct-reporting-visual__comparison-ranked-list">
      ${items}
    </ol>
    ${overflowMarkup}
  </div>`;
};

const renderComparisonGraphic = (
  normalizedSeries: readonly ReportingVisualSeriesPoint[],
  titleId: string,
  descriptionIds: string,
): string => {
  const maxValue = Math.max(...normalizedSeries.map((point) => normalizeValue(point.value)), 1);
  const barHeight = 18;
  const gap = 14;
  const chartHeight =
    REPORTING_VISUAL_PADDING * 2 +
    normalizedSeries.length * barHeight +
    (normalizedSeries.length - 1) * gap;
  const availableWidth = REPORTING_VISUAL_WIDTH - REPORTING_VISUAL_PADDING * 2;

  const bars = normalizedSeries
    .map((point, index) => {
      const y = REPORTING_VISUAL_PADDING + index * (barHeight + gap);
      const width = Math.max((normalizeValue(point.value) / maxValue) * availableWidth, 2);

      return `<g class="ct-reporting-visual__bar-row">
        <rect class="ct-reporting-visual__bar-track" x="${String(REPORTING_VISUAL_PADDING)}" y="${String(y)}" width="${String(availableWidth)}" height="${String(barHeight)}" rx="9"></rect>
        <rect class="ct-reporting-visual__bar ct-reporting-visual__bar--${String(index % 4)}" x="${String(REPORTING_VISUAL_PADDING)}" y="${String(y)}" width="${width.toFixed(2)}" height="${String(barHeight)}" rx="9"></rect>
      </g>`;
    })
    .join("");

  return `<svg class="ct-reporting-visual__graphic" viewBox="0 0 ${String(REPORTING_VISUAL_WIDTH)} ${String(chartHeight)}" role="img" aria-labelledby="${titleId}" aria-describedby="${descriptionIds}">
    <desc>Visible labels and numeric values are listed in the legend below.</desc>
    ${bars}
  </svg>`;
};

const renderStackedGraphic = (
  normalizedSeries: readonly ReportingVisualSeriesPoint[],
  titleId: string,
  descriptionIds: string,
): string => {
  const totalValue = normalizedSeries.reduce((sum, point) => sum + normalizeValue(point.value), 0);
  const chartHeight = 68;
  const availableWidth = REPORTING_VISUAL_WIDTH - REPORTING_VISUAL_PADDING * 2;
  let x = REPORTING_VISUAL_PADDING;

  const segments = normalizedSeries
    .map((point, index) => {
      const width = Math.max((normalizeValue(point.value) / totalValue) * availableWidth, 2);
      const segment = `<rect class="ct-reporting-visual__segment ct-reporting-visual__segment--${String(index % 4)}" x="${x.toFixed(2)}" y="22" width="${width.toFixed(2)}" height="24" rx="10"></rect>`;
      x += width;
      return segment;
    })
    .join("");

  return `<svg class="ct-reporting-visual__graphic" viewBox="0 0 ${String(REPORTING_VISUAL_WIDTH)} ${String(chartHeight)}" role="img" aria-labelledby="${titleId}" aria-describedby="${descriptionIds}">
    <desc>Visible labels and numeric values are listed in the legend below.</desc>
    <rect class="ct-reporting-visual__segment-track" x="${String(REPORTING_VISUAL_PADDING)}" y="22" width="${String(availableWidth)}" height="24" rx="10"></rect>
    ${segments}
  </svg>`;
};

const renderTrendGraphic = (
  normalizedSeries: readonly ReportingVisualSeriesPoint[],
  titleId: string,
  descriptionIds: string,
): string => {
  const maxValue = Math.max(...normalizedSeries.map((point) => normalizeValue(point.value)), 1);
  const chartHeight = 160;
  const chartWidth = REPORTING_VISUAL_WIDTH;
  const baseline = chartHeight - REPORTING_VISUAL_PADDING;
  const usableHeight = chartHeight - REPORTING_VISUAL_PADDING * 3;
  const usableWidth = chartWidth - REPORTING_VISUAL_PADDING * 2;
  const xStep = normalizedSeries.length === 1 ? 0 : usableWidth / (normalizedSeries.length - 1);

  const points = normalizedSeries.map((point, index) => {
    const x = REPORTING_VISUAL_PADDING + index * xStep;
    const y = baseline - (normalizeValue(point.value) / maxValue) * usableHeight;

    return {
      index,
      x,
      y,
      label: point.label,
    };
  });

  const polyline = points.map((point) => `${point.x.toFixed(2)},${point.y.toFixed(2)}`).join(" ");
  const pointMarkup = points
    .map((point) => {
      return `<g class="ct-reporting-visual__point-group">
        <circle class="ct-reporting-visual__point ct-reporting-visual__point--${String(point.index % 4)}" cx="${point.x.toFixed(2)}" cy="${point.y.toFixed(2)}" r="4"></circle>
      </g>`;
    })
    .join("");

  return `<svg class="ct-reporting-visual__graphic" viewBox="0 0 ${String(chartWidth)} ${String(chartHeight)}" role="img" aria-labelledby="${titleId}" aria-describedby="${descriptionIds}">
    <desc>Visible labels and numeric values are listed in the legend below.</desc>
    <line class="ct-reporting-visual__baseline" x1="${String(REPORTING_VISUAL_PADDING)}" y1="${String(baseline)}" x2="${String(chartWidth - REPORTING_VISUAL_PADDING)}" y2="${String(baseline)}"></line>
    <polyline class="ct-reporting-visual__trend-line" points="${polyline}"></polyline>
    ${pointMarkup}
  </svg>`;
};

const renderTrendContext = (normalizedSeries: readonly ReportingVisualSeriesPoint[]): string => {
  const startPoint = normalizedSeries[0];
  const latestPoint = normalizedSeries[normalizedSeries.length - 1] ?? startPoint;
  const peakPoint =
    [...normalizedSeries].sort((left, right) => right.value - left.value)[0] ?? latestPoint;

  if (startPoint === undefined || latestPoint === undefined || peakPoint === undefined) {
    return "";
  }

  const renderAxisItem = (label: "Start" | "Latest", point: ReportingVisualSeriesPoint): string => {
    return `<div class="ct-reporting-visual__trend-axis-item" data-reporting-trend-point="${slugify(label)}">
      <span class="ct-reporting-visual__trend-axis-label">${escapeHtml(label)}</span>
      <strong class="ct-reporting-visual__trend-axis-value">${escapeHtml(point.label)}</strong>
      <span class="ct-reporting-visual__trend-axis-detail">${escapeHtml(formatValue(point.value))}</span>
    </div>`;
  };

  const renderCallout = (label: "Peak" | "Latest", point: ReportingVisualSeriesPoint): string => {
    const detailMarkup =
      point.detail === undefined || point.detail.trim().length === 0
        ? ""
        : `<span class="ct-reporting-visual__trend-callout-detail">${escapeHtml(point.detail)}</span>`;

    return `<li class="ct-reporting-visual__trend-callout" data-reporting-trend-callout="${slugify(label)}">
      <span class="ct-reporting-visual__trend-callout-label">${escapeHtml(label)}</span>
      <strong class="ct-reporting-visual__trend-callout-value">${escapeHtml(point.label)}</strong>
      <span class="ct-reporting-visual__trend-callout-metric">${escapeHtml(formatValue(point.value))}</span>
      ${detailMarkup}
    </li>`;
  };

  return `<div class="ct-reporting-visual__trend-context">
    <div class="ct-reporting-visual__trend-axis">
      ${renderAxisItem("Start", startPoint)}
      ${renderAxisItem("Latest", latestPoint)}
    </div>
    <ol class="ct-reporting-visual__trend-callouts">
      ${renderCallout("Peak", peakPoint)}
      ${renderCallout("Latest", latestPoint)}
    </ol>
  </div>`;
};

const renderGraphic = (
  input: ReportingVisualProps,
  normalizedSeries: readonly ReportingVisualSeriesPoint[],
  titleId: string,
  descriptionIds: string,
): string => {
  switch (input.kind) {
    case "comparison-ranked":
      return renderComparisonRankedGraphic(input, normalizedSeries, titleId, descriptionIds);
    case "comparison-bars":
      return renderComparisonGraphic(normalizedSeries, titleId, descriptionIds);
    case "stacked-summary":
      return renderStackedGraphic(normalizedSeries, titleId, descriptionIds);
    case "trend-series":
      return renderTrendGraphic(normalizedSeries, titleId, descriptionIds);
  }
};

export const renderReporting = (input: ReportingVisualProps): string => {
  const visualId = buildVisualId(input);
  const titleId = `${visualId}-title`;
  const descriptionId = `${visualId}-description`;
  const summaryId = `${visualId}-summary`;
  const titleTag = input.headingLevel ?? "h3";
  const normalizedSeries = input.series.map((point) => ({
    ...point,
    value: normalizeValue(point.value),
  }));
  const totalValue = normalizedSeries.reduce((sum, point) => sum + point.value, 0);
  const maxValue = Math.max(...normalizedSeries.map((point) => point.value), 0);
  const descriptionIds = [input.description !== undefined ? descriptionId : null, summaryId]
    .filter((value): value is string => value !== null)
    .join(" ");
  const descriptionMarkup =
    input.description === undefined
      ? ""
      : `<p id="${descriptionId}" class="ct-reporting-visual__description">${escapeHtml(input.description)}</p>`;

  if (!hasRenderableData(normalizedSeries)) {
    return `<figure class="ct-reporting-visual" data-reporting-visual-kind="${escapeHtml(input.kind)}" data-reporting-visual-state="empty">
      <figcaption class="ct-reporting-visual__header">
        <${titleTag} id="${titleId}" class="ct-reporting-visual__title">${escapeHtml(input.title)}</${titleTag}>
        ${descriptionMarkup}
      </figcaption>
      <div id="${summaryId}" class="ct-reporting-visual__empty">
        ${escapeHtml(input.emptyMessage ?? REPORTING_VISUAL_EMPTY_MESSAGE)}
      </div>
    </figure>`;
  }

  const trimmedSparseMessage = input.sparseMessage?.trim();

  if (trimmedSparseMessage !== undefined && trimmedSparseMessage.length > 0) {
    return `<figure class="ct-reporting-visual" data-reporting-visual-kind="${escapeHtml(input.kind)}" data-reporting-visual-state="sparse">
      <figcaption class="ct-reporting-visual__header">
        <${titleTag} id="${titleId}" class="ct-reporting-visual__title">${escapeHtml(input.title)}</${titleTag}>
        ${descriptionMarkup}
      </figcaption>
      <div id="${summaryId}" class="ct-reporting-visual__empty ct-reporting-visual__empty--sparse">
        ${escapeHtml(trimmedSparseMessage)}
      </div>
    </figure>`;
  }

  const trimmedSummaryOverride = input.summaryOverride?.trim();
  const summaryText =
    trimmedSummaryOverride === undefined || trimmedSummaryOverride.length === 0
      ? buildSummaryText(input, normalizedSeries, totalValue)
      : trimmedSummaryOverride;
  const graphicMarkup = renderGraphic(input, normalizedSeries, titleId, descriptionIds);
  const trendContextMarkup =
    input.kind === "trend-series" ? renderTrendContext(normalizedSeries) : "";
  const legendMarkup = renderLegend(input, normalizedSeries, totalValue, maxValue);

  return `<figure class="ct-reporting-visual" data-reporting-visual-kind="${escapeHtml(input.kind)}" data-reporting-visual-state="ready">
    <figcaption class="ct-reporting-visual__header">
      <${titleTag} id="${titleId}" class="ct-reporting-visual__title">${escapeHtml(input.title)}</${titleTag}>
      ${descriptionMarkup}
    </figcaption>
    <div class="ct-reporting-visual__surface">
      ${graphicMarkup}
    </div>
    ${trendContextMarkup}
    <p id="${summaryId}" class="ct-reporting-visual__summary">${escapeHtml(summaryText)}</p>
    ${legendMarkup}
  </figure>`;
};

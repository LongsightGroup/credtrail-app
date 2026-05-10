import { scaleLinear } from "d3-scale";
import { curveMonotoneX, line } from "d3-shape";
import type { HtmlEscapedString } from "hono/utils/html";

type HonoElement = HtmlEscapedString | Promise<HtmlEscapedString>;

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

interface ReportingTrendPoint {
  index: number;
  x: number;
  y: number;
  label: string;
  value: number;
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

const VisualHeading = (input: {
  headingLevel: ReportingVisualHeadingLevel;
  id: string;
  title: string;
}): HonoElement => {
  if (input.headingLevel === "h4") {
    return (
      <h4 id={input.id} class="ct-reporting-visual__title">
        {input.title}
      </h4>
    );
  }

  return (
    <h3 id={input.id} class="ct-reporting-visual__title">
      {input.title}
    </h3>
  );
};

const VisualDescription = (input: {
  id: string;
  description?: string | undefined;
}): HonoElement | null => {
  if (input.description === undefined) {
    return null;
  }

  return (
    <p id={input.id} class="ct-reporting-visual__description">
      {input.description}
    </p>
  );
};

const renderLegend = (
  input: ReportingVisualProps,
  normalizedSeries: readonly ReportingVisualSeriesPoint[],
  totalValue: number,
  maxValue: number,
): HonoElement | null => {
  if (input.kind === "comparison-ranked") {
    return null;
  }

  return (
    <div class="ct-reporting-visual__legend-block">
      <p class="ct-reporting-visual__legend-title">Legend</p>
      <ol class="ct-reporting-visual__legend">
        {normalizedSeries.map((point, index) => {
          const detail = buildLegendDetail(input, point, maxValue, totalValue);

          return (
            <li
              key={`${point.label}:${String(index)}`}
              class="ct-reporting-visual__legend-item"
              data-reporting-visual-index={String(index)}
            >
              <span
                class={`ct-reporting-visual__swatch ct-reporting-visual__swatch--${String(index % 4)}`}
                aria-hidden="true"
              ></span>
              <span class="ct-reporting-visual__legend-label">{point.label}</span>
              <strong class="ct-reporting-visual__legend-value">{formatValue(point.value)}</strong>
              {detail === null ? null : (
                <span class="ct-reporting-visual__legend-detail">{detail}</span>
              )}
            </li>
          );
        })}
      </ol>
    </div>
  );
};

const renderComparisonRankedGraphic = (
  input: ReportingVisualProps,
  normalizedSeries: readonly ReportingVisualSeriesPoint[],
  titleId: string,
  descriptionIds: string,
): HonoElement => {
  const sortedSeries = sortComparisonRankedSeries(input, normalizedSeries);
  const emphasizedSeries = sortedSeries.slice(0, REPORTING_COMPARISON_RANKED_LIMIT);
  const maxValue = Math.max(...emphasizedSeries.map((point) => point.value), 1);

  return (
    <div
      class="ct-reporting-visual__comparison-ranked"
      role="img"
      aria-labelledby={titleId}
      aria-describedby={descriptionIds}
      data-reporting-visual-emphasis-count={String(
        Math.min(sortedSeries.length, REPORTING_COMPARISON_RANKED_LIMIT),
      )}
    >
      <ol class="ct-reporting-visual__comparison-ranked-list">
        {emphasizedSeries.map((point, index) => {
          const width = Math.max((point.value / maxValue) * 100, 12);

          return (
            <li
              key={`${point.label}:${String(index)}`}
              class="ct-reporting-visual__comparison-ranked-item"
              data-reporting-visual-index={String(index)}
            >
              <div class="ct-reporting-visual__comparison-ranked-head">
                <span class="ct-reporting-visual__comparison-ranked-label">{point.label}</span>
                <strong class="ct-reporting-visual__comparison-ranked-value">
                  {formatValue(point.value)}
                </strong>
              </div>
              <div class="ct-reporting-visual__comparison-ranked-bar-track" aria-hidden="true">
                <span
                  class={`ct-reporting-visual__comparison-ranked-bar ct-reporting-visual__comparison-ranked-bar--${String(index % 4)}`}
                  style={`width:${width.toFixed(2)}%`}
                ></span>
              </div>
              {point.detail === undefined || point.detail.trim().length === 0 ? null : (
                <span class="ct-reporting-visual__comparison-ranked-detail">{point.detail}</span>
              )}
            </li>
          );
        })}
      </ol>
      {sortedSeries.length > REPORTING_COMPARISON_RANKED_LIMIT ? (
        <p class="ct-reporting-visual__comparison-ranked-overflow">
          Top {String(REPORTING_COMPARISON_RANKED_LIMIT)} shown here. The exact table below keeps
          all {String(sortedSeries.length)} visible rows.
        </p>
      ) : null}
    </div>
  );
};

const renderComparisonGraphic = (
  normalizedSeries: readonly ReportingVisualSeriesPoint[],
  titleId: string,
  descriptionIds: string,
): HonoElement => {
  const maxValue = Math.max(...normalizedSeries.map((point) => normalizeValue(point.value)), 1);
  const barHeight = 18;
  const gap = 14;
  const chartHeight =
    REPORTING_VISUAL_PADDING * 2 +
    normalizedSeries.length * barHeight +
    (normalizedSeries.length - 1) * gap;
  const availableWidth = REPORTING_VISUAL_WIDTH - REPORTING_VISUAL_PADDING * 2;

  return (
    <svg
      class="ct-reporting-visual__graphic"
      viewBox={`0 0 ${String(REPORTING_VISUAL_WIDTH)} ${String(chartHeight)}`}
      role="img"
      aria-labelledby={titleId}
      aria-describedby={descriptionIds}
    >
      <desc>Visible labels and numeric values are listed in the legend below.</desc>
      {normalizedSeries.map((point, index) => {
        const y = REPORTING_VISUAL_PADDING + index * (barHeight + gap);
        const width = Math.max((normalizeValue(point.value) / maxValue) * availableWidth, 2);

        return (
          <g key={`${point.label}:${String(index)}`} class="ct-reporting-visual__bar-row">
            <rect
              class="ct-reporting-visual__bar-track"
              x={String(REPORTING_VISUAL_PADDING)}
              y={String(y)}
              width={String(availableWidth)}
              height={String(barHeight)}
              rx="9"
            ></rect>
            <rect
              class={`ct-reporting-visual__bar ct-reporting-visual__bar--${String(index % 4)}`}
              x={String(REPORTING_VISUAL_PADDING)}
              y={String(y)}
              width={width.toFixed(2)}
              height={String(barHeight)}
              rx="9"
            ></rect>
          </g>
        );
      })}
    </svg>
  );
};

const renderStackedGraphic = (
  normalizedSeries: readonly ReportingVisualSeriesPoint[],
  titleId: string,
  descriptionIds: string,
): HonoElement => {
  const totalValue = normalizedSeries.reduce((sum, point) => sum + normalizeValue(point.value), 0);
  const chartHeight = 68;
  const availableWidth = REPORTING_VISUAL_WIDTH - REPORTING_VISUAL_PADDING * 2;
  let x = REPORTING_VISUAL_PADDING;

  return (
    <svg
      class="ct-reporting-visual__graphic"
      viewBox={`0 0 ${String(REPORTING_VISUAL_WIDTH)} ${String(chartHeight)}`}
      role="img"
      aria-labelledby={titleId}
      aria-describedby={descriptionIds}
    >
      <desc>Visible labels and numeric values are listed in the legend below.</desc>
      <rect
        class="ct-reporting-visual__segment-track"
        x={String(REPORTING_VISUAL_PADDING)}
        y="22"
        width={String(availableWidth)}
        height="24"
        rx="10"
      ></rect>
      {normalizedSeries.map((point, index) => {
        const width = Math.max((normalizeValue(point.value) / totalValue) * availableWidth, 2);
        const segmentX = x;
        x += width;

        return (
          <rect
            key={`${point.label}:${String(index)}`}
            class={`ct-reporting-visual__segment ct-reporting-visual__segment--${String(index % 4)}`}
            x={segmentX.toFixed(2)}
            y="22"
            width={width.toFixed(2)}
            height="24"
            rx="10"
          ></rect>
        );
      })}
    </svg>
  );
};

const renderTrendGraphic = (
  normalizedSeries: readonly ReportingVisualSeriesPoint[],
  titleId: string,
  descriptionIds: string,
): HonoElement => {
  const maxValue = Math.max(...normalizedSeries.map((point) => normalizeValue(point.value)), 1);
  const chartHeight = 160;
  const chartWidth = REPORTING_VISUAL_WIDTH;
  const baseline = chartHeight - REPORTING_VISUAL_PADDING;
  const usableHeight = chartHeight - REPORTING_VISUAL_PADDING * 3;
  const maxIndex = Math.max(normalizedSeries.length - 1, 1);
  const xScale = scaleLinear()
    .domain([0, maxIndex])
    .range([REPORTING_VISUAL_PADDING, chartWidth - REPORTING_VISUAL_PADDING]);
  const yScale = scaleLinear()
    .domain([0, maxValue])
    .range([baseline, baseline - usableHeight]);

  const points: ReportingTrendPoint[] = normalizedSeries.map((point, index) => ({
    index,
    x: normalizedSeries.length === 1 ? chartWidth / 2 : xScale(index),
    y: yScale(normalizeValue(point.value)),
    label: point.label,
    value: normalizeValue(point.value),
  }));
  const trendPath =
    line<ReportingTrendPoint>()
      .x((point) => point.x)
      .y((point) => point.y)
      .curve(curveMonotoneX)(points) ?? "";

  return (
    <svg
      class="ct-reporting-visual__graphic"
      viewBox={`0 0 ${String(chartWidth)} ${String(chartHeight)}`}
      role="img"
      aria-labelledby={titleId}
      aria-describedby={descriptionIds}
    >
      <desc>Visible labels and numeric values are listed in the legend below.</desc>
      <line
        class="ct-reporting-visual__baseline"
        x1={String(REPORTING_VISUAL_PADDING)}
        y1={String(baseline)}
        x2={String(chartWidth - REPORTING_VISUAL_PADDING)}
        y2={String(baseline)}
      ></line>
      <path class="ct-reporting-visual__trend-line" d={trendPath}></path>
      {points.map((point) => (
        <g key={`${point.label}:${String(point.index)}`} class="ct-reporting-visual__point-group">
          <circle
            class={`ct-reporting-visual__point ct-reporting-visual__point--${String(point.index % 4)}`}
            cx={point.x.toFixed(2)}
            cy={point.y.toFixed(2)}
            r="4"
          ></circle>
        </g>
      ))}
    </svg>
  );
};

const renderTrendContext = (
  normalizedSeries: readonly ReportingVisualSeriesPoint[],
): HonoElement | null => {
  const startPoint = normalizedSeries[0];
  const latestPoint = normalizedSeries[normalizedSeries.length - 1] ?? startPoint;
  const peakPoint =
    [...normalizedSeries].sort((left, right) => right.value - left.value)[0] ?? latestPoint;

  if (startPoint === undefined || latestPoint === undefined || peakPoint === undefined) {
    return null;
  }

  const axisItems = [
    {
      label: "Start" as const,
      point: startPoint,
    },
    {
      label: "Latest" as const,
      point: latestPoint,
    },
  ];
  const callouts = [
    {
      label: "Peak" as const,
      point: peakPoint,
    },
    {
      label: "Latest" as const,
      point: latestPoint,
    },
  ];

  return (
    <div class="ct-reporting-visual__trend-context">
      <div class="ct-reporting-visual__trend-axis">
        {axisItems.map((item) => (
          <div
            key={item.label}
            class="ct-reporting-visual__trend-axis-item"
            data-reporting-trend-point={slugify(item.label)}
          >
            <span class="ct-reporting-visual__trend-axis-label">{item.label}</span>
            <strong class="ct-reporting-visual__trend-axis-value">{item.point.label}</strong>
            <span class="ct-reporting-visual__trend-axis-detail">
              {formatValue(item.point.value)}
            </span>
          </div>
        ))}
      </div>
      <ol class="ct-reporting-visual__trend-callouts">
        {callouts.map((item) => (
          <li
            key={item.label}
            class="ct-reporting-visual__trend-callout"
            data-reporting-trend-callout={slugify(item.label)}
          >
            <span class="ct-reporting-visual__trend-callout-label">{item.label}</span>
            <strong class="ct-reporting-visual__trend-callout-value">{item.point.label}</strong>
            <span class="ct-reporting-visual__trend-callout-metric">
              {formatValue(item.point.value)}
            </span>
            {item.point.detail === undefined || item.point.detail.trim().length === 0 ? null : (
              <span class="ct-reporting-visual__trend-callout-detail">{item.point.detail}</span>
            )}
          </li>
        ))}
      </ol>
    </div>
  );
};

const renderGraphic = (
  input: ReportingVisualProps,
  normalizedSeries: readonly ReportingVisualSeriesPoint[],
  titleId: string,
  descriptionIds: string,
): HonoElement => {
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

export const renderReporting = (input: ReportingVisualProps): HonoElement => {
  const visualId = buildVisualId(input);
  const titleId = `${visualId}-title`;
  const descriptionId = `${visualId}-description`;
  const summaryId = `${visualId}-summary`;
  const headingLevel = input.headingLevel ?? "h3";
  const normalizedSeries = input.series.map((point) => ({
    ...point,
    value: normalizeValue(point.value),
  }));
  const totalValue = normalizedSeries.reduce((sum, point) => sum + point.value, 0);
  const maxValue = Math.max(...normalizedSeries.map((point) => point.value), 0);
  const descriptionIds = [input.description !== undefined ? descriptionId : null, summaryId]
    .filter((value): value is string => value !== null)
    .join(" ");

  if (!hasRenderableData(normalizedSeries)) {
    return (
      <figure
        class="ct-reporting-visual"
        data-reporting-visual-kind={input.kind}
        data-reporting-visual-state="empty"
      >
        <figcaption class="ct-reporting-visual__header">
          <VisualHeading headingLevel={headingLevel} id={titleId} title={input.title} />
          <VisualDescription id={descriptionId} description={input.description} />
        </figcaption>
        <div id={summaryId} class="ct-reporting-visual__empty">
          {input.emptyMessage ?? REPORTING_VISUAL_EMPTY_MESSAGE}
        </div>
      </figure>
    );
  }

  const trimmedSparseMessage = input.sparseMessage?.trim();

  if (trimmedSparseMessage !== undefined && trimmedSparseMessage.length > 0) {
    return (
      <figure
        class="ct-reporting-visual"
        data-reporting-visual-kind={input.kind}
        data-reporting-visual-state="sparse"
      >
        <figcaption class="ct-reporting-visual__header">
          <VisualHeading headingLevel={headingLevel} id={titleId} title={input.title} />
          <VisualDescription id={descriptionId} description={input.description} />
        </figcaption>
        <div id={summaryId} class="ct-reporting-visual__empty ct-reporting-visual__empty--sparse">
          {trimmedSparseMessage}
        </div>
      </figure>
    );
  }

  const trimmedSummaryOverride = input.summaryOverride?.trim();
  const summaryText =
    trimmedSummaryOverride === undefined || trimmedSummaryOverride.length === 0
      ? buildSummaryText(input, normalizedSeries, totalValue)
      : trimmedSummaryOverride;

  return (
    <figure
      class="ct-reporting-visual"
      data-reporting-visual-kind={input.kind}
      data-reporting-visual-state="ready"
    >
      <figcaption class="ct-reporting-visual__header">
        <VisualHeading headingLevel={headingLevel} id={titleId} title={input.title} />
        <VisualDescription id={descriptionId} description={input.description} />
      </figcaption>
      <div class="ct-reporting-visual__surface">
        {renderGraphic(input, normalizedSeries, titleId, descriptionIds)}
      </div>
      {input.kind === "trend-series" ? renderTrendContext(normalizedSeries) : null}
      <p id={summaryId} class="ct-reporting-visual__summary">
        {summaryText}
      </p>
      {renderLegend(input, normalizedSeries, totalValue, maxValue)}
    </figure>
  );
};

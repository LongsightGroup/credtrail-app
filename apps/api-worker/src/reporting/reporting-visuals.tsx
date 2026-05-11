import { scaleLinear } from "d3-scale";
import { area, curveMonotoneX, line } from "d3-shape";
import type { HtmlEscapedString } from "hono/utils/html";

type HonoElement = HtmlEscapedString | Promise<HtmlEscapedString>;

export type ReportingVisualKind =
  | "comparison-bars"
  | "comparison-ranked"
  | "journey-funnel"
  | "stacked-summary"
  | "trend-area"
  | "trend-series";
export type ReportingVisualDensity = "regular" | "compact";
export type ReportingVisualHeadingLevel = "h3" | "h4";

export interface ReportingVisualSeriesPoint {
  label: string;
  value: number;
  detail?: string;
}

export interface ReportingVisualProps {
  kind: ReportingVisualKind;
  title: string;
  density?: ReportingVisualDensity;
  description?: string;
  series: readonly ReportingVisualSeriesPoint[];
  id?: string;
  emptyMessage?: string;
  sparseMessage?: string;
  headingLevel?: ReportingVisualHeadingLevel;
  showLegend?: boolean;
  showTrendContext?: boolean;
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

const formatLabelList = (labels: readonly string[]): string => {
  const cleanedLabels = labels.map((label) => label.trim()).filter((label) => label.length > 0);

  if (cleanedLabels.length === 0) {
    return "listed categories";
  }

  if (cleanedLabels.length === 1) {
    return cleanedLabels[0] ?? "listed category";
  }

  const finalLabel = cleanedLabels[cleanedLabels.length - 1] ?? "listed category";
  const leadingLabels = cleanedLabels.slice(0, -1);

  if (leadingLabels.length === 1) {
    return `${leadingLabels[0] ?? "listed category"} and ${finalLabel}`;
  }

  return `${leadingLabels.join(", ")}, and ${finalLabel}`;
};

const lowercaseInitial = (value: string): string => {
  const trimmedValue = value.trim();
  const firstCharacter = trimmedValue[0];

  if (firstCharacter === undefined) {
    return "this category";
  }

  return `${firstCharacter.toLocaleLowerCase("en-US")}${trimmedValue.slice(1)}`;
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

  if (input.kind === "journey-funnel" && totalValue > 0) {
    return `${((normalizeValue(point.value) / totalValue) * 100).toFixed(1)}% of listed signals`;
  }

  return null;
};

const buildSummaryText = (
  input: ReportingVisualProps,
  normalizedSeries: readonly ReportingVisualSeriesPoint[],
  totalValue: number,
): string => {
  if (input.kind === "stacked-summary") {
    const positiveSeries = normalizedSeries.filter((point) => point.value > 0);

    if (positiveSeries.length === 1) {
      const positivePoint = positiveSeries[0];
      const totalLabel = formatValue(totalValue);
      const categoryLabel = lowercaseInitial(positivePoint?.label ?? "");

      if (totalValue === 1) {
        return `${totalLabel} total; ${categoryLabel} in this slice.`;
      }

      return `${totalLabel} total; all ${categoryLabel} in this slice.`;
    }

    const summaryLabels =
      positiveSeries.length > 0
        ? positiveSeries.map((point) => point.label)
        : normalizedSeries.map((point) => point.label);

    return `Total ${formatValue(totalValue)} across ${formatLabelList(summaryLabels)}.`;
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

  if (input.kind === "trend-area") {
    const startPoint = normalizedSeries[0] ?? highestPoint;
    const latestPoint = normalizedSeries[normalizedSeries.length - 1] ?? highestPoint;

    return `${startPoint.label} starts at ${formatValue(startPoint.value)}; ${latestPoint.label} is now ${formatValue(latestPoint.value)} with a peak of ${formatValue(highestPoint.value)}.`;
  }

  if (input.kind === "journey-funnel") {
    const firstPoint = normalizedSeries[0] ?? highestPoint;
    const finalPoint = normalizedSeries[normalizedSeries.length - 1] ?? highestPoint;
    const finalShare =
      firstPoint.value > 0
        ? ` (${((finalPoint.value / firstPoint.value) * 100).toFixed(1)}% of the first signal)`
        : "";

    return `${firstPoint.label} records ${formatValue(firstPoint.value)}; ${finalPoint.label} records ${formatValue(finalPoint.value)}${finalShare}.`;
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
  if (
    input.kind === "comparison-ranked" ||
    input.kind === "journey-funnel" ||
    input.kind === "trend-area"
  ) {
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
                <span class="ct-reporting-visual__comparison-ranked-rank">{String(index + 1)}</span>
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
  const clipPathId = `${titleId}-stack-clip`;
  const positiveSegments = normalizedSeries
    .map((point, index) => ({
      index,
      label: point.label,
      value: normalizeValue(point.value),
    }))
    .filter((segment) => segment.value > 0);
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
      <defs>
        <clipPath id={clipPathId}>
          <rect
            x={String(REPORTING_VISUAL_PADDING)}
            y="22"
            width={String(availableWidth)}
            height="24"
            rx="10"
          ></rect>
        </clipPath>
      </defs>
      <rect
        class="ct-reporting-visual__segment-track"
        x={String(REPORTING_VISUAL_PADDING)}
        y="22"
        width={String(availableWidth)}
        height="24"
        rx="10"
      ></rect>
      <g clip-path={`url(#${clipPathId})`}>
        {positiveSegments.map((segment, segmentIndex) => {
          const segmentCount = positiveSegments.length;
          const isLastSegment = segmentIndex === segmentCount - 1;
          const width = isLastSegment
            ? REPORTING_VISUAL_PADDING + availableWidth - x
            : (segment.value / totalValue) * availableWidth;
          const segmentX = x;
          x += width;

          return (
            <rect
              key={`${segment.label}:${String(segment.index)}`}
              class={`ct-reporting-visual__segment ct-reporting-visual__segment--${String(segment.index % 4)}`}
              x={segmentX.toFixed(2)}
              y="22"
              width={Math.max(width, 0).toFixed(2)}
              height="24"
            ></rect>
          );
        })}
      </g>
    </svg>
  );
};

const buildTrendPoints = (input: {
  chartHeight: number;
  chartWidth: number;
  normalizedSeries: readonly ReportingVisualSeriesPoint[];
}): { baseline: number; points: ReportingTrendPoint[]; usableHeight: number } => {
  const maxValue = Math.max(
    ...input.normalizedSeries.map((point) => normalizeValue(point.value)),
    1,
  );
  const baseline = input.chartHeight - REPORTING_VISUAL_PADDING;
  const usableHeight = input.chartHeight - REPORTING_VISUAL_PADDING * 3;
  const maxIndex = Math.max(input.normalizedSeries.length - 1, 1);
  const xScale = scaleLinear()
    .domain([0, maxIndex])
    .range([REPORTING_VISUAL_PADDING, input.chartWidth - REPORTING_VISUAL_PADDING]);
  const yScale = scaleLinear()
    .domain([0, maxValue])
    .range([baseline, baseline - usableHeight]);
  const points = input.normalizedSeries.map((point, index) => ({
    index,
    x: input.normalizedSeries.length === 1 ? input.chartWidth / 2 : xScale(index),
    y: yScale(normalizeValue(point.value)),
    label: point.label,
    value: normalizeValue(point.value),
  }));

  return { baseline, points, usableHeight };
};

const renderTrendGraphic = (
  input: ReportingVisualProps,
  normalizedSeries: readonly ReportingVisualSeriesPoint[],
  titleId: string,
  descriptionIds: string,
): HonoElement => {
  const chartHeight = input.density === "compact" ? 104 : 160;
  const chartWidth = REPORTING_VISUAL_WIDTH;
  const { baseline, points } = buildTrendPoints({ chartHeight, chartWidth, normalizedSeries });
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
      <desc>
        {input.showLegend === false
          ? "Trend line summarizes the values across the selected range."
          : "Trend line plots the values listed in the legend below."}
      </desc>
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

const renderTrendAreaGraphic = (
  normalizedSeries: readonly ReportingVisualSeriesPoint[],
  titleId: string,
  descriptionIds: string,
): HonoElement => {
  const chartHeight = 122;
  const chartWidth = REPORTING_VISUAL_WIDTH;
  const { baseline, points, usableHeight } = buildTrendPoints({
    chartHeight,
    chartWidth,
    normalizedSeries,
  });
  const trendPath =
    line<ReportingTrendPoint>()
      .x((point) => point.x)
      .y((point) => point.y)
      .curve(curveMonotoneX)(points) ?? "";
  const areaPath =
    area<ReportingTrendPoint>()
      .x((point) => point.x)
      .y0(baseline)
      .y1((point) => point.y)
      .curve(curveMonotoneX)(points) ?? "";
  const peakPoint =
    [...points].sort((left, right) => {
      if (right.value !== left.value) {
        return right.value - left.value;
      }

      return left.index - right.index;
    })[0] ?? points[0];
  const latestPoint = points[points.length - 1] ?? peakPoint;
  const guideY = baseline - usableHeight * 0.5;

  return (
    <svg
      class="ct-reporting-visual__graphic ct-reporting-visual__graphic--area"
      viewBox={`0 0 ${String(chartWidth)} ${String(chartHeight)}`}
      role="img"
      aria-labelledby={titleId}
      aria-describedby={descriptionIds}
    >
      <desc>Momentum area chart; the text summary lists start, latest, and peak values.</desc>
      <line
        class="ct-reporting-visual__guide"
        x1={String(REPORTING_VISUAL_PADDING)}
        y1={guideY.toFixed(2)}
        x2={String(chartWidth - REPORTING_VISUAL_PADDING)}
        y2={guideY.toFixed(2)}
      ></line>
      <line
        class="ct-reporting-visual__baseline"
        x1={String(REPORTING_VISUAL_PADDING)}
        y1={String(baseline)}
        x2={String(chartWidth - REPORTING_VISUAL_PADDING)}
        y2={String(baseline)}
      ></line>
      <path class="ct-reporting-visual__trend-area" d={areaPath}></path>
      <path class="ct-reporting-visual__trend-line" d={trendPath}></path>
      {peakPoint === undefined ? null : (
        <circle
          class="ct-reporting-visual__point ct-reporting-visual__point--peak"
          cx={peakPoint.x.toFixed(2)}
          cy={peakPoint.y.toFixed(2)}
          r="4.5"
        ></circle>
      )}
      {latestPoint === undefined ? null : (
        <circle
          class="ct-reporting-visual__point ct-reporting-visual__point--latest"
          cx={latestPoint.x.toFixed(2)}
          cy={latestPoint.y.toFixed(2)}
          r="4.5"
        ></circle>
      )}
    </svg>
  );
};

const renderJourneyFunnelGraphic = (
  normalizedSeries: readonly ReportingVisualSeriesPoint[],
  titleId: string,
  descriptionIds: string,
): HonoElement => {
  const maxValue = Math.max(...normalizedSeries.map((point) => normalizeValue(point.value)), 1);

  return (
    <div
      class="ct-reporting-visual__journey-funnel"
      role="img"
      aria-labelledby={titleId}
      aria-describedby={descriptionIds}
    >
      <ol class="ct-reporting-visual__journey-list">
        {normalizedSeries.map((point, index) => {
          const width =
            normalizeValue(point.value) === 0 ? 0 : Math.max((point.value / maxValue) * 100, 10);

          return (
            <li
              key={`${point.label}:${String(index)}`}
              class="ct-reporting-visual__journey-item"
              data-reporting-visual-index={String(index)}
            >
              <div class="ct-reporting-visual__journey-head">
                <span class="ct-reporting-visual__journey-step">{String(index + 1)}</span>
                <span class="ct-reporting-visual__journey-label">{point.label}</span>
                <strong class="ct-reporting-visual__journey-value">
                  {formatValue(point.value)}
                </strong>
              </div>
              <div class="ct-reporting-visual__journey-track" aria-hidden="true">
                <span
                  class={`ct-reporting-visual__journey-fill ct-reporting-visual__journey-fill--${String(index % 4)}`}
                  style={`width:${width.toFixed(2)}%`}
                ></span>
              </div>
              {point.detail === undefined || point.detail.trim().length === 0 ? null : (
                <span class="ct-reporting-visual__journey-detail">{point.detail}</span>
              )}
            </li>
          );
        })}
      </ol>
    </div>
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
    case "journey-funnel":
      return renderJourneyFunnelGraphic(normalizedSeries, titleId, descriptionIds);
    case "stacked-summary":
      return renderStackedGraphic(normalizedSeries, titleId, descriptionIds);
    case "trend-area":
      return renderTrendAreaGraphic(normalizedSeries, titleId, descriptionIds);
    case "trend-series":
      return renderTrendGraphic(input, normalizedSeries, titleId, descriptionIds);
  }
};

export const renderReporting = (input: ReportingVisualProps): HonoElement => {
  const visualId = buildVisualId(input);
  const titleId = `${visualId}-title`;
  const descriptionId = `${visualId}-description`;
  const summaryId = `${visualId}-summary`;
  const visualDensity = input.density ?? "regular";
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
        data-reporting-visual-density={visualDensity}
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
        data-reporting-visual-density={visualDensity}
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
      data-reporting-visual-density={visualDensity}
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
      {input.kind === "trend-series" && input.showTrendContext !== false
        ? renderTrendContext(normalizedSeries)
        : null}
      <p id={summaryId} class="ct-reporting-visual__summary">
        {summaryText}
      </p>
      {input.showLegend === false
        ? null
        : renderLegend(input, normalizedSeries, totalValue, maxValue)}
    </figure>
  );
};

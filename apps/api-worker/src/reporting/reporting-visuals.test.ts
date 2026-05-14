import { describe, expect, it } from "vitest";

import { INSTITUTION_ADMIN_CSS } from "../ui/page-assets/content/institution-admin-css";
import { renderReporting } from "./reporting-visuals";

const renderReportingString = (input: Parameters<typeof renderReporting>[0]): string => {
  return (renderReporting(input) as { toString(): string }).toString();
};

describe("renderReporting", () => {
  it.each([
    {
      kind: "comparison-bars" as const,
      title: "Template performance",
      description: "Issued badges by template for the selected window.",
    },
    {
      kind: "stacked-summary" as const,
      title: "Engagement mix",
      description: "Claimed and shared badges from the same reporting slice.",
    },
    {
      kind: "trend-series" as const,
      title: "Weekly badge activity",
      description: "Issued badges by week.",
    },
  ])("renders %s visuals with visible labels and numeric values", (input) => {
    const html = renderReportingString({
      ...input,
      series: [
        { label: "Engineering", value: 12 },
        { label: "Mathematics", value: 6 },
        { label: "History", value: 3 },
      ],
    });

    expect(html).toContain("<figure");
    expect(html).toContain("<svg");
    expect(html).toContain('role="img"');
    expect(html).toContain("Engineering");
    expect(html).toContain("Mathematics");
    expect(html).toContain("History");
    expect(html).toContain("12");
    expect(html).toContain("6");
    expect(html).toContain("3");
  });

  it("renders legends and text summaries so the visual is understandable without color alone", () => {
    const html = renderReportingString({
      kind: "stacked-summary",
      title: "Recipient engagement",
      description: "Breakdown of post-issuance engagement.",
      series: [
        { label: "Claimed", value: 5 },
        { label: "Shared", value: 3 },
      ],
    });

    expect(html).toContain("Legend");
    expect(html).toContain("Claimed");
    expect(html).toContain("Shared");
    expect(html).toContain("Total");
    expect(html).toContain("8");
    expect(html).toContain("aria-describedby");
  });

  it("does not render zero-value stacked-summary segments as visible slivers", () => {
    const html = renderReportingString({
      kind: "stacked-summary",
      title: "Current badge state mix",
      description:
        "Shows whether badges in this slice are active, suspended, revoked, or waiting for review.",
      series: [
        { label: "Active", value: 7 },
        { label: "Suspended", value: 0 },
        { label: "Revoked", value: 0 },
        { label: "Pending review", value: 0 },
      ],
    });

    const renderedSegments = html.match(
      /ct-reporting-visual__segment ct-reporting-visual__segment--/g,
    );

    expect(renderedSegments).toHaveLength(1);
    expect(html).toContain('width="328.00"');
    expect(html).toContain("<clipPath");
    expect(html).toContain("7 total; all active in this slice.");
    expect(html).not.toContain(
      'class="ct-reporting-visual__segment ct-reporting-visual__segment--1"',
    );
    expect(html).not.toContain(
      'class="ct-reporting-visual__segment ct-reporting-visual__segment--2"',
    );
    expect(html).not.toContain(
      'class="ct-reporting-visual__segment ct-reporting-visual__segment--3"',
    );
  });

  it("renders trend visuals with visible time anchors and chart callouts for chart-first reading", () => {
    const html = renderReportingString({
      kind: "trend-series",
      title: "Issued over time",
      description: "Issued badges by day.",
      series: [
        { label: "Mar 1", value: 3, detail: "8 public views" },
        { label: "Mar 2", value: 2, detail: "5 public views" },
      ],
    });

    expect(html).toContain('class="ct-reporting-visual__trend-axis"');
    expect(html).toContain("Start");
    expect(html).toContain("Latest");
    expect(html).toContain("Peak");
    expect(html).toContain("Mar 1");
    expect(html).toContain("Mar 2");
    expect(html).toContain("8 public views");
  });

  it("can render trend visuals in summary mode without per-date detail cards", () => {
    const html = renderReportingString({
      kind: "trend-series",
      title: "Issued over time",
      density: "compact",
      description: "Issued badges by day.",
      showLegend: false,
      showTrendContext: false,
      series: [
        { label: "Mar 1", value: 3, detail: "8 public views" },
        { label: "Mar 2", value: 2, detail: "5 public views" },
      ],
    });

    expect(html).toContain('data-reporting-visual-kind="trend-series"');
    expect(html).toContain('data-reporting-visual-density="compact"');
    expect(html).toContain("<svg");
    expect(html).toContain(
      "Trend line summarizes issued badge counts with start, peak, and latest markers.",
    );
    expect(html).toContain('class="ct-reporting-visual__chart-key"');
    expect(html).toContain("Issued badges");
    expect(html).toContain('class="ct-reporting-visual__axis ct-reporting-visual__axis--x');
    expect(html).toContain('class="ct-reporting-visual__axis-label');
    expect(html).not.toContain('class="ct-reporting-visual__trend-axis"');
    expect(html).not.toContain('class="ct-reporting-visual__trend-callouts"');
    expect(html).not.toContain('class="ct-reporting-visual__legend"');
    expect(html).not.toContain("legend below");
    expect(html).not.toContain("8 public views");
  });

  it("keeps compact trend visuals sparse when many date buckets are present", () => {
    const html = renderReportingString({
      kind: "trend-series",
      title: "Issued over time",
      density: "compact",
      description: "Issued badges by day.",
      showLegend: false,
      showTrendContext: false,
      series: Array.from({ length: 30 }, (_, index) => ({
        label: `Day ${String(index + 1)}`,
        value: index === 3 ? 2 : index === 18 ? 4 : 0,
        detail: `${String(index)} public views`,
      })),
    });
    const pointCount = html.match(/class="ct-reporting-visual__point /g)?.length ?? 0;

    expect(pointCount).toBeLessThanOrEqual(3);
    expect(html).toContain("Day 1");
    expect(html).toContain("Day 30");
    expect(html).toContain("Issued badges");
    expect(html).not.toContain("public views");
    expect(html).not.toContain('class="ct-reporting-visual__legend"');
  });

  it("renders compact trend-area visuals with an area path and peak/latest markers", () => {
    const html = renderReportingString({
      kind: "trend-area",
      title: "90-day issuance momentum",
      description: "Issued badges for the default reporting window.",
      series: [
        { label: "Mar 1", value: 3 },
        { label: "Mar 2", value: 8 },
        { label: "Mar 3", value: 5 },
      ],
    });

    expect(html).toContain('data-reporting-visual-kind="trend-area"');
    expect(html).toContain('class="ct-reporting-visual__trend-area"');
    expect(html).toContain('class="ct-reporting-visual__point ct-reporting-visual__point--peak"');
    expect(html).toContain('class="ct-reporting-visual__point ct-reporting-visual__point--latest"');
    expect(html).toContain("Mar 1 starts at 3; Mar 3 is now 5 with a peak of 8.");
    expect(html).not.toContain("Legend");
  });

  it("renders journey-funnel visuals as staged post-issuance signal rows", () => {
    const html = renderReportingString({
      kind: "journey-funnel",
      title: "Credential journey",
      description: "Signals after issuance.",
      series: [
        { label: "Issued", value: 30, detail: "Badges issued." },
        { label: "Public viewed", value: 18, detail: "Public page views." },
        { label: "Verified", value: 6, detail: "Verification responses." },
      ],
    });

    expect(html).toContain('data-reporting-visual-kind="journey-funnel"');
    expect(html).toContain('class="ct-reporting-visual__journey-list"');
    expect(html).toContain('class="ct-reporting-visual__journey-step"');
    expect(html).toContain("Issued records 30; Verified records 6 (20.0% of the first signal).");
    expect(html).toContain("Public page views.");
    expect(html).not.toContain("Legend");
  });

  it("renders comparison-ranked visuals with top-five emphasis and adjacent rate detail", () => {
    const html = renderReportingString({
      kind: "comparison-ranked" as unknown as Parameters<typeof renderReporting>[0]["kind"],
      title: "Compare by badge template",
      description: "Issued volume stays primary while rate detail remains visible beside each row.",
      series: [
        {
          label: "Mathematics",
          value: 22,
          detail: "28 public views · 50.0% claim · 20.0% share",
        },
        {
          label: "Architecture",
          value: 22,
          detail: "31 public views · 47.0% claim · 25.0% share",
        },
        {
          label: "Biology",
          value: 18,
          detail: "24 public views · 44.0% claim · 19.0% share",
        },
        {
          label: "Design",
          value: 14,
          detail: "19 public views · 39.0% claim · 18.0% share",
        },
        {
          label: "History",
          value: 9,
          detail: "12 public views · 35.0% claim · 14.0% share",
        },
        {
          label: "Chemistry",
          value: 4,
          detail: "8 public views · 25.0% claim · 10.0% share",
        },
      ],
    });

    expect(html).toContain('data-reporting-visual-kind="comparison-ranked"');
    expect(html).toContain('class="ct-reporting-visual__comparison-ranked-list"');
    expect(html).toContain('class="ct-reporting-visual__comparison-ranked-rank"');
    expect(html).toContain('class="ct-reporting-visual__comparison-ranked-detail"');
    expect(html).toContain('data-reporting-visual-emphasis-count="5"');
    expect(html).toContain("Top 5 shown here. The exact table below keeps all 6 visible rows.");
    expect(html).toContain("31 public views · 47.0% claim · 25.0% share");
    expect(html.indexOf("Architecture")).toBeLessThan(html.indexOf("Mathematics"));
    expect(html).not.toContain("Chemistry");
  });

  it("renders an honesty-focused summary override when comparison context must stay explicit", () => {
    const html = renderReportingString({
      kind: "comparison-ranked" as unknown as Parameters<typeof renderReporting>[0]["kind"],
      title: "Highest claim rate",
      description:
        "Rate leaders should still state the compare level and keep issued totals visible.",
      summaryOverride:
        "Comparing department rows by claim rate. Issued totals stay visible beside each ranked rate row.",
      series: [
        {
          label: "Computer Science",
          value: 50,
          detail: "8 issued · 37.5% share",
        },
        {
          label: "History",
          value: 33.3,
          detail: "6 issued · 16.7% share",
        },
      ],
    } as Parameters<typeof renderReporting>[0]);

    expect(html).toContain(
      "Comparing department rows by claim rate. Issued totals stay visible beside each ranked rate row.",
    );
    expect(html).not.toContain("Computer Science leads at 50");
  });

  it("renders a dedicated sparse-state wrapper when only one comparison row is visible", () => {
    const html = renderReportingString({
      kind: "comparison-ranked" as unknown as Parameters<typeof renderReporting>[0]["kind"],
      title: "Compare by badge template",
      description: "Thin-data slices should stay honest about how much comparison context exists.",
      sparseMessage:
        "Only one visible comparison row matches this slice, so use the exact row below for detail.",
      series: [
        {
          label: "Applied Analytics",
          value: 9,
          detail: "12 public views · 44.4% claim · 22.2% share",
        },
      ],
    } as Parameters<typeof renderReporting>[0] & { sparseMessage: string });

    expect(html).toContain('data-reporting-visual-state="sparse"');
    expect(html).toContain(
      "Only one visible comparison row matches this slice, so use the exact row below for detail.",
    );
    expect(html).not.toContain("Applied Analytics leads at 9");
  });

  it("emits stable reporting-visual hooks for the chart surface, legend, and visible values", () => {
    const html = renderReportingString({
      kind: "comparison-bars",
      title: "Program performance",
      description: "Issued badges by program.",
      series: [
        { label: "Computer Science", value: 18 },
        { label: "History", value: 9 },
      ],
    });

    expect(html).toContain('class="ct-reporting-visual"');
    expect(html).toContain('data-reporting-visual-kind="comparison-bars"');
    expect(html).toContain('class="ct-reporting-visual__surface"');
    expect(html).toContain('class="ct-reporting-visual__legend"');
    expect(html).toContain('class="ct-reporting-visual__legend-value"');
    expect(html).toContain('data-reporting-visual-index="0"');
  });

  it("defines reporting visual CSS tokens, responsive surface rules, and non-color emphasis states", () => {
    expect(INSTITUTION_ADMIN_CSS).toContain("--ct-reporting-visual-surface");
    expect(INSTITUTION_ADMIN_CSS).toContain("--ct-reporting-visual-accent");
    expect(INSTITUTION_ADMIN_CSS).toContain(".ct-reporting-visual");
    expect(INSTITUTION_ADMIN_CSS).toContain(".ct-reporting-visual__legend");
    expect(INSTITUTION_ADMIN_CSS).toContain(".ct-reporting-visual__surface");
    expect(INSTITUTION_ADMIN_CSS).toContain(".ct-reporting-visual__chart-key");
    expect(INSTITUTION_ADMIN_CSS).toContain(".ct-reporting-visual__axis");
    expect(INSTITUTION_ADMIN_CSS).toContain(".ct-reporting-visual__trend-axis");
    expect(INSTITUTION_ADMIN_CSS).toContain(".ct-reporting-visual__trend-area");
    expect(INSTITUTION_ADMIN_CSS).toContain(".ct-reporting-visual__journey-list");
    expect(INSTITUTION_ADMIN_CSS).toContain(".ct-reporting-visual__trend-callouts");
    expect(INSTITUTION_ADMIN_CSS).toContain(".ct-reporting-visual__comparison-ranked-list");
    expect(INSTITUTION_ADMIN_CSS).toContain(".ct-reporting-visual__comparison-ranked-rank");
    expect(INSTITUTION_ADMIN_CSS).toContain(".ct-reporting-visual__comparison-ranked-detail");
    expect(INSTITUTION_ADMIN_CSS).toContain("data-reporting-visual-kind='comparison-ranked'");
    expect(INSTITUTION_ADMIN_CSS).toContain("ct-reporting-rise-in");
    expect(INSTITUTION_ADMIN_CSS).toContain("prefers-reduced-motion: reduce");
    expect(INSTITUTION_ADMIN_CSS).toContain(".ct-admin__reporting-trend-hero");
    expect(INSTITUTION_ADMIN_CSS).toContain("data-reporting-visual-kind");
    expect(INSTITUTION_ADMIN_CSS).toContain("@media (max-width: 960px)");
    expect(INSTITUTION_ADMIN_CSS).toContain("repeating-linear-gradient");
  });

  it("renders a deliberate fallback for empty or zero-data visuals", () => {
    const html = renderReportingString({
      kind: "trend-series",
      title: "Credential activity",
      description: "This visual should explain when there is no data to chart yet.",
      series: [
        { label: "Week 1", value: 0 },
        { label: "Week 2", value: 0 },
      ],
    });

    expect(html).toContain("Credential activity");
    expect(html).toContain('data-reporting-visual-state="empty"');
    expect(html).toContain("No reporting data available for this view yet.");
    expect(html).not.toContain("<svg");
  });
});

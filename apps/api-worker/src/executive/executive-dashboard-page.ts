import { renderPageShell } from "@credtrail/ui-components";

import {
  buildExecutiveDashboardInsights,
  type ExecutiveDashboardInsight,
} from "./executive-dashboard-insights";
import type { TenantExecutiveDashboardRecord } from "./executive-rollup-loader";
import { buildExecutiveDashboardQueryEntries } from "./executive-dashboard-paths";
import { renderReporting } from "../reporting/reporting-visuals";
import { renderPageAssetTags } from "../ui/page-assets";
import { escapeHtml, formatIsoTimestamp } from "../utils/display-format";

interface ExecutiveMetricSummary {
  issued: number;
  active: number;
  claimRate: number;
  shareRate: number;
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

const isSystemAudience = (dashboard: TenantExecutiveDashboardRecord): boolean => {
  return dashboard.defaults.audience === "system" || dashboard.defaults.audience === "institution";
};

const buildHeroTitle = (dashboard: TenantExecutiveDashboardRecord): string => {
  if (dashboard.defaults.audience === "system") {
    return "System credential momentum";
  }

  return `${dashboard.rollup.focusDisplayName} credential momentum`;
};

const buildHeroEyebrow = (dashboard: TenantExecutiveDashboardRecord): string => {
  if (dashboard.defaults.audience === "system") {
    return "System-level executive view";
  }

  return `${titleCase(dashboard.defaults.audience)} executive view`;
};

const buildHeroSubtitle = (dashboard: TenantExecutiveDashboardRecord): string => {
  if (dashboard.rollup.rows.length === 0) {
    return `This slice stays centered on ${dashboard.rollup.focusDisplayName} because no deeper visible comparison level is available right now.`;
  }

  if (isSystemAudience(dashboard)) {
    return `Read institution-wide issuance, claim, and share momentum first, then compare the next visible level without crossing into operational admin work.`;
  }

  return `Read how ${dashboard.rollup.focusDisplayName} is performing first, then compare the next visible ${titleCase(
    dashboard.rollup.comparisonLevel,
  ).toLowerCase()} slice without dropping into operational admin work.`;
};

const buildExecutiveApiPath = (
  tenantId: string,
  query: Parameters<typeof buildExecutiveDashboardQueryEntries>[0],
): string => {
  const url = new URL(
    `/v1/tenants/${encodeURIComponent(tenantId)}/executive`,
    "https://credtrail.local",
  );

  for (const [key, value] of buildExecutiveDashboardQueryEntries(query)) {
    if (value === undefined || value === null || value === "") {
      continue;
    }

    url.searchParams.set(key, value);
  }

  return url.searchParams.size === 0 ? url.pathname : `${url.pathname}${url.search}`;
};

const summarizeExecutiveMetrics = (
  dashboard: TenantExecutiveDashboardRecord,
): ExecutiveMetricSummary => {
  if (dashboard.rollup.rows.length === 0) {
    return {
      issued: dashboard.overview.counts.issued,
      active: dashboard.overview.counts.active,
      claimRate: dashboard.overview.counts.claimRate ?? 0,
      shareRate: dashboard.overview.counts.shareRate ?? 0,
    };
  }

  const totals = dashboard.rollup.rows.reduce(
    (accumulator, row) => {
      accumulator.issued += row.issuedCount;
      accumulator.claims += row.learnerClaimCount;
      accumulator.shares += row.shareClickCount;
      return accumulator;
    },
    {
      issued: 0,
      claims: 0,
      shares: 0,
    },
  );

  return {
    issued: totals.issued,
    active: dashboard.overview.counts.active,
    claimRate: totals.issued === 0 ? 0 : (totals.claims / totals.issued) * 100,
    shareRate: totals.issued === 0 ? 0 : (totals.shares / totals.issued) * 100,
  };
};

const renderExecutiveMetrics = (dashboard: TenantExecutiveDashboardRecord): string => {
  const metricSummary = summarizeExecutiveMetrics(dashboard);
  const metricValues = new Map<string, string>([
    ["issued", formatCount(metricSummary.issued)],
    ["active", formatCount(metricSummary.active)],
    ["claimRate", `${formatPercent(metricSummary.claimRate)}%`],
    ["shareRate", `${formatPercent(metricSummary.shareRate)}%`],
  ]);

  return dashboard.kpiCatalog.kpis
    .map((kpi, index) => {
      const value = metricValues.get(kpi.key) ?? "Tracked";
      const cardClass =
        index === 0 ? "executive-kpi-card executive-kpi-card--primary" : "executive-kpi-card";

      return `<article class="${cardClass}">
        <p class="executive-kpi-label">${escapeHtml(kpi.label)}</p>
        <p class="executive-kpi-value">${escapeHtml(value)}</p>
        <p class="executive-kpi-description">${escapeHtml(kpi.description)}</p>
      </article>`;
    })
    .join("");
};

const renderInsightSummaryItems = (insight: ExecutiveDashboardInsight): string => {
  if (insight.summaryItems === undefined || insight.summaryItems.length === 0) {
    return "";
  }

  return `<ul class="executive-summary-list">
    ${insight.summaryItems
      .map((item) => {
        return `<li class="executive-summary-item">
          <strong>${escapeHtml(item.label)}</strong>
          <p>${escapeHtml(item.value)}</p>
        </li>`;
      })
      .join("")}
  </ul>`;
};

const renderInsightLinks = (insight: ExecutiveDashboardInsight): string => {
  if (insight.links === undefined || insight.links.length === 0) {
    return "";
  }

  return `<ul class="executive-link-list">
    ${insight.links
      .map((link) => {
        return `<li class="executive-link-item">
          <a class="executive-link-anchor" href="${escapeHtml(link.href)}">${escapeHtml(link.label)}</a>
        </li>`;
      })
      .join("")}
  </ul>`;
};

const renderInsightPanel = (
  insight: ExecutiveDashboardInsight,
  input: { fullWidth?: boolean } = {},
): string => {
  const panelClass =
    input.fullWidth === true ? "executive-section executive-panel--full" : "executive-section";
  const visualMarkup = insight.visual === undefined ? "" : renderReporting(insight.visual);
  const noteMarkup =
    insight.note === undefined ? "" : `<p class="executive-note">${escapeHtml(insight.note)}</p>`;

  return `<article class="${panelClass}">
    <div class="executive-section-header">
      <div>
        <p class="executive-section-kicker">${escapeHtml(insight.kicker)}</p>
        <h2>${escapeHtml(insight.title)}</h2>
      </div>
    </div>
    <p>${escapeHtml(insight.description)}</p>
    ${noteMarkup}
    ${visualMarkup}
    ${renderInsightSummaryItems(insight)}
    ${renderInsightLinks(insight)}
  </article>`;
};

const renderExecutiveBreadcrumbs = (dashboard: TenantExecutiveDashboardRecord): string => {
  if (dashboard.navigation.breadcrumbs.length === 0) {
    return "";
  }

  const lastIndex = dashboard.navigation.breadcrumbs.length - 1;

  return `<nav class="executive-breadcrumbs" aria-label="Executive drilldown path">
    <ol class="executive-breadcrumb-list">
      ${dashboard.navigation.breadcrumbs
        .map((link, index) => {
          return `<li class="executive-breadcrumb-item">
            ${
              index === lastIndex
                ? `<span class="executive-breadcrumb-current">${escapeHtml(link.label)}</span>`
                : `<a class="executive-breadcrumb-link" href="${escapeHtml(link.href)}">${escapeHtml(link.label)}</a>`
            }
          </li>`;
        })
        .join("")}
    </ol>
  </nav>`;
};

const renderStoryCards = (dashboard: TenantExecutiveDashboardRecord): string => {
  return [
    {
      label: "Current slice",
      value: titleCase(dashboard.defaults.audience),
      detail: isSystemAudience(dashboard)
        ? `Focused on ${dashboard.rollup.focusDisplayName} across the visible system slice`
        : `Focused on ${dashboard.rollup.focusDisplayName}`,
    },
    {
      label: "Compare next",
      value: titleCase(dashboard.rollup.comparisonLevel),
      detail:
        dashboard.rollup.rows.length === 0
          ? "No deeper visible slice is available yet, so the dashboard stays summary-first."
          : `${formatCount(dashboard.rollup.rows.length)} visible rows in this slice`,
    },
    {
      label: "Generated",
      value: formatIsoTimestamp(dashboard.rollup.generatedAt),
      detail: "Same reporting truth as the JSON executive payload",
    },
  ]
    .map((item) => {
      return `<article class="executive-story-card">
        <p class="executive-story-card-label">${escapeHtml(item.label)}</p>
        <p class="executive-story-card-value">${escapeHtml(item.value)}</p>
        <p class="executive-story-card-detail">${escapeHtml(item.detail)}</p>
      </article>`;
    })
    .join("");
};

export const renderExecutiveDashboardPage = (dashboard: TenantExecutiveDashboardRecord): string => {
  const insights = buildExecutiveDashboardInsights(dashboard);
  const primaryModule = insights.modules[0] ?? null;
  const secondaryModules = primaryModule === null ? [] : insights.modules.slice(1);
  const heroTitle = buildHeroTitle(dashboard);
  const heroEyebrow = buildHeroEyebrow(dashboard);
  const heroSubtitle = buildHeroSubtitle(dashboard);
  const storyKicker = dashboard.rollup.rows.length === 0 ? "Focused slice" : "First read";
  const storyHeading =
    dashboard.rollup.rows.length === 0 ? "Summary-first view" : "Executive snapshot";
  const storyMicrocopy =
    dashboard.rollup.rows.length === 0
      ? "This view stays intentionally narrow so leaders can trust the current slice instead of reading invented rankings."
      : isSystemAudience(dashboard)
        ? "This route starts with the system story, then moves into current momentum and the next visible comparison layer."
        : `This route starts with ${dashboard.rollup.focusDisplayName}, then moves into the visible comparison layer leaders can act on next.`;
  const jsonPath = buildExecutiveApiPath(dashboard.tenantId, dashboard.defaults.pathState);

  return renderPageShell(
    "Executive Dashboard",
    `<section class="executive-dashboard" data-executive-audience="${escapeHtml(dashboard.defaults.audience)}">
      <section class="executive-hero">
        <p class="executive-eyebrow">${escapeHtml(heroEyebrow)}</p>
        <p class="executive-hero-title-context">Executive Dashboard</p>
        <h1>${escapeHtml(heroTitle)}</h1>
        <p class="executive-subtitle">${escapeHtml(heroSubtitle)}</p>
        <div class="executive-context">
          <article class="executive-context-item">
            <p class="executive-context-label">Audience</p>
            <p class="executive-context-value">${escapeHtml(titleCase(dashboard.defaults.audience))}</p>
          </article>
          <article class="executive-context-item">
            <p class="executive-context-label">Focus</p>
            <p class="executive-context-value">${escapeHtml(dashboard.rollup.focusDisplayName)}</p>
          </article>
          <article class="executive-context-item">
            <p class="executive-context-label">Comparison level</p>
            <p class="executive-context-value">${escapeHtml(titleCase(dashboard.rollup.comparisonLevel))}</p>
          </article>
          <article class="executive-context-item">
            <p class="executive-context-label">Generated</p>
            <p class="executive-context-value">${escapeHtml(formatIsoTimestamp(dashboard.rollup.generatedAt))}</p>
          </article>
        </div>
        <div class="executive-chip-row executive-chip-row--hero">
          <span class="executive-chip">${escapeHtml(`Window ${titleCase(dashboard.defaults.window)}`)}</span>
          <span class="executive-chip">${escapeHtml(`State ${titleCase(dashboard.defaults.reportingFilters.state ?? "all")}`)}</span>
          <span class="executive-chip">${escapeHtml(`Compare ${titleCase(dashboard.rollup.comparisonLevel)}`)}</span>
          <span class="executive-chip">Read-only route</span>
          <span class="executive-chip">${escapeHtml(
            dashboard.access.visibility === "scoped" ? "Scoped view" : "Tenant-wide view",
          )}</span>
        </div>
        ${renderExecutiveBreadcrumbs(dashboard)}
        <div class="executive-actions">
          ${
            dashboard.navigation.back === null
              ? ""
              : `<a class="executive-action-link" href="${escapeHtml(dashboard.navigation.back.href)}">${escapeHtml(
                  `Back to ${dashboard.navigation.back.label}`,
                )}</a>`
          }
          <a class="executive-action-link" href="${escapeHtml(jsonPath)}">View JSON payload</a>
        </div>
      </section>

      <section class="executive-first-screen">
        <article class="executive-story">
          <div class="executive-section-header">
            <div>
              <p class="executive-section-kicker">${escapeHtml(storyKicker)}</p>
              <h2>${escapeHtml(storyHeading)}</h2>
            </div>
            <p class="executive-note">The same filters, focus, and scope flow through the read-only JSON endpoint.</p>
          </div>
          <p class="executive-microcopy">${escapeHtml(storyMicrocopy)}</p>
          <div class="executive-story-grid">
            ${renderStoryCards(dashboard)}
          </div>
        </article>

        <section class="executive-kpis" aria-label="Executive KPI summary">
          ${renderExecutiveMetrics(dashboard)}
        </section>
      </section>

      <section class="executive-grid">
        ${renderInsightPanel(insights.trend, { fullWidth: true })}
        ${
          primaryModule === null
            ? ""
            : renderInsightPanel(primaryModule, {
                fullWidth: true,
              })
        }
        ${secondaryModules.map((module) => renderInsightPanel(module)).join("")}
      </section>
    </section>`,
    renderPageAssetTags(["foundationCss", "executiveDashboardCss"]),
    "open",
  );
};

export const renderExecutiveUnavailablePage = (): string => {
  return renderPageShell(
    "Executive dashboard unavailable",
    `<section class="executive-dashboard" data-executive-audience="institution">
      <section class="executive-hero">
        <p class="executive-eyebrow">Executive access</p>
        <h1>Executive dashboard unavailable</h1>
        <p class="executive-subtitle">Your tenant membership does not expose an executive dashboard slice.</p>
      </section>
    </section>`,
    renderPageAssetTags(["foundationCss", "executiveDashboardCss"]),
    "open",
  );
};

export const renderInvalidExecutiveDashboardRequestPage = (): string => {
  return renderPageShell(
    "Invalid executive dashboard request",
    `<section class="executive-dashboard" data-executive-audience="institution">
      <section class="executive-hero">
        <p class="executive-eyebrow">Executive access</p>
        <h1>Invalid executive dashboard request</h1>
        <p class="executive-subtitle">The requested executive dashboard filters could not be understood.</p>
      </section>
    </section>`,
    renderPageAssetTags(["foundationCss", "executiveDashboardCss"]),
    "open",
  );
};

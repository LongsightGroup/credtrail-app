import type { HtmlEscapedString } from "hono/utils/html";
import { appPage, type AppPage } from "../ui/render-page";
import {
  buildExecutiveDashboardInsights,
  type ExecutiveDashboardInsight,
} from "./executive-dashboard-insights";
import type { TenantExecutiveDashboardRecord } from "./executive-rollup-loader";
import { buildExecutiveDashboardQueryEntries } from "./executive-dashboard-paths";
import { renderReporting } from "../reporting/reporting-visuals";
import { formatIsoTimestamp } from "../utils/display-format";

type HonoElement = HtmlEscapedString | Promise<HtmlEscapedString>;

interface ExecutiveMetricSummary {
  issued: number;
  active: number;
  claimRate: number;
  shareRate: number;
}

const executivePage = (input: { title: string; body: HonoElement }): AppPage => {
  return appPage({
    title: input.title,
    body: input.body,
    assets: ["executiveDashboardCss"],
    variant: "open",
  });
};

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
    return "Read institution-wide issuance, claim, and share momentum first, then compare the next visible level without crossing into operational admin work.";
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

const ExecutiveMetrics = (input: { dashboard: TenantExecutiveDashboardRecord }): HonoElement => {
  const metricSummary = summarizeExecutiveMetrics(input.dashboard);
  const metricValues = new Map<string, string>([
    ["issued", formatCount(metricSummary.issued)],
    ["active", formatCount(metricSummary.active)],
    ["claimRate", `${formatPercent(metricSummary.claimRate)}%`],
    ["shareRate", `${formatPercent(metricSummary.shareRate)}%`],
  ]);

  return (
    <>
      {input.dashboard.kpiCatalog.kpis.map((kpi, index) => {
        const value = metricValues.get(kpi.key) ?? "Tracked";
        const cardClass =
          index === 0 ? "executive-kpi-card executive-kpi-card--primary" : "executive-kpi-card";

        return (
          <article key={kpi.key} class={cardClass}>
            <p class="executive-kpi-label">{kpi.label}</p>
            <p class="executive-kpi-value">{value}</p>
            <p class="executive-kpi-description">{kpi.description}</p>
          </article>
        );
      })}
    </>
  );
};

const InsightSummaryItems = (input: { insight: ExecutiveDashboardInsight }): HonoElement | null => {
  if (input.insight.summaryItems === undefined || input.insight.summaryItems.length === 0) {
    return null;
  }

  return (
    <ul class="executive-summary-list">
      {input.insight.summaryItems.map((item) => (
        <li key={item.label} class="executive-summary-item">
          <strong>{item.label}</strong>
          <p>{item.value}</p>
        </li>
      ))}
    </ul>
  );
};

const InsightLinks = (input: { insight: ExecutiveDashboardInsight }): HonoElement | null => {
  if (input.insight.links === undefined || input.insight.links.length === 0) {
    return null;
  }

  return (
    <ul class="executive-link-list">
      {input.insight.links.map((link) => (
        <li key={link.href} class="executive-link-item">
          <a class="executive-link-anchor" href={link.href}>
            {link.label}
          </a>
        </li>
      ))}
    </ul>
  );
};

const InsightPanel = (input: {
  insight: ExecutiveDashboardInsight;
  fullWidth?: boolean | undefined;
}): HonoElement => {
  const panelClass =
    input.fullWidth === true ? "executive-section executive-panel--full" : "executive-section";

  return (
    <article class={panelClass}>
      <div class="executive-section-header">
        <div>
          <p class="executive-section-kicker">{input.insight.kicker}</p>
          <h2>{input.insight.title}</h2>
        </div>
      </div>
      <p>{input.insight.description}</p>
      {input.insight.note === undefined ? null : <p class="executive-note">{input.insight.note}</p>}
      {input.insight.visual === undefined ? null : renderReporting(input.insight.visual)}
      <InsightSummaryItems insight={input.insight} />
      <InsightLinks insight={input.insight} />
    </article>
  );
};

const ExecutiveBreadcrumbs = (input: {
  dashboard: TenantExecutiveDashboardRecord;
}): HonoElement | null => {
  if (input.dashboard.navigation.breadcrumbs.length === 0) {
    return null;
  }

  const lastIndex = input.dashboard.navigation.breadcrumbs.length - 1;

  return (
    <nav class="executive-breadcrumbs" aria-label="Executive drilldown path">
      <ol class="executive-breadcrumb-list">
        {input.dashboard.navigation.breadcrumbs.map((link, index) => (
          <li key={link.href} class="executive-breadcrumb-item">
            {index === lastIndex ? (
              <span class="executive-breadcrumb-current">{link.label}</span>
            ) : (
              <a class="executive-breadcrumb-link" href={link.href}>
                {link.label}
              </a>
            )}
          </li>
        ))}
      </ol>
    </nav>
  );
};

const StoryCards = (input: { dashboard: TenantExecutiveDashboardRecord }): HonoElement => {
  const items = [
    {
      label: "Current slice",
      value: titleCase(input.dashboard.defaults.audience),
      detail: isSystemAudience(input.dashboard)
        ? `Focused on ${input.dashboard.rollup.focusDisplayName} across the visible system slice`
        : `Focused on ${input.dashboard.rollup.focusDisplayName}`,
    },
    {
      label: "Compare next",
      value: titleCase(input.dashboard.rollup.comparisonLevel),
      detail:
        input.dashboard.rollup.rows.length === 0
          ? "No deeper visible slice is available yet, so the dashboard stays summary-first."
          : `${formatCount(input.dashboard.rollup.rows.length)} visible rows in this slice`,
    },
    {
      label: "Generated",
      value: formatIsoTimestamp(input.dashboard.rollup.generatedAt),
      detail: "Same reporting truth as the JSON executive payload",
    },
  ];

  return (
    <>
      {items.map((item) => (
        <article key={item.label} class="executive-story-card">
          <p class="executive-story-card-label">{item.label}</p>
          <p class="executive-story-card-value">{item.value}</p>
          <p class="executive-story-card-detail">{item.detail}</p>
        </article>
      ))}
    </>
  );
};

export const renderExecutiveDashboardPage = (
  dashboard: TenantExecutiveDashboardRecord,
): AppPage => {
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

  return executivePage({
    title: "Executive Dashboard",
    body: (
      <section class="executive-dashboard" data-executive-audience={dashboard.defaults.audience}>
        <section class="executive-hero">
          <p class="executive-eyebrow">{heroEyebrow}</p>
          <p class="executive-hero-title-context">Executive Dashboard</p>
          <h1>{heroTitle}</h1>
          <p class="executive-subtitle">{heroSubtitle}</p>
          <div class="executive-context">
            <article class="executive-context-item">
              <p class="executive-context-label">Audience</p>
              <p class="executive-context-value">{titleCase(dashboard.defaults.audience)}</p>
            </article>
            <article class="executive-context-item">
              <p class="executive-context-label">Focus</p>
              <p class="executive-context-value">{dashboard.rollup.focusDisplayName}</p>
            </article>
            <article class="executive-context-item">
              <p class="executive-context-label">Comparison level</p>
              <p class="executive-context-value">{titleCase(dashboard.rollup.comparisonLevel)}</p>
            </article>
            <article class="executive-context-item">
              <p class="executive-context-label">Generated</p>
              <p class="executive-context-value">
                {formatIsoTimestamp(dashboard.rollup.generatedAt)}
              </p>
            </article>
          </div>
          <div class="executive-chip-row executive-chip-row--hero">
            <span class="executive-chip">Window {titleCase(dashboard.defaults.window)}</span>
            <span class="executive-chip">
              State {titleCase(dashboard.defaults.reportingFilters.state ?? "all")}
            </span>
            <span class="executive-chip">
              Compare {titleCase(dashboard.rollup.comparisonLevel)}
            </span>
            <span class="executive-chip">Read-only route</span>
            <span class="executive-chip">
              {dashboard.access.visibility === "scoped" ? "Scoped view" : "Tenant-wide view"}
            </span>
          </div>
          <ExecutiveBreadcrumbs dashboard={dashboard} />
          <div class="executive-actions">
            {dashboard.navigation.back === null ? null : (
              <a class="executive-action-link" href={dashboard.navigation.back.href}>
                Back to {dashboard.navigation.back.label}
              </a>
            )}
            <a class="executive-action-link" href={jsonPath}>
              View JSON payload
            </a>
          </div>
        </section>

        <section class="executive-first-screen">
          <article class="executive-story">
            <div class="executive-section-header">
              <div>
                <p class="executive-section-kicker">{storyKicker}</p>
                <h2>{storyHeading}</h2>
              </div>
              <p class="executive-note">
                The same filters, focus, and scope flow through the read-only JSON endpoint.
              </p>
            </div>
            <p class="executive-microcopy">{storyMicrocopy}</p>
            <div class="executive-story-grid">
              <StoryCards dashboard={dashboard} />
            </div>
          </article>

          <section class="executive-kpis" aria-label="Executive KPI summary">
            <ExecutiveMetrics dashboard={dashboard} />
          </section>
        </section>

        <section class="executive-grid">
          <InsightPanel insight={insights.trend} fullWidth />
          {primaryModule === null ? null : <InsightPanel insight={primaryModule} fullWidth />}
          {secondaryModules.map((module) => (
            <InsightPanel key={module.title} insight={module} />
          ))}
        </section>
      </section>
    ),
  });
};

export const renderExecutiveUnavailablePage = (): AppPage => {
  return executivePage({
    title: "Executive dashboard unavailable",
    body: (
      <section class="executive-dashboard" data-executive-audience="institution">
        <section class="executive-hero">
          <p class="executive-eyebrow">Executive access</p>
          <h1>Executive dashboard unavailable</h1>
          <p class="executive-subtitle">
            Your tenant membership does not expose an executive dashboard slice.
          </p>
        </section>
      </section>
    ),
  });
};

export const renderInvalidExecutiveDashboardRequestPage = (): AppPage => {
  return executivePage({
    title: "Invalid executive dashboard request",
    body: (
      <section class="executive-dashboard" data-executive-audience="institution">
        <section class="executive-hero">
          <p class="executive-eyebrow">Executive access</p>
          <h1>Invalid executive dashboard request</h1>
          <p class="executive-subtitle">
            The requested executive dashboard filters could not be understood.
          </p>
        </section>
      </section>
    ),
  });
};

export const EXECUTIVE_DASHBOARD_CSS = String.raw`
.executive-dashboard {
  --ct-executive-shell: rgba(255, 255, 255, 0.92);
  --ct-executive-shell-strong: rgba(255, 255, 255, 0.97);
  --ct-executive-border: rgba(13, 46, 84, 0.12);
  --ct-executive-shadow: 0 10px 24px rgba(7, 27, 51, 0.08);
  --ct-executive-accent: rgba(17, 93, 159, 0.96);
  display: grid;
  gap: 1.35rem;
  max-width: 84rem;
  margin: 0 auto;
  padding: clamp(0.2rem, 1vw, 0.4rem);
}
.executive-hero,
.executive-story,
.executive-panel,
.executive-kpi-card,
.executive-section {
  border: 1px solid var(--ct-executive-border);
  border-radius: var(--ct-radius-lg);
  background: var(--ct-executive-shell);
  box-shadow: var(--ct-executive-shadow);
}
.executive-hero {
  position: relative;
  overflow: hidden;
  padding: clamp(1.35rem, 3vw, 2rem);
  background: linear-gradient(135deg, rgba(11, 39, 72, 0.98), rgba(18, 86, 146, 0.95));
  color: #f8fbff;
}
.executive-hero::after {
  content: none;
}
.executive-eyebrow {
  margin: 0 0 0.75rem;
  color: rgba(239, 247, 255, 0.78);
  font-size: 0.8rem;
  font-weight: 700;
  letter-spacing: 0.1em;
  text-transform: uppercase;
}
.executive-hero h1 {
  margin: 0;
  max-width: 12ch;
  font-family: var(--ct-font-sans);
  font-size: clamp(2.05rem, 4.6vw, 4rem);
  line-height: 1;
  letter-spacing: 0;
}
.executive-hero-title-context {
  margin: 0 0 0.55rem;
  color: rgba(248, 252, 255, 0.9);
  font-size: 0.92rem;
  font-weight: 600;
}
.executive-subtitle {
  margin: 0.9rem 0 0;
  max-width: 52rem;
  color: rgba(244, 250, 255, 0.9);
  font-size: 1rem;
  line-height: 1.6;
}
.executive-context {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(10rem, 1fr));
  gap: 0.85rem;
  margin-top: 1.3rem;
}
.executive-context-item {
  padding: 0.85rem 0.95rem;
  border-radius: 1rem;
  border: 1px solid rgba(255, 255, 255, 0.16);
  background: rgba(255, 255, 255, 0.11);
}
.executive-context-label {
  margin: 0;
  color: rgba(240, 247, 255, 0.72);
  font-size: 0.72rem;
  font-weight: 700;
  letter-spacing: 0.08em;
  text-transform: uppercase;
}
.executive-context-value {
  margin: 0.4rem 0 0;
  color: #fff;
  font-size: 1rem;
  font-weight: 700;
}
.executive-actions {
  display: flex;
  flex-wrap: wrap;
  gap: 0.7rem;
  margin-top: 1.25rem;
}
.executive-breadcrumbs {
  margin-top: 1rem;
}
.executive-breadcrumb-list {
  list-style: none;
  display: flex;
  flex-wrap: wrap;
  gap: 0.55rem;
  margin: 0;
  padding: 0;
}
.executive-breadcrumb-item {
  display: inline-flex;
  align-items: center;
  gap: 0.55rem;
}
.executive-breadcrumb-item:not(:last-child)::after {
  content: "/";
  color: rgba(248, 252, 255, 0.62);
  font-size: 0.78rem;
}
.executive-breadcrumb-link,
.executive-breadcrumb-current {
  display: inline-flex;
  align-items: center;
  min-height: 2rem;
  padding: 0.32rem 0.7rem;
  border-radius: 999px;
  border: 1px solid rgba(255, 255, 255, 0.18);
  font-size: 0.8rem;
  font-weight: 600;
}
.executive-breadcrumb-link {
  background: rgba(255, 255, 255, 0.12);
  color: #f8fbff;
  text-decoration: none;
}
.executive-breadcrumb-link:hover,
.executive-breadcrumb-link:focus-visible {
  background: rgba(255, 255, 255, 0.18);
}
.executive-breadcrumb-current {
  background: rgba(255, 255, 255, 0.2);
  color: #fff;
}
.executive-action-link {
  display: inline-flex;
  align-items: center;
  gap: 0.45rem;
  min-height: 2.8rem;
  padding: 0.72rem 1rem;
  border-radius: 999px;
  border: 1px solid rgba(255, 255, 255, 0.16);
  background: rgba(255, 255, 255, 0.12);
  color: #f8fbff;
  font-weight: 700;
  text-decoration: none;
}
.executive-action-link:hover,
.executive-action-link:focus-visible {
  background: rgba(255, 255, 255, 0.18);
}
.executive-first-screen {
  display: grid;
  gap: 1.2rem;
  grid-template-columns: minmax(0, 1.4fr) minmax(18rem, 0.92fr);
}
.executive-story {
  display: grid;
  gap: 1rem;
  padding: 1.15rem 1.2rem;
  background:
    linear-gradient(180deg, rgba(255, 255, 255, 0.98), rgba(245, 250, 255, 0.94)),
    var(--ct-executive-shell);
}
.executive-story h2,
.executive-panel h2,
.executive-section h2 {
  margin: 0;
  color: var(--ct-theme-text-title);
  font-size: 1.15rem;
  line-height: 1.25;
}
.executive-story p,
.executive-panel p,
.executive-section p {
  margin: 0;
  color: var(--ct-theme-text-muted);
  line-height: 1.6;
}
.executive-story-grid {
  display: grid;
  gap: 0.9rem;
  grid-template-columns: repeat(auto-fit, minmax(11rem, 1fr));
}
.executive-story-card {
  padding: 0.95rem 1rem;
  border-radius: var(--ct-radius-md);
  border: 1px solid rgba(15, 95, 166, 0.12);
  background: var(--ct-theme-surface-card-strong);
}
.executive-story-card-label {
  margin: 0;
  color: var(--ct-theme-text-subtle);
  font-size: 0.72rem;
  font-weight: 700;
  letter-spacing: 0.08em;
  text-transform: uppercase;
}
.executive-story-card-value {
  margin: 0.35rem 0 0;
  color: var(--ct-theme-text-title);
  font-size: 1.25rem;
  font-weight: 700;
}
.executive-story-card-detail {
  margin: 0.25rem 0 0;
  font-size: 0.8rem;
  line-height: 1.45;
}
.executive-kpis {
  display: grid;
  gap: 0.85rem;
  grid-template-columns: repeat(auto-fit, minmax(11rem, 1fr));
}
.executive-kpi-card {
  padding: 1rem 1.05rem;
}
.executive-kpi-label {
  margin: 0;
  color: var(--ct-theme-text-muted);
  font-size: 0.76rem;
  font-weight: 700;
  letter-spacing: 0.08em;
  text-transform: uppercase;
}
.executive-kpi-value {
  margin: 0.55rem 0 0;
  color: var(--ct-theme-text-title);
  font-size: 1.9rem;
  line-height: 1;
  font-weight: 700;
}
.executive-kpi-description {
  margin: 0.45rem 0 0;
  color: var(--ct-theme-text-muted);
  font-size: 0.88rem;
  line-height: 1.45;
}
.executive-kpi-card--primary {
  background: var(--ct-theme-surface-info);
}
.executive-grid {
  display: grid;
  gap: 1.2rem;
  grid-template-columns: repeat(2, minmax(0, 1fr));
}
.executive-section,
.executive-panel {
  display: grid;
  gap: 0.95rem;
  padding: 1.1rem 1.15rem;
}
.executive-panel--full {
  grid-column: 1 / -1;
}
.executive-section-header {
  display: flex;
  flex-wrap: wrap;
  justify-content: space-between;
  gap: 0.75rem;
  align-items: baseline;
}
.executive-section-kicker {
  margin: 0;
  color: var(--ct-theme-text-subtle);
  font-size: 0.72rem;
  font-weight: 700;
  letter-spacing: 0.08em;
  text-transform: uppercase;
}
.executive-note {
  margin: 0;
  font-size: 0.82rem;
  line-height: 1.45;
  color: var(--ct-theme-text-muted);
}
.executive-chip-row {
  display: flex;
  flex-wrap: wrap;
  gap: 0.55rem;
}
.executive-chip-row--hero {
  margin-top: 1rem;
}
.executive-chip {
  display: inline-flex;
  align-items: center;
  min-height: 2rem;
  padding: 0.38rem 0.75rem;
  border-radius: 999px;
  border: 1px solid rgba(15, 95, 166, 0.12);
  background: rgba(237, 244, 252, 0.74);
  color: var(--ct-theme-text-title);
  font-size: 0.78rem;
  font-weight: 600;
}
.executive-dashboard[data-executive-audience='system'] .executive-hero {
  background:
    linear-gradient(130deg, rgba(8, 31, 58, 0.98), rgba(16, 72, 132, 0.95) 56%, rgba(201, 146, 36, 0.92)),
    var(--ct-executive-shell);
}
.executive-dashboard[data-executive-audience='college'] .executive-hero,
.executive-dashboard[data-executive-audience='department'] .executive-hero,
.executive-dashboard[data-executive-audience='program'] .executive-hero {
  background:
    linear-gradient(135deg, rgba(7, 36, 68, 0.98), rgba(19, 105, 135, 0.94) 55%, rgba(84, 176, 148, 0.88)),
    var(--ct-executive-shell);
}
.executive-microcopy {
  margin: 0;
  font-size: 0.84rem;
  line-height: 1.5;
  color: var(--ct-theme-text-body);
}
.executive-summary-list {
  list-style: none;
  display: grid;
  gap: 0.75rem;
  padding: 0;
  margin: 0;
}
.executive-summary-item {
  display: grid;
  gap: 0.28rem;
  padding: 0.85rem 0.9rem;
  border-radius: 1rem;
  border: 1px solid rgba(15, 95, 166, 0.12);
  background: rgba(247, 250, 255, 0.94);
}
.executive-summary-item strong {
  color: var(--ct-theme-text-title);
}
.executive-link-list {
  list-style: none;
  display: grid;
  gap: 0.55rem;
  margin: 0;
  padding: 0;
}
.executive-link-item {
  margin: 0;
}
.executive-link-anchor {
  display: inline-flex;
  align-items: center;
  min-height: 2.4rem;
  padding: 0.55rem 0.85rem;
  border-radius: 0.95rem;
  border: 1px solid rgba(15, 95, 166, 0.16);
  background: rgba(247, 250, 255, 0.96);
  color: var(--ct-theme-link);
  font-size: 0.84rem;
  font-weight: 700;
  text-decoration: none;
}
.executive-link-anchor:hover,
.executive-link-anchor:focus-visible {
  background: rgba(237, 244, 252, 0.96);
  color: var(--ct-theme-link-hover);
}

.executive-dashboard .ct-reporting-visual {
  --ct-reporting-visual-surface: linear-gradient(
    180deg,
    rgba(253, 254, 255, 0.99),
    rgba(242, 248, 255, 0.95)
  );
  --ct-reporting-visual-border: rgba(15, 95, 166, 0.16);
  --ct-reporting-visual-accent: rgba(17, 93, 159, 0.96);
  --ct-reporting-visual-accent-muted: rgba(17, 93, 159, 0.62);
  --ct-reporting-visual-track: rgba(17, 93, 159, 0.12);
  display: grid;
  gap: 0.85rem;
  padding: 1rem;
  border: 1px solid var(--ct-reporting-visual-border);
  border-radius: 1.1rem;
  background: var(--ct-reporting-visual-surface);
  box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.75);
}
.executive-dashboard .ct-reporting-visual__header {
  display: grid;
  gap: 0.28rem;
}
.executive-dashboard .ct-reporting-visual__title {
  margin: 0;
  font-size: 1rem;
  color: var(--ct-theme-text-title);
}
.executive-dashboard .ct-reporting-visual__description {
  margin: 0;
  font-size: 0.84rem;
  line-height: 1.45;
  color: var(--ct-theme-text-muted);
}
.executive-dashboard .ct-reporting-visual__surface {
  padding: 0.9rem;
  border-radius: 0.95rem;
  border: 1px solid rgba(15, 95, 166, 0.1);
  background: rgba(255, 255, 255, 0.92);
  overflow: hidden;
}
.executive-dashboard .ct-reporting-visual__graphic {
  display: block;
  width: 100%;
  height: auto;
}
.executive-dashboard .ct-reporting-visual__summary {
  margin: 0;
  font-size: 0.82rem;
  line-height: 1.45;
  color: var(--ct-theme-text-muted);
}
.executive-dashboard .ct-reporting-visual__legend-block {
  display: grid;
  gap: 0.45rem;
}
.executive-dashboard .ct-reporting-visual__legend-title {
  margin: 0;
  font-size: 0.72rem;
  font-weight: 700;
  letter-spacing: 0.08em;
  text-transform: uppercase;
  color: var(--ct-theme-text-subtle);
}
.executive-dashboard .ct-reporting-visual__legend {
  list-style: none;
  margin: 0;
  padding: 0;
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(11rem, 1fr));
  gap: 0.55rem;
}
.executive-dashboard .ct-reporting-visual__legend-item {
  display: grid;
  grid-template-columns: auto minmax(0, 1fr) auto;
  gap: 0.28rem 0.65rem;
  align-items: center;
  padding: 0.6rem 0.7rem;
  border: 1px solid rgba(15, 95, 166, 0.12);
  border-radius: 0.95rem;
  background: rgba(255, 255, 255, 0.72);
}
.executive-dashboard .ct-reporting-visual__legend-item[data-reporting-visual-index='1'] {
  border-style: dashed;
}
.executive-dashboard .ct-reporting-visual__legend-item[data-reporting-visual-index='2'] {
  border-left-width: 3px;
}
.executive-dashboard .ct-reporting-visual__legend-item[data-reporting-visual-index='3'] {
  box-shadow: inset 0 0 0 1px rgba(15, 95, 166, 0.14);
}
.executive-dashboard .ct-reporting-visual__swatch {
  inline-size: 0.88rem;
  block-size: 0.88rem;
  border-radius: 0.28rem;
  border: 2px solid var(--ct-reporting-visual-accent);
  background: var(--ct-reporting-visual-accent);
}
.executive-dashboard .ct-reporting-visual__swatch--1 {
  background: repeating-linear-gradient(
    -45deg,
    rgba(17, 93, 159, 0.2),
    rgba(17, 93, 159, 0.2) 0.18rem,
    rgba(17, 93, 159, 0.78) 0.18rem,
    rgba(17, 93, 159, 0.78) 0.36rem
  );
}
.executive-dashboard .ct-reporting-visual__swatch--2 {
  border-style: dashed;
  background: linear-gradient(180deg, rgba(17, 93, 159, 0.88), rgba(17, 93, 159, 0.32));
}
.executive-dashboard .ct-reporting-visual__swatch--3 {
  background: linear-gradient(90deg, rgba(17, 93, 159, 0.16), rgba(17, 93, 159, 0.86));
}
.executive-dashboard .ct-reporting-visual__legend-label {
  min-width: 0;
  font-size: 0.84rem;
  color: var(--ct-theme-text-title);
}
.executive-dashboard .ct-reporting-visual__legend-value {
  font-variant-numeric: tabular-nums;
  font-weight: 700;
  color: var(--ct-theme-text-title);
}
.executive-dashboard .ct-reporting-visual__legend-detail {
  grid-column: 2 / 4;
  font-size: 0.74rem;
  line-height: 1.35;
  color: var(--ct-theme-text-muted);
}
.executive-dashboard[data-executive-audience='system'] .ct-reporting-visual__title {
  letter-spacing: 0;
}
.executive-dashboard .ct-reporting-visual[data-reporting-visual-kind='comparison-ranked'] .ct-reporting-visual__surface {
  padding: 0.8rem;
  background: rgba(255, 255, 255, 0.96);
}
.executive-dashboard .ct-reporting-visual__comparison-ranked {
  display: grid;
  gap: 0.75rem;
}
.executive-dashboard .ct-reporting-visual__comparison-ranked-list {
  list-style: none;
  margin: 0;
  padding: 0;
  display: grid;
  gap: 0.65rem;
}
.executive-dashboard .ct-reporting-visual__comparison-ranked-item {
  display: grid;
  gap: 0.45rem;
  padding: 0.72rem 0.78rem;
  border: 1px solid rgba(15, 95, 166, 0.12);
  border-radius: 0.95rem;
  background: rgba(255, 255, 255, 0.76);
}
.executive-dashboard .ct-reporting-visual__comparison-ranked-item[data-reporting-visual-index='1'] {
  border-style: dashed;
}
.executive-dashboard .ct-reporting-visual__comparison-ranked-item[data-reporting-visual-index='2'] {
  border-left-width: 3px;
}
.executive-dashboard .ct-reporting-visual__comparison-ranked-item[data-reporting-visual-index='3'] {
  box-shadow: inset 0 0 0 1px rgba(15, 95, 166, 0.14);
}
.executive-dashboard .ct-reporting-visual__comparison-ranked-head {
  display: flex;
  align-items: baseline;
  justify-content: space-between;
  gap: 0.8rem;
}
.executive-dashboard .ct-reporting-visual__comparison-ranked-label {
  min-width: 0;
  font-size: 0.86rem;
  font-weight: 600;
  color: var(--ct-theme-text-title);
}
.executive-dashboard .ct-reporting-visual__comparison-ranked-value {
  flex-shrink: 0;
  font-variant-numeric: tabular-nums;
  font-weight: 700;
  color: var(--ct-theme-text-title);
}
.executive-dashboard .ct-reporting-visual__comparison-ranked-bar-track {
  block-size: 0.52rem;
  border-radius: 999px;
  background: var(--ct-reporting-visual-track);
  overflow: hidden;
}
.executive-dashboard .ct-reporting-visual__comparison-ranked-bar {
  display: block;
  block-size: 100%;
  border-radius: inherit;
  background: var(--ct-reporting-visual-accent);
}
.executive-dashboard .ct-reporting-visual__comparison-ranked-bar--1 {
  background: rgba(17, 93, 159, 0.78);
}
.executive-dashboard .ct-reporting-visual__comparison-ranked-bar--2 {
  background: rgba(17, 93, 159, 0.58);
}
.executive-dashboard .ct-reporting-visual__comparison-ranked-bar--3 {
  background: rgba(17, 93, 159, 0.92);
}
.executive-dashboard .ct-reporting-visual__comparison-ranked-detail {
  font-size: 0.76rem;
  line-height: 1.4;
  color: var(--ct-theme-text-muted);
}
.executive-dashboard .ct-reporting-visual__comparison-ranked-overflow {
  margin: 0;
  padding-top: 0.1rem;
  font-size: 0.78rem;
  line-height: 1.4;
  color: var(--ct-theme-text-muted);
}
.executive-dashboard .ct-reporting-visual__bar-track,
.executive-dashboard .ct-reporting-visual__segment-track {
  fill: var(--ct-reporting-visual-track);
}
.executive-dashboard .ct-reporting-visual__bar,
.executive-dashboard .ct-reporting-visual__segment {
  fill: var(--ct-reporting-visual-accent);
  stroke: rgba(17, 93, 159, 0.18);
  stroke-width: 1.5;
}
.executive-dashboard .ct-reporting-visual__segment {
  stroke: none;
}
.executive-dashboard .ct-reporting-visual__bar--1,
.executive-dashboard .ct-reporting-visual__segment--1 {
  fill: rgba(17, 93, 159, 0.78);
  stroke-dasharray: 6 4;
}
.executive-dashboard .ct-reporting-visual__bar--2,
.executive-dashboard .ct-reporting-visual__segment--2 {
  fill: rgba(17, 93, 159, 0.5);
}
.executive-dashboard .ct-reporting-visual__bar--3,
.executive-dashboard .ct-reporting-visual__segment--3 {
  fill: rgba(17, 93, 159, 0.92);
}
.executive-dashboard .ct-reporting-visual__baseline {
  stroke: rgba(17, 93, 159, 0.2);
  stroke-width: 2;
}
.executive-dashboard .ct-reporting-visual__trend-line {
  fill: none;
  stroke: var(--ct-reporting-visual-accent);
  stroke-width: 3;
  stroke-linecap: round;
  stroke-linejoin: round;
}
.executive-dashboard .ct-reporting-visual[data-reporting-visual-kind='trend-series'] .ct-reporting-visual__trend-line {
  stroke-dasharray: 10 6;
}
.executive-dashboard .ct-reporting-visual__point {
  fill: rgba(255, 255, 255, 0.95);
  stroke: var(--ct-reporting-visual-accent);
  stroke-width: 3;
}
.executive-dashboard .ct-reporting-visual__point--1 {
  stroke: rgba(17, 93, 159, 0.82);
}
.executive-dashboard .ct-reporting-visual__point--2 {
  stroke: rgba(17, 93, 159, 0.58);
}
.executive-dashboard .ct-reporting-visual__point--3 {
  stroke: rgba(17, 93, 159, 0.98);
}
.executive-dashboard .ct-reporting-visual__trend-context {
  display: grid;
  gap: 0.8rem;
}
.executive-dashboard .ct-reporting-visual__trend-axis {
  display: grid;
  gap: 0.7rem;
  grid-template-columns: repeat(2, minmax(0, 1fr));
}
.executive-dashboard .ct-reporting-visual__trend-axis-item {
  display: grid;
  gap: 0.2rem;
  padding: 0.7rem 0.8rem;
  border: 1px solid rgba(17, 93, 159, 0.12);
  border-radius: 0.95rem;
  background: rgba(255, 255, 255, 0.78);
}
.executive-dashboard .ct-reporting-visual__trend-axis-label,
.executive-dashboard .ct-reporting-visual__trend-callout-label {
  font-size: 0.72rem;
  font-weight: 700;
  letter-spacing: 0.08em;
  text-transform: uppercase;
  color: var(--ct-theme-text-subtle);
}
.executive-dashboard .ct-reporting-visual__trend-axis-value,
.executive-dashboard .ct-reporting-visual__trend-callout-value,
.executive-dashboard .ct-reporting-visual__trend-callout-metric {
  color: var(--ct-theme-text-title);
  font-variant-numeric: tabular-nums;
}
.executive-dashboard .ct-reporting-visual__trend-axis-detail,
.executive-dashboard .ct-reporting-visual__trend-callout-detail {
  font-size: 0.78rem;
  line-height: 1.4;
  color: var(--ct-theme-text-muted);
}
.executive-dashboard .ct-reporting-visual__trend-callouts {
  list-style: none;
  margin: 0;
  padding: 0;
  display: grid;
  gap: 0.7rem;
  grid-template-columns: repeat(auto-fit, minmax(11rem, 1fr));
}
.executive-dashboard .ct-reporting-visual__trend-callout {
  display: grid;
  gap: 0.28rem;
  padding: 0.75rem 0.8rem;
  border-radius: 0.95rem;
  border: 1px solid rgba(17, 93, 159, 0.12);
  background: linear-gradient(180deg, rgba(255, 255, 255, 0.82), rgba(238, 246, 255, 0.76));
}
.executive-dashboard .ct-reporting-visual__empty {
  padding: 1rem;
  border: 1px dashed rgba(17, 93, 159, 0.28);
  border-radius: 0.95rem;
  background: rgba(255, 255, 255, 0.78);
  color: var(--ct-theme-text-muted);
}
.executive-dashboard .ct-reporting-visual__empty--sparse,
.executive-dashboard .ct-reporting-visual[data-reporting-visual-state='sparse'] .ct-reporting-visual__empty {
  border-style: solid;
  border-color: rgba(17, 93, 159, 0.16);
  background:
    linear-gradient(160deg, rgba(255, 255, 255, 0.96), rgba(238, 246, 255, 0.86)),
    rgba(255, 255, 255, 0.9);
  color: var(--ct-theme-text-body);
}
@media (max-width: 980px) {
  .executive-first-screen,
  .executive-grid {
    grid-template-columns: minmax(0, 1fr);
  }
}
@media (max-width: 960px) {
  .executive-breadcrumb-list,
  .executive-actions {
    gap: 0.5rem;
  }
  .executive-dashboard .ct-reporting-visual {
    padding: 0.9rem;
  }
  .executive-dashboard .ct-reporting-visual__surface {
    padding: 0.75rem;
  }
  .executive-dashboard .ct-reporting-visual__legend,
  .executive-dashboard .ct-reporting-visual__trend-axis,
  .executive-dashboard .ct-reporting-visual__trend-callouts {
    grid-template-columns: minmax(0, 1fr);
  }
}
@media (max-width: 720px) {
  .executive-dashboard {
    padding: 0.85rem;
  }
  .executive-breadcrumb-list,
  .executive-actions {
    flex-direction: column;
    align-items: stretch;
  }
  .executive-breadcrumb-item {
    justify-content: space-between;
  }
  .executive-hero,
  .executive-story,
  .executive-panel,
  .executive-kpi-card,
  .executive-section {
    border-radius: 1.15rem;
  }
  .executive-context,
  .executive-kpis,
  .executive-story-grid {
    grid-template-columns: minmax(0, 1fr);
  }
}
`;

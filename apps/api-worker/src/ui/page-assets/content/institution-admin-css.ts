export const INSTITUTION_ADMIN_CSS = `
/* ── Admin shell layout ── */
.ct-admin-shell {
  display: grid;
  grid-template-columns: 15rem 1fr;
  min-height: 100vh;
}
.ct-admin-sidebar {
  position: sticky;
  top: 0;
  height: 100vh;
  overflow-y: auto;
  background: #ffffff;
  border-right: 1px solid var(--ct-border-soft);
  display: grid;
  grid-template-rows: auto 1fr auto;
  padding: 0;
}
.ct-admin-sidebar__brand {
  padding: 1.25rem 1.25rem 1rem;
  font-family: var(--ct-font-sans);
  font-size: 1.05rem;
  font-weight: 600;
  color: var(--ct-theme-text-title);
  letter-spacing: 0;
  text-decoration: none;
  display: block;
  border-bottom: 1px solid var(--ct-border-soft);
}
.ct-admin-sidebar__nav {
  padding: 0.75rem 0;
  display: grid;
  gap: 0.2rem;
  align-content: start;
}
.ct-admin-sidebar__section {
  min-width: 0;
  margin: 0.08rem 0;
}
.ct-admin-sidebar__section-summary {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 0.75rem;
  margin: 0 0.6rem;
  padding: 0.54rem 0.65rem;
  color: var(--ct-theme-text-muted);
  cursor: pointer;
  list-style: none;
  border: 1px solid transparent;
  border-radius: var(--ct-radius-sm);
  transition:
    background var(--ct-duration-fast) var(--ct-ease-standard),
    border-color var(--ct-duration-fast) var(--ct-ease-standard),
    color var(--ct-duration-fast) var(--ct-ease-standard);
}
.ct-admin-sidebar__section-summary::-webkit-details-marker {
  display: none;
}
.ct-admin-sidebar__section-summary:hover {
  background: var(--ct-theme-surface-soft);
  color: var(--ct-theme-text-title);
}
.ct-admin-sidebar__section-summary:focus-visible {
  outline: 2px solid var(--ct-theme-border-focus);
  outline-offset: 2px;
}
.ct-admin-sidebar__section-caret {
  flex: 0 0 auto;
  width: 0.42rem;
  height: 0.42rem;
  border-right: 1.5px solid currentColor;
  border-bottom: 1.5px solid currentColor;
  transform: rotate(-45deg);
  transition: transform var(--ct-duration-fast) var(--ct-ease-standard);
}
.ct-admin-sidebar__section[open] .ct-admin-sidebar__section-caret {
  transform: rotate(45deg);
}
.ct-admin-sidebar__section-title {
  min-width: 0;
  display: inline-flex;
  align-items: center;
  gap: 0.5rem;
}
.ct-admin-sidebar__section-icon {
  flex: 0 0 auto;
  width: 1rem;
  height: 1rem;
  stroke-width: 1.8;
}
.ct-admin-sidebar__section-label {
  margin: 0;
  font-size: 0.7rem;
  text-transform: uppercase;
  letter-spacing: 0.09em;
  font-weight: 700;
  line-height: 1.2;
}
.ct-admin-sidebar__section-links {
  display: grid;
  gap: 0.1rem;
  margin: 0.22rem 0 0.55rem 1.55rem;
  padding-left: 0.62rem;
  border-left: 1px solid var(--ct-border-soft);
}
.ct-admin-sidebar__section-links .ct-admin-sidebar__link {
  margin-left: 0;
}
.ct-admin-sidebar__link {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  margin: 0 0.6rem;
  padding: 0.52rem 0.65rem;
  font-size: 0.86rem;
  font-weight: 500;
  color: var(--ct-theme-text-body);
  text-decoration: none;
  border: 1px solid transparent;
  border-radius: var(--ct-radius-sm);
  transition:
    background var(--ct-duration-fast) var(--ct-ease-standard),
    color var(--ct-duration-fast) var(--ct-ease-standard),
    border-color var(--ct-duration-fast) var(--ct-ease-standard);
}
.ct-admin-sidebar__link:hover {
  background: var(--ct-theme-surface-soft);
  color: var(--ct-theme-text-title);
}
.ct-admin-sidebar__link[aria-current='page'] {
  background: var(--ct-theme-surface-info);
  border-color: var(--ct-theme-border-info);
  color: var(--ct-brand-lake-700);
  font-weight: 600;
}
.ct-admin-sidebar__link--sub {
  padding-left: 0.95rem;
  font-size: 0.83rem;
}
.ct-admin-sidebar__link--external::after {
  content: '↗';
  font-size: 0.72rem;
  opacity: 0.5;
  margin-left: auto;
}
.ct-admin-sidebar__footer {
  padding: 0.75rem 1.25rem;
  border-top: 1px solid var(--ct-border-soft);
}
.ct-admin-sidebar__footer-link {
  display: block;
  padding: 0.4rem 0;
  font-size: 0.82rem;
  color: var(--ct-theme-text-muted);
  text-decoration: none;
}
.ct-admin-sidebar__footer-link:hover {
  color: var(--ct-theme-text-title);
}
.ct-admin-main {
  display: grid;
  grid-template-rows: auto 1fr;
  min-height: 100vh;
  min-width: 0;
}
.ct-admin-topbar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 1rem;
  padding: 0.6rem 1.5rem;
  border-bottom: 1px solid var(--ct-border-soft);
  background: #ffffff;
  position: sticky;
  top: 0;
  z-index: 10;
}
.ct-admin-topbar__title {
  margin: 0;
  font-family: var(--ct-font-sans);
  font-size: 0.88rem;
  font-weight: 600;
  color: var(--ct-theme-text-title);
}
.ct-admin-topbar__user {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  font-size: 0.8rem;
  color: var(--ct-theme-text-muted);
}
.ct-admin-topbar__chip {
  display: inline-flex;
  align-items: center;
  padding: 0.18rem 0.5rem;
  border-radius: var(--ct-radius-pill);
  font-size: 0.73rem;
  font-weight: 600;
  background: var(--ct-theme-surface-soft);
  border: 1px solid var(--ct-border-soft);
  color: var(--ct-theme-text-muted);
}
.ct-admin-topbar__toggle {
  display: none;
  box-sizing: border-box;
  appearance: none;
  align-items: center;
  justify-content: center;
  width: 2.25rem;
  height: 2.25rem;
  border: 1px solid var(--ct-border-soft);
  border-radius: var(--ct-radius-sm);
  background: transparent;
  cursor: pointer;
  font-family: var(--ct-font-sans);
  font-size: 1.1rem;
  line-height: 1;
  color: var(--ct-theme-text-body);
}
.ct-admin-topbar__toggle:focus-visible {
  outline: 2px solid var(--ct-theme-border-focus);
  outline-offset: 3px;
}
.ct-admin-content {
  padding: 1.75rem 2rem;
  max-width: 1200px;
}
.ct-admin-page-header {
  margin-bottom: 1.5rem;
}
.ct-admin-page-header h1 {
  margin: 0 0 0.35rem;
  font-size: clamp(1.2rem, 2.2vw, 1.5rem);
  font-weight: 700;
  color: var(--ct-theme-text-title);
  line-height: 1.25;
}
.ct-admin-page-header p {
  margin: 0;
  color: var(--ct-theme-text-muted);
  font-size: 0.92rem;
  line-height: 1.5;
  max-width: 46rem;
}
.ct-admin-page-header__note {
  margin-top: 1rem;
  padding: 0.85rem 1rem;
  border-radius: var(--ct-radius-md);
  border: 1px solid var(--ct-theme-border-info);
  background: var(--ct-theme-surface-info);
}
.ct-admin-page-header__note h2 {
  margin: 0 0 0.25rem;
  font-family: var(--ct-font-sans);
  font-size: 0.92rem;
  font-weight: 600;
  letter-spacing: 0;
}
.ct-admin-page-header__note p {
  margin: 0;
  font-size: 0.85rem;
  color: var(--ct-theme-text-muted);
}

/* ── Mobile responsive ── */
@media (max-width: 768px) {
  .ct-admin-shell {
    grid-template-columns: 1fr;
  }
  .ct-admin-main {
    max-width: 100vw;
    overflow-x: hidden;
  }
  .ct-admin-sidebar {
    position: fixed;
    top: 0;
    left: 0;
    width: 16rem;
    height: 100vh;
    z-index: 100;
    transform: translateX(-100%);
    transition: transform var(--ct-duration-standard) var(--ct-ease-standard);
    box-shadow: var(--ct-shadow-soft);
  }
  .ct-admin-sidebar--open {
    transform: translateX(0);
  }
  .ct-admin-sidebar__backdrop {
    display: none;
    position: fixed;
    inset: 0;
    background: rgba(7, 26, 49, 0.3);
    z-index: 99;
  }
  .ct-admin-sidebar--open + .ct-admin-main .ct-admin-sidebar__backdrop {
    display: block;
  }
  .ct-admin-topbar__toggle {
    display: inline-flex;
  }
  .ct-admin-topbar {
    min-width: 0;
    gap: 0.65rem;
    padding-inline: 1rem;
  }
  .ct-admin-topbar__title {
    min-width: 0;
    max-width: 8rem;
    overflow-wrap: anywhere;
  }
  .ct-admin-topbar__user {
    min-width: 0;
    justify-content: flex-end;
    overflow: hidden;
  }
  .ct-admin-topbar__user > span:not(.ct-admin-topbar__chip) {
    min-width: 0;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .ct-admin-content {
    padding: 1.25rem 1rem;
    max-width: 100%;
    box-sizing: border-box;
  }
}

/* ── Legacy admin content styles ── */
.ct-admin {
  --ct-stack-gap: var(--ct-space-4);
}
.ct-admin__eyebrow {
  margin: 0;
  font-size: 0.7rem;
  text-transform: uppercase;
  letter-spacing: 0.1em;
  font-weight: 700;
  color: var(--ct-theme-text-subtle);
}
.ct-admin__workspace-grid.ct-grid {
  --ct-grid-gap: 0.9rem;
  grid-template-columns: repeat(3, minmax(0, 1fr));
}
.ct-admin__workspace-card {
  --ct-stack-gap: 0.7rem;
  display: block;
  color: inherit;
  text-decoration: none;
  padding: 1rem;
  border-radius: var(--ct-radius-lg);
  border: 1px solid var(--ct-border-soft);
  background: var(--ct-theme-surface-card-strong);
  box-shadow: var(--ct-shadow-soft);
  transition:
    background var(--ct-duration-fast) var(--ct-ease-standard),
    border-color var(--ct-duration-fast) var(--ct-ease-standard),
    box-shadow var(--ct-duration-fast) var(--ct-ease-standard);
}
a.ct-admin__workspace-card {
  cursor: pointer;
}
a.ct-admin__workspace-card:hover {
  border-color: var(--ct-theme-border-info);
  background: var(--ct-theme-surface-info);
  box-shadow: var(--ct-shadow-card);
}
a.ct-admin__workspace-card:focus-visible {
  outline: 2px solid var(--ct-theme-border-focus);
  outline-offset: 3px;
  border-color: var(--ct-theme-border-info);
  background: var(--ct-theme-surface-info);
}
a.ct-admin__workspace-card:active {
  border-color: var(--ct-brand-lake-600);
}
.ct-admin__workspace-card h2 {
  margin: 0;
  font-size: 1.05rem;
}
.ct-admin__workspace-card p {
  margin: 0;
  color: var(--ct-theme-text-muted);
  font-size: 0.9rem;
}
.ct-admin__workspace-stats {
  --ct-cluster-gap: 0.4rem;
}
.ct-admin__workspace-actions {
  --ct-cluster-gap: 0.45rem;
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 0.45rem;
}
.ct-admin__workspace-actions .ct-admin__button,
.ct-admin__workspace-actions .ct-admin__cta-link {
  min-height: 2.24rem;
  border-radius: var(--ct-radius-sm);
}
.ct-admin__metric-grid {
  display: grid;
  gap: 0.9rem;
  grid-template-columns: repeat(auto-fit, minmax(10rem, 1fr));
}
.ct-admin__metric-grid--rates {
  grid-template-columns: repeat(auto-fit, minmax(13rem, 1fr));
}
.ct-admin__metric-card {
  padding: 1rem;
  border-radius: var(--ct-radius-lg);
  border: 1px solid var(--ct-border-soft);
  background: var(--ct-theme-surface-card);
  box-shadow: var(--ct-shadow-soft);
}
.ct-admin__metric-card--rate {
  background: var(--ct-theme-surface-info);
}
.ct-admin__metric-value {
  font-size: 2rem;
  line-height: 1;
}
.ct-admin__reporting-bar-value {
  --ct-reporting-bar-ratio: 0;
  display: grid;
  gap: 0.32rem;
  min-width: 6.2rem;
}
.ct-admin__reporting-bar-number {
  font-variant-numeric: tabular-nums;
  font-weight: 600;
  color: var(--ct-theme-text-title);
}
.ct-admin__reporting-bar-track {
  display: block;
  width: 100%;
  height: 0.38rem;
  border-radius: 999px;
  overflow: hidden;
  background: rgba(15, 95, 166, 0.12);
}
.ct-admin__reporting-bar-fill {
  display: block;
  width: calc(var(--ct-reporting-bar-ratio) * 100%);
  min-width: 0;
  height: 100%;
  border-radius: inherit;
  background: linear-gradient(90deg, var(--ct-brand-lake-500), var(--ct-brand-lake-700));
  transition: width var(--ct-duration-standard) var(--ct-ease-standard);
}
.ct-reporting-visual {
  --ct-reporting-visual-surface: linear-gradient(
    180deg,
    rgba(250, 252, 255, 0.98),
    rgba(240, 246, 252, 0.95)
  );
  --ct-reporting-visual-border: rgba(15, 95, 166, 0.16);
  --ct-reporting-visual-accent: var(--ct-brand-lake-700);
  --ct-reporting-visual-accent-muted: rgba(15, 95, 166, 0.6);
  --ct-reporting-visual-track: rgba(15, 95, 166, 0.12);
  display: grid;
  gap: 0.85rem;
  padding: 1rem;
  border: 1px solid var(--ct-reporting-visual-border);
  border-radius: var(--ct-radius-lg);
  background: var(--ct-reporting-visual-surface);
  box-shadow: var(--ct-shadow-soft);
}
.ct-reporting-visual__header {
  display: grid;
  gap: 0.28rem;
}
.ct-reporting-visual__title {
  margin: 0;
  font-size: 1rem;
  color: var(--ct-theme-text-title);
}
.ct-reporting-visual__description {
  margin: 0;
  font-size: 0.84rem;
  line-height: 1.45;
  color: var(--ct-theme-text-muted);
}
.ct-reporting-visual__surface {
  padding: 0.9rem;
  border-radius: var(--ct-radius-md);
  border: 1px solid rgba(15, 95, 166, 0.1);
  background: rgba(255, 255, 255, 0.92);
  overflow: hidden;
}
.ct-reporting-visual__graphic {
  display: block;
  width: 100%;
  height: auto;
}
.ct-reporting-visual__summary {
  margin: 0;
  font-size: 0.82rem;
  line-height: 1.45;
  color: var(--ct-theme-text-muted);
}
.ct-reporting-visual__legend-block {
  display: grid;
  gap: 0.45rem;
}
.ct-reporting-visual__legend-title {
  margin: 0;
  font-size: 0.72rem;
  font-weight: 700;
  letter-spacing: 0.08em;
  text-transform: uppercase;
  color: var(--ct-theme-text-subtle);
}
.ct-reporting-visual__legend {
  list-style: none;
  margin: 0;
  padding: 0;
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(11rem, 1fr));
  gap: 0.55rem;
}
.ct-reporting-visual__legend-item {
  display: grid;
  grid-template-columns: auto minmax(0, 1fr) auto;
  gap: 0.28rem 0.65rem;
  align-items: center;
  padding: 0.6rem 0.7rem;
  border: 1px solid rgba(15, 95, 166, 0.12);
  border-radius: var(--ct-radius-md);
  background: rgba(255, 255, 255, 0.72);
}
.ct-reporting-visual__legend-item[data-reporting-visual-index='1'] {
  border-style: dashed;
}
.ct-reporting-visual__legend-item[data-reporting-visual-index='2'] {
  outline: 1px dashed rgba(15, 95, 166, 0.2);
  outline-offset: -0.28rem;
}
.ct-reporting-visual__legend-item[data-reporting-visual-index='3'] {
  box-shadow: inset 0 0 0 1px rgba(15, 95, 166, 0.14);
}
.ct-reporting-visual__swatch {
  inline-size: 0.88rem;
  block-size: 0.88rem;
  border-radius: 0.28rem;
  border: 2px solid var(--ct-reporting-visual-accent);
  background: var(--ct-reporting-visual-accent);
}
.ct-reporting-visual__swatch--1 {
  background: repeating-linear-gradient(
    -45deg,
    rgba(15, 95, 166, 0.2),
    rgba(15, 95, 166, 0.2) 0.18rem,
    rgba(15, 95, 166, 0.78) 0.18rem,
    rgba(15, 95, 166, 0.78) 0.36rem
  );
}
.ct-reporting-visual__swatch--2 {
  border-style: dashed;
  background: linear-gradient(
    180deg,
    rgba(15, 95, 166, 0.88),
    rgba(15, 95, 166, 0.32)
  );
}
.ct-reporting-visual__swatch--3 {
  background: linear-gradient(
    90deg,
    rgba(15, 95, 166, 0.16),
    rgba(15, 95, 166, 0.86)
  );
}
.ct-reporting-visual__legend-label {
  min-width: 0;
  font-size: 0.84rem;
  color: var(--ct-theme-text-title);
}
.ct-reporting-visual__legend-value {
  font-variant-numeric: tabular-nums;
  font-weight: 700;
  color: var(--ct-theme-text-title);
}
.ct-reporting-visual__legend-detail {
  grid-column: 2 / 4;
  font-size: 0.74rem;
  line-height: 1.35;
  color: var(--ct-theme-text-muted);
}
.ct-reporting-visual[data-reporting-visual-kind='comparison-ranked'] .ct-reporting-visual__surface {
  padding: 0.8rem;
  background: linear-gradient(180deg, rgba(255, 255, 255, 0.96), rgba(242, 248, 255, 0.92));
}
.ct-reporting-visual__comparison-ranked {
  display: grid;
  gap: 0.75rem;
}
.ct-reporting-visual__comparison-ranked-list {
  list-style: none;
  margin: 0;
  padding: 0;
  display: grid;
  gap: 0.65rem;
}
.ct-reporting-visual__comparison-ranked-item {
  display: grid;
  gap: 0.45rem;
  padding: 0.72rem 0.78rem;
  border: 1px solid rgba(15, 95, 166, 0.12);
  border-radius: var(--ct-radius-md);
  background: rgba(255, 255, 255, 0.76);
}
.ct-reporting-visual__comparison-ranked-item[data-reporting-visual-index='0'] {
  background:
    linear-gradient(180deg, rgba(255, 255, 255, 0.96), rgba(239, 247, 255, 0.92)),
    rgba(255, 255, 255, 0.9);
  box-shadow: 0 14px 28px rgba(7, 26, 49, 0.08);
}
.ct-reporting-visual__comparison-ranked-item[data-reporting-visual-index='1'] {
  border-style: dashed;
}
.ct-reporting-visual__comparison-ranked-item[data-reporting-visual-index='2'] {
  outline: 1px dashed rgba(15, 95, 166, 0.2);
  outline-offset: -0.28rem;
}
.ct-reporting-visual__comparison-ranked-item[data-reporting-visual-index='3'] {
  box-shadow: inset 0 0 0 1px rgba(15, 95, 166, 0.14);
}
.ct-reporting-visual__comparison-ranked-head {
  display: grid;
  grid-template-columns: auto minmax(0, 1fr) auto;
  align-items: baseline;
  gap: 0.55rem;
}
.ct-reporting-visual__comparison-ranked-rank {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  min-inline-size: 1.65rem;
  block-size: 1.65rem;
  border-radius: var(--ct-radius-pill);
  border: 1px solid rgba(15, 95, 166, 0.18);
  background: rgba(15, 95, 166, 0.08);
  font-size: 0.76rem;
  font-weight: 800;
  font-variant-numeric: tabular-nums;
  color: var(--ct-brand-midnight-900);
}
.ct-reporting-visual__comparison-ranked-label {
  min-width: 0;
  font-size: 0.86rem;
  font-weight: 600;
  color: var(--ct-theme-text-title);
}
.ct-reporting-visual__comparison-ranked-value {
  flex-shrink: 0;
  font-variant-numeric: tabular-nums;
  font-weight: 700;
  color: var(--ct-theme-text-title);
}
.ct-reporting-visual__comparison-ranked-bar-track {
  block-size: 0.52rem;
  border-radius: var(--ct-radius-pill);
  background: var(--ct-reporting-visual-track);
  overflow: hidden;
}
.ct-reporting-visual__comparison-ranked-bar {
  display: block;
  block-size: 100%;
  border-radius: inherit;
  background: var(--ct-reporting-visual-accent);
}
.ct-reporting-visual__comparison-ranked-bar--1 {
  background: rgba(15, 95, 166, 0.78);
}
.ct-reporting-visual__comparison-ranked-bar--2 {
  background: rgba(15, 95, 166, 0.58);
}
.ct-reporting-visual__comparison-ranked-bar--3 {
  background: rgba(15, 95, 166, 0.92);
}
.ct-reporting-visual__comparison-ranked-detail {
  font-size: 0.76rem;
  line-height: 1.4;
  color: var(--ct-theme-text-muted);
}
.ct-reporting-visual__comparison-ranked-overflow {
  margin: 0;
  padding-top: 0.1rem;
  font-size: 0.78rem;
  line-height: 1.4;
  color: var(--ct-theme-text-muted);
}
.ct-reporting-visual__bar-track,
.ct-reporting-visual__segment-track {
  fill: var(--ct-reporting-visual-track);
}
.ct-reporting-visual__bar,
.ct-reporting-visual__segment {
  fill: var(--ct-reporting-visual-accent);
  stroke: rgba(15, 95, 166, 0.18);
  stroke-width: 1.5;
}
.ct-reporting-visual__segment {
  stroke: none;
}
.ct-reporting-visual__bar--1,
.ct-reporting-visual__segment--1 {
  fill: rgba(15, 95, 166, 0.78);
  stroke-dasharray: 6 4;
}
.ct-reporting-visual__bar--2,
.ct-reporting-visual__segment--2 {
  fill: rgba(15, 95, 166, 0.5);
}
.ct-reporting-visual__bar--3,
.ct-reporting-visual__segment--3 {
  fill: rgba(15, 95, 166, 0.92);
}
.ct-reporting-visual__baseline {
  stroke: rgba(15, 95, 166, 0.2);
  stroke-width: 2;
}
.ct-reporting-visual__guide {
  stroke: rgba(15, 95, 166, 0.14);
  stroke-width: 1;
  stroke-dasharray: 5 5;
}
.ct-reporting-visual__axis {
  stroke: rgba(15, 95, 166, 0.2);
  stroke-width: 1.25;
}
.ct-reporting-visual__trend-area {
  fill: rgba(15, 95, 166, 0.14);
}
.ct-reporting-visual__trend-line {
  fill: none;
  stroke: var(--ct-reporting-visual-accent);
  stroke-width: 2.75;
  stroke-linecap: round;
  stroke-linejoin: round;
}
.ct-reporting-visual[data-reporting-visual-kind='trend-series'] .ct-reporting-visual__trend-line {
  stroke-dasharray: none;
}
.ct-reporting-visual[data-reporting-visual-kind='trend-series'][data-reporting-visual-density='compact'] {
  gap: 0.65rem;
}
.ct-reporting-visual[data-reporting-visual-kind='trend-series'][data-reporting-visual-density='compact'] .ct-reporting-visual__surface {
  padding: 0.65rem;
}
.ct-reporting-visual[data-reporting-visual-kind='trend-series'][data-reporting-visual-density='compact'] .ct-reporting-visual__graphic {
  width: min(100%, 42rem);
  margin-inline: auto;
}
.ct-reporting-visual[data-reporting-visual-kind='trend-area'] {
  --ct-reporting-visual-surface: linear-gradient(
    180deg,
    rgba(255, 255, 255, 0.98),
    rgba(235, 245, 255, 0.92)
  );
}
.ct-reporting-visual[data-reporting-visual-kind='trend-area'] .ct-reporting-visual__surface {
  padding: 0.72rem;
}
.ct-reporting-visual__point {
  fill: rgba(255, 255, 255, 0.95);
  stroke: var(--ct-reporting-visual-accent);
  stroke-width: 3;
}
.ct-reporting-visual__point--trend-marker {
  fill: rgba(255, 255, 255, 0.98);
  stroke: var(--ct-brand-lake-700);
}
.ct-reporting-visual__point--peak {
  fill: var(--ct-brand-sun-400);
  stroke: var(--ct-brand-midnight-900);
}
.ct-reporting-visual__point--latest {
  fill: rgba(255, 255, 255, 0.98);
  stroke: var(--ct-brand-lake-700);
}
.ct-reporting-visual__point--1 {
  stroke: rgba(15, 95, 166, 0.82);
}
.ct-reporting-visual__point--2 {
  stroke: rgba(15, 95, 166, 0.58);
}
.ct-reporting-visual__point--3 {
  stroke: rgba(15, 95, 166, 0.98);
}
.ct-reporting-visual__chart-key {
  pointer-events: none;
}
.ct-reporting-visual__axis-label,
.ct-reporting-visual__chart-key text {
  fill: var(--ct-theme-text-subtle);
  font-size: 10px;
  font-weight: 650;
  letter-spacing: 0;
}
.ct-reporting-visual__axis-label--x {
  text-anchor: start;
}
.ct-reporting-visual__axis-label--end {
  text-anchor: end;
}
.ct-reporting-visual__chart-key line {
  stroke: var(--ct-reporting-visual-accent);
  stroke-width: 2.75;
  stroke-linecap: round;
}
.ct-reporting-visual__chart-key circle {
  fill: rgba(255, 255, 255, 0.98);
  stroke: var(--ct-reporting-visual-accent);
  stroke-width: 2.5;
}
.ct-reporting-visual__trend-context {
  display: grid;
  gap: 0.8rem;
}
.ct-reporting-visual__trend-axis {
  display: grid;
  gap: 0.7rem;
  grid-template-columns: repeat(2, minmax(0, 1fr));
}
.ct-reporting-visual__trend-axis-item {
  display: grid;
  gap: 0.2rem;
  padding: 0.7rem 0.8rem;
  border: 1px solid rgba(15, 95, 166, 0.12);
  border-radius: var(--ct-radius-md);
  background: rgba(255, 255, 255, 0.78);
}
.ct-reporting-visual__trend-axis-label,
.ct-reporting-visual__trend-callout-label {
  font-size: 0.72rem;
  font-weight: 700;
  letter-spacing: 0.08em;
  text-transform: uppercase;
  color: var(--ct-theme-text-subtle);
}
.ct-reporting-visual__trend-axis-value,
.ct-reporting-visual__trend-callout-value,
.ct-reporting-visual__trend-callout-metric {
  color: var(--ct-theme-text-title);
  font-variant-numeric: tabular-nums;
}
.ct-reporting-visual__trend-axis-detail,
.ct-reporting-visual__trend-callout-detail {
  font-size: 0.78rem;
  line-height: 1.4;
  color: var(--ct-theme-text-muted);
}
.ct-reporting-visual__trend-callouts {
  list-style: none;
  margin: 0;
  padding: 0;
  display: grid;
  gap: 0.7rem;
  grid-template-columns: repeat(auto-fit, minmax(11rem, 1fr));
}
.ct-reporting-visual__trend-callout {
  display: grid;
  gap: 0.28rem;
  padding: 0.75rem 0.8rem;
  border-radius: var(--ct-radius-md);
  border: 1px solid rgba(15, 95, 166, 0.12);
  background: linear-gradient(180deg, rgba(255, 255, 255, 0.82), rgba(238, 246, 255, 0.76));
}
.ct-reporting-visual__empty {
  padding: 1rem;
  border: 1px dashed rgba(15, 95, 166, 0.28);
  border-radius: var(--ct-radius-md);
  background: rgba(255, 255, 255, 0.78);
  color: var(--ct-theme-text-muted);
}
.ct-reporting-visual__empty--sparse,
.ct-reporting-visual[data-reporting-visual-state='sparse'] .ct-reporting-visual__empty {
  border-style: solid;
  border-color: rgba(15, 95, 166, 0.16);
  background:
    linear-gradient(160deg, rgba(255, 255, 255, 0.96), rgba(238, 246, 255, 0.86)),
    rgba(255, 255, 255, 0.9);
  color: var(--ct-theme-text-body);
}
.ct-reporting-visual[data-reporting-visual-kind='journey-funnel'] .ct-reporting-visual__surface {
  padding: 0.8rem;
  background:
    linear-gradient(180deg, rgba(255, 255, 255, 0.98), rgba(244, 249, 255, 0.92)),
    rgba(255, 255, 255, 0.96);
}
.ct-reporting-visual__journey-funnel {
  display: grid;
}
.ct-reporting-visual__journey-list {
  list-style: none;
  margin: 0;
  padding: 0;
  display: grid;
  gap: 0.72rem;
}
.ct-reporting-visual__journey-item {
  display: grid;
  gap: 0.42rem;
  padding: 0.7rem 0.78rem;
  border-radius: var(--ct-radius-md);
  border: 1px solid rgba(15, 95, 166, 0.12);
  background: rgba(255, 255, 255, 0.78);
}
.ct-reporting-visual__journey-head {
  display: grid;
  grid-template-columns: auto minmax(0, 1fr) auto;
  gap: 0.55rem;
  align-items: baseline;
}
.ct-reporting-visual__journey-step {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  min-inline-size: 1.55rem;
  block-size: 1.55rem;
  border-radius: var(--ct-radius-pill);
  border: 1px solid rgba(15, 95, 166, 0.18);
  background: rgba(15, 95, 166, 0.08);
  font-size: 0.74rem;
  font-weight: 800;
  color: var(--ct-brand-midnight-900);
}
.ct-reporting-visual__journey-label {
  min-width: 0;
  font-size: 0.86rem;
  font-weight: 650;
  color: var(--ct-theme-text-title);
}
.ct-reporting-visual__journey-value {
  font-variant-numeric: tabular-nums;
  color: var(--ct-theme-text-title);
}
.ct-reporting-visual__journey-track {
  block-size: 0.58rem;
  border-radius: var(--ct-radius-pill);
  background: rgba(15, 95, 166, 0.1);
  overflow: hidden;
}
.ct-reporting-visual__journey-fill {
  display: block;
  block-size: 100%;
  border-radius: inherit;
  background: linear-gradient(90deg, var(--ct-brand-lake-500), var(--ct-brand-lake-700));
}
.ct-reporting-visual__journey-fill--1 {
  background: linear-gradient(90deg, rgba(15, 95, 166, 0.52), rgba(15, 95, 166, 0.86));
}
.ct-reporting-visual__journey-fill--2 {
  background: linear-gradient(90deg, rgba(212, 164, 67, 0.72), rgba(15, 95, 166, 0.78));
}
.ct-reporting-visual__journey-fill--3 {
  background: linear-gradient(90deg, rgba(15, 95, 166, 0.42), rgba(15, 95, 166, 0.72));
}
.ct-reporting-visual__journey-detail {
  font-size: 0.76rem;
  line-height: 1.4;
  color: var(--ct-theme-text-muted);
}
@keyframes ct-reporting-rise-in {
  from {
    opacity: 0;
    transform: translateY(0.55rem);
  }
  to {
    opacity: 1;
    transform: translateY(0);
  }
}
@keyframes ct-reporting-scale-x {
  from {
    transform: scaleX(0);
  }
  to {
    transform: scaleX(1);
  }
}
@media (prefers-reduced-motion: no-preference) {
  .ct-admin__reporting-summary-band,
  .ct-admin__reporting-highlight-panel {
    animation: ct-reporting-rise-in 420ms cubic-bezier(0.22, 1, 0.36, 1) both;
  }
  .ct-admin__reporting-highlight-panel:nth-child(2) {
    animation-delay: 70ms;
  }
  .ct-admin__reporting-highlight-panel:nth-child(3) {
    animation-delay: 130ms;
  }
  .ct-reporting-visual__bar,
  .ct-reporting-visual__comparison-ranked-bar,
  .ct-reporting-visual__journey-fill,
  .ct-reporting-visual__segment {
    transform-box: fill-box;
    transform-origin: left center;
    animation: ct-reporting-scale-x 520ms cubic-bezier(0.22, 1, 0.36, 1) both;
  }
  .ct-reporting-visual__journey-item:nth-child(2) .ct-reporting-visual__journey-fill,
  .ct-reporting-visual__comparison-ranked-item:nth-child(2) .ct-reporting-visual__comparison-ranked-bar {
    animation-delay: 70ms;
  }
  .ct-reporting-visual__journey-item:nth-child(3) .ct-reporting-visual__journey-fill,
  .ct-reporting-visual__comparison-ranked-item:nth-child(3) .ct-reporting-visual__comparison-ranked-bar {
    animation-delay: 120ms;
  }
  .ct-reporting-visual__journey-item:nth-child(4) .ct-reporting-visual__journey-fill,
  .ct-reporting-visual__comparison-ranked-item:nth-child(4) .ct-reporting-visual__comparison-ranked-bar {
    animation-delay: 170ms;
  }
  .ct-reporting-visual__journey-item:nth-child(5) .ct-reporting-visual__journey-fill,
  .ct-reporting-visual__comparison-ranked-item:nth-child(5) .ct-reporting-visual__comparison-ranked-bar {
    animation-delay: 220ms;
  }
}
@media (prefers-reduced-motion: reduce) {
  .ct-admin__reporting-summary-band,
  .ct-admin__reporting-highlight-panel,
  .ct-reporting-visual__bar,
  .ct-reporting-visual__comparison-ranked-bar,
  .ct-reporting-visual__journey-fill,
  .ct-reporting-visual__segment {
    animation: none;
  }
}
@media (max-width: 960px) {
  .ct-reporting-visual {
    padding: 0.9rem;
  }
  .ct-reporting-visual__surface {
    padding: 0.75rem;
  }
  .ct-reporting-visual__legend {
    grid-template-columns: minmax(0, 1fr);
  }
  .ct-reporting-visual__trend-axis,
  .ct-reporting-visual__trend-callouts {
    grid-template-columns: minmax(0, 1fr);
  }
}
.ct-admin__reporting-root-links {
  display: flex;
  flex-wrap: wrap;
  gap: 0.55rem;
}
.ct-admin__reporting-explore-workspace {
  gap: 0.85rem;
}
.ct-admin__reporting-slice-strip {
  display: grid;
  gap: 0.9rem;
  align-items: center;
  grid-template-columns: minmax(0, 1fr) minmax(22rem, 0.72fr);
  padding: 0.85rem 0.95rem;
  border-radius: var(--ct-radius-lg);
  border: 1px solid rgba(15, 95, 166, 0.16);
  background:
    linear-gradient(135deg, rgba(255, 255, 255, 0.96), rgba(239, 247, 255, 0.88)),
    var(--ct-theme-surface-card-strong);
}
.ct-admin__reporting-slice-main {
  display: grid;
  gap: 0.55rem;
  min-width: 0;
}
.ct-admin__reporting-slice-tags {
  display: flex;
  flex-wrap: wrap;
  gap: 0.42rem;
}
.ct-admin__reporting-slice-tag {
  display: inline-flex;
  gap: 0.35rem;
  align-items: center;
  min-height: 1.8rem;
  padding: 0.24rem 0.58rem;
  border: 1px solid rgba(15, 95, 166, 0.12);
  border-radius: var(--ct-radius-pill);
  background: rgba(255, 255, 255, 0.74);
  color: var(--ct-theme-text-body);
  font-size: 0.78rem;
  line-height: 1.2;
}
.ct-admin__reporting-slice-tag strong {
  color: var(--ct-theme-text-subtle);
  font-size: 0.68rem;
  font-weight: 750;
  letter-spacing: 0.04em;
  text-transform: uppercase;
}
.ct-admin__reporting-slice-metrics {
  display: grid;
  gap: 0.55rem;
  grid-template-columns: repeat(4, minmax(0, 1fr));
  margin: 0;
}
.ct-admin__reporting-slice-metrics div {
  min-width: 0;
  padding: 0.62rem 0.7rem;
  border-radius: var(--ct-radius-md);
  border: 1px solid rgba(15, 95, 166, 0.12);
  background: rgba(255, 255, 255, 0.82);
}
.ct-admin__reporting-slice-metrics dt {
  margin: 0 0 0.18rem;
  color: var(--ct-theme-text-subtle);
  font-size: 0.68rem;
  font-weight: 750;
  letter-spacing: 0.04em;
  text-transform: uppercase;
}
.ct-admin__reporting-slice-metrics dd {
  margin: 0;
  color: var(--ct-theme-text-title);
  font-size: 1.18rem;
  font-weight: 750;
  line-height: 1;
  font-variant-numeric: tabular-nums;
}
.ct-admin__reporting-overview-panel {
  gap: 0.72rem;
}
.ct-admin__reporting-state-summary {
  display: grid;
  gap: 0.75rem;
  padding: 0.85rem;
  border-radius: var(--ct-radius-md);
  border: 1px solid rgba(15, 95, 166, 0.12);
  background: rgba(238, 246, 255, 0.56);
}
.ct-admin__reporting-state-summary-head {
  display: flex;
  flex-wrap: wrap;
  gap: 0.45rem 1rem;
  align-items: baseline;
  justify-content: space-between;
}
.ct-admin__reporting-state-summary-head h3 {
  font-size: 0.95rem;
}
.ct-admin__reporting-state-summary-head p {
  max-width: none;
  font-size: 0.82rem;
}
.ct-admin__reporting-state-meter {
  display: flex;
  width: 100%;
  height: 0.82rem;
  overflow: hidden;
  border-radius: var(--ct-radius-pill);
  border: 1px solid rgba(15, 95, 166, 0.14);
  background: rgba(15, 95, 166, 0.1);
}
.ct-admin__reporting-state-meter-empty {
  flex: 1 1 auto;
  background: rgba(15, 95, 166, 0.1);
}
.ct-admin__reporting-state-segment {
  min-width: 0.18rem;
  background: var(--ct-brand-lake-700);
}
.ct-admin__reporting-state-segment--suspended {
  background: repeating-linear-gradient(
    135deg,
    var(--ct-brand-lake-600),
    var(--ct-brand-lake-600) 0.22rem,
    rgba(255, 255, 255, 0.78) 0.22rem,
    rgba(255, 255, 255, 0.78) 0.42rem
  );
}
.ct-admin__reporting-state-segment--revoked {
  background: var(--ct-brand-midnight-800);
}
.ct-admin__reporting-state-segment--pending-review {
  background: linear-gradient(90deg, var(--ct-brand-lake-500), rgba(212, 164, 67, 0.72));
}
.ct-admin__reporting-state-list {
  display: grid;
  gap: 0.5rem;
  grid-template-columns: repeat(4, minmax(0, 1fr));
  margin: 0;
}
.ct-admin__reporting-state-item {
  min-width: 0;
  padding: 0.45rem 0.55rem;
  border-left: 0.22rem solid var(--ct-brand-lake-700);
  background: rgba(255, 255, 255, 0.64);
}
.ct-admin__reporting-state-item--suspended {
  border-left-color: var(--ct-brand-lake-600);
}
.ct-admin__reporting-state-item--revoked {
  border-left-color: var(--ct-brand-midnight-800);
}
.ct-admin__reporting-state-item--pending-review {
  border-left-color: var(--ct-brand-sun-500);
}
.ct-admin__reporting-state-item dt {
  margin: 0;
  color: var(--ct-theme-text-muted);
  font-size: 0.74rem;
  font-weight: 650;
}
.ct-admin__reporting-state-item dd {
  margin: 0.08rem 0 0;
  color: var(--ct-theme-text-title);
  font-size: 1.08rem;
  font-weight: 750;
  line-height: 1;
  font-variant-numeric: tabular-nums;
}
.ct-admin__reporting-summary-band {
  display: grid;
  gap: 0.95rem;
  padding: 1rem;
  border-radius: var(--ct-radius-lg);
  border-color: rgba(15, 95, 166, 0.16);
  background: var(--ct-theme-surface-card-strong);
  box-shadow: none;
}
.ct-admin__reporting-readout-head {
  display: flex;
  gap: 1rem;
  align-items: flex-start;
  justify-content: space-between;
}
.ct-admin__reporting-summary-copy {
  margin: 0;
  max-width: 48rem;
  font-size: 0.96rem;
  color: var(--ct-theme-text-body);
}
.ct-admin__reporting-summary-metrics {
  display: grid;
  gap: 0.1rem;
  grid-template-columns: repeat(4, minmax(0, 1fr));
  margin: 0;
}
.ct-admin__reporting-summary-metrics div {
  display: grid;
  gap: 0.2rem;
  min-width: 0;
  padding: 0.55rem 0.75rem;
  border-left: 1px solid rgba(15, 95, 166, 0.12);
}
.ct-admin__reporting-summary-metrics div:first-child {
  border-left: 0;
  padding-left: 0;
}
.ct-admin__reporting-summary-metrics dt {
  margin: 0;
  color: var(--ct-theme-text-subtle);
  font-size: 0.68rem;
  font-weight: 750;
  letter-spacing: 0.06em;
  line-height: 1.2;
  text-transform: uppercase;
}
.ct-admin__reporting-summary-metrics dd {
  margin: 0;
  color: var(--ct-theme-text-title);
  font-size: 1.35rem;
  font-weight: 760;
  line-height: 1.05;
  font-variant-numeric: tabular-nums;
}
.ct-admin__reporting-summary-metrics span {
  color: var(--ct-theme-text-muted);
  font-size: 0.78rem;
  line-height: 1.35;
}
.ct-admin__reporting-summary-context {
  padding-top: 0.2rem;
  border-top: 1px solid rgba(15, 95, 166, 0.12);
}
.ct-admin__reporting-summary-context .ct-cluster {
  gap: 0.55rem;
  align-items: flex-start;
}
.ct-admin__reporting-presentation-shell {
  display: grid;
  gap: 1rem;
  padding: 0;
  border: 0;
  background: transparent;
  box-shadow: none;
}
.ct-admin__reporting-presentation-shell--highlights {
  gap: 0.95rem;
}
.ct-admin__reporting-presentation-note {
  display: flex;
  flex-wrap: wrap;
  gap: 0.45rem 1rem;
  align-items: center;
  justify-content: space-between;
  padding: 0.68rem 0.8rem;
  border-radius: var(--ct-radius-md);
  border: 1px solid rgba(15, 95, 166, 0.12);
  background: rgba(255, 255, 255, 0.78);
}
.ct-admin__reporting-presentation-note p,
.ct-admin__reporting-presentation-note p:last-child {
  margin: 0;
  max-width: none;
  font-size: 0.84rem;
  line-height: 1.4;
  color: var(--ct-theme-text-body);
}
.ct-admin__reporting-presentation-note .ct-admin__hint {
  flex-shrink: 0;
  color: var(--ct-theme-text-muted);
}
.ct-admin__reporting-primary-story,
.ct-admin__reporting-secondary-story {
  display: grid;
  gap: 0.9rem;
}
.ct-admin__reporting-secondary-story {
  padding-top: 0.95rem;
  border-top: 1px solid rgba(15, 95, 166, 0.14);
}
.ct-admin__reporting-secondary-story > * {
  min-width: 0;
}
.ct-admin__reporting-first-screen {
  display: grid;
  gap: 1rem;
}
.ct-admin__reporting-first-screen > * {
  min-width: 0;
}
.ct-admin__reporting-lower-story {
  display: grid;
  gap: 0.85rem;
}
.ct-admin__reporting-inline-disclosure {
  display: block;
  border-radius: var(--ct-radius-md);
  border: 1px solid rgba(15, 95, 166, 0.12);
  background: rgba(255, 255, 255, 0.72);
}
.ct-admin__reporting-inline-disclosure[open] {
  background: rgba(255, 255, 255, 0.88);
}
.ct-admin__reporting-inline-summary {
  display: flex;
  gap: 0.65rem;
  align-items: center;
  justify-content: space-between;
  padding: 0.72rem 0.82rem;
  cursor: pointer;
  color: var(--ct-theme-text-title);
  font-weight: 700;
}
.ct-admin__reporting-inline-summary::-webkit-details-marker {
  color: var(--ct-brand-lake-700);
}
.ct-admin__reporting-inline-summary small {
  color: var(--ct-theme-text-muted);
  font-size: 0.78rem;
  font-weight: 500;
  line-height: 1.35;
  text-align: right;
}
.ct-admin__reporting-inline-body {
  display: grid;
  gap: 0.8rem;
  padding: 0 0.82rem 0.82rem;
}
.ct-admin__reporting-inline-disclosure--definitions {
  background: rgba(238, 246, 255, 0.54);
}
.ct-admin__reporting-comparison-summary {
  display: grid;
  gap: 0.75rem;
  align-items: center;
  grid-template-columns: minmax(13rem, 0.72fr) minmax(0, 1fr);
  padding: 0.78rem 0.85rem;
  border-radius: var(--ct-radius-md);
  border: 1px solid rgba(15, 95, 166, 0.12);
  background: rgba(238, 246, 255, 0.58);
}
.ct-admin__reporting-comparison-identity strong {
  color: var(--ct-theme-text-title);
}
.ct-admin__reporting-comparison-metrics {
  display: grid;
  gap: 0.45rem;
  grid-template-columns: repeat(4, minmax(0, 1fr));
  margin: 0;
}
.ct-admin__reporting-comparison-metrics div {
  min-width: 0;
  padding: 0.48rem 0.55rem;
  border-radius: var(--ct-radius-sm);
  background: rgba(255, 255, 255, 0.76);
}
.ct-admin__reporting-comparison-metrics dt {
  margin: 0 0 0.12rem;
  color: var(--ct-theme-text-subtle);
  font-size: 0.66rem;
  font-weight: 750;
  letter-spacing: 0.04em;
  text-transform: uppercase;
}
.ct-admin__reporting-comparison-metrics dd {
  margin: 0;
  color: var(--ct-theme-text-title);
  font-size: 1rem;
  font-weight: 750;
  line-height: 1;
  font-variant-numeric: tabular-nums;
}
.ct-admin__reporting-advanced-drilldowns {
  padding: 0.95rem 1rem;
  border-radius: var(--ct-radius-lg);
  border: 1px solid rgba(15, 95, 166, 0.12);
  background: linear-gradient(180deg, rgba(255, 255, 255, 0.9), rgba(238, 246, 255, 0.78));
}
.ct-admin__reporting-advanced-drilldowns {
  display: grid;
  gap: 0.85rem;
}
.ct-admin__reporting-advanced-summary {
  display: grid;
  gap: 0.25rem;
  cursor: pointer;
  color: var(--ct-theme-text-title);
  font-weight: 700;
}
.ct-admin__reporting-advanced-summary::-webkit-details-marker {
  color: var(--ct-brand-lake-700);
}
.ct-admin__reporting-advanced-summary small {
  color: var(--ct-theme-text-muted);
  font-size: 0.84rem;
  font-weight: 500;
  line-height: 1.45;
}
.ct-admin__reporting-advanced-body {
  display: grid;
  gap: 1rem;
  padding-top: 0.85rem;
}
.ct-admin__reporting-supporting-grid {
  display: grid;
  gap: 1rem;
  align-items: start;
  grid-template-columns: minmax(0, 1.24fr) minmax(18rem, 0.8fr);
}
.ct-admin__reporting-supporting-grid > * {
  min-width: 0;
}
.ct-admin__reporting-highlight-grid {
  display: grid;
  gap: 1rem;
  align-items: stretch;
  grid-template-columns: repeat(2, minmax(0, 1fr));
}
.ct-admin__reporting-highlight-grid > * {
  min-width: 0;
}
.ct-admin__reporting-highlight-panel {
  border-color: rgba(15, 95, 166, 0.16);
  background:
    linear-gradient(180deg, rgba(255, 255, 255, 0.96), rgba(244, 249, 255, 0.9)),
    var(--ct-theme-surface-card-strong);
}
.ct-admin__reporting-highlight-panel .ct-reporting-visual {
  border-color: rgba(15, 95, 166, 0.14);
}
.ct-admin__reporting-focus-area-list {
  display: grid;
  gap: 0.15rem;
}
.ct-admin__reporting-focus-area-item {
  display: grid;
  gap: 0.75rem;
  align-items: center;
  grid-template-columns: minmax(5rem, 0.24fr) minmax(0, 1fr) auto;
  padding: 0.72rem 0;
  border-top: 1px solid rgba(15, 95, 166, 0.12);
}
.ct-admin__reporting-focus-area-item:first-child {
  border-top: 0;
  padding-top: 0.25rem;
}
.ct-admin__reporting-focus-area-item:last-child {
  padding-bottom: 0.25rem;
}
.ct-admin__reporting-focus-area-metric {
  color: var(--ct-theme-text-title);
  font-size: 1.08rem;
  font-weight: 760;
  line-height: 1.05;
  font-variant-numeric: tabular-nums;
}
.ct-admin__reporting-focus-area-copy {
  display: grid;
  gap: 0.18rem;
  min-width: 0;
}
.ct-admin__reporting-focus-area-copy h3 {
  color: var(--ct-theme-text-title);
  font-size: 1rem;
}
.ct-admin__reporting-highlight-actions {
  display: flex;
  flex-wrap: wrap;
  gap: 0.55rem;
  align-items: center;
}
.ct-admin__reporting-deep-links {
  display: flex;
  flex-wrap: wrap;
  gap: 0.55rem;
  align-items: center;
}
.ct-admin__reporting-deep-link {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  min-height: 2.25rem;
  padding: 0.45rem 0.85rem;
  border-radius: var(--ct-radius-sm);
  border: 1px solid var(--ct-border-soft);
  background: var(--ct-theme-surface-card-strong);
  color: var(--ct-theme-text-title);
  font-size: 0.86rem;
  font-weight: 650;
  line-height: 1.2;
  text-decoration: none;
  transition:
    border-color 180ms ease,
    background-color 180ms ease,
    color 180ms ease;
}
.ct-admin__reporting-deep-link--primary {
  border-color: var(--ct-brand-lake-700);
  background: var(--ct-brand-lake-700);
  color: var(--ct-theme-text-inverse);
}
.ct-admin__reporting-deep-link:hover {
  border-color: rgba(15, 95, 166, 0.28);
  background: rgba(238, 246, 255, 0.92);
  color: var(--ct-theme-text-title);
}
.ct-admin__reporting-deep-link--primary:hover {
  border-color: var(--ct-brand-lake-700);
  background: var(--ct-brand-midnight-900);
  color: var(--ct-theme-text-inverse);
}
.ct-admin__reporting-deep-link:focus-visible {
  outline: 2px solid rgba(15, 95, 166, 0.36);
  outline-offset: 3px;
}
.ct-admin__reporting-placeholder-panel {
  max-width: 52rem;
}
.ct-admin__reporting-supporting-rail {
  display: grid;
  gap: 0.95rem;
  align-content: start;
}
.ct-admin__reporting-supporting-rail .ct-admin__panel {
  position: sticky;
  top: 4.75rem;
  border-color: rgba(15, 95, 166, 0.12);
  background: linear-gradient(
    180deg,
    rgba(255, 255, 255, 0.92),
    rgba(244, 249, 255, 0.94)
  );
}
.ct-admin__reporting-trend-hero {
  display: grid;
  gap: 1rem;
  align-items: start;
  grid-template-columns: minmax(17rem, 0.9fr) minmax(0, 1.2fr);
}
.ct-admin__reporting-trend-intro {
  padding: 0.9rem 1rem;
  border: 1px solid rgba(15, 95, 166, 0.12);
  border-radius: var(--ct-radius-lg);
  background: var(--ct-theme-surface-info);
}
.ct-admin__reporting-trend-callouts {
  display: grid;
  gap: 0.75rem;
  grid-template-columns: repeat(auto-fit, minmax(10rem, 1fr));
}
.ct-admin__reporting-trend-callout {
  padding: 0.75rem 0.85rem;
  border-radius: var(--ct-radius-md);
  border: 1px solid rgba(15, 95, 166, 0.12);
  background: rgba(255, 255, 255, 0.78);
}
.ct-admin__reporting-trend-callout h3 {
  margin: 0;
  font-size: 1rem;
}
.ct-admin__reporting-trend-callout .ct-admin__meta + .ct-admin__meta {
  margin-top: 0.2rem;
}
.ct-admin__reporting-visual-grid {
  display: grid;
  gap: 0.9rem;
  grid-template-columns: repeat(auto-fit, minmax(18rem, 1fr));
  align-items: start;
}
.ct-admin__reporting-visual-shell {
  display: grid;
  gap: 0.55rem;
  min-width: 0;
}
.ct-admin__reporting-visual-note {
  margin: 0;
  padding: 0.65rem 0.75rem;
  border: 1px solid rgba(15, 95, 166, 0.16);
  border-radius: var(--ct-radius-sm);
  background: var(--ct-theme-surface-info);
  font-size: 0.82rem;
  line-height: 1.45;
  color: var(--ct-theme-text-muted);
}
.ct-admin__panel[data-reporting-state='empty'],
.ct-admin__panel[data-reporting-state='sparse'] {
  border-color: rgba(15, 95, 166, 0.16);
}
.ct-admin__panel[data-reporting-state='sparse'] {
  background: var(--ct-theme-surface-card);
}
.ct-admin__reporting-state-shell {
  display: grid;
  gap: 0.55rem;
  padding: 1rem;
  border-radius: var(--ct-radius-md);
  border: 1px dashed rgba(15, 95, 166, 0.22);
  background: var(--ct-theme-surface-card-strong);
}
.ct-admin__reporting-state-shell h3 {
  margin: 0;
  font-family: var(--ct-font-sans);
  font-size: 1.05rem;
  line-height: 1.2;
  color: var(--ct-theme-text-title);
}
.ct-admin__reporting-state-shell[data-reporting-panel-state='sparse'] {
  border-style: solid;
  border-color: rgba(15, 95, 166, 0.16);
  background: var(--ct-theme-surface-info);
}
[data-reporting-submit-status] {
  margin: 0;
}
#reporting-filters-form[data-reporting-submit-state='pending'] {
  opacity: 0.84;
}
#reporting-filters-form[data-reporting-submit-state='pending'] button[type='submit'] {
  cursor: progress;
}
#reporting-filters-form[data-reporting-submit-state='pending'] + [data-reporting-submit-status] {
  color: var(--ct-theme-text-title);
}
.ct-admin__reporting-panel-media {
  display: grid;
  gap: 1rem;
  align-items: start;
  grid-template-columns: minmax(18rem, 24rem) minmax(0, 1fr);
}
.ct-admin__reporting-panel-media > * {
  min-width: 0;
}
.ct-admin__reporting-panel-media .ct-admin__metric-grid,
.ct-admin__reporting-panel-media .ct-admin__table-wrap {
  min-width: 0;
}
.ct-admin__reporting-table-number {
  display: inline-flex;
  align-items: center;
  justify-content: flex-end;
  min-height: 1.85rem;
  padding: 0.15rem 0.58rem;
  border-radius: var(--ct-radius-pill);
  border: 1px solid rgba(15, 95, 166, 0.12);
  background: rgba(15, 95, 166, 0.08);
  color: var(--ct-theme-text-title);
  font-variant-numeric: tabular-nums;
  font-weight: 700;
  white-space: nowrap;
}
.ct-admin__reporting-root-link {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  gap: 0.35rem;
  min-height: 2.25rem;
  padding: 0.35rem 0.85rem;
  border-radius: var(--ct-radius-pill);
  border: 1px solid var(--ct-border-soft);
  background: var(--ct-theme-surface-card);
  font-size: 0.82rem;
  font-weight: 600;
  text-decoration: none;
  color: var(--ct-theme-text-title);
  transition:
    border-color 180ms ease,
    background-color 180ms ease,
    box-shadow 180ms ease,
    color 180ms ease;
}
.ct-admin__reporting-root-link:hover {
  border-color: rgba(15, 95, 166, 0.24);
  background: rgba(238, 246, 255, 0.82);
}
.ct-admin__reporting-root-link:focus-visible,
.ct-admin__reporting-breadcrumb-link:focus-visible {
  outline: 2px solid rgba(15, 95, 166, 0.36);
  outline-offset: 2px;
}
.ct-admin__reporting-root-link[data-reporting-focus-active='true'],
.ct-admin__reporting-root-link[aria-current='location'] {
  border-color: var(--ct-theme-border-info);
  background: rgba(238, 246, 255, 0.92);
  box-shadow: 0 0 0 3px rgba(15, 95, 166, 0.1);
}
.ct-admin__reporting-focus-section {
  display: grid;
  gap: 0.85rem;
  padding: 1rem;
  border-radius: var(--ct-radius-md);
  border: 1px solid var(--ct-border-soft);
  background: rgba(255, 255, 255, 0.72);
  scroll-margin-top: 1rem;
}
.ct-admin__reporting-focus-section:target,
.ct-admin__reporting-focus-section[data-reporting-focus-active='true'] {
  border-color: var(--ct-theme-border-info);
  box-shadow: 0 0 0 3px rgba(15, 95, 166, 0.12);
  background: rgba(238, 246, 255, 0.72);
}
.ct-admin__reporting-breadcrumb-nav {
  padding-block: 0.1rem 0.15rem;
}
.ct-admin__reporting-breadcrumb-list {
  display: flex;
  flex-wrap: wrap;
  gap: 0.45rem 0.65rem;
  margin: 0;
  padding: 0;
  list-style: none;
}
.ct-admin__reporting-breadcrumb-item {
  display: inline-flex;
  align-items: center;
  gap: 0.65rem;
  min-width: 0;
}
.ct-admin__reporting-breadcrumb-item:not(:last-child)::after {
  content: "/";
  color: var(--ct-theme-text-muted);
}
.ct-admin__reporting-breadcrumb-link,
.ct-admin__reporting-breadcrumb-current {
  font-size: 0.82rem;
  font-weight: 600;
  color: var(--ct-theme-text-title);
}
.ct-admin__reporting-breadcrumb-link {
  text-decoration: none;
}
.ct-admin__reporting-breadcrumb-link:hover {
  color: var(--ct-theme-link);
}
.ct-admin__reporting-breadcrumb-current {
  display: inline-flex;
  align-items: center;
  min-height: 2rem;
  padding: 0.2rem 0.7rem;
  border-radius: var(--ct-radius-pill);
  background: rgba(15, 95, 166, 0.08);
}
.ct-admin__reporting-focus-summary {
  gap: 0.8rem;
  padding: 0.9rem 1rem;
  border-radius: var(--ct-radius-md);
  border: 1px solid rgba(15, 95, 166, 0.14);
  background: var(--ct-theme-surface-card-strong);
}
.ct-admin__reporting-focus-summary-title {
  margin: 0;
  font-family: var(--ct-font-sans);
  font-size: 1.08rem;
  line-height: 1.2;
  color: var(--ct-theme-text-title);
}
.ct-admin__reporting-focus-summary-grid {
  display: grid;
  gap: 0.7rem;
  grid-template-columns: repeat(auto-fit, minmax(13rem, 1fr));
  margin: 0;
}
.ct-admin__reporting-focus-summary-item {
  display: grid;
  gap: 0.2rem;
  min-width: 0;
  padding: 0.75rem 0.85rem;
  border-radius: var(--ct-radius-md);
  background: rgba(255, 255, 255, 0.78);
  border: 1px solid rgba(15, 95, 166, 0.1);
}
.ct-admin__reporting-focus-summary-item dt {
  margin: 0;
  font-size: 0.72rem;
  font-weight: 700;
  letter-spacing: 0.04em;
  text-transform: uppercase;
  color: var(--ct-theme-text-muted);
}
.ct-admin__reporting-focus-summary-item dd {
  margin: 0;
  color: var(--ct-theme-text-title);
  font-size: 0.86rem;
  line-height: 1.45;
}
.ct-admin__reporting-focus-section[data-reporting-focus-active='true'] .ct-admin__reporting-focus-summary,
.ct-admin__reporting-focus-section:target .ct-admin__reporting-focus-summary {
  border-color: rgba(15, 95, 166, 0.24);
  background:
    linear-gradient(160deg, rgba(255, 255, 255, 0.98), rgba(234, 244, 255, 0.96)),
    rgba(255, 255, 255, 0.94);
}
.ct-admin__reporting-performer-grid {
  display: grid;
  gap: 0.85rem;
  grid-template-columns: repeat(auto-fit, minmax(18rem, 1fr));
}
.ct-admin__reporting-performer-groups {
  display: grid;
  gap: 1rem;
}
.ct-admin__reporting-performer-group {
  padding: 0.95rem 1rem;
  border-radius: var(--ct-radius-lg);
  border: 1px solid rgba(15, 95, 166, 0.12);
  background: linear-gradient(180deg, rgba(255, 255, 255, 0.94), rgba(241, 247, 255, 0.82));
}
.ct-admin__reporting-performer-group .ct-admin__eyebrow {
  margin-bottom: 0;
}
.ct-admin__reporting-performer-group .ct-admin__reporting-performer-grid {
  gap: 0.9rem;
}
.ct-admin__panel--nested .ct-reporting-visual {
  padding: 0.85rem;
}
.ct-admin__panel--nested .ct-reporting-visual__surface {
  padding: 0.75rem;
}
.ct-admin__table--compact th,
.ct-admin__table--compact td {
  padding-block: 0.55rem;
}
@media (max-width: 1280px) {
  .ct-admin__reporting-presentation-note {
    grid-template-columns: minmax(0, 1fr);
  }
  .ct-admin__reporting-panel-media {
    grid-template-columns: minmax(16rem, 21rem) minmax(0, 1fr);
  }
}
@media (max-width: 900px) {
  .ct-admin__reporting-presentation-shell,
  .ct-admin__reporting-secondary-story {
    gap: 0.9rem;
  }
  .ct-admin__reporting-presentation-note {
    gap: 0.6rem;
  }
  .ct-admin__reporting-supporting-grid,
  .ct-admin__reporting-highlight-grid,
  .ct-admin__reporting-panel-media,
  .ct-admin__reporting-focus-summary-grid {
    grid-template-columns: minmax(0, 1fr);
  }
  .ct-admin__reporting-advanced-drilldowns,
  .ct-admin__reporting-focus-section,
  .ct-admin__reporting-performer-group {
    padding: 0.9rem;
  }
  .ct-admin__reporting-state-list,
  .ct-admin__reporting-comparison-metrics {
    grid-template-columns: repeat(2, minmax(0, 1fr));
  }
  .ct-admin__reporting-inline-summary {
    align-items: flex-start;
    flex-direction: column;
  }
  .ct-admin__reporting-inline-summary small {
    text-align: left;
  }
  .ct-admin__reporting-focus-area-item {
    grid-template-columns: minmax(0, 1fr);
  }
}
@media (max-width: 1100px) {
  .ct-admin__reporting-presentation-note,
  .ct-admin__reporting-trend-hero,
  .ct-admin__reporting-supporting-grid,
  .ct-admin__reporting-highlight-grid,
  .ct-admin__reporting-panel-media,
  .ct-admin__reporting-visual-grid,
  .ct-admin__reporting-performer-grid,
  .ct-admin__reporting-deep-links,
  .ct-admin__reporting-slice-strip,
  .ct-admin__reporting-comparison-summary {
    grid-template-columns: minmax(0, 1fr);
  }
  .ct-admin__reporting-supporting-rail .ct-admin__panel {
    position: static;
  }
  .ct-admin__reporting-summary-metrics {
    grid-template-columns: repeat(2, minmax(0, 1fr));
  }
}
@media (max-width: 768px) {
  .ct-admin__reporting-presentation-shell,
  .ct-admin__reporting-presentation-note {
    padding: 0.85rem;
  }
  .ct-admin__reporting-secondary-story {
    padding-top: 0.85rem;
  }
  .ct-admin__reporting-summary-band {
    padding: 1rem;
  }
  .ct-admin__reporting-advanced-drilldowns,
  .ct-admin__reporting-performer-group {
    padding: 0.85rem;
  }
  .ct-admin__reporting-summary-metrics {
    grid-template-columns: minmax(0, 1fr);
  }
  .ct-admin__reporting-root-links {
    gap: 0.45rem;
  }
  .ct-admin__reporting-root-link,
  .ct-admin__reporting-breadcrumb-current {
    width: 100%;
    justify-content: flex-start;
  }
  .ct-admin__reporting-focus-section {
    padding: 0.85rem;
  }
  .ct-admin__reporting-breadcrumb-list,
  .ct-admin__reporting-focus-summary-grid {
    grid-template-columns: minmax(0, 1fr);
  }
  .ct-admin__reporting-visual-note {
    padding-inline-start: 0.65rem;
  }
  .ct-admin__reporting-table-number {
    min-height: 1.7rem;
    padding-inline: 0.5rem;
  }
}
.ct-admin__cta-link {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  border-radius: var(--ct-radius-sm);
  border: 1px solid var(--ct-border-strong);
  min-height: 2.24rem;
  padding: 0.4rem 0.66rem;
  font-family: var(--ct-font-sans);
  font-size: 0.77rem;
  font-weight: 600;
  line-height: 1.1;
  color: var(--ct-color-ink);
  text-decoration: none;
  background: linear-gradient(
    180deg,
    var(--ct-theme-surface-card-strong),
    var(--ct-theme-surface-info)
  );
  transition:
    background var(--ct-duration-fast) var(--ct-ease-standard),
    border-color var(--ct-duration-fast) var(--ct-ease-standard),
    color var(--ct-duration-fast) var(--ct-ease-standard),
    transform var(--ct-duration-fast) var(--ct-ease-standard);
}
@media (hover: hover) {
  .ct-admin__cta-link:hover {
    transform: translateY(-1px);
    border-color: var(--ct-border-strong);
    color: var(--ct-theme-text-title);
    background: var(--ct-theme-surface-info);
  }
}
.ct-admin__cta-link:focus-visible {
  outline: 2px solid var(--ct-theme-border-focus);
  outline-offset: 3px;
  box-shadow: var(--ct-shadow-soft);
}
.ct-admin__cta-link:active {
  transform: translateY(0);
}
.ct-admin__layout {
  --ct-grid-gap: var(--ct-space-4);
  --ct-sidebar-width: 360px;
  min-width: 0;
}
.ct-admin__layout > * {
  min-width: 0;
}
.ct-admin__panel {
  --ct-stack-gap: 0.7rem;
  background: linear-gradient(
    170deg,
    var(--ct-theme-surface-card-strong),
    var(--ct-theme-surface-soft)
  );
  border: 1px solid var(--ct-border-soft);
  border-radius: var(--ct-radius-lg);
  padding: var(--ct-space-4);
  min-width: 0;
}
.ct-admin__panel h2 {
  margin: 0;
  font-family: var(--ct-font-sans);
  font-size: 1rem;
  font-weight: 600;
  letter-spacing: 0;
}
.ct-admin__panel p {
  margin: 0;
  color: var(--ct-color-ink-soft);
  font-size: 0.9rem;
}
.ct-admin__panel h3,
.ct-admin__panel h4 {
  margin: 0;
}
.ct-admin__video-frame {
  position: relative;
  width: 100%;
  aspect-ratio: 16 / 9;
  border: 1px solid var(--ct-border-soft);
  border-radius: var(--ct-radius-md);
  overflow: hidden;
  background: var(--ct-theme-surface-info);
}
.ct-admin__video-frame iframe {
  width: 100%;
  height: 100%;
  border: 0;
}
.ct-admin__grid {
  --ct-stack-gap: var(--ct-space-4);
  min-width: 0;
}
.ct-admin__form {
  --ct-stack-gap: 0.65rem;
  min-width: 0;
}
.ct-admin__form--inline.ct-grid {
  --ct-grid-gap: 0.6rem;
  grid-template-columns: repeat(4, minmax(0, 1fr)) auto;
  align-items: end;
}
.ct-admin__add-disclosure {
  padding: 0;
  overflow: hidden;
}
.ct-admin__add-disclosure-summary {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: var(--ct-space-3);
  padding: var(--ct-space-4);
  cursor: pointer;
  list-style: none;
}
.ct-admin__add-disclosure-summary::-webkit-details-marker {
  display: none;
}
.ct-admin__add-disclosure-summary strong,
.ct-admin__add-disclosure-summary small {
  display: block;
}
.ct-admin__add-disclosure-summary strong {
  color: var(--ct-theme-text-title);
  font-family: var(--ct-font-sans);
  font-size: 1rem;
  font-weight: 600;
  letter-spacing: 0;
}
.ct-admin__add-disclosure-summary small {
  max-width: 68ch;
  color: var(--ct-theme-text-muted);
  font-size: 0.86rem;
  line-height: 1.45;
}
.ct-admin__add-disclosure-control {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  min-height: 2.3rem;
  padding: 0.44rem 0.74rem;
  border: 1px solid var(--ct-border-soft);
  border-radius: var(--ct-radius-sm);
  background: var(--ct-theme-surface-card-strong);
  color: var(--ct-theme-text-body);
  font-size: 0.8rem;
  font-weight: 600;
  line-height: 1.1;
  white-space: nowrap;
  transition:
    background var(--ct-duration-fast) var(--ct-ease-standard),
    border-color var(--ct-duration-fast) var(--ct-ease-standard),
    color var(--ct-duration-fast) var(--ct-ease-standard);
}
.ct-admin__add-disclosure[open] .ct-admin__add-disclosure-control {
  background: var(--ct-theme-surface-soft);
}
.ct-admin__add-disclosure-summary:hover .ct-admin__add-disclosure-control {
  border-color: var(--ct-border-strong);
  color: var(--ct-theme-text-title);
}
.ct-admin__add-disclosure-control-close {
  display: none;
}
.ct-admin__add-disclosure[open] .ct-admin__add-disclosure-control-open {
  display: none;
}
.ct-admin__add-disclosure[open] .ct-admin__add-disclosure-control-close {
  display: inline;
}
.ct-admin__add-disclosure-form.ct-grid {
  --ct-grid-gap: var(--ct-space-3);
  grid-template-columns: repeat(4, minmax(0, 1fr)) auto;
  align-items: end;
  padding: 0 var(--ct-space-4) var(--ct-space-4);
}
.ct-admin__add-disclosure-form--member.ct-grid {
  grid-template-columns: minmax(16rem, 2fr) minmax(10rem, 0.9fr) minmax(12rem, max-content) auto;
}
.ct-admin__add-disclosure-form--api-key.ct-grid {
  grid-template-columns: minmax(14rem, 1fr) minmax(18rem, 1.4fr) auto;
}
.ct-admin__add-disclosure-form--template-image.ct-grid {
  grid-template-columns: minmax(16rem, 1fr) minmax(16rem, 1fr) auto;
}
.ct-admin__add-disclosure-form--template-image-generation.ct-grid {
  grid-template-columns:
    minmax(13rem, 1fr) minmax(10rem, 0.8fr) minmax(10rem, 0.8fr) minmax(16rem, 1.4fr)
    auto;
}
.ct-admin__add-disclosure-form--template-image-revisions.ct-grid {
  grid-template-columns: minmax(16rem, 1fr) auto;
}
.ct-admin__add-disclosure-form--org-unit.ct-grid {
  grid-template-columns: repeat(4, minmax(0, 1fr)) auto;
}
.ct-admin__add-disclosure-form .ct-admin__checkbox-row {
  min-height: 2.75rem;
  align-items: center;
}
.ct-admin__add-disclosure > .ct-admin__hint {
  margin: 0;
  padding: 0 var(--ct-space-4) var(--ct-space-3);
}
.ct-admin__add-disclosure > .ct-admin__status,
.ct-admin__add-disclosure > .ct-admin__secret {
  margin: 0;
  padding: 0 var(--ct-space-4) var(--ct-space-4);
}
.ct-admin__form label {
  --ct-stack-gap: 0.28rem;
  display: grid;
  gap: 0.28rem;
  font-size: 0.88rem;
  color: var(--ct-color-ink);
}
.ct-admin__fieldset {
  border: 1px solid var(--ct-border-soft);
  border-radius: var(--ct-radius-md);
  padding: 0.55rem;
}
.ct-admin__fieldset legend {
  padding-inline: 0.2rem;
  font-size: 0.82rem;
  font-weight: 700;
  color: var(--ct-color-ink-soft);
}
.ct-admin__form input:not([type='checkbox']),
.ct-admin__form select,
.ct-admin__form textarea {
  width: 100%;
  max-width: 100%;
  min-width: 0;
  box-sizing: border-box;
  border: 1px solid var(--ct-border-strong);
  border-radius: var(--ct-radius-md);
  min-height: 2.75rem;
  padding: 0.65rem 0.72rem;
  background: var(--ct-theme-surface-card-strong);
  color: var(--ct-theme-text-body);
  font-family: var(--ct-font-sans);
  font-size: 0.92rem;
  line-height: 1.2;
  box-shadow: inset 0 1px 0 rgba(7, 26, 49, 0.03);
  transition:
    border-color var(--ct-duration-fast) var(--ct-ease-standard),
    box-shadow var(--ct-duration-fast) var(--ct-ease-standard),
    background var(--ct-duration-fast) var(--ct-ease-standard);
}
.ct-admin__form select,
.ct-admin__table select {
  -webkit-appearance: none;
  appearance: none;
  background-image:
    linear-gradient(45deg, transparent 50%, var(--ct-theme-text-muted) 50%),
    linear-gradient(135deg, var(--ct-theme-text-muted) 50%, transparent 50%);
  background-position:
    calc(100% - 0.96rem) 52%,
    calc(100% - 0.72rem) 52%;
  background-repeat: no-repeat;
  background-size:
    0.28rem 0.28rem,
    0.28rem 0.28rem;
  padding-right: 2.15rem;
}
.ct-admin__form input:not([type='checkbox']):focus,
.ct-admin__form select:focus,
.ct-admin__form textarea:focus,
.ct-admin__table select:focus {
  outline: none;
  border-color: var(--ct-theme-border-focus);
  box-shadow: var(--ct-focus-ring);
}
.ct-admin__form select:disabled,
.ct-admin__table select:disabled {
  cursor: progress;
  opacity: 0.68;
}
.ct-admin__form textarea {
  min-height: 5.5rem;
  resize: vertical;
  font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
  font-size: 0.84rem;
  line-height: 1.35;
}
.ct-admin__builder-grid {
  --ct-grid-gap: 0.65rem;
}
.ct-admin__builder-grid.ct-grid {
  grid-template-columns: repeat(2, minmax(0, 1fr));
}
.ct-admin-content--rule-builder {
  max-width: none;
}
.ct-admin-page-header--compact {
  max-width: 76rem;
}
.ct-admin__builder-shell {
  --ct-grid-gap: var(--ct-space-4);
  --ct-stack-gap: var(--ct-space-4);
  width: 100%;
  max-width: none;
}
.ct-admin__builder-shell > * {
  min-width: 0;
}
.ct-admin__builder-sidebar,
.ct-admin__builder-rail {
  position: static;
}
.ct-admin__builder-main {
  min-width: 0;
  width: 100%;
}
.ct-admin__builder-stepper-panel {
  --ct-stack-gap: 0.7rem;
}
.ct-admin__builder-stepper-panel h2 {
  display: none;
}
.ct-admin__builder-stepper-panel .ct-admin__eyebrow {
  display: none;
}
.ct-admin__builder-stepper-panel .ct-admin__builder-steps {
  grid-template-columns: repeat(3, minmax(0, 1fr));
}
.ct-admin__builder-stepper-panel .ct-admin__step-button {
  align-items: center;
  min-height: 2.6rem;
  padding: 0.5rem 0.58rem;
}
.ct-admin__builder-stepper-panel .ct-admin__step-copy small {
  display: none;
}
.ct-admin__builder-stepper-panel .ct-admin__builder-progress {
  margin: 0;
}
.ct-admin__builder-intro-grid.ct-grid {
  --ct-grid-gap: 0.7rem;
  grid-template-columns: repeat(3, minmax(0, 1fr));
}
.ct-admin__builder-intro-card {
  --ct-stack-gap: 0.35rem;
  padding: 0.8rem 0.82rem;
  border-radius: var(--ct-radius-md);
  border: 1px solid var(--ct-border-soft);
  background: var(--ct-theme-surface-soft);
}
.ct-admin__builder-support {
  --ct-stack-gap: 0.85rem;
}
.ct-admin__builder-support-grid.ct-grid {
  --ct-grid-gap: 1rem;
  grid-template-columns: repeat(auto-fit, minmax(18rem, 1fr));
  align-items: start;
}
.ct-admin__builder-support-section {
  --ct-stack-gap: 0.55rem;
  min-width: 0;
}
.ct-admin__builder-support-section--wide {
  grid-column: 1 / -1;
}
.ct-admin__builder-support-section h3,
.ct-admin__builder-support-section h4 {
  margin: 0;
}
.ct-admin__builder-support-section h3 {
  font-size: 0.98rem;
}
.ct-admin__builder-support-section h4 {
  font-size: 0.92rem;
}
.ct-admin__pattern-panel {
  --ct-stack-gap: 0.7rem;
  padding: 0.82rem;
  border-radius: var(--ct-radius-md);
  border: 1px solid var(--ct-theme-border-info);
  background: var(--ct-theme-surface-info);
}
.ct-admin__pattern-panel h4,
.ct-admin__pattern-panel p {
  margin: 0;
}
.ct-admin__pattern-panel h4 {
  font-size: 0.98rem;
}
.ct-admin__pattern-panel p {
  max-width: 65ch;
  font-size: 0.86rem;
  color: var(--ct-theme-text-muted);
}
.ct-admin__builder-inline {
  --ct-cluster-gap: 0.5rem;
  align-items: end;
}
.ct-admin__builder-progress {
  margin-top: -0.15rem;
  font-size: 0.85rem;
  font-weight: 700;
}
.ct-admin__builder-workbench.ct-grid {
  --ct-grid-gap: 0.8rem;
  grid-template-columns: minmax(0, 1fr);
  align-items: start;
}
.ct-admin__builder-workbench.ct-stack {
  --ct-stack-gap: 0.8rem;
}
.ct-admin__builder-workbench-main {
  min-width: 0;
}
.ct-admin__builder-patterns {
  --ct-stack-gap: 0.6rem;
  padding: 0.75rem;
  border-radius: var(--ct-radius-md);
  border: 1px solid var(--ct-border-soft);
  background: linear-gradient(
    180deg,
    var(--ct-theme-surface-card-strong),
    var(--ct-theme-surface-soft)
  );
}
.ct-admin__builder-patterns-head {
  --ct-stack-gap: 0.28rem;
}
.ct-admin__step-head {
  --ct-stack-gap: 0.28rem;
  border: 1px solid var(--ct-border-soft);
  border-radius: var(--ct-radius-md);
  background: linear-gradient(
    180deg,
    var(--ct-theme-surface-card-strong),
    var(--ct-theme-surface-soft)
  );
  padding: 0.62rem 0.66rem;
}
.ct-admin__step-kicker {
  margin: 0;
  font-size: 0.73rem;
  text-transform: uppercase;
  letter-spacing: 0.08em;
  color: var(--ct-theme-text-subtle);
  font-weight: 700;
}
.ct-admin__step-head h3 {
  margin: 0;
  font-size: 0.98rem;
}
.ct-admin__step-head p {
  margin: 0;
  font-size: 0.87rem;
  color: var(--ct-theme-text-muted);
}
.ct-admin__builder-toolbar {
  --ct-cluster-gap: 0.45rem;
}
.ct-admin__builder-principle {
  --ct-stack-gap: 0.22rem;
  padding: 0.68rem 0.72rem;
  border-radius: var(--ct-radius-md);
  border: 1px solid var(--ct-theme-border-info);
  background: var(--ct-theme-surface-info);
}
.ct-admin__builder-principle strong,
.ct-admin__builder-principle p {
  margin: 0;
}
.ct-admin__builder-principle strong {
  color: var(--ct-color-ink);
  font-size: 0.9rem;
}
.ct-admin__builder-principle p {
  max-width: 70ch;
  color: var(--ct-theme-text-muted);
  font-size: 0.84rem;
}
.ct-admin__inline-control {
  display: grid;
  gap: 0.25rem;
  min-width: 12rem;
}
.ct-admin__field-label {
  font-size: 0.88rem;
  color: var(--ct-color-ink);
}
.ct-admin__segmented-control {
  display: inline-grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 0.18rem;
  padding: 0.18rem;
  border: 1px solid var(--ct-border-soft);
  border-radius: var(--ct-radius-sm);
  background: var(--ct-theme-surface-soft);
}
.ct-admin__segmented-control label {
  display: block;
  min-width: 0;
  cursor: pointer;
}
.ct-admin__segmented-control input {
  position: absolute;
  inline-size: 1px;
  block-size: 1px;
  width: 1px;
  height: 1px;
  margin: -1px;
  overflow: hidden;
  clip: rect(0 0 0 0);
  white-space: nowrap;
  border: 0;
}
.ct-admin__segmented-control span {
  display: flex;
  align-items: center;
  justify-content: center;
  min-height: 2rem;
  padding: 0.36rem 0.58rem;
  border-radius: calc(var(--ct-radius-sm) - 2px);
  color: var(--ct-theme-text-muted);
  font-size: 0.82rem;
  font-weight: 700;
  line-height: 1.2;
  text-align: center;
  transition:
    background-color 160ms ease,
    color 160ms ease,
    box-shadow 160ms ease;
}
.ct-admin__segmented-control input:checked + span {
  background: var(--ct-theme-surface-card-strong);
  color: var(--ct-color-ink);
  box-shadow: var(--ct-shadow-soft);
}
.ct-admin__segmented-control input:focus-visible + span {
  outline: 2px solid var(--ct-theme-border-focus);
  outline-offset: 2px;
}
.ct-admin__builder-canvas {
  --ct-stack-gap: 0.55rem;
  border: 1px solid var(--ct-border-soft);
  border-radius: var(--ct-radius-md);
  background: var(--ct-theme-surface-info);
  padding: 0.58rem;
}
.ct-admin__builder-canvas-header {
  justify-content: space-between;
}
.ct-admin__builder-canvas-meta {
  --ct-cluster-gap: 0.35rem;
}
.ct-admin__builder-canvas-empty {
  margin: 0;
  padding: 0.62rem 0.66rem;
  border-radius: var(--ct-radius-sm);
  border: 1px dashed var(--ct-border-soft);
  background: var(--ct-theme-surface-card-strong);
  color: var(--ct-theme-text-subtle);
  font-size: 0.84rem;
}
.ct-admin__builder-condition-list {
  --ct-stack-gap: 0.55rem;
}
.ct-admin__builder-flow {
  --ct-stack-gap: 0.58rem;
  padding: 0.72rem;
  border: 1px solid var(--ct-border-soft);
  border-radius: var(--ct-radius-md);
  background: var(--ct-theme-surface-card-strong);
}
.ct-admin__builder-flow-list {
  display: grid;
  gap: 0.5rem;
  margin: 0;
  padding: 0;
  list-style: none;
}
.ct-admin__builder-flow-item {
  display: grid;
  grid-template-columns: minmax(3rem, 4rem) minmax(0, 1fr);
  gap: 0.48rem;
  align-items: stretch;
}
.ct-admin__builder-flow-item:first-child {
  grid-template-columns: minmax(0, 1fr);
}
.ct-admin__builder-flow-connector {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  align-self: center;
  min-height: 1.8rem;
  padding: 0.16rem 0.48rem;
  border: 1px solid var(--ct-border-soft);
  border-radius: var(--ct-radius-pill);
  background: var(--ct-theme-surface-soft);
  color: var(--ct-theme-text-muted);
  font-size: 0.72rem;
  font-weight: 800;
  letter-spacing: 0;
}
.ct-admin__builder-flow-node {
  display: grid;
  gap: 0.12rem;
  min-width: 0;
  padding: 0.56rem 0.62rem;
  border: 1px solid var(--ct-theme-border-info);
  border-radius: var(--ct-radius-sm);
  background: var(--ct-theme-surface-info);
}
.ct-admin__builder-flow-node strong {
  color: var(--ct-color-ink);
  font-size: 0.88rem;
  line-height: 1.25;
}
.ct-admin__builder-flow-node p {
  margin: 0;
  color: var(--ct-theme-text-muted);
  font-size: 0.78rem;
  line-height: 1.35;
  overflow-wrap: anywhere;
}
.ct-admin__builder-flow-kicker {
  color: var(--ct-theme-text-subtle);
  font-size: 0.68rem;
  font-weight: 800;
  letter-spacing: 0;
  text-transform: uppercase;
}
.ct-admin__builder-flow-item--course_completion .ct-admin__builder-flow-node,
.ct-admin__builder-flow-item--issue .ct-admin__builder-flow-node {
  border-color: var(--ct-theme-border-success);
  background: var(--ct-theme-surface-success);
}
.ct-admin__builder-flow-item--grade_threshold .ct-admin__builder-flow-node,
.ct-admin__builder-flow-item--custom_field .ct-admin__builder-flow-node {
  border-color: var(--ct-theme-border-focus);
  background: var(--ct-theme-surface-card-strong);
}
.ct-admin__builder-flow-item--assignment_submission .ct-admin__builder-flow-node,
.ct-admin__builder-flow-item--time_window .ct-admin__builder-flow-node {
  border-color: var(--ct-theme-border-warning);
  background: var(--ct-theme-surface-warning);
}
.ct-admin__builder-flow-item--prerequisite_badge .ct-admin__builder-flow-node {
  border-color: var(--ct-theme-border-danger);
  background: var(--ct-theme-surface-danger);
}
.ct-admin__builder-test-layout.ct-grid,
.ct-admin__builder-review-layout.ct-grid {
  --ct-grid-gap: 0.8rem;
  grid-template-columns: minmax(0, 1fr);
  align-items: start;
}
.ct-admin__builder-test-actions {
  display: flex;
  justify-content: flex-start;
}
.ct-admin__builder-governance {
  --ct-stack-gap: 0.75rem;
  margin-top: 0.9rem;
}
.ct-admin__builder-simulation {
  padding: 0.82rem;
  border-radius: var(--ct-radius-md);
  border: 1px solid var(--ct-border-soft);
  background: linear-gradient(
    180deg,
    var(--ct-theme-surface-card-strong),
    var(--ct-theme-surface-soft)
  );
}
.ct-admin__builder-test-rail,
.ct-admin__builder-checklist-panel,
.ct-admin__builder-rail-card {
  padding: 0.78rem 0.82rem;
  border-radius: var(--ct-radius-md);
  border: 1px solid var(--ct-border-soft);
  background: var(--ct-theme-surface-soft);
}
.ct-admin__builder-source-panel {
  --ct-stack-gap: 0.56rem;
  padding-top: 0.74rem;
  border-top: 1px solid var(--ct-border-soft);
}
.ct-admin__builder-source-list {
  display: grid;
  gap: 0.46rem;
  margin: 0;
  padding: 0;
}
.ct-admin__builder-source-list > div {
  display: grid;
  gap: 0.18rem;
  padding: 0.54rem 0.58rem;
  border: 1px solid var(--ct-border-soft);
  border-radius: var(--ct-radius-sm);
  background: var(--ct-theme-surface-card-strong);
}
.ct-admin__builder-source-list dt {
  color: var(--ct-color-ink);
  font-size: 0.82rem;
  font-weight: 700;
}
.ct-admin__builder-source-list dd {
  display: flex;
  flex-wrap: wrap;
  gap: 0.36rem;
  align-items: center;
  margin: 0;
  color: var(--ct-theme-text-muted);
  font-size: 0.78rem;
  line-height: 1.35;
}
.ct-admin__builder-rail-card > summary,
.ct-admin__builder-simulation > summary {
  display: flex;
  align-items: center;
  min-height: 2.4rem;
  cursor: pointer;
  font-weight: 700;
  color: var(--ct-color-ink);
}
.ct-admin__builder-summary-list {
  grid-template-columns: repeat(5, minmax(0, 1fr));
}
.ct-admin__builder-checklist {
  margin: 0;
  padding: 0 0 0 1rem;
  display: grid;
  gap: 0.34rem;
  color: var(--ct-theme-text-body);
}
.ct-admin__builder-checklist li {
  line-height: 1.35;
}
.ct-admin__condition-card {
  --ct-stack-gap: 0.5rem;
  border: 1px solid var(--ct-theme-border-info);
  border-radius: var(--ct-radius-md);
  background: var(--ct-theme-surface-card-strong);
  padding: 0.58rem;
}
.ct-admin__condition-card.is-dragging {
  opacity: 0.65;
  box-shadow: var(--ct-focus-ring);
}
.ct-admin__condition-card--course_completion {
  border-color: var(--ct-theme-border-success);
}
.ct-admin__condition-card--grade_threshold {
  border-color: var(--ct-theme-border-focus);
}
.ct-admin__condition-card--program_completion {
  border-color: var(--ct-theme-border-info);
}
.ct-admin__condition-card--assignment_submission {
  border-color: var(--ct-theme-border-warning);
}
.ct-admin__condition-card--survey_completion {
  border-color: var(--ct-theme-border-info);
}
.ct-admin__condition-card--time_window {
  border-color: var(--ct-border-strong);
}
.ct-admin__condition-card--prerequisite_badge {
  border-color: var(--ct-theme-border-danger);
}
.ct-admin__condition-card--custom_field {
  border-color: var(--ct-theme-border-focus);
}
.ct-admin__condition-card--result-idle {
  box-shadow: none;
}
.ct-admin__condition-card--result-pass {
  border-color: var(--ct-theme-border-success);
  background: var(--ct-theme-surface-success);
}
.ct-admin__condition-card--result-fail {
  border-color: var(--ct-theme-border-danger);
  background: var(--ct-theme-surface-danger);
}
.ct-admin__condition-card--result-review {
  border-color: var(--ct-theme-border-warning);
  background: var(--ct-theme-surface-warning);
}
.ct-admin__condition-header {
  --ct-cluster-gap: 0.5rem;
  align-items: stretch;
}
.ct-admin__condition-header-row {
  --ct-cluster-gap: 0.42rem;
  justify-content: space-between;
  align-items: center;
}
.ct-admin__condition-index {
  display: inline-flex;
  align-items: center;
  border-radius: var(--ct-radius-pill);
  border: 1px solid var(--ct-border-soft);
  background: var(--ct-theme-surface-soft);
  color: var(--ct-theme-text-muted);
  font-size: 0.74rem;
  font-weight: 700;
  letter-spacing: 0.03em;
  padding: 0.16rem 0.48rem;
}
.ct-admin__condition-drag {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  width: auto;
  height: 1.7rem;
  border-radius: var(--ct-radius-sm);
  border: 1px solid var(--ct-border-soft);
  background: var(--ct-theme-surface-info);
  color: var(--ct-theme-text-muted);
  font-size: 0.72rem;
  font-weight: 700;
  letter-spacing: 0;
  padding: 0 0.42rem;
  cursor: grab;
  user-select: none;
}
.ct-admin__condition-actions {
  --ct-cluster-gap: 0.36rem;
}
.ct-admin__condition-header-fields.ct-grid {
  --ct-grid-gap: 0.5rem;
  grid-template-columns: minmax(0, 1fr) minmax(10rem, auto);
  align-items: end;
}
.ct-admin__condition-header-fields label {
  min-width: 0;
}
.ct-admin__condition-advanced {
  align-self: end;
  border: 1px solid var(--ct-border-soft);
  border-radius: var(--ct-radius-sm);
  background: var(--ct-theme-surface-soft);
  padding: 0.22rem 0.42rem;
}
.ct-admin__condition-advanced > summary {
  cursor: pointer;
  color: var(--ct-theme-text-muted);
  font-size: 0.78rem;
  font-weight: 700;
}
.ct-admin__condition-advanced[open] > summary {
  margin-bottom: 0.36rem;
}
.ct-admin__condition-fields.ct-grid {
  --ct-grid-gap: 0.5rem;
  grid-template-columns: repeat(2, minmax(0, 1fr));
}
.ct-admin__condition-help {
  margin: 0;
  font-size: 0.79rem;
  color: var(--ct-theme-text-subtle);
}
.ct-admin__condition-result {
  margin: 0;
  font-size: 0.78rem;
  font-weight: 700;
}
.ct-admin__condition-result[data-state='idle'] {
  color: var(--ct-theme-text-subtle);
}
.ct-admin__condition-result[data-state='pass'] {
  color: var(--ct-theme-state-success);
}
.ct-admin__condition-result[data-state='fail'] {
  color: var(--ct-theme-state-danger);
}
.ct-admin__condition-result[data-state='review'] {
  color: var(--ct-theme-state-warning);
}
.ct-admin__checkbox-row {
  font-size: 0.92rem;
}
.ct-admin__checkbox-row input[type='checkbox'] {
  margin: 0;
}
.ct-admin__form button {
  display: inline-flex;
  box-sizing: border-box;
  appearance: none;
  align-items: center;
  justify-content: center;
  justify-self: start;
  border: none;
  border-radius: var(--ct-radius-sm);
  min-height: 2.45rem;
  padding: 0.5rem 0.86rem;
  font-family: var(--ct-font-sans);
  font-weight: 600;
  font-size: 0.84rem;
  line-height: 1.1;
  color: var(--ct-theme-text-on-brand);
  background: var(--ct-theme-gradient-action);
  cursor: pointer;
  transition:
    transform var(--ct-duration-fast) var(--ct-ease-standard),
    box-shadow var(--ct-duration-fast) var(--ct-ease-standard),
    filter var(--ct-duration-fast) var(--ct-ease-standard);
}
.ct-admin__button {
  display: inline-flex;
  box-sizing: border-box;
  appearance: none;
  align-items: center;
  justify-content: center;
  border: none;
  border-radius: var(--ct-radius-sm);
  min-height: 2.45rem;
  padding: 0.5rem 0.78rem;
  font-family: var(--ct-font-sans);
  font-size: 0.8rem;
  font-weight: 600;
  color: var(--ct-theme-text-on-brand);
  background: var(--ct-theme-gradient-action);
  text-decoration: none;
  line-height: 1.1;
  cursor: pointer;
  transition:
    transform var(--ct-duration-fast) var(--ct-ease-standard),
    box-shadow var(--ct-duration-fast) var(--ct-ease-standard),
    filter var(--ct-duration-fast) var(--ct-ease-standard);
}
@media (hover: hover) {
  .ct-admin__form button:hover:not(:disabled),
  .ct-admin__button:hover:not(:disabled) {
    transform: translateY(-1px);
    box-shadow: var(--ct-shadow-soft);
    filter: brightness(1.03);
  }

  .ct-admin__action-menu-item:hover {
    transform: translateY(-1px);
  }

  .ct-admin__action-menu-item:hover {
    background: var(--ct-theme-surface-info);
  }

  .ct-admin__action-menu-item--danger:hover {
    background: var(--ct-theme-surface-danger);
  }

  .ct-admin__button--danger:hover:not(:disabled) {
    background: #ffe8e3;
    border-color: rgba(173, 61, 49, 0.34);
    color: #8f1c13;
    box-shadow: 0 8px 16px rgba(173, 61, 49, 0.08);
    filter: none;
  }
}
.ct-admin__form button:focus-visible,
.ct-admin__button:focus-visible {
  outline: 2px solid var(--ct-theme-border-focus);
  outline-offset: 3px;
  box-shadow: var(--ct-shadow-soft);
}
.ct-admin__action-menu-item:focus-visible {
  outline: 2px solid var(--ct-theme-border-focus);
  outline-offset: 2px;
}
.ct-admin__form button:active:not(:disabled),
.ct-admin__button:active {
  transform: translateY(0);
  box-shadow: none;
  filter: none;
}
.ct-admin__action-menu-item:active {
  transform: translateY(0);
}
.ct-admin__form button:disabled {
  opacity: 0.66;
  cursor: progress;
}
.ct-admin__button:disabled {
  opacity: 0.66;
  cursor: progress;
}
.ct-admin__button--tiny {
  min-height: 2.24rem;
  padding: 0.4rem 0.66rem;
  font-size: 0.77rem;
}
.ct-admin__button--danger {
  color: var(--ct-theme-state-danger);
  border: 1px solid var(--ct-theme-border-danger);
  background: var(--ct-theme-surface-danger);
}
.ct-admin__button--secondary {
  color: var(--ct-color-ink);
  border: 1px solid var(--ct-border-strong);
  background: linear-gradient(
    180deg,
    var(--ct-theme-surface-card-strong),
    var(--ct-theme-surface-info)
  );
}
.ct-admin__button--ghost {
  color: var(--ct-theme-text-body);
  border: 1px solid var(--ct-border-soft);
  background: var(--ct-theme-surface-card-strong);
}
.ct-admin__status {
  margin: 0;
  font-size: 0.88rem;
  color: var(--ct-theme-text-muted);
}
.ct-admin__status[data-tone='error'] {
  color: var(--ct-theme-state-danger);
}
.ct-admin__status[data-tone='success'] {
  color: var(--ct-theme-state-success);
}
.ct-admin__status[data-tone='info'] {
  color: var(--ct-theme-text-muted);
}
.ct-admin__status[data-tone='warning'] {
  color: var(--ct-theme-state-warning);
}
.ct-admin__hint {
  margin: 0;
  font-size: 0.8rem;
  color: var(--ct-theme-text-subtle);
}
.ct-admin__secret {
  margin: 0;
  font-size: 0.84rem;
  line-height: 1.4;
  padding: 0.6rem;
  border-radius: var(--ct-radius-sm);
  background: var(--ct-theme-surface-info);
  border: 1px solid var(--ct-border-soft);
  overflow-wrap: anywhere;
}
.ct-admin__code-output {
  margin: 0;
  padding: 0.68rem;
  border-radius: var(--ct-radius-sm);
  border: 1px solid var(--ct-border-soft);
  background: var(--ct-theme-surface-info);
  color: var(--ct-theme-text-body);
  font-size: 0.79rem;
  line-height: 1.35;
  overflow: auto;
  max-height: 14rem;
}
.ct-admin__table-wrap {
  overflow: auto;
  border: 1px solid var(--ct-border-soft);
  border-radius: var(--ct-radius-md);
  background: var(--ct-theme-surface-shell);
}
.ct-admin__table {
  width: 100%;
  border-collapse: collapse;
}
.ct-admin__table th,
.ct-admin__table td {
  text-align: left;
  border-bottom: 1px solid var(--ct-border-soft);
  padding: 0.55rem;
  vertical-align: top;
  font-size: 0.88rem;
}
.ct-admin__table th {
  color: var(--ct-theme-text-title);
  font-weight: 600;
}
.ct-admin__member-identity {
  display: block;
  color: var(--ct-theme-text-title);
  font-weight: 600;
  line-height: 1.35;
  overflow-wrap: anywhere;
}
.ct-admin__table a {
  display: inline-flex;
  align-items: center;
  min-height: 2.75rem;
}
.ct-admin__empty {
  color: var(--ct-color-ink-soft);
  text-align: center;
  padding: 0.8rem 0.55rem;
}
.ct-admin__meta {
  color: var(--ct-color-ink-soft);
  font-size: 0.82rem;
}
.ct-admin__status-pill {
  display: inline-flex;
  padding: 0.14rem 0.45rem;
  border-radius: 999px;
  font-size: 0.76rem;
  font-weight: 700;
  border: 1px solid var(--ct-border-soft);
  background: var(--ct-theme-surface-soft);
  color: var(--ct-theme-text-muted);
}
.ct-admin__status-pill--draft,
.ct-admin__status-pill--pending_approval {
  background: var(--ct-theme-surface-warning);
  color: var(--ct-theme-state-warning);
  border-color: var(--ct-theme-border-warning);
}
.ct-admin__status-pill--approved,
.ct-admin__status-pill--active {
  background: var(--ct-theme-surface-success);
  color: var(--ct-theme-state-success);
  border-color: var(--ct-theme-border-success);
}
.ct-admin__status-pill--suspended,
.ct-admin__status-pill--expired {
  background: var(--ct-theme-surface-warning);
  color: var(--ct-theme-state-warning);
  border-color: var(--ct-theme-border-warning);
}
.ct-admin__status-pill--rejected,
.ct-admin__status-pill--deprecated,
.ct-admin__status-pill--revoked {
  background: var(--ct-theme-surface-danger);
  color: var(--ct-theme-state-danger);
  border-color: var(--ct-theme-border-danger);
}
.ct-admin__assertion-id {
  font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
  font-size: 0.78rem;
  color: var(--ct-theme-text-subtle);
  overflow-wrap: anywhere;
}
.ct-admin__issued-actions-cell {
  width: 1%;
  white-space: nowrap;
}
.ct-admin__issued-actions {
  display: grid;
  justify-items: start;
  gap: 0.4rem;
}
.ct-admin__action-bar {
  display: inline-flex;
  align-items: center;
  flex-wrap: nowrap;
  gap: 0.32rem;
}
.ct-admin__issued-actions .ct-admin__button {
  box-sizing: border-box;
  min-height: 1.9rem;
  height: 1.9rem;
  max-height: 1.9rem;
  padding: 0.28rem 0.5rem;
  font-size: 0.72rem;
  line-height: 1;
  box-shadow: none;
  user-select: none;
}
.ct-admin__issued-actions .ct-admin__button--secondary {
  color: var(--ct-color-ink);
  border: 1px solid var(--ct-border-strong);
  background: linear-gradient(
    180deg,
    var(--ct-theme-surface-card-strong),
    var(--ct-theme-surface-info)
  );
}
.ct-admin__action-menu-trigger {
  min-width: 1.9rem;
  width: 1.9rem;
  padding-inline: 0;
}
.ct-admin__issued-actions .ct-admin__button:focus-visible {
  outline-offset: 1px;
  box-shadow: none;
}
.ct-admin__action-menu {
  position: relative;
  display: inline-flex;
}
.ct-admin__action-menu > summary {
  list-style: none;
}
.ct-admin__action-menu > summary::-webkit-details-marker {
  display: none;
}
.ct-admin__action-menu[open] > .ct-admin__action-menu-trigger {
  background: var(--ct-theme-surface-info);
}
.ct-admin__action-menu-popover {
  display: none;
}
.ct-admin__action-menu[open] .ct-admin__action-menu-popover {
  position: absolute;
  z-index: 20;
  top: calc(100% + 0.32rem);
  right: 0;
  display: grid;
  gap: 0.18rem;
  min-width: 11rem;
  padding: 0.32rem;
  border: 1px solid var(--ct-border-strong);
  border-radius: var(--ct-radius-md);
  background: var(--ct-theme-surface-card-strong);
  box-shadow: var(--ct-shadow-soft);
}
.ct-admin__table .ct-admin__action-menu-item,
.ct-admin__table button.ct-admin__action-menu-item {
  display: flex;
  align-items: center;
  width: 100%;
  min-height: 0;
  padding: 0.55rem 0.7rem;
  border: none;
  border-radius: var(--ct-radius-sm);
  background: transparent;
  color: var(--ct-theme-text-body);
  font-size: 0.78rem;
  font-weight: 600;
  line-height: 1.25;
  text-align: left;
  text-decoration: none;
  cursor: pointer;
}
.ct-admin__table button.ct-admin__action-menu-item {
  font-family: var(--ct-font-sans);
}
.ct-admin__action-menu-item--danger {
  color: var(--ct-theme-state-danger);
}
.ct-admin__actions {
  display: inline-flex;
  flex-wrap: wrap;
  gap: 0.32rem;
}
.ct-admin__template-image-link,
.ct-admin__image-revision-thumbnail-link {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  border-radius: var(--ct-radius-sm);
  color: inherit;
}
.ct-admin__template-image-link:focus-visible,
.ct-admin__image-revision-thumbnail-link:focus-visible {
  outline: 2px solid var(--ct-theme-border-focus);
  outline-offset: 2px;
}
.ct-admin__template-image {
  width: 3.2rem;
  height: 3.2rem;
  border-radius: var(--ct-radius-sm);
  object-fit: cover;
  border: 1px solid var(--ct-border-strong);
}
.ct-admin__image-generation-preview {
  display: flex;
  gap: var(--ct-space-4);
  align-items: center;
  padding: 0 var(--ct-space-4) var(--ct-space-4);
}
.ct-admin__image-generation-preview[hidden] {
  display: none;
}
.ct-admin__image-generation-preview img {
  width: 7rem;
  height: 7rem;
  border: 1px solid var(--ct-border-soft);
  border-radius: var(--ct-radius-md);
  object-fit: cover;
  background: var(--ct-surface-subtle);
}
.ct-admin__image-generation-actions {
  display: flex;
  align-items: center;
  flex-wrap: wrap;
  gap: var(--ct-space-2);
}
.ct-admin__text-action {
  color: var(--ct-theme-link);
  font-size: 0.88rem;
  font-weight: 650;
  text-decoration: none;
}
.ct-admin__text-action:hover,
.ct-admin__text-action:focus-visible {
  text-decoration: underline;
}
.ct-admin__image-revision-list {
  display: grid;
  gap: var(--ct-space-2);
  padding: 0 var(--ct-space-4) var(--ct-space-4);
}
.ct-admin__image-revision-item {
  display: flex;
  align-items: center;
  gap: var(--ct-space-3);
  border: 1px solid var(--ct-border-soft);
  border-radius: var(--ct-radius-md);
  padding: var(--ct-space-2) var(--ct-space-3);
  background: var(--ct-surface);
}
.ct-admin__image-revision-meta {
  display: grid;
  gap: 0.15rem;
  min-width: 0;
  flex: 1;
}
.ct-admin__image-revision-meta span {
  color: var(--ct-color-muted);
  font-size: 0.84rem;
}
.ct-admin__image-revision-actions {
  display: inline-flex;
  align-items: center;
  flex-wrap: wrap;
  justify-content: flex-end;
  gap: var(--ct-space-2);
  flex: 0 0 auto;
}
.ct-admin__image-revision-thumbnail {
  width: 2.6rem;
  height: 2.6rem;
  border: 1px solid var(--ct-border-soft);
  border-radius: var(--ct-radius-sm);
  object-fit: cover;
  background: var(--ct-surface-subtle);
}
.ct-admin__image-revision-thumbnail-link--empty {
  width: 2.6rem;
  height: 2.6rem;
  border: 1px dashed var(--ct-border-strong);
  font-size: 0.66rem;
  color: var(--ct-color-ink-soft);
}
.ct-admin__template-placeholder {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  width: 3.2rem;
  height: 3.2rem;
  border-radius: var(--ct-radius-sm);
  border: 1px dashed var(--ct-border-strong);
  font-size: 0.72rem;
  color: var(--ct-color-ink-soft);
}
.ct-admin__panel--table {
  padding: 0.9rem;
}
.ct-admin__members-table .ct-admin__table {
  min-width: 980px;
}
.ct-admin__api-keys-table .ct-admin__table,
.ct-admin__org-units-table .ct-admin__table {
  min-width: 760px;
}
.ct-admin__members-table .ct-admin__table th:first-child,
.ct-admin__members-table .ct-admin__table td:first-child {
  width: 32%;
}
.ct-admin__api-keys-table .ct-admin__table th:first-child,
.ct-admin__api-keys-table .ct-admin__table td:first-child {
  width: 28%;
}
.ct-admin__org-units-table .ct-admin__table th:nth-child(3),
.ct-admin__org-units-table .ct-admin__table td:nth-child(3) {
  width: 42%;
}
.ct-admin__members-table .ct-admin__table th:last-child,
.ct-admin__members-table .ct-admin__table td:last-child {
  width: 13rem;
}
.ct-admin__api-keys-table .ct-admin__table th:last-child,
.ct-admin__api-keys-table .ct-admin__table td:last-child {
  width: 9rem;
}
.ct-admin__members-table select {
  min-width: 6.8rem;
  min-height: 2.12rem;
  padding: 0.32rem 1.9rem 0.32rem 0.56rem;
  border: 1px solid var(--ct-border-soft);
  border-radius: var(--ct-radius-sm);
  background-color: var(--ct-theme-surface-card-strong);
  color: var(--ct-theme-text-body);
  font-family: var(--ct-font-sans);
  font-size: 0.82rem;
  font-weight: 500;
  line-height: 1.2;
}
.ct-admin__panel--table > h2,
.ct-admin__panel--table > p,
.ct-admin__panel--table > .ct-admin__status {
  padding-inline: 0.1rem;
}
.ct-admin__panel--nested {
  padding: 0.75rem;
  background: var(--ct-theme-surface-soft);
}
.ct-admin__builder-step[hidden] {
  display: none;
}
.ct-admin__builder-step-nav {
  --ct-grid-gap: 0.5rem;
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  border: 1px solid var(--ct-border-soft);
  border-radius: var(--ct-radius-md);
  background: var(--ct-theme-surface-shell);
  box-shadow: var(--ct-shadow-soft);
  padding: 0.58rem 0.62rem;
}
.ct-admin__builder-step-nav #rule-builder-submit {
  grid-column: 1 / -1;
}
.ct-admin__builder-steps {
  list-style: none;
  margin: 0;
  padding: 0;
  display: grid;
  gap: 0.48rem;
}
.ct-admin__step-button {
  width: 100%;
  display: grid;
  box-sizing: border-box;
  appearance: none;
  grid-template-columns: auto minmax(0, 1fr);
  align-items: start;
  gap: 0.65rem;
  text-align: left;
  border: 1px solid var(--ct-border-strong);
  border-radius: var(--ct-radius-md);
  background: var(--ct-theme-surface-info);
  color: var(--ct-theme-text-body);
  min-height: 2.75rem;
  font-family: var(--ct-font-sans);
  font-size: 0.82rem;
  font-weight: 700;
  line-height: 1.2;
  padding: 0.7rem 0.8rem;
  cursor: pointer;
  transition:
    border-color var(--ct-duration-fast) var(--ct-ease-standard),
    background var(--ct-duration-fast) var(--ct-ease-standard),
    color var(--ct-duration-fast) var(--ct-ease-standard),
    box-shadow var(--ct-duration-fast) var(--ct-ease-standard);
}
.ct-admin__step-number {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  inline-size: 1.7rem;
  block-size: 1.7rem;
  border-radius: 999px;
  border: 1px solid var(--ct-border-soft);
  background: var(--ct-theme-surface-card-strong);
  color: var(--ct-theme-text-subtle);
  font-size: 0.78rem;
}
.ct-admin__step-copy {
  display: grid;
  gap: 0.16rem;
}
.ct-admin__step-copy strong {
  font-size: 0.84rem;
}
.ct-admin__step-copy small {
  font-size: 0.75rem;
  font-weight: 500;
  line-height: 1.35;
  color: var(--ct-theme-text-muted);
}
.ct-admin__step-button:hover {
  border-color: var(--ct-theme-border-focus);
}
.ct-admin__step-button.is-done {
  border-color: var(--ct-theme-border-success);
  background: var(--ct-theme-surface-success);
  color: var(--ct-theme-state-success);
}
.ct-admin__step-button.is-done .ct-admin__step-number {
  border-color: var(--ct-theme-border-success);
  background: var(--ct-theme-surface-card-strong);
  color: var(--ct-theme-state-success);
}
.ct-admin__step-button.is-done .ct-admin__step-copy strong::after {
  content: ' \u2713';
  font-weight: 800;
}
.ct-admin__step-button.is-active {
  color: var(--ct-theme-text-on-brand);
  border-color: transparent;
  background: var(--ct-theme-gradient-action);
  box-shadow: var(--ct-shadow-soft);
}
.ct-admin__step-button.is-active .ct-admin__step-number {
  border-color: rgba(255, 255, 255, 0.28);
  background: rgba(255, 255, 255, 0.18);
  color: var(--ct-theme-text-on-brand);
}
.ct-admin__step-button.is-active .ct-admin__step-copy small {
  color: rgba(255, 255, 255, 0.78);
}
.ct-admin__builder-advanced {
  border: 1px solid var(--ct-border-soft);
  border-radius: var(--ct-radius-md);
  background: var(--ct-theme-surface-soft);
  padding: 0.58rem 0.64rem;
}
.ct-admin__builder-advanced > summary {
  display: flex;
  align-items: center;
  min-height: 2.75rem;
  cursor: pointer;
  font-weight: 700;
  color: var(--ct-color-ink);
}
.ct-admin__builder-advanced[open] > summary {
  margin-bottom: 0.45rem;
}
.ct-admin__builder-advanced--inline {
  min-width: min(100%, 22rem);
  padding-block: 0.36rem;
}
.ct-admin__builder-advanced--inline > summary {
  min-height: 2.15rem;
}
.ct-admin__builder-guide {
  border: 1px solid var(--ct-border-soft);
  border-radius: var(--ct-radius-md);
  background: var(--ct-theme-surface-soft);
  padding: 0.58rem 0.64rem;
}
.ct-admin__builder-guide > summary {
  display: flex;
  align-items: center;
  min-height: 2.75rem;
  cursor: pointer;
  font-weight: 700;
  color: var(--ct-color-ink);
}
.ct-admin__builder-guide[open] > summary {
  margin-bottom: 0.45rem;
}
.ct-admin__builder-guide-list {
  margin: 0;
  padding: 0;
  display: grid;
  gap: 0.45rem;
}
.ct-admin__builder-guide-list > div {
  display: grid;
  gap: 0.1rem;
}
.ct-admin__builder-guide-list dt {
  font-size: 0.82rem;
  font-weight: 700;
  color: var(--ct-color-ink);
}
.ct-admin__builder-guide-list dd {
  margin: 0;
  font-size: 0.79rem;
  color: var(--ct-theme-text-muted);
}
.ct-admin__builder-summary-list {
  margin: 0;
  padding: 0;
  display: grid;
  gap: 0.48rem;
}
.ct-admin__builder-summary-list > div {
  display: grid;
  gap: 0.12rem;
}
.ct-admin__builder-summary-list dt {
  font-size: 0.8rem;
  color: var(--ct-color-ink-soft);
}
.ct-admin__builder-summary-list dd {
  margin: 0;
  color: var(--ct-color-ink);
  font-weight: 700;
}
.ct-admin__builder-summary-value[data-tone='success'] {
  color: var(--ct-theme-state-success);
}
.ct-admin__builder-summary-value[data-tone='warning'] {
  color: var(--ct-theme-state-warning);
}
.ct-admin__builder-summary-value[data-tone='error'] {
  color: var(--ct-theme-state-danger);
}

/* ── Responsive breakpoints ── */
@media (max-width: 780px) {
  .ct-admin__form--inline.ct-grid,
  .ct-admin__add-disclosure-form.ct-grid,
  .ct-admin__builder-grid.ct-grid,
  .ct-admin__condition-fields.ct-grid,
  .ct-admin__condition-header-fields.ct-grid,
  .ct-admin__builder-intro-grid.ct-grid,
  .ct-admin__builder-workbench.ct-grid,
  .ct-admin__builder-test-layout.ct-grid,
  .ct-admin__builder-review-layout.ct-grid,
  .ct-admin__workspace-grid.ct-grid {
    grid-template-columns: minmax(0, 1fr);
  }

  .ct-admin__builder-inline,
  .ct-admin__builder-toolbar,
  .ct-admin__builder-step-nav {
    display: grid;
    grid-template-columns: minmax(0, 1fr);
  }

  .ct-admin__builder-step-nav {
    justify-items: stretch;
  }

  .ct-admin__add-disclosure-summary {
    align-items: flex-start;
    flex-direction: column;
  }

  .ct-admin__add-disclosure-control {
    width: 100%;
  }

  .ct-admin__builder-stepper-panel .ct-admin__builder-steps,
  .ct-admin__builder-summary-list {
    grid-template-columns: minmax(0, 1fr);
  }

  .ct-admin__builder-flow-item,
  .ct-admin__builder-flow-item:first-child {
    grid-template-columns: minmax(0, 1fr);
  }

  .ct-admin__builder-flow-connector {
    justify-self: start;
  }

  .ct-admin__add-disclosure-control,
  .ct-admin__form button,
  .ct-admin__button,
  .ct-admin__button--tiny,
  .ct-admin__table select {
    min-height: 2.75rem;
  }

  .ct-admin__builder-inline > .ct-admin__button,
  .ct-admin__builder-toolbar .ct-admin__button,
  .ct-admin__builder-step-nav .ct-admin__button,
  .ct-admin__builder-step-nav #rule-builder-submit {
    width: 100%;
  }

  .ct-admin__image-revision-item {
    align-items: flex-start;
    flex-wrap: wrap;
  }

  .ct-admin__image-revision-actions {
    width: 100%;
    justify-content: flex-start;
  }
}
@media (max-width: 1180px) {
  .ct-admin__builder-shell,
  .ct-admin__workspace-grid.ct-grid {
    grid-template-columns: minmax(0, 1fr);
  }

  .ct-admin__builder-sidebar,
  .ct-admin__builder-rail {
    position: static;
    top: auto;
  }
}
@media (max-width: 980px) {
  .ct-admin__layout.ct-grid--sidebar {
    grid-template-columns: minmax(0, 1fr);
  }
}
@media (min-width: 980px) {
  .ct-admin__layout {
    align-items: start;
  }
}

`;

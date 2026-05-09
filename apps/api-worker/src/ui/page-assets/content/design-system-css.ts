export const DESIGN_SYSTEM_CSS = `
.ct-design-system {
  display: grid;
  gap: 1.35rem;
  max-width: 1180px;
  padding: 1.75rem 2rem 2.5rem;
}

.ct-design-system__header {
  margin-bottom: 0;
}

.ct-design-system__nav {
  display: flex;
  flex-wrap: wrap;
  gap: 0.4rem;
  padding-bottom: 0.9rem;
  border-bottom: 1px solid var(--ct-border-soft);
}

.ct-design-system__nav a {
  display: inline-flex;
  align-items: center;
  min-height: 2rem;
  padding: 0.35rem 0.65rem;
  border: 1px solid var(--ct-border-soft);
  border-radius: var(--ct-radius-sm);
  background: var(--ct-theme-surface-card-strong);
  color: var(--ct-theme-text-body);
  font-size: 0.78rem;
  font-weight: 600;
  line-height: 1.1;
  text-decoration: none;
}

.ct-design-system__nav a:hover {
  border-color: var(--ct-border-strong);
  background: var(--ct-theme-surface-info);
  color: var(--ct-theme-text-title);
}

.ct-design-system__section {
  display: grid;
  gap: 0.95rem;
  padding-block: 0.3rem 0.85rem;
}

.ct-design-system__section + .ct-design-system__section {
  border-top: 1px solid var(--ct-border-soft);
  padding-top: 1.3rem;
}

.ct-design-system__section h2 {
  margin: 0;
  font-size: clamp(1.05rem, 2vw, 1.28rem);
  line-height: 1.2;
}

.ct-design-system__section-copy {
  margin: 0;
  max-width: 46rem;
  color: var(--ct-theme-text-muted);
  font-size: 0.9rem;
  line-height: 1.5;
}

.ct-design-system__grid {
  display: grid;
  gap: 0.75rem;
  grid-template-columns: repeat(auto-fit, minmax(14rem, 1fr));
}

.ct-design-system__doc-grid {
  display: grid;
  gap: 0.75rem;
  grid-template-columns: repeat(auto-fit, minmax(18rem, 1fr));
}

.ct-design-system__specimen,
.ct-design-system__token,
.ct-design-system__example,
.ct-design-system__doc-card {
  display: grid;
  gap: 0.65rem;
  align-content: start;
  min-width: 0;
  padding: 0.85rem;
  border: 1px solid var(--ct-border-soft);
  border-radius: var(--ct-radius-md);
  background: var(--ct-theme-surface-card-strong);
}

.ct-design-system__specimen h3,
.ct-design-system__token h3,
.ct-design-system__example h3,
.ct-design-system__doc-card h3,
.ct-design-system__pipeline-row h3 {
  margin: 0;
  font-family: var(--ct-font-sans);
  font-size: 0.9rem;
  font-weight: 700;
  letter-spacing: 0;
}

.ct-design-system__doc-card-head {
  display: grid;
  gap: 0.35rem;
  min-width: 0;
}

.ct-design-system__doc-card code,
.ct-design-system__pipeline-row code {
  display: inline-flex;
  max-width: 100%;
  padding: 0.2rem 0.35rem;
  border: 1px solid var(--ct-border-soft);
  border-radius: var(--ct-radius-sm);
  background: var(--ct-theme-surface-soft);
  color: var(--ct-theme-text-body);
  font-family: var(--ct-font-mono);
  font-size: 0.7rem;
  line-height: 1.35;
  overflow-wrap: anywhere;
}

.ct-design-system__display-text {
  margin: 0;
  font-family: var(--ct-font-display);
  font-size: clamp(1.45rem, 3vw, 2rem);
  line-height: 1.05;
  color: var(--ct-theme-text-title);
}

.ct-design-system__body-text {
  margin: 0;
  color: var(--ct-theme-text-body);
  font-size: 0.92rem;
  line-height: 1.55;
}

.ct-design-system__meta-text {
  margin: 0;
  color: var(--ct-theme-text-muted);
  font-size: 0.78rem;
  line-height: 1.45;
}

.ct-design-system__pipeline {
  display: grid;
  gap: 0.55rem;
}

.ct-design-system__pipeline-row {
  display: grid;
  gap: 0.7rem;
  align-items: start;
  grid-template-columns: minmax(12rem, 0.42fr) minmax(0, 1fr);
  padding: 0.72rem 0.8rem;
  border: 1px solid var(--ct-border-soft);
  border-radius: var(--ct-radius-md);
  background: var(--ct-theme-surface-card-strong);
}

.ct-design-system__pipeline-row > div {
  display: grid;
  gap: 0.35rem;
  min-width: 0;
}

.ct-design-system__pipeline-row p {
  margin: 0;
  color: var(--ct-theme-text-muted);
  font-size: 0.82rem;
  line-height: 1.45;
}

.ct-design-system__token-head {
  display: flex;
  align-items: center;
  gap: 0.6rem;
  min-width: 0;
}

.ct-design-system__swatch {
  flex: 0 0 auto;
  width: 2.4rem;
  height: 2.4rem;
  border: 1px solid var(--ct-border-soft);
  border-radius: var(--ct-radius-sm);
  background: var(--ct-design-system-swatch);
}

.ct-design-system__swatch[data-swatch='midnight-900'] {
  --ct-design-system-swatch: var(--ct-brand-midnight-900);
}

.ct-design-system__swatch[data-swatch='lake-700'] {
  --ct-design-system-swatch: var(--ct-brand-lake-700);
}

.ct-design-system__swatch[data-swatch='lake-500'] {
  --ct-design-system-swatch: var(--ct-brand-lake-500);
}

.ct-design-system__swatch[data-swatch='sun-400'] {
  --ct-design-system-swatch: var(--ct-brand-sun-400);
}

.ct-design-system__swatch[data-swatch='mint-600'] {
  --ct-design-system-swatch: var(--ct-brand-mint-600);
}

.ct-design-system__swatch[data-swatch='amber-600'] {
  --ct-design-system-swatch: var(--ct-brand-amber-600);
}

.ct-design-system__swatch[data-swatch='rose-600'] {
  --ct-design-system-swatch: var(--ct-brand-rose-600);
}

.ct-design-system__swatch[data-swatch='surface-info'] {
  --ct-design-system-swatch: var(--ct-theme-surface-info);
}

.ct-design-system__token-name {
  margin: 0;
  color: var(--ct-theme-text-title);
  font-size: 0.84rem;
  font-weight: 700;
  line-height: 1.25;
}

.ct-design-system__token-var {
  margin: 0;
  color: var(--ct-theme-text-muted);
  font-family: var(--ct-font-mono);
  font-size: 0.72rem;
  line-height: 1.35;
  overflow-wrap: anywhere;
}

.ct-design-system__code-block {
  display: grid;
  gap: 0.4rem;
  margin: 0;
  min-width: 0;
}

.ct-design-system__code-block figcaption {
  color: var(--ct-theme-text-muted);
  font-size: 0.72rem;
  font-weight: 700;
  letter-spacing: 0.08em;
  text-transform: uppercase;
}

.ct-design-system__code-block pre {
  margin: 0;
  padding: 0.85rem;
  border: 1px solid var(--ct-border-soft);
  border-radius: var(--ct-radius-md);
  background: var(--ct-brand-midnight-950);
  color: var(--ct-theme-text-inverse);
  font-family: var(--ct-font-mono);
  font-size: 0.76rem;
  line-height: 1.5;
  overflow-x: auto;
}

.ct-design-system__code-block code {
  font-family: inherit;
}

.ct-design-system__example-row {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 0.45rem;
}

.ct-design-system__sidebar-toggle-demo .ct-admin-topbar__toggle {
  display: inline-flex;
}

.ct-design-system__example-note {
  margin: 0;
  color: var(--ct-theme-text-muted);
  font-size: 0.78rem;
  line-height: 1.45;
}

.ct-design-system__action-demo {
  display: inline-flex;
  max-width: 100%;
  padding: 0.45rem;
  border: 1px solid var(--ct-border-soft);
  border-radius: var(--ct-radius-md);
  background: var(--ct-theme-surface-soft);
}

.ct-design-system__code-list {
  display: grid;
  gap: 0.4rem;
  margin: 0;
  padding: 0;
  list-style: none;
}

.ct-design-system__code-list code {
  display: inline-flex;
  max-width: 100%;
  padding: 0.22rem 0.38rem;
  border: 1px solid var(--ct-border-soft);
  border-radius: var(--ct-radius-sm);
  background: var(--ct-theme-surface-soft);
  color: var(--ct-theme-text-body);
  font-family: var(--ct-font-mono);
  font-size: 0.72rem;
  overflow-wrap: anywhere;
}

.ct-design-system__table-demo {
  overflow-x: auto;
}

.ct-design-system__table-demo .ct-admin__table {
  min-width: 48rem;
}

@media (max-width: 720px) {
  .ct-design-system {
    padding: 1.25rem 1rem 2rem;
  }

  .ct-design-system__grid {
    grid-template-columns: minmax(0, 1fr);
  }

  .ct-design-system__doc-grid,
  .ct-design-system__pipeline-row {
    grid-template-columns: minmax(0, 1fr);
  }
}
`;

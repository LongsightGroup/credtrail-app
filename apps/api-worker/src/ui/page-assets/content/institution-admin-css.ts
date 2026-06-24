import {
  INSTITUTION_ADMIN_BUTTONS_CSS,
  INSTITUTION_ADMIN_BUTTONS_COARSE_POINTER_CSS,
  INSTITUTION_ADMIN_BUTTONS_RESPONSIVE_CSS,
} from "./institution-admin-buttons-css";
import {
  INSTITUTION_ADMIN_FORMS_CSS,
  INSTITUTION_ADMIN_FORMS_RESPONSIVE_CSS,
} from "./institution-admin-forms-css";
import { INSTITUTION_ADMIN_REPORTING_CSS } from "./institution-admin-reporting-css";
import {
  INSTITUTION_ADMIN_SHELL_COARSE_POINTER_CSS,
  INSTITUTION_ADMIN_SHELL_CSS,
} from "./institution-admin-shell-css";
import {
  INSTITUTION_ADMIN_TABLES_CSS,
  INSTITUTION_ADMIN_TABLES_RESPONSIVE_CSS,
} from "./institution-admin-tables-css";
import {
  INSTITUTION_ADMIN_RULE_BUILDER_CSS,
  INSTITUTION_ADMIN_RULE_BUILDER_RESPONSIVE_CSS,
} from "./institution-admin-rule-builder-css";

export const INSTITUTION_ADMIN_CSS = `
${INSTITUTION_ADMIN_SHELL_CSS}
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
${INSTITUTION_ADMIN_REPORTING_CSS}
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
${INSTITUTION_ADMIN_FORMS_CSS}
${INSTITUTION_ADMIN_RULE_BUILDER_CSS}
${INSTITUTION_ADMIN_BUTTONS_CSS}
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
${INSTITUTION_ADMIN_TABLES_CSS}
/* ── Responsive breakpoints ── */
@media (max-width: 780px) {
${INSTITUTION_ADMIN_FORMS_RESPONSIVE_CSS}
${INSTITUTION_ADMIN_RULE_BUILDER_RESPONSIVE_CSS}
${INSTITUTION_ADMIN_BUTTONS_RESPONSIVE_CSS}
${INSTITUTION_ADMIN_TABLES_RESPONSIVE_CSS}
}
@media (pointer: coarse) {
${INSTITUTION_ADMIN_SHELL_COARSE_POINTER_CSS}
${INSTITUTION_ADMIN_BUTTONS_COARSE_POINTER_CSS}
}
@media (max-width: 1180px) {
  .ct-admin__workspace-grid.ct-grid {
    grid-template-columns: minmax(0, 1fr);
  }

  .ct-admin__builder-sidebar {
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

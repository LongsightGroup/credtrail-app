import {
  INSTITUTION_ADMIN_BUTTONS_CSS,
  INSTITUTION_ADMIN_BUTTONS_RESPONSIVE_CSS,
} from "./institution-admin-buttons-css";
import { INSTITUTION_ADMIN_REPORTING_CSS } from "./institution-admin-reporting-css";
import {
  INSTITUTION_ADMIN_RULE_BUILDER_CSS,
  INSTITUTION_ADMIN_RULE_BUILDER_RESPONSIVE_CSS,
} from "./institution-admin-rule-builder-css";

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
  padding: 0.9rem 1.25rem;
  display: grid;
  gap: 0.28rem;
  align-content: start;
}
.ct-admin-sidebar__section {
  min-width: 0;
  margin: 0;
}
.ct-admin-sidebar__menu,
.ct-admin-sidebar__groups,
.ct-admin-sidebar__menu-sub {
  list-style: none;
  margin: 0;
  padding: 0;
}
.ct-admin-sidebar__menu,
.ct-admin-sidebar__groups {
  display: grid;
  gap: 0.16rem;
}
.ct-admin-sidebar__group {
  min-width: 0;
}
.ct-admin-sidebar__group-details {
  min-width: 0;
}
.ct-admin-sidebar__group-trigger {
  box-sizing: border-box;
  width: 100%;
  min-height: 2.12rem;
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 0.7rem;
  padding: 0 0.35rem 0 0.5rem;
  color: var(--ct-theme-text-body);
  background: transparent;
  border: 1px solid transparent;
  border-radius: var(--ct-radius-sm);
  font: inherit;
  font-size: 0.86rem;
  font-weight: 600;
  text-align: left;
  cursor: pointer;
  list-style: none;
  transition:
    background var(--ct-duration-fast) var(--ct-ease-standard),
    border-color var(--ct-duration-fast) var(--ct-ease-standard),
    color var(--ct-duration-fast) var(--ct-ease-standard);
}
.ct-admin-sidebar__group-trigger::-webkit-details-marker {
  display: none;
}
.ct-admin-sidebar__group-trigger:hover {
  background: var(--ct-theme-surface-soft);
  color: var(--ct-theme-text-title);
}
.ct-admin-sidebar__group-trigger:focus-visible {
  outline: 2px solid var(--ct-theme-border-focus);
  outline-offset: 2px;
}
.ct-admin-sidebar__group-title {
  min-width: 0;
  display: inline-flex;
  align-items: center;
  gap: 0.56rem;
}
.ct-admin-sidebar__group-title span:last-child,
.ct-admin-sidebar__link-label {
  min-width: 0;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.ct-admin-sidebar__nav-icon {
  flex: 0 0 auto;
  width: 1rem;
  height: 1rem;
  color: var(--ct-theme-text-muted);
}
.ct-admin-sidebar__group-trigger:hover .ct-admin-sidebar__nav-icon,
.ct-admin-sidebar__link:hover .ct-admin-sidebar__nav-icon {
  color: var(--ct-theme-text-body);
}
.ct-admin-sidebar__link[aria-current='page'] .ct-admin-sidebar__nav-icon {
  color: var(--ct-brand-lake-700);
}
.ct-admin-sidebar__menu-chevron {
  flex: 0 0 auto;
  width: 0.88rem;
  height: 0.88rem;
  margin-left: auto;
  margin-inline-end: 0.1rem;
  color: var(--ct-theme-text-muted);
  transition: transform var(--ct-duration-fast) var(--ct-ease-standard);
}
.ct-admin-sidebar__group-details[open] .ct-admin-sidebar__menu-chevron {
  transform: rotate(90deg);
}
.ct-admin-sidebar__group--flat .ct-admin-sidebar__link {
  font-weight: 600;
}
.ct-admin-sidebar__group-content {
  margin: 0.18rem 0 0.56rem 0.78rem;
  padding-left: 0.72rem;
  border-left: 1px solid var(--ct-border-soft);
}
.ct-admin-sidebar__link {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  min-height: 2.12rem;
  padding: 0 0.66rem;
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
.ct-admin-sidebar__link:focus-visible {
  outline: 2px solid var(--ct-theme-border-focus);
  outline-offset: 2px;
}
.ct-admin-sidebar__link:hover {
  background: var(--ct-theme-surface-soft);
  color: var(--ct-theme-text-title);
}
.ct-admin-sidebar__link[aria-current='page'] {
  background: var(--ct-theme-surface-info);
  border-color: transparent;
  color: var(--ct-brand-lake-700);
  font-weight: 600;
}
.ct-admin-sidebar__link--nested {
  min-height: 1.96rem;
  padding-inline: 0.72rem;
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
.ct-admin__advanced-tools {
  border: 1px solid var(--ct-border-soft);
  border-radius: var(--ct-radius-lg);
  background: var(--ct-theme-surface-card);
}
.ct-admin__advanced-tools > summary {
  display: flex;
  justify-content: space-between;
  gap: var(--ct-space-3);
  padding: var(--ct-space-4);
  cursor: pointer;
  list-style: none;
}
.ct-admin__advanced-tools > summary::-webkit-details-marker {
  display: none;
}
.ct-admin__advanced-tools > summary span,
.ct-admin__advanced-tools > summary small {
  display: block;
}
.ct-admin__advanced-tools > summary span {
  color: var(--ct-theme-text-title);
  font-size: 1rem;
  font-weight: 600;
}
.ct-admin__advanced-tools > summary small {
  max-width: 64ch;
  color: var(--ct-theme-text-muted);
  font-size: 0.86rem;
  line-height: 1.45;
}
.ct-admin__advanced-tools > .ct-admin__hint {
  margin: 0;
  padding: 0 var(--ct-space-4) var(--ct-space-4);
}
.ct-admin__advanced-tools-body.ct-grid {
  --ct-grid-gap: var(--ct-space-4);
  grid-template-columns: minmax(0, 1fr);
  padding: 0 var(--ct-space-4) var(--ct-space-4);
}
.ct-admin__add-disclosure-form.ct-grid {
  --ct-grid-gap: var(--ct-space-3);
  grid-template-columns: repeat(4, minmax(0, 1fr)) auto;
  align-items: end;
  padding: 0 var(--ct-space-4) var(--ct-space-4);
}
.ct-admin__add-disclosure-form.ct-stack {
  padding: 0 var(--ct-space-4) var(--ct-space-4);
}
.ct-admin__add-disclosure-form--member.ct-grid {
  grid-template-columns: minmax(16rem, 2fr) minmax(10rem, 0.9fr) minmax(12rem, max-content) auto;
}
.ct-admin__add-disclosure-form--api-key.ct-grid {
  grid-template-columns: minmax(14rem, 1fr) minmax(18rem, 1.4fr) auto;
}
.ct-admin__add-disclosure-form--governance.ct-grid {
  grid-template-columns: minmax(0, 44rem);
  align-items: start;
}
.ct-admin__add-disclosure-form--issued-revoke.ct-grid {
  grid-template-columns: minmax(12rem, 0.8fr) minmax(18rem, 1.4fr) auto;
  align-items: end;
}
.ct-admin__add-disclosure-form--template-create.ct-grid {
  grid-template-columns: minmax(0, 44rem);
  align-items: start;
  gap: var(--ct-space-3);
}
.ct-admin__add-disclosure-form--lms-connection {
  grid-template-columns: minmax(0, 44rem);
  align-items: start;
  gap: var(--ct-space-3);
}
.ct-admin__add-disclosure-form--lms-connection.ct-stack {
  max-width: 44rem;
}
.ct-admin__setup-form.ct-grid {
  --ct-grid-gap: var(--ct-space-3);
  grid-template-columns: minmax(0, 44rem);
  align-items: start;
  max-width: 44rem;
}
.ct-admin__setup-form.ct-stack {
  max-width: 44rem;
}
.ct-admin__template-create-field--wide,
.ct-admin__template-create-actions {
  grid-column: 1;
}
.ct-admin__template-create-actions {
  display: flex;
  justify-content: flex-end;
  padding-top: var(--ct-space-1);
}
.ct-admin__template-create-status.ct-admin__status {
  max-width: 44rem;
}
.ct-admin__template-create-next-actions {
  display: grid;
  gap: var(--ct-space-2);
  max-width: 44rem;
  padding: 0 var(--ct-space-4) var(--ct-space-4);
}
.ct-admin__template-create-next-actions[hidden] {
  display: none;
}
.ct-admin__template-create-next-actions p {
  margin: 0;
  color: var(--ct-theme-text-muted);
  font-size: 0.88rem;
}
.ct-admin__template-create-next-action-row {
  display: flex;
  flex-wrap: wrap;
  gap: var(--ct-space-2);
}
.ct-admin__template-create-next-actions[data-artwork-ready='false']
  .ct-admin__template-create-rule-action,
.ct-admin__template-create-next-actions[data-artwork-ready='false']
  .ct-admin__template-create-public-action {
  display: none;
}
.ct-admin__add-disclosure-form--template-create textarea {
  min-height: 6.75rem;
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
  grid-template-columns: minmax(0, 44rem);
  align-items: start;
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
.ct-admin__field {
  --ct-stack-gap: 0.28rem;
  display: grid;
  gap: 0.28rem;
  font-size: 0.88rem;
  font-weight: 600;
  color: var(--ct-color-ink);
}
.ct-admin__field-hint {
  color: var(--ct-theme-text-subtle);
  font-size: 0.78rem;
  line-height: 1.35;
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
.ct-admin__builder-clone select,
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
.ct-admin__builder-clone select,
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
.ct-admin__builder-clone select:focus,
.ct-admin__form textarea:focus,
.ct-admin__table select:focus:focus:focus:focus {
  outline: none;
  border-color: var(--ct-theme-border-focus);
  box-shadow: var(--ct-focus-ring);
}
.ct-admin__form input:not([type='checkbox']):user-invalid,
.ct-admin__form select:user-invalid,
.ct-admin__builder-clone select:user-invalid,
.ct-admin__form textarea:user-invalid,
.ct-admin__form input:not([type='checkbox']).user-invalid-fallback,
.ct-admin__form select.user-invalid-fallback,
.ct-admin__builder-clone select.user-invalid-fallback,
.ct-admin__form textarea.user-invalid-fallback:user-invalid:user-invalid:user-invalid.user-invalid-fallback.user-invalid-fallback.user-invalid-fallback {
  border-color: var(--ct-theme-state-danger);
  background: var(--ct-theme-surface-danger);
}
.ct-admin__form select:disabled,
.ct-admin__table select:disabled:disabled {
  cursor: not-allowed;
  opacity: 0.68;
}
.ct-admin__form textarea {
  min-height: 5.5rem;
  resize: vertical;
  font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
  font-size: 0.84rem;
  line-height: 1.35;
}
.ct-admin__template-editor-body .ct-admin__template-editor-prose-textarea {
  font-family: var(--ct-font-sans);
  font-size: 0.92rem;
  line-height: 1.45;
}
.ct-admin__template-editor-body input[type='file'] {
  width: 100%;
  border: 1px dashed var(--ct-border-soft);
  border-radius: var(--ct-radius-md);
  padding: 0.55rem 0.72rem;
  background: var(--ct-theme-surface-soft);
  font-size: 0.86rem;
  min-height: auto;
}
${INSTITUTION_ADMIN_RULE_BUILDER_CSS}
.ct-admin__checkbox-row {
  font-size: 0.92rem;
}
.ct-admin__checkbox-row input[type='checkbox'] {
  margin: 0;
}
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
.ct-admin__inline-action-panel {
  padding: var(--ct-space-4);
  border: 1px solid var(--ct-border-soft);
  border-radius: var(--ct-radius-md);
  background: var(--ct-theme-surface-raised);
}
.ct-admin__inline-action-panel[hidden] {
  display: none;
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
.ct-admin__table .ct-admin__rule-name-link {
  display: inline;
  min-height: 0;
  color: var(--ct-theme-text-title);
  text-decoration-thickness: 1px;
  text-underline-offset: 0.18em;
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
.ct-admin__status-pill--pending_approval,
.ct-admin__status-pill--warning {
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
.ct-admin__template-primary-action {
  font-weight: 700;
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
  background: var(--ct-theme-surface-soft);
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
.ct-admin__history-dialog {
  width: min(42rem, calc(100vw - 2rem));
  max-height: calc(100vh - 2rem);
  border: 1px solid var(--ct-border-soft);
  border-radius: var(--ct-radius-lg);
  padding: 0;
  background: var(--ct-theme-surface-card-strong);
  color: var(--ct-theme-text-body);
  box-shadow: var(--ct-shadow-shell);
}
.ct-admin__history-dialog::backdrop {
  background: rgba(15, 23, 42, 0.45);
}
.ct-admin__history-dialog-surface {
  display: grid;
  gap: var(--ct-space-3);
  padding: var(--ct-space-4);
  margin: 0;
  border: 0;
  background: var(--ct-theme-surface-card-strong);
}
.ct-admin__history-dialog-header {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: var(--ct-space-3);
}
.ct-admin__history-dialog-header h2 {
  margin: 0;
  font-size: 1.15rem;
}
.ct-admin__history-audit-list {
  display: grid;
  gap: var(--ct-space-2);
  max-height: 18rem;
  overflow: auto;
}
.ct-admin__history-audit-item {
  display: grid;
  gap: 0.2rem;
  border: 1px solid var(--ct-border-soft);
  border-radius: var(--ct-radius-md);
  padding: var(--ct-space-2) var(--ct-space-3);
  background: var(--ct-theme-surface-soft);
}
.ct-admin__history-audit-meta {
  color: var(--ct-theme-text-muted);
  font-size: 0.84rem;
}
.ct-admin__history-audit-detail {
  margin: 0;
  color: var(--ct-theme-text-body);
  font-size: 0.88rem;
  overflow-wrap: anywhere;
}
.ct-admin__history-image-section {
  border: 1px solid var(--ct-border-soft);
  border-radius: var(--ct-radius-md);
  padding: 0 var(--ct-space-3) var(--ct-space-3);
  background: var(--ct-theme-surface-info);
}
.ct-admin__history-image-section > summary {
  cursor: pointer;
  font-weight: 600;
  padding: var(--ct-space-3) 0;
}
.ct-admin__history-image-section .ct-admin__image-revision-list {
  padding: 0;
}
button.ct-admin__text-action {
  background: none;
  border: 0;
  padding: 0;
  font: inherit;
  cursor: pointer;
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
  background: var(--ct-theme-surface-card-strong);
}
.ct-admin__image-revision-meta {
  display: grid;
  gap: 0.15rem;
  min-width: 0;
  flex: 1;
}
.ct-admin__image-revision-meta span {
  color: var(--ct-theme-text-muted);
  font-size: 0.84rem;
}
.ct-admin__image-revision-thumbnail {
  width: 2.6rem;
  height: 2.6rem;
  border: 1px solid var(--ct-border-soft);
  border-radius: var(--ct-radius-sm);
  object-fit: cover;
  background: var(--ct-theme-surface-soft);
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
/* ── Responsive breakpoints ── */
@media (max-width: 780px) {
  .ct-admin__form--inline.ct-grid,
  .ct-admin__add-disclosure-form.ct-grid,
${INSTITUTION_ADMIN_RULE_BUILDER_RESPONSIVE_CSS}

  .ct-admin__add-disclosure-summary {
    align-items: flex-start;
    flex-direction: row;
  }

  .ct-admin__add-disclosure-control {
    flex: 0 0 auto;
  }

  .ct-admin__add-disclosure-control,
  .ct-admin__table select {
    min-height: 2.75rem;
  }

${INSTITUTION_ADMIN_BUTTONS_RESPONSIVE_CSS}

  .ct-admin__image-revision-item {
    align-items: flex-start;
    flex-wrap: wrap;
  }
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

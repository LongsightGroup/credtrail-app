export const INSTITUTION_ADMIN_SHELL_CSS = `
/* ── Admin shell layout ── */
.ct-admin-shell {
  display: grid;
  grid-template-columns: 16rem minmax(0, 1fr);
  min-height: 100vh;
}
.ct-admin-sidebar {
  position: sticky;
  top: 0;
  height: 100vh;
  overflow-y: auto;
  overscroll-behavior: contain;
  scrollbar-gutter: stable;
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
  display: grid;
  grid-template-columns: auto minmax(0, 1fr) auto;
  align-items: center;
  gap: 1rem;
  padding: 0.6rem 1.5rem;
  border-bottom: 1px solid var(--ct-border-soft);
  background: rgba(255, 255, 255, 0.96);
  position: sticky;
  top: 0;
  z-index: 10;
  backdrop-filter: saturate(1.1) blur(10px);
}
.ct-admin-topbar__title {
  margin: 0;
  font-family: var(--ct-font-sans);
  font-size: 0.88rem;
  font-weight: 600;
  color: var(--ct-theme-text-title);
  min-width: 0;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.ct-admin-topbar__user {
  display: flex;
  align-items: center;
  justify-content: flex-end;
  gap: 0.5rem;
  min-width: 0;
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
  box-sizing: border-box;
  width: min(100%, 1200px);
  margin-inline: auto;
  padding: clamp(1.5rem, 2.2vw, 2.5rem);
}
.ct-admin-page-header {
  margin-bottom: 1.5rem;
}
.ct-admin-page-header h1 {
  margin: 0 0 0.35rem;
  font-size: 1.45rem;
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
@media (max-width: 900px) {
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
    inset-inline-start: 0;
    width: 16rem;
    height: 100dvh;
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
    grid-template-columns: auto minmax(0, 1fr) minmax(0, auto);
    min-width: 0;
    gap: 0.65rem;
    padding-inline: 1rem;
    box-shadow: 0 1px 0 rgba(13, 46, 84, 0.04);
  }
  .ct-admin-topbar__title {
    max-width: none;
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
    padding: 1.15rem 1rem 2rem;
    max-width: 100%;
    box-sizing: border-box;
  }
}

@media (max-width: 520px) {
  .ct-admin-topbar {
    gap: 0.5rem;
    padding-inline: 0.75rem;
  }

  .ct-admin-topbar__chip {
    display: none;
  }

  .ct-admin-page-header {
    margin-bottom: 1rem;
  }

  .ct-admin-page-header h1 {
    font-size: 1.25rem;
  }
}

`;

export const INSTITUTION_ADMIN_SHELL_COARSE_POINTER_CSS = `
  .ct-admin-sidebar__group-trigger,
  .ct-admin-sidebar__link {
    min-height: 2.75rem;
  }
`;

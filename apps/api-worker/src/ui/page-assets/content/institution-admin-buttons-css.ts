export const INSTITUTION_ADMIN_BUTTONS_CSS = `
.ct-admin__button {
  justify-self: start;
}
@media (hover: hover) {
  .ct-admin__action-menu-item:hover {
    transform: translateY(-1px);
  }

  .ct-admin__action-menu-item:hover {
    background: var(--ct-theme-surface-info);
  }

  .ct-admin__action-menu-item--danger:hover {
    background: var(--ct-theme-surface-danger);
  }

}
.ct-admin__action-menu-item:focus-visible {
  outline: 2px solid var(--ct-theme-border-focus);
  outline-offset: 2px;
}
.ct-admin__action-menu-item:active {
  transform: translateY(0);
}

.ct-admin__actions .ct-admin__button,
.ct-admin__actions .ct-admin__cta-link {
  border-radius: var(--ct-radius-sm);
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
  box-shadow: none;
  user-select: none;
}
.ct-admin__icon-button {
  display: inline-flex;
  box-sizing: border-box;
  appearance: none;
  align-items: center;
  justify-content: center;
  padding: 0;
  border: none;
  background: transparent;
  color: var(--ct-theme-text-muted);
  font-family: var(--ct-font-sans);
  cursor: pointer;
}
.ct-admin__action-menu-trigger {
  min-width: 2.15rem;
  width: 2.15rem;
  height: 2.15rem;
  min-height: 2.15rem;
  font-size: 1.25rem;
  line-height: 1;
  border-radius: var(--ct-radius-md);
  transition:
    background var(--ct-duration-fast) var(--ct-ease-standard),
    color var(--ct-duration-fast) var(--ct-ease-standard);
}
.ct-admin__action-menu-trigger:hover {
  background: var(--ct-theme-surface-info);
  color: var(--ct-theme-text-body);
}
.ct-admin__action-menu-trigger:focus-visible {
  outline: 2px solid var(--ct-theme-border-focus);
  outline-offset: 1px;
  box-shadow: none;
}
.ct-admin__issued-actions .ct-admin__button:focus-visible {
  outline-offset: 1px;
  box-shadow: none;
}
.ct-admin__action-menu {
  position: relative;
  display: inline-flex;
  align-items: center;
}
.ct-admin__action-menu-trigger[aria-expanded='true'],
.ct-admin__action-menu:has(.ct-admin__action-menu-popover[data-open='true']) .ct-admin__action-menu-trigger {
  background: var(--ct-theme-surface-info);
}
.ct-admin__action-menu-popover {
  position: fixed;
  inset: auto;
  z-index: 20;
  display: grid;
  margin: 0;
  gap: 0.18rem;
  min-width: 11rem;
  padding: 0.32rem;
  border: 1px solid var(--ct-border-strong);
  border-radius: var(--ct-radius-md);
  background: var(--ct-theme-surface-card-strong);
  box-shadow: var(--ct-shadow-soft);
}
.ct-admin__action-menu-popover[hidden] {
  display: none;
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
  align-items: center;
  justify-content: flex-start;
  justify-self: start;
  gap: 0.45rem;
}
.ct-admin__table .ct-admin__actions {
  flex-wrap: nowrap;
  align-items: center;
  gap: 0.32rem;
  white-space: nowrap;
}
.ct-admin__actions--end {
  justify-content: flex-end;
  justify-self: end;
  flex: 0 0 auto;
}
`;

export const INSTITUTION_ADMIN_BUTTONS_RESPONSIVE_CSS = `
  .ct-admin__builder-inline > .ct-admin__button,
  .ct-admin__builder-toolbar .ct-admin__button,
  .ct-admin__builder-step-nav .ct-admin__button,
  .ct-admin__builder-step-nav #rule-builder-submit {
    width: 100%;
  }

  .ct-admin__actions--end {
    width: 100%;
    justify-content: flex-start;
    justify-self: stretch;
  }
`;

export const INSTITUTION_ADMIN_BUTTONS_COARSE_POINTER_CSS = `
  .ct-admin__cta-link {
    min-height: 2.75rem;
  }

  .ct-admin__issued-actions .ct-admin__button {
    height: auto;
    max-height: none;
  }
`;

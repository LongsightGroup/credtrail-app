export const INSTITUTION_ADMIN_TABLES_CSS = `
.ct-admin__inline-action-panel {
  padding: var(--ct-space-4);
  border: 1px solid var(--ct-border-soft);
  border-radius: var(--ct-radius-md);
  background: var(--ct-theme-surface-card-strong);
}
.ct-admin__inline-action-panel[hidden] {
  display: none;
}
.ct-admin__table-wrap {
  overflow: auto;
  overscroll-behavior-inline: contain;
  scrollbar-gutter: stable;
  -webkit-overflow-scrolling: touch;
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
  padding: 0.68rem 0.62rem;
  vertical-align: top;
  font-size: 0.88rem;
}
.ct-admin__table th {
  background: var(--ct-theme-surface-card-strong);
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
  padding: 1.4rem 0.8rem;
}
.ct-admin__meta {
  color: var(--ct-color-ink-soft);
  font-size: 0.82rem;
}
.ct-admin__status-pill {
  display: inline-flex;
  align-items: center;
  min-height: 1.45rem;
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
.ct-admin__image-fallback-frame {
  display: inline-grid;
  place-items: center;
}
.ct-admin__image-fallback-frame [hidden] {
  display: none;
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
  display: block;
  width: 3.2rem;
  height: 3.2rem;
  border-radius: var(--ct-radius-sm);
  object-fit: cover;
  border: 1px solid var(--ct-border-strong);
  background: var(--ct-theme-surface-soft);
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
  display: block;
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
  padding: 1rem;
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
`;

export const INSTITUTION_ADMIN_TABLES_RESPONSIVE_CSS = `
  .ct-admin__table select {
    min-height: 2.75rem;
  }

  .ct-admin__panel {
    padding: 0.85rem;
  }

  .ct-admin__panel--table {
    padding: 0.7rem;
  }

  .ct-admin__table th,
  .ct-admin__table td {
    padding: 0.72rem 0.65rem;
  }

  .ct-admin__image-revision-item {
    align-items: flex-start;
    flex-wrap: wrap;
  }
`;

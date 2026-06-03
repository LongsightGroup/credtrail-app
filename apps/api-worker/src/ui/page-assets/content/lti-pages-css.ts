export const LTI_PAGES_CSS = `
.lti-launch {
  display: grid;
  gap: var(--ct-space-4);
  max-width: 58rem;
}

.lti-launch__sr-only {
  position: absolute;
  width: 1px;
  height: 1px;
  padding: 0;
  margin: -1px;
  overflow: hidden;
  clip: rect(0, 0, 0, 0);
  white-space: nowrap;
  border: 0;
}

.lti-launch__hero {
  border: 1px solid var(--ct-border-soft);
  border-radius: var(--ct-radius-lg);
  padding: var(--ct-space-4);
  background: var(--ct-theme-gradient-hero);
  color: var(--ct-theme-text-on-brand);
}

.lti-launch__hero h1 {
  margin: 0;
  color: var(--ct-theme-text-on-brand);
}

.lti-launch__hero p {
  margin: 0.25rem 0 0 0;
  color: var(--ct-theme-text-inverse);
}

.lti-launch__card {
  border: 1px solid var(--ct-border-soft);
  border-radius: var(--ct-radius-lg);
  padding: var(--ct-space-4);
  background: var(--ct-theme-surface-card-strong);
  box-shadow: var(--ct-shadow-soft);
}

.lti-launch__card--stack {
  display: grid;
  gap: 0.45rem;
}

.lti-launch__hint {
  margin: 0;
  color: var(--ct-theme-text-muted);
}

.lti-launch__link-row {
  margin: 0;
}

.lti-launch__section-head {
  display: grid;
  gap: 0.28rem;
}

.lti-launch__details {
  margin: 0;
  display: grid;
  grid-template-columns: minmax(12rem, max-content) 1fr;
  gap: 0.45rem 0.8rem;
}

.lti-launch__details dt {
  font-weight: 600;
  color: var(--ct-theme-text-title);
}

.lti-launch__details dd {
  margin: 0;
  overflow-wrap: anywhere;
  color: var(--ct-theme-text-muted);
}

.lti-launch__technical-details {
  border: 1px solid var(--ct-border-soft);
  border-radius: var(--ct-radius-md);
  padding: 0.88rem 1rem;
  background: var(--ct-theme-surface-soft);
}

.lti-launch__technical-details summary {
  cursor: pointer;
  font-weight: 600;
  color: var(--ct-theme-text-body);
}

.lti-launch__technical-details .lti-launch__details {
  margin-top: 0.85rem;
}

.lti-launch__bulk-title {
  margin: 0;
  font-size: 1.06rem;
}

.lti-launch__bulk-status {
  margin: 0;
  padding: 0.55rem 0.68rem;
  border-radius: 0.68rem;
  border: 1px solid var(--ct-theme-border-info);
  color: var(--ct-theme-text-body);
  background: var(--ct-theme-surface-info);
}

.lti-launch__bulk-status--ready {
  border-color: var(--ct-theme-border-success);
  background: var(--ct-theme-surface-success);
  color: var(--ct-theme-state-success);
}

.lti-launch__bulk-status--error {
  border-color: var(--ct-theme-border-danger);
  background: var(--ct-theme-surface-danger);
  color: var(--ct-theme-state-danger);
}

.lti-launch__bulk-status--unavailable {
  border-color: var(--ct-theme-border-warning);
  background: var(--ct-theme-surface-warning);
  color: var(--ct-theme-state-warning);
}

.lti-launch__bulk-meta {
  margin: 0;
  display: grid;
  grid-template-columns: minmax(12rem, max-content) 1fr;
  gap: 0.35rem 0.7rem;
}

.lti-launch__bulk-meta dt {
  font-weight: 600;
  color: var(--ct-theme-text-title);
}

.lti-launch__bulk-meta dd {
  margin: 0;
  color: var(--ct-theme-text-muted);
  overflow-wrap: anywhere;
}

.lti-launch__bulk-table-wrap {
  overflow: auto;
}

.lti-launch__bulk-form {
  display: grid;
  gap: var(--ct-space-3);
}

.lti-launch__bulk-actions {
  display: flex;
  align-items: center;
  justify-content: flex-end;
  gap: var(--ct-space-3);
  flex-wrap: wrap;
}

.lti-launch__bulk-table {
  width: 100%;
  border-collapse: collapse;
  font-size: 0.9rem;
}

.lti-launch__bulk-table th {
  text-align: left;
  padding: 0.44rem 0.5rem;
  border-bottom: 1px solid var(--ct-border-soft);
  color: var(--ct-theme-text-body);
}

.lti-launch__bulk-table td {
  padding: 0.44rem 0.5rem;
  vertical-align: top;
  border-bottom: 1px solid var(--ct-border-soft);
  color: var(--ct-theme-text-muted);
}

.lti-launch__bulk-empty {
  color: var(--ct-theme-text-muted);
}

.lti-launch__course-summary {
  display: grid;
  gap: var(--ct-space-3);
}

.lti-launch__bulk-meta--summary {
  grid-template-columns: repeat(auto-fit, minmax(8rem, 1fr));
  gap: 0.75rem;
}

.lti-launch__bulk-meta--summary dt {
  font-size: 0.84rem;
}

.lti-launch__bulk-meta--summary dd {
  color: var(--ct-theme-text-title);
  font-weight: 700;
}

.lti-launch__summary-controls {
  display: grid;
  grid-template-columns: minmax(14rem, 1fr) minmax(10rem, 0.6fr) minmax(9rem, 0.5fr) auto;
  gap: 0.75rem;
  align-items: end;
}

.lti-launch__summary-field {
  display: grid;
  gap: 0.3rem;
  color: var(--ct-theme-text-title);
  font-weight: 600;
}

.lti-launch__summary-field input,
.lti-launch__summary-field select {
  min-height: 2.5rem;
  border: 1px solid var(--ct-border-soft);
  border-radius: var(--ct-radius-sm);
  padding: 0.5rem 0.68rem;
  color: var(--ct-theme-text-body);
  background: var(--ct-theme-surface-card-strong);
  font: inherit;
}

.lti-launch__summary-count {
  margin: 0;
  color: var(--ct-theme-text-muted);
  white-space: nowrap;
}

.lti-launch__summary-table caption {
  text-align: left;
  padding: 0 0 0.5rem;
  color: var(--ct-theme-text-muted);
}

.lti-launch__status-pill {
  display: inline-flex;
  align-items: center;
  min-height: 1.55rem;
  border: 1px solid var(--ct-theme-border-info);
  border-radius: 999px;
  padding: 0.16rem 0.52rem;
  background: var(--ct-theme-surface-info);
  color: var(--ct-theme-text-body);
  font-size: 0.84rem;
  font-weight: 700;
  white-space: nowrap;
}

.lti-launch__status-pill--issued {
  border-color: var(--ct-theme-border-success);
  background: var(--ct-theme-surface-success);
  color: var(--ct-theme-state-success);
}

.lti-launch__status-pill--not_issued {
  border-color: var(--ct-border-soft);
  background: var(--ct-theme-surface-soft);
  color: var(--ct-theme-text-muted);
}

.lti-launch__status-pill--suspended,
.lti-launch__status-pill--expired {
  border-color: var(--ct-theme-border-warning);
  background: var(--ct-theme-surface-warning);
  color: var(--ct-theme-state-warning);
}

.lti-launch__status-pill--revoked {
  border-color: var(--ct-theme-border-danger);
  background: var(--ct-theme-surface-danger);
  color: var(--ct-theme-state-danger);
}

.lti-launch__status-stack {
  display: grid;
  gap: 0.22rem;
  justify-items: start;
}

.lti-launch__summary-timestamp,
.lti-launch__summary-status-detail {
  color: var(--ct-theme-text-muted);
  font-size: 0.82rem;
  line-height: 1.35;
}

.lti-launch__summary-status-detail {
  max-width: 22rem;
}

@media (max-width: 760px) {
  .lti-launch__summary-controls {
    grid-template-columns: 1fr;
  }
}

.lti-deep-link {
  display: grid;
  gap: var(--ct-space-4);
  max-width: 64rem;
}

.lti-deep-link__hero {
  border: 1px solid var(--ct-border-soft);
  border-radius: var(--ct-radius-lg);
  padding: var(--ct-space-4);
  background: var(--ct-theme-gradient-hero);
  color: var(--ct-theme-text-on-brand);
}

.lti-deep-link__hero h1 {
  margin: 0;
  color: var(--ct-theme-text-on-brand);
}

.lti-deep-link__hero p {
  margin: 0.3rem 0 0 0;
  color: var(--ct-theme-text-inverse);
}

.lti-deep-link__details {
  margin: 0;
  display: grid;
  grid-template-columns: minmax(11rem, max-content) 1fr;
  gap: 0.35rem 0.7rem;
}

.lti-deep-link__details dt {
  font-weight: 600;
}

.lti-deep-link__details dd {
  margin: 0;
  overflow-wrap: anywhere;
}

.lti-deep-link__details-card {
  border: 1px solid var(--ct-border-soft);
  border-radius: var(--ct-radius-md);
  padding: 0.9rem;
  background: var(--ct-theme-surface-card);
}

.lti-deep-link__options {
  display: grid;
  gap: var(--ct-space-3);
}

.lti-deep-link__option {
  border: 1px solid var(--ct-border-soft);
  border-radius: var(--ct-radius-md);
  padding: 0.9rem;
  background: var(--ct-theme-surface-card-strong);
  box-shadow: var(--ct-shadow-soft);
  display: grid;
  gap: 0.4rem;
}

.lti-deep-link__option h2 {
  margin: 0;
  font-size: 1.08rem;
}

.lti-deep-link__meta,
.lti-deep-link__description {
  margin: 0;
  color: var(--ct-theme-text-muted);
  overflow-wrap: anywhere;
}

.lti-deep-link__form {
  margin-top: 0.25rem;
}

.lti-deep-link__form button {
  border: none;
  border-radius: var(--ct-radius-md);
  padding: 0.5rem 0.9rem;
  font-weight: 700;
  color: var(--ct-theme-text-on-brand);
  background: var(--ct-theme-gradient-action);
  cursor: pointer;
}

.lti-deep-link__notice {
  margin: 0;
  padding: 0.75rem;
  border-radius: 0.7rem;
  border: 1px solid var(--ct-theme-border-warning);
  background: var(--ct-theme-surface-warning);
  color: var(--ct-theme-state-warning);
}

.lti-deep-link__empty {
  margin: 0;
  color: var(--ct-theme-text-muted);
}

.lti-registration {
  display: grid;
  gap: var(--ct-space-4);
  max-width: 64rem;
}

.lti-registration__title,
.lti-registration__lede {
  margin: 0;
}

.lti-registration__lede {
  color: var(--ct-theme-text-muted);
}

.lti-registration__error {
  margin: 0;
  padding: 0.75rem;
  border: 1px solid var(--ct-theme-border-danger);
  background: var(--ct-theme-surface-danger);
  color: var(--ct-theme-state-danger);
}

.lti-registration__form {
  display: grid;
  gap: 0.75rem;
  padding: 1rem;
  border: 1px solid var(--ct-border-soft);
  border-radius: 0.5rem;
  background: var(--ct-theme-surface-card);
}

.lti-registration__field {
  display: grid;
  gap: 0.35rem;
}

.lti-registration__checkbox {
  display: flex;
  gap: 0.5rem;
  align-items: center;
}

.lti-registration__actions {
  display: flex;
  gap: 0.5rem;
}

.lti-registration__table-wrap {
  overflow: auto;
}

.lti-registration__table {
  width: 100%;
  border-collapse: collapse;
}

.lti-registration__table th {
  text-align: left;
  padding: 0.5rem;
  border-bottom: 1px solid var(--ct-border-soft);
}

.lti-registration__table td {
  padding: 0.5rem;
  vertical-align: top;
}

.lti-registration__wrap-anywhere {
  word-break: break-word;
}

.lti-registration__empty {
  padding: 0.75rem;
}
`;

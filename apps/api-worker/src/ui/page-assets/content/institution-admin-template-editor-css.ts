export const INSTITUTION_ADMIN_TEMPLATE_EDITOR_CSS = `
.ct-admin__template-editor-identity-form {
  display: none;
}
.ct-admin__template-editor-overview {
  display: grid;
  grid-template-columns: clamp(8rem, 18vw, 12rem) minmax(0, 1fr);
  gap: var(--ct-space-4);
  align-items: center;
}
.ct-admin__template-editor-preview {
  box-sizing: border-box;
  display: grid;
  place-items: center;
  width: 100%;
  aspect-ratio: 1;
  border: 1px solid var(--ct-border-subtle);
  border-radius: var(--ct-radius-lg);
  padding: var(--ct-space-3);
  background: var(--ct-theme-surface-soft);
}
.ct-admin__template-editor-preview a,
.ct-admin__template-editor-preview img {
  display: block;
  width: 100%;
  height: 100%;
}
.ct-admin__template-editor-preview img {
  box-sizing: border-box;
  object-fit: contain;
  border-radius: var(--ct-radius-md);
  padding: clamp(0.75rem, 7%, 1.2rem);
  background: var(--ct-theme-surface-card-strong);
}
.ct-admin__template-editor-preview-empty {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  width: 100%;
  height: 100%;
  border: 1px dashed var(--ct-border-strong);
  border-radius: var(--ct-radius-md);
  color: var(--ct-theme-text-muted);
  font-size: 0.84rem;
  font-weight: 700;
  text-align: center;
  background: var(--ct-theme-surface-card-strong);
}
.ct-admin__template-editor-summary {
  min-width: 0;
  display: grid;
  gap: var(--ct-space-3);
  padding: var(--ct-space-3) var(--ct-space-3) var(--ct-space-3) 0;
}
.ct-admin__template-editor-title-row {
  display: flex;
  flex-wrap: wrap;
  gap: var(--ct-space-2);
  align-items: center;
  margin-bottom: var(--ct-space-1);
}
.ct-admin__template-editor-summary h2 {
  margin: 0;
  color: var(--ct-theme-text-title);
  font-size: 1.15rem;
  line-height: 1.25;
}
.ct-admin__template-editor-summary p,
.ct-admin__template-editor-page-panel > p {
  max-width: 68ch;
  margin: 0;
  color: var(--ct-theme-text-muted);
  font-size: 0.9rem;
  line-height: 1.5;
  overflow-wrap: anywhere;
}
.ct-admin__template-editor-summary-actions {
  display: flex;
  flex-wrap: wrap;
  gap: var(--ct-space-2);
  align-items: center;
  min-width: 0;
}
.ct-admin__template-editor-page-panel {
  display: grid;
  gap: var(--ct-space-3);
}
.ct-admin__template-editor-body {
  display: grid;
  gap: var(--ct-space-4);
  max-width: 58rem;
  padding: 0;
}
.ct-admin__template-editor-subform {
  display: grid;
  gap: var(--ct-space-2);
}
.ct-admin__template-editor-section {
  display: grid;
  gap: var(--ct-space-3);
}
.ct-admin__template-editor-section--artwork {
  gap: var(--ct-space-4);
}
.ct-admin__template-editor-current-artwork {
  display: grid;
  grid-template-columns: 4.75rem minmax(0, 1fr);
  gap: var(--ct-space-3);
  align-items: center;
  max-width: 42rem;
}
.ct-admin__template-editor-current-artwork a,
.ct-admin__template-editor-current-artwork img,
.ct-admin__template-editor-current-artwork-empty {
  display: block;
  width: 100%;
  aspect-ratio: 1;
}
.ct-admin__template-editor-current-artwork img {
  box-sizing: border-box;
  object-fit: contain;
  border: 1px solid var(--ct-border-subtle);
  border-radius: var(--ct-radius-sm);
  padding: 0.45rem;
  background: var(--ct-theme-surface-card-strong);
}
.ct-admin__template-editor-current-artwork-empty {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  border: 1px dashed var(--ct-border-strong);
  border-radius: var(--ct-radius-sm);
  color: var(--ct-theme-text-muted);
  font-size: 0.78rem;
  font-weight: 700;
  text-align: center;
  background: var(--ct-theme-surface-card-strong);
}
.ct-admin__template-editor-current-artwork strong {
  display: block;
  color: var(--ct-theme-text-title);
  font-size: 0.88rem;
  line-height: 1.3;
}
.ct-admin__template-editor-current-artwork p {
  max-width: 56ch;
  margin: 0.14rem 0 0;
  color: var(--ct-theme-text-muted);
  font-size: 0.82rem;
  line-height: 1.45;
}
.ct-admin__template-editor-artwork-status-row {
  display: flex;
  flex-wrap: wrap;
  gap: var(--ct-space-2);
  align-items: center;
}
.ct-admin__template-editor-artwork-actions {
  display: grid;
  max-width: 48rem;
  border: 1px solid var(--ct-border-subtle);
  border-radius: var(--ct-radius-md);
  background: var(--ct-theme-surface-card-strong);
}
.ct-admin__template-editor-artwork-actions-summary {
  display: flex;
  gap: var(--ct-space-3);
  align-items: center;
  justify-content: space-between;
  padding: 0.82rem 0.92rem;
  cursor: pointer;
}
.ct-admin__template-editor-artwork-actions-summary::-webkit-details-marker {
  display: none;
}
.ct-admin__template-editor-artwork-actions-summary strong,
.ct-admin__template-editor-artwork-actions-summary small {
  display: block;
}
.ct-admin__template-editor-artwork-actions-summary strong {
  color: var(--ct-theme-text-title);
  font-size: 0.9rem;
  line-height: 1.3;
}
.ct-admin__template-editor-artwork-actions-summary small {
  margin-top: 0.12rem;
  color: var(--ct-theme-text-muted);
  font-size: 0.78rem;
  line-height: 1.35;
}
.ct-admin__template-editor-artwork-actions-control {
  flex: 0 0 auto;
  border: 1px solid var(--ct-border-subtle);
  border-radius: var(--ct-radius-sm);
  padding: 0.42rem 0.58rem;
  color: var(--ct-theme-link);
  font-size: 0.78rem;
  font-weight: 700;
  line-height: 1;
  background: var(--ct-theme-surface-soft);
}
.ct-admin__template-editor-artwork-actions-close {
  display: none;
}
.ct-admin__template-editor-artwork-actions[open]
  .ct-admin__template-editor-artwork-actions-open {
  display: none;
}
.ct-admin__template-editor-artwork-actions[open]
  .ct-admin__template-editor-artwork-actions-close {
  display: inline;
}
.ct-admin__template-editor-artwork-action-grid {
  display: grid;
  gap: var(--ct-space-3);
  padding: 0 var(--ct-space-3) var(--ct-space-3);
}
.ct-admin__template-editor-artwork-option {
  display: grid;
  gap: var(--ct-space-2);
  border-top: 1px solid var(--ct-border-subtle);
  padding-top: var(--ct-space-3);
}
.ct-admin__template-editor-subgroup {
  display: grid;
  gap: var(--ct-space-2);
}
.ct-admin__template-editor-subgroup-title {
  margin: 0;
  color: var(--ct-theme-text-title);
  font-size: 0.86rem;
  font-weight: 700;
  line-height: 1.25;
}
.ct-admin__template-editor-divider {
  width: 100%;
  margin: 0;
  border: none;
  border-top: 1px dashed var(--ct-border-subtle);
}
.ct-admin__template-editor-section-header {
  display: grid;
  gap: 0.18rem;
}
.ct-admin__template-editor-section-header h2 {
  margin: 0;
  color: var(--ct-theme-text-title);
  font-size: 0.98rem;
  line-height: 1.25;
}
.ct-admin__template-editor-section-header p {
  max-width: 64ch;
  margin: 0;
  color: var(--ct-theme-text-muted);
  font-size: 0.84rem;
  line-height: 1.45;
}
.ct-admin__template-editor-fields {
  display: grid;
  grid-template-columns: minmax(0, 1fr);
  gap: var(--ct-space-3);
  align-items: end;
}
.ct-admin__template-editor-fields--generation {
  grid-template-columns: minmax(13rem, 1fr) minmax(13rem, 1fr);
  align-items: end;
}
.ct-admin__template-editor-fields--upload {
  grid-template-columns: minmax(0, 1fr) auto;
  align-items: end;
  gap: var(--ct-space-3);
}
.ct-admin__template-editor-generation-prompt,
.ct-admin__template-editor-generation-action {
  grid-column: 1 / -1;
}
.ct-admin__template-editor-generation-action {
  display: flex;
  justify-content: flex-start;
}
.ct-admin__template-editor-advanced {
  display: grid;
  gap: var(--ct-space-2);
}
.ct-admin__template-editor-advanced > summary {
  color: var(--ct-theme-link);
  font-size: 0.84rem;
  font-weight: 700;
  cursor: pointer;
}
.ct-admin__template-editor-advanced > .ct-admin__field {
  margin-top: var(--ct-space-2);
}
.ct-admin__template-editor-submit {
  display: flex;
  justify-content: flex-start;
}
.ct-admin__template-editor-meta-list {
  display: grid;
  gap: var(--ct-space-2);
  margin: 0;
  padding: 0;
}
.ct-admin__template-editor-meta-list > div {
  display: grid;
  grid-template-columns: minmax(6rem, 9rem) minmax(0, 1fr);
  gap: var(--ct-space-2);
  align-items: baseline;
}
.ct-admin__template-editor-meta-list dt {
  color: var(--ct-theme-text-subtle);
  font-size: 0.78rem;
  font-weight: 700;
  line-height: 1.35;
}
.ct-admin__template-editor-meta-list dd {
  min-width: 0;
  margin: 0;
  color: var(--ct-theme-text-body);
  font-size: 0.84rem;
  line-height: 1.4;
  overflow-wrap: anywhere;
}
.ct-admin__template-editor-link-row {
  display: flex;
  flex-wrap: wrap;
  gap: var(--ct-space-2);
  align-items: center;
}
.ct-admin__template-editor-body input:not([type='checkbox']):not([type='hidden']),
.ct-admin__template-editor-body select,
.ct-admin__template-editor-body textarea {
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
.ct-admin__template-editor-body select {
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
.ct-admin__template-editor-body input:not([type='checkbox']):not([type='hidden']):focus,
.ct-admin__template-editor-body select:focus,
.ct-admin__template-editor-body textarea:focus {
  outline: none;
  border-color: var(--ct-theme-border-focus);
  box-shadow: var(--ct-focus-ring);
}
.ct-admin__template-editor-body input:not([type='checkbox']):not([type='hidden']):user-invalid,
.ct-admin__template-editor-body select:user-invalid,
.ct-admin__template-editor-body textarea:user-invalid,
.ct-admin__template-editor-body input:not([type='checkbox']):not([type='hidden']).user-invalid-fallback,
.ct-admin__template-editor-body select.user-invalid-fallback,
.ct-admin__template-editor-body textarea.user-invalid-fallback {
  border-color: var(--ct-theme-state-danger);
  background: var(--ct-theme-surface-danger);
}
.ct-admin__template-editor-body select:disabled {
  cursor: progress;
  opacity: 0.68;
}
.ct-admin__template-editor-body textarea {
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
@media (max-width: 960px) {
  .ct-admin__template-editor-fields--generation,
  .ct-admin__template-editor-fields--upload {
    grid-template-columns: minmax(0, 1fr);
  }

  .ct-admin__template-editor-overview {
    grid-template-columns: minmax(0, 1fr);
  }

  .ct-admin__template-editor-preview {
    max-width: 12rem;
  }

  .ct-admin__template-editor-summary {
    padding: 0;
  }

  .ct-admin__template-editor-current-artwork,
  .ct-admin__template-editor-meta-list > div {
    grid-template-columns: minmax(0, 1fr);
  }

  .ct-admin__template-editor-current-artwork a,
  .ct-admin__template-editor-current-artwork img,
  .ct-admin__template-editor-current-artwork-empty {
    max-width: 8rem;
  }
}
`;

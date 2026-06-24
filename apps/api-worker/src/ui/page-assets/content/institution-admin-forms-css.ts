export const INSTITUTION_ADMIN_FORMS_CSS = `
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
.ct-admin__add-disclosure-summary:focus-visible,
.ct-admin__advanced-tools > summary:focus-visible {
  outline: 2px solid var(--ct-theme-border-focus);
  outline-offset: -3px;
  border-radius: var(--ct-radius-md);
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
.ct-admin__table select:focus-visible {
  outline: none;
  border-color: var(--ct-theme-border-focus);
  box-shadow: var(--ct-focus-ring);
}
.ct-admin__table select:disabled {
  cursor: not-allowed;
  opacity: 0.68;
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
`;

export const INSTITUTION_ADMIN_FORMS_RESPONSIVE_CSS = `
  .ct-admin__form--inline.ct-grid,
  .ct-admin__add-disclosure-form.ct-grid {
    grid-template-columns: minmax(0, 1fr);
  }

  .ct-admin__add-disclosure-summary {
    align-items: flex-start;
    flex-direction: column;
  }

  .ct-admin__add-disclosure-control {
    flex: 0 0 auto;
    width: 100%;
  }

  .ct-admin__add-disclosure-control {
    min-height: 2.75rem;
  }
`;

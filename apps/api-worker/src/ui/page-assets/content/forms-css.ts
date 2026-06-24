export const FORMS_CSS = `
.ct-form {
  min-width: 0;
}

.ct-field {
  --ct-field-gap: 0.3rem;
  display: grid;
  gap: var(--ct-field-gap);
  min-width: 0;
  color: var(--ct-color-ink);
  font-size: 0.88rem;
  font-weight: 600;
}

.ct-field--inline {
  align-items: center;
  grid-template-columns: max-content minmax(0, 1fr);
  gap: 0.45rem 0.65rem;
}

.ct-field--compact {
  --ct-field-gap: 0.22rem;
  font-size: 0.8rem;
}

.ct-field__label {
  color: var(--ct-color-ink);
  font-size: 0.88rem;
  font-weight: 600;
  line-height: 1.3;
}

.ct-field__hint,
.ct-field__error {
  font-size: 0.78rem;
  font-weight: 500;
  line-height: 1.35;
}

.ct-field__hint {
  color: var(--ct-theme-text-subtle);
}

.ct-field__error {
  color: var(--ct-theme-state-danger);
}

.ct-input,
.ct-select,
.ct-textarea {
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
  font-weight: 500;
  line-height: 1.2;
  box-shadow: inset 0 1px 0 rgba(7, 26, 49, 0.03);
  transition:
    border-color var(--ct-duration-fast) var(--ct-ease-standard),
    box-shadow var(--ct-duration-fast) var(--ct-ease-standard),
    background var(--ct-duration-fast) var(--ct-ease-standard),
    color var(--ct-duration-fast) var(--ct-ease-standard);
}

.ct-field--compact .ct-input,
.ct-field--compact .ct-select,
.ct-field--compact .ct-textarea {
  min-height: 2.25rem;
  padding-block: 0.42rem;
  font-size: 0.82rem;
}

.ct-select {
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

.ct-select[multiple] {
  min-height: 5.5rem;
  background-image: none;
  padding-right: 0.72rem;
}

.ct-input::placeholder,
.ct-textarea::placeholder {
  color: var(--ct-theme-text-muted);
  opacity: 1;
}

.ct-input:hover:not(:disabled, [readonly]),
.ct-select:hover:not(:disabled),
.ct-textarea:hover:not(:disabled, [readonly]) {
  border-color: var(--ct-theme-border-strong);
}

.ct-input:focus-visible,
.ct-select:focus-visible,
.ct-textarea:focus-visible {
  outline: none;
  border-color: var(--ct-theme-border-focus);
  box-shadow: var(--ct-focus-ring);
}

.ct-input:user-invalid,
.ct-select:user-invalid,
.ct-textarea:user-invalid,
.ct-input.user-invalid-fallback,
.ct-select.user-invalid-fallback,
.ct-textarea.user-invalid-fallback {
  border-color: var(--ct-theme-state-danger);
  background: var(--ct-theme-surface-danger);
}

.ct-input:disabled,
.ct-select:disabled,
.ct-textarea:disabled {
  cursor: not-allowed;
  opacity: 0.68;
}

.ct-input[readonly],
.ct-textarea[readonly] {
  background: var(--ct-theme-surface-soft);
  color: var(--ct-theme-text-muted);
}

.ct-textarea {
  min-height: 5.5rem;
  resize: vertical;
  font-family: var(--ct-font-mono);
  font-size: 0.84rem;
  line-height: 1.35;
}

.ct-textarea--prose {
  font-family: var(--ct-font-sans);
  font-size: 0.92rem;
  line-height: 1.45;
}

.ct-textarea--code {
  font-family: var(--ct-font-mono);
  font-size: 0.84rem;
  line-height: 1.35;
}

.ct-checkbox-field {
  display: flex;
  align-items: center;
  gap: var(--ct-space-2);
  min-width: 0;
  color: var(--ct-color-ink);
  font-size: 0.88rem;
  font-weight: 600;
  line-height: 1.35;
}

.ct-checkbox-field__control {
  margin: 0;
  width: 1.2rem;
  height: 1.2rem;
  flex: 0 0 auto;
  accent-color: var(--ct-theme-link);
}

.ct-checkbox-field__control:focus-visible {
  outline: 2px solid var(--ct-theme-border-focus);
  outline-offset: 2px;
}

@media (max-width: 780px), (pointer: coarse) {
  .ct-input,
  .ct-select {
    min-height: 2.75rem;
  }

  .ct-checkbox-field {
    align-items: flex-start;
    min-height: 2.75rem;
    padding-block: 0.35rem;
  }
}
`;

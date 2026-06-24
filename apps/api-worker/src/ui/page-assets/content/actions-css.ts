export const ACTIONS_CSS = `
.ct-action {
  display: inline-flex;
  box-sizing: border-box;
  appearance: none;
  align-items: center;
  justify-content: center;
  justify-self: start;
  gap: 0.5rem;
  min-inline-size: 0;
  min-block-size: 2.45rem;
  padding: 0.5rem 0.78rem;
  border: 1px solid transparent;
  border-radius: var(--ct-radius-sm);
  font-family: var(--ct-font-sans);
  font-size: 0.82rem;
  font-weight: 650;
  line-height: 1.1;
  text-align: center;
  text-decoration: none;
  cursor: pointer;
  user-select: none;
  transition:
    transform var(--ct-duration-fast) var(--ct-ease-standard),
    box-shadow var(--ct-duration-fast) var(--ct-ease-standard),
    background var(--ct-duration-fast) var(--ct-ease-standard),
    border-color var(--ct-duration-fast) var(--ct-ease-standard),
    color var(--ct-duration-fast) var(--ct-ease-standard),
    filter var(--ct-duration-fast) var(--ct-ease-standard);
}

.ct-action--primary {
  color: var(--ct-theme-text-on-brand);
  background: var(--ct-theme-gradient-action);
}

.ct-action--secondary {
  color: var(--ct-color-ink);
  border-color: var(--ct-border-strong);
  background: linear-gradient(
    180deg,
    var(--ct-theme-surface-card-strong),
    var(--ct-theme-surface-info)
  );
}

.ct-action--quiet {
  color: var(--ct-theme-text-body);
  border-color: var(--ct-border-soft);
  background: var(--ct-theme-surface-card-strong);
}

.ct-action--danger {
  color: var(--ct-theme-state-danger);
  border-color: var(--ct-theme-border-danger);
  background: var(--ct-theme-surface-danger);
}

.ct-action--sm {
  min-block-size: 2.24rem;
  padding: 0.4rem 0.66rem;
  font-size: 0.77rem;
}

.ct-action--md {
  min-block-size: 2.45rem;
}

.ct-action--lg {
  min-block-size: 2.75rem;
  padding: 0.6rem 0.95rem;
  border-radius: var(--ct-radius-md);
  font-size: 0.9rem;
  font-weight: 700;
}

.ct-action--compact {
  min-block-size: 1.9rem;
  padding: 0.28rem 0.5rem;
  font-size: 0.72rem;
  line-height: 1;
}

.ct-action--text {
  min-block-size: 0;
  padding: 0;
  border: 0;
  border-radius: 0;
  background: transparent;
  color: var(--ct-theme-link);
  font: inherit;
  font-weight: 650;
  text-align: inherit;
  text-decoration: underline;
  text-decoration-color: color-mix(in srgb, var(--ct-theme-link) 35%, transparent);
  text-underline-offset: 0.14em;
  user-select: auto;
}

.ct-action-group {
  display: inline-flex;
  flex-wrap: wrap;
  align-items: center;
  justify-content: flex-start;
  justify-self: start;
  gap: 0.45rem;
  min-width: 0;
}

@media (hover: hover) {
  .ct-action:hover:not(:disabled, [aria-disabled='true']) {
    transform: translateY(-1px);
    box-shadow: var(--ct-theme-shadow-soft, var(--ct-shadow-soft));
    filter: brightness(1.03);
  }

  .ct-action--secondary:hover:not(:disabled, [aria-disabled='true']) {
    color: var(--ct-color-ink);
    border-color: var(--ct-border-strong);
  }

  .ct-action--quiet:hover:not(:disabled, [aria-disabled='true']) {
    color: var(--ct-theme-text-body);
    border-color: var(--ct-border-strong);
    background: var(--ct-theme-surface-info);
  }

  .ct-action--danger:hover:not(:disabled, [aria-disabled='true']) {
    border-color: rgba(173, 61, 49, 0.34);
    background: #ffe8e3;
    color: #8f1c13;
    box-shadow: 0 8px 16px rgba(173, 61, 49, 0.08);
    filter: none;
  }

  .ct-action--text:hover:not(:disabled, [aria-disabled='true']) {
    transform: none;
    box-shadow: none;
    filter: none;
    color: var(--ct-theme-link-hover, var(--ct-theme-link));
    text-decoration-color: currentColor;
  }
}

.ct-action:focus-visible {
  outline: 2px solid var(--ct-theme-border-focus);
  outline-offset: 3px;
  box-shadow: var(--ct-theme-shadow-soft, var(--ct-shadow-soft));
}

.ct-action--compact:focus-visible {
  outline-offset: 1px;
  box-shadow: none;
}

.ct-action--text:focus-visible {
  outline-offset: 0.2rem;
  box-shadow: none;
}

.ct-action:active:not(:disabled, [aria-disabled='true']) {
  transform: translateY(0);
  box-shadow: none;
  filter: none;
}

.ct-action:disabled,
.ct-action[aria-disabled='true'] {
  opacity: 0.66;
  cursor: not-allowed;
}

@media (max-width: 780px), (pointer: coarse) {
  .ct-action:not(.ct-action--text) {
    min-block-size: 2.75rem;
  }

  .ct-action--compact:not(.ct-action--text),
  .ct-action--sm:not(.ct-action--text) {
    min-block-size: 2.5rem;
  }
}

@media (forced-colors: active) {
  .ct-action {
    border-color: ButtonBorder;
    color: ButtonText;
    background: ButtonFace;
  }

  .ct-action:focus-visible {
    outline-color: Highlight;
  }
}
`;

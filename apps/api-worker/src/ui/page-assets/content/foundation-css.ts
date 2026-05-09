import { GENERATED_DESIGN_TOKENS_CSS } from "./generated/design-tokens-css";
import { FONT_FACE_CSS } from "./font-assets";

export const FOUNDATION_CSS = `
${FONT_FACE_CSS}
${GENERATED_DESIGN_TOKENS_CSS}

:root {
  color-scheme: light;
}

body {
  margin: 0;
  min-height: 100vh;
  color: var(--ct-theme-text-body);
  background: var(--ct-theme-gradient-canvas);
  font-family: var(--ct-font-sans);
  font-size: 1rem;
  font-kerning: normal;
}

h1,
h2,
h3,
h4 {
  margin-top: 0;
  color: var(--ct-theme-text-title);
  font-family: var(--ct-font-display);
  letter-spacing: 0;
  text-wrap: balance;
}

button,
input,
textarea,
select {
  font: inherit;
}

p {
  line-height: 1.6;
}

main {
  max-width: var(--ct-max-content-width);
  margin: clamp(0.85rem, 2.4vw, 2rem) auto;
  padding: clamp(1rem, 2.5vw, 2rem);
  border: 1px solid var(--ct-theme-border-default);
  border-radius: var(--ct-radius-lg);
  background: var(--ct-theme-surface-shell);
  box-shadow: var(--ct-theme-shadow-shell);
  animation: ct-shell-enter 440ms ease-out both;
}

a {
  color: var(--ct-theme-link);
  text-underline-offset: 0.15em;
}

a:hover {
  color: var(--ct-theme-link-hover);
}

@keyframes ct-shell-enter {
  from {
    opacity: 0;
    transform: translateY(9px) scale(0.995);
  }

  to {
    opacity: 1;
    transform: translateY(0) scale(1);
  }
}

@media (max-width: 640px) {
  main {
    margin: 0.4rem;
    border-radius: 1rem;
  }
}

@media (prefers-reduced-motion: reduce) {
  main {
    animation: none;
  }
}

body[data-variant='open'] {
  background: linear-gradient(180deg, #f8fbff 0%, #ffffff 100%);
}

body[data-variant='open'] main {
  border: none;
  border-radius: 0;
  background: transparent;
  backdrop-filter: none;
  box-shadow: none;
  animation: none;
  margin: 0 auto;
  padding: clamp(1.5rem, 3vw, 3rem) clamp(1rem, 2.5vw, 2rem);
  max-width: 1120px;
}

body[data-variant='admin'] {
  background: #f7f9fc;
}

body[data-variant='admin'] h1,
body[data-variant='admin'] h2,
body[data-variant='admin'] h3,
body[data-variant='admin'] h4 {
  font-family: var(--ct-font-sans);
  letter-spacing: 0;
}

body[data-variant='admin'] main {
  max-width: none;
  margin: 0;
  padding: 0;
  border: none;
  border-radius: 0;
  background: transparent;
  backdrop-filter: none;
  box-shadow: none;
  animation: none;
}

.ct-container {
  width: min(100%, var(--ct-max-content-width));
  margin-inline: auto;
}

.ct-stack {
  display: grid;
  gap: var(--ct-stack-gap, var(--ct-space-4));
  min-width: 0;
}

.ct-cluster {
  display: flex;
  align-items: center;
  flex-wrap: wrap;
  gap: var(--ct-cluster-gap, var(--ct-space-2));
  min-width: 0;
}

.ct-grid {
  display: grid;
  gap: var(--ct-grid-gap, var(--ct-space-4));
  min-width: 0;
}

.ct-grid > * {
  min-width: 0;
}

.ct-grid--sidebar {
  grid-template-columns: minmax(0, var(--ct-sidebar-width, 360px)) minmax(0, 1fr);
  align-items: start;
}

.ct-card {
  border: 1px solid var(--ct-border-soft);
  border-radius: var(--ct-radius-lg);
  background: var(--ct-theme-surface-card);
  box-shadow: var(--ct-shadow-soft);
}

.ct-muted {
  color: var(--ct-theme-text-muted);
}

.ct-checkbox-row {
  display: flex;
  align-items: center;
  gap: var(--ct-space-2);
}

.ct-checkbox-row input[type='checkbox'] {
  margin: 0;
  width: 1.2rem;
  height: 1.2rem;
  flex: 0 0 auto;
  accent-color: var(--ct-theme-link);
}

@media (max-width: 780px), (pointer: coarse) {
  .ct-checkbox-row {
    align-items: flex-start;
  }

  .ct-checkbox-row input[type='checkbox'] {
    width: 2.75rem;
    height: 2.75rem;
  }
}

@media (max-width: 980px) {
  .ct-grid--sidebar {
    grid-template-columns: minmax(0, 1fr);
  }
}
`;

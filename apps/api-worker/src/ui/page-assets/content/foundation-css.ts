export const FOUNDATION_CSS = `
:root {
  color-scheme: light;
  --ct-font-sans: 'Space Grotesk', 'Avenir Next', 'Segoe UI', sans-serif;
  --ct-font-display: 'Newsreader', Georgia, serif;
  --ct-font-mono: ui-monospace, SFMono-Regular, Menlo, monospace;

  /* Raw brand palette. Use semantic tokens for component/page styles. */
  --ct-brand-midnight-950: #071a31;
  --ct-brand-midnight-900: #0b2748;
  --ct-brand-midnight-800: #153a63;
  --ct-brand-lake-700: #0f5fa6;
  --ct-brand-lake-600: #1f74bb;
  --ct-brand-lake-500: #3a8fcb;
  --ct-brand-lake-400: #61a8d8;
  --ct-brand-sun-400: #f0c251;
  --ct-brand-mint-600: #166b46;
  --ct-brand-amber-600: #7a4700;
  --ct-brand-rose-600: #ad3d31;

  /* Semantic text tokens. */
  --ct-theme-text-title: #0d2543;
  --ct-theme-text-body: #173a5c;
  --ct-theme-text-muted: #4c6784;
  --ct-theme-text-subtle: #6c829b;
  --ct-theme-text-inverse: #f5fbff;
  --ct-theme-text-on-brand: #f7fcff;
  --ct-theme-link: var(--ct-brand-lake-700);
  --ct-theme-link-hover: #0b4e89;

  /* Semantic surface tokens. */
  --ct-theme-surface-canvas: #edf3fb;
  --ct-theme-surface-shell: rgba(255, 255, 255, 0.84);
  --ct-theme-surface-soft: #f4f8fd;
  --ct-theme-surface-card: rgba(255, 255, 255, 0.95);
  --ct-theme-surface-card-strong: #ffffff;
  --ct-theme-surface-info: #eef6ff;
  --ct-theme-surface-success: #edf9f1;
  --ct-theme-surface-warning: #fff5e6;
  --ct-theme-surface-danger: #fff2f0;
  --ct-theme-surface-brand-chip: rgba(255, 255, 255, 0.14);
  --ct-theme-surface-brand-chip-strong: rgba(255, 255, 255, 0.22);

  /* Semantic border tokens. */
  --ct-theme-border-soft: rgba(23, 60, 102, 0.14);
  --ct-theme-border-default: rgba(13, 46, 84, 0.2);
  --ct-theme-border-strong: rgba(8, 39, 77, 0.3);
  --ct-theme-border-focus: rgba(15, 95, 166, 0.34);
  --ct-theme-border-info: rgba(15, 95, 166, 0.24);
  --ct-theme-border-success: rgba(31, 138, 90, 0.3);
  --ct-theme-border-warning: rgba(163, 100, 18, 0.28);
  --ct-theme-border-danger: rgba(173, 61, 49, 0.28);

  /* Gradients and accents. */
  --ct-theme-gradient-hero: linear-gradient(
    132deg,
    var(--ct-brand-midnight-900) 0%,
    var(--ct-brand-lake-700) 68%,
    var(--ct-brand-lake-500) 100%
  );
  --ct-theme-gradient-action: linear-gradient(
    115deg,
    var(--ct-brand-midnight-900) 0%,
    var(--ct-brand-lake-700) 78%
  );
  --ct-theme-gradient-action-hover: linear-gradient(
    115deg,
    var(--ct-brand-midnight-800) 0%,
    var(--ct-brand-lake-600) 78%
  );
  --ct-theme-gradient-success: linear-gradient(
    120deg,
    #0f7f4f 0%,
    #005b4f 64%,
    #003d5c 100%
  );
  --ct-theme-gradient-danger: linear-gradient(
    120deg,
    #bd2f1b 0%,
    #8f1c13 64%,
    #5b1212 100%
  );
  --ct-theme-gradient-warning: linear-gradient(
    120deg,
    #a66a00 0%,
    #7f4b00 64%,
    #5b3300 100%
  );
  --ct-theme-gradient-neutral: linear-gradient(
    120deg,
    #4b5d75 0%,
    #36475d 64%,
    #233246 100%
  );
  --ct-theme-gradient-canvas: linear-gradient(
    165deg,
    #eef5ff 0%,
    #f8fbff 44%,
    #ffffff 100%
  );
  --ct-theme-accent-glow-1: rgba(255, 203, 5, 0.32);
  --ct-theme-accent-glow-2: rgba(0, 39, 76, 0.2);
  --ct-theme-accent-glow-3: rgba(0, 94, 184, 0.15);

  /* Elevation, focus, and status. */
  --ct-theme-shadow-card: 0 16px 32px rgba(7, 27, 51, 0.2);
  --ct-theme-shadow-soft: 0 10px 22px rgba(8, 45, 86, 0.12);
  --ct-theme-shadow-shell: 0 28px 48px rgba(13, 32, 58, 0.17);
  --ct-theme-shadow-focus: 0 0 0 3px rgba(15, 95, 166, 0.24);

  --ct-theme-state-success: var(--ct-brand-mint-600);
  --ct-theme-state-danger: var(--ct-brand-rose-600);
  --ct-theme-state-warning: var(--ct-brand-amber-600);

  --ct-color-ink-strong: var(--ct-theme-text-title);
  --ct-color-ink: var(--ct-theme-text-body);
  --ct-color-ink-soft: var(--ct-theme-text-muted);
  --ct-color-link: var(--ct-theme-link);
  --ct-color-link-hover: var(--ct-theme-link-hover);
  --ct-color-primary-900: var(--ct-brand-midnight-900);
  --ct-color-primary-700: var(--ct-brand-lake-700);
  --ct-color-primary-500: var(--ct-brand-lake-500);
  --ct-color-success: var(--ct-theme-state-success);
  --ct-color-danger: var(--ct-theme-state-danger);
  --ct-color-warning: var(--ct-theme-state-warning);

  --ct-surface-base: var(--ct-theme-surface-card-strong);
  --ct-surface-soft: var(--ct-theme-surface-soft);
  --ct-surface-elevated: var(--ct-theme-surface-card);
  --ct-surface-shell: var(--ct-theme-surface-shell);
  --ct-border-soft: var(--ct-theme-border-soft);
  --ct-border-strong: var(--ct-theme-border-default);
  --ct-border-focus: var(--ct-theme-border-focus);

  --ct-space-1: 0.25rem;
  --ct-space-2: 0.5rem;
  --ct-space-3: 0.75rem;
  --ct-space-4: 1rem;
  --ct-space-5: 1.25rem;
  --ct-space-6: 1.5rem;

  --ct-radius-sm: 0.5rem;
  --ct-radius-md: 0.75rem;
  --ct-radius-lg: 1rem;
  --ct-radius-xl: 1.25rem;
  --ct-radius-pill: 999px;

  --ct-shadow-card: var(--ct-theme-shadow-card);
  --ct-shadow-soft: var(--ct-theme-shadow-soft);
  --ct-shadow-shell: var(--ct-theme-shadow-shell);
  --ct-focus-ring: var(--ct-theme-shadow-focus);
  --ct-duration-fast: 120ms;
  --ct-duration-standard: 220ms;
  --ct-ease-standard: cubic-bezier(0.2, 0.7, 0.2, 1);
  --ct-max-content-width: 1080px;
}

body {
  margin: 0;
  min-height: 100vh;
  color: var(--ct-theme-text-body);
  background:
    radial-gradient(circle at 8% 5%, var(--ct-theme-accent-glow-1), transparent 36%),
    radial-gradient(circle at 88% 12%, var(--ct-theme-accent-glow-2), transparent 34%),
    radial-gradient(circle at 52% 96%, var(--ct-theme-accent-glow-3), transparent 32%),
    var(--ct-theme-gradient-canvas);
  font-family: var(--ct-font-sans);
}

h1,
h2,
h3,
h4 {
  margin-top: 0;
  color: var(--ct-theme-text-title);
  font-family: var(--ct-font-display);
  letter-spacing: -0.02em;
  text-wrap: balance;
}

p {
  line-height: 1.6;
}

main {
  max-width: var(--ct-max-content-width);
  margin: clamp(0.85rem, 2.4vw, 2rem) auto;
  padding: clamp(1rem, 2.5vw, 2rem);
  border: 1px solid var(--ct-theme-border-default);
  border-radius: 1.3rem;
  background: var(--ct-theme-surface-shell);
  backdrop-filter: blur(7px);
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

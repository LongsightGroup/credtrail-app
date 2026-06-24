export const DESIGN_SYSTEM_CSS = `
.ct-design-system {
  display: grid;
  gap: 1.35rem;
  max-width: 1180px;
  padding: 1.75rem 2rem 2.5rem;
}

.ct-design-system__header {
  margin-bottom: 0;
}

.ct-design-system__nav {
  display: flex;
  flex-wrap: wrap;
  gap: 0.4rem;
  padding-bottom: 0.9rem;
  border-bottom: 1px solid var(--ct-border-soft);
}

.ct-design-system__nav a {
  display: inline-flex;
  align-items: center;
  min-height: 2rem;
  padding: 0.35rem 0.65rem;
  border: 1px solid var(--ct-border-soft);
  border-radius: var(--ct-radius-sm);
  background: var(--ct-theme-surface-card-strong);
  color: var(--ct-theme-text-body);
  font-size: 0.78rem;
  font-weight: 600;
  line-height: 1.1;
  text-decoration: none;
}

.ct-design-system__nav a:hover {
  border-color: var(--ct-border-strong);
  background: var(--ct-theme-surface-info);
  color: var(--ct-theme-text-title);
}

.ct-design-system__section {
  display: grid;
  gap: 0.95rem;
  padding-block: 0.3rem 0.85rem;
}

.ct-design-system__section h2 {
  margin: 0;
  font-size: clamp(1.05rem, 2vw, 1.28rem);
  line-height: 1.2;
}

.ct-design-system__section-copy {
  margin: 0;
  max-width: 46rem;
  color: var(--ct-theme-text-muted);
  font-size: 0.9rem;
  line-height: 1.5;
}

.ct-design-system__grid {
  display: grid;
  gap: 0.75rem;
  grid-template-columns: repeat(auto-fit, minmax(14rem, 1fr));
}

.ct-design-system__form-grid {
  display: grid;
  gap: 0.75rem;
  grid-template-columns: repeat(auto-fit, minmax(16rem, 1fr));
}

.ct-design-system__example {
  display: grid;
  gap: 0.65rem;
  align-content: start;
  min-width: 0;
  padding: 0.85rem;
  border: 1px solid var(--ct-border-soft);
  border-radius: var(--ct-radius-md);
  background: var(--ct-theme-surface-card-strong);
}

.ct-design-system__example h3 {
  margin: 0;
  font-family: var(--ct-font-sans);
  font-size: 0.9rem;
  font-weight: 700;
  letter-spacing: 0;
}

@media (max-width: 720px) {
  .ct-design-system {
    padding: 1.25rem 1rem 2rem;
  }

  .ct-design-system__grid {
    grid-template-columns: minmax(0, 1fr);
  }
}
`;

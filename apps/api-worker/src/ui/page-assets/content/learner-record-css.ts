export const LEARNER_RECORD_CSS = String.raw`
.learner-record {
  --ct-learner-record-border: rgba(10, 44, 79, 0.12);
  --ct-learner-record-shadow: 0 10px 24px rgba(10, 35, 62, 0.08);
  --ct-learner-record-surface: rgba(255, 255, 255, 0.95);
  --ct-learner-record-surface-strong: rgba(255, 252, 246, 0.98);
  --ct-learner-record-accent: #114f86;
  display: grid;
  gap: 1.3rem;
  max-width: 78rem;
  margin: 0 auto;
  padding: clamp(0.2rem, 1vw, 0.45rem);
}
.learner-record__hero,
.learner-record__section,
.learner-record__card,
.learner-record__metric-card,
.learner-record__empty-state {
  border: 1px solid var(--ct-learner-record-border);
  border-radius: var(--ct-radius-lg);
  background: var(--ct-learner-record-surface);
  box-shadow: var(--ct-learner-record-shadow);
}
.learner-record__hero {
  display: grid;
  gap: 1rem;
  padding: clamp(1.25rem, 2vw, 1.8rem);
  background: linear-gradient(140deg, rgba(7, 30, 53, 0.98), rgba(19, 81, 132, 0.94));
  color: #f8fbff;
}
@media (min-width: 52rem) {
  .learner-record__hero {
    grid-template-columns: minmax(0, 1.4fr) minmax(15rem, 0.8fr);
    align-items: stretch;
  }
}
.learner-record__eyebrow,
.learner-record__section-kicker,
.learner-record__metric-label,
.learner-record__card-kicker,
.learner-record__meta-block h4 {
  margin: 0;
  font-size: 0.76rem;
  font-weight: 700;
  letter-spacing: 0.1em;
  text-transform: uppercase;
}
.learner-record__eyebrow {
  color: rgba(247, 220, 137, 0.96);
}
.learner-record__hero h1 {
  margin: 0;
  max-width: 12ch;
  color: #fff;
  font-family: var(--ct-font-display);
  font-size: clamp(2rem, 4.6vw, 3.6rem);
  line-height: 1.02;
}
.learner-record__hero-lead {
  margin: 0.75rem 0 0;
  max-width: 42rem;
  color: rgba(247, 251, 255, 0.94);
  font-size: 1.05rem;
  line-height: 1.6;
}
.learner-record__hero-note {
  margin: 0.7rem 0 0;
  max-width: 42rem;
  color: rgba(238, 246, 255, 0.84);
  line-height: 1.6;
}
.learner-record__hero-actions {
  display: flex;
  flex-wrap: wrap;
  gap: 0.7rem;
  margin-top: 1rem;
}
.learner-record__hero-link {
  display: inline-flex;
  align-items: center;
  min-height: 2.8rem;
  padding: 0.7rem 1rem;
  border-radius: 999px;
  border: 1px solid rgba(255, 255, 255, 0.16);
  background: rgba(255, 255, 255, 0.12);
  color: #fff;
  font-weight: 700;
  text-decoration: none;
}
.learner-record__hero-link:hover,
.learner-record__hero-link:focus-visible {
  background: rgba(255, 255, 255, 0.18);
}
.learner-record__hero-link--secondary {
  background: rgba(255, 255, 255, 0.08);
}
.learner-record__hero-metrics {
  display: grid;
  gap: 0.8rem;
}
.learner-record__metric-card {
  padding: 1rem 1.05rem;
  background: var(--ct-learner-record-surface-strong);
  color: #143452;
}
.learner-record__metric-label {
  color: #6b5321;
}
.learner-record__metric-value {
  margin: 0.45rem 0 0;
  font-size: 1.9rem;
  font-weight: 700;
  line-height: 1;
}
.learner-record__metric-note {
  margin: 0.35rem 0 0;
  color: #4e6983;
  line-height: 1.5;
}
.learner-record__section {
  display: grid;
  gap: 1rem;
  padding: 1.1rem;
}
.learner-record__section-heading {
  display: flex;
  justify-content: space-between;
  gap: 1rem;
  align-items: start;
}
.learner-record__section h2,
.learner-record__empty-state h2 {
  margin: 0.12rem 0 0;
  color: var(--ct-theme-text-title);
}
.learner-record__section p,
.learner-record__empty-state p,
.learner-record__card-description,
.learner-record__provenance,
.learner-record__subtle {
  margin: 0;
  color: var(--ct-theme-text-muted);
  line-height: 1.6;
}
.learner-record__section-kicker {
  color: var(--ct-theme-text-subtle);
}
.learner-record__card-grid {
  display: grid;
  gap: 0.95rem;
  grid-template-columns: repeat(auto-fit, minmax(17rem, 1fr));
}
.learner-record__card {
  display: grid;
  gap: 0.8rem;
  padding: 1rem;
  background:
    linear-gradient(180deg, rgba(255, 255, 255, 0.99), rgba(244, 249, 255, 0.95)),
    var(--ct-learner-record-surface);
}
.learner-record__card-topline {
  display: flex;
  justify-content: space-between;
  gap: 0.8rem;
  align-items: start;
}
.learner-record__card h3 {
  margin: 0;
  color: var(--ct-theme-text-title);
  font-size: 1.08rem;
  line-height: 1.25;
}
.learner-record__pill-row {
  display: flex;
  flex-wrap: wrap;
  gap: 0.45rem;
  justify-content: end;
}
.learner-record__pill {
  display: inline-flex;
  align-items: center;
  min-height: 2rem;
  padding: 0.28rem 0.7rem;
  border-radius: 999px;
  border: 1px solid rgba(17, 79, 134, 0.12);
  font-size: 0.76rem;
  font-weight: 700;
}
.learner-record__pill--trust {
  color: #13517d;
  background: rgba(224, 239, 252, 0.92);
}
.learner-record__pill--status {
  color: #3b5872;
  background: rgba(238, 244, 250, 0.9);
}
.learner-record__pill--status-revoked,
.learner-record__pill--status-expired {
  color: #9b2619;
  background: rgba(255, 239, 237, 0.96);
}
.learner-record__meta-grid {
  display: grid;
  gap: 0.8rem;
}
@media (min-width: 42rem) {
  .learner-record__meta-grid {
    grid-template-columns: repeat(2, minmax(0, 1fr));
  }
}
.learner-record__meta-block {
  display: grid;
  gap: 0.55rem;
  padding: 0.8rem 0.9rem;
  border-radius: 1rem;
  border: 1px solid rgba(17, 79, 134, 0.1);
  background: rgba(247, 250, 255, 0.9);
}
.learner-record__meta-block h4 {
  color: var(--ct-theme-text-subtle);
}
.learner-record__detail-list {
  display: grid;
  gap: 0.55rem;
  margin: 0;
}
.learner-record__detail-row {
  display: grid;
  gap: 0.12rem;
}
.learner-record__detail-row dt {
  color: var(--ct-theme-text-subtle);
  font-size: 0.78rem;
  font-weight: 700;
}
.learner-record__detail-row dd {
  margin: 0;
  color: var(--ct-theme-text-title);
  font-size: 0.92rem;
  line-height: 1.5;
  overflow-wrap: anywhere;
}
.learner-record__link-list {
  display: grid;
  gap: 0.4rem;
  margin: 0;
  padding-left: 1rem;
}
.learner-record__link-list a,
.learner-record__card-action {
  color: var(--ct-learner-record-accent);
  font-weight: 700;
  text-decoration: none;
}
.learner-record__link-list a:hover,
.learner-record__link-list a:focus-visible,
.learner-record__card-action:hover,
.learner-record__card-action:focus-visible {
  text-decoration: underline;
}
.learner-record__empty-state {
  display: grid;
  gap: 0.55rem;
  padding: 1.25rem;
  background:
    linear-gradient(180deg, rgba(255, 252, 245, 0.92), rgba(247, 250, 255, 0.94)),
    var(--ct-learner-record-surface);
}
@media (max-width: 41rem) {
  .learner-record__card-topline {
    flex-direction: column;
  }
  .learner-record__pill-row {
    justify-content: start;
  }
}
`;

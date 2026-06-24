export const LEARNER_DASHBOARD_CSS = `.learner-dashboard {
  --learner-ink: #12314f;
  --learner-ink-soft: #47627d;
  --learner-line: rgba(0, 39, 76, 0.14);
  --learner-line-strong: rgba(0, 39, 76, 0.2);
  --learner-surface: #f8fbff;
  --learner-shadow: 0 10px 24px rgba(0, 39, 76, 0.08);
  display: grid;
  gap: clamp(1.4rem, 1.15rem + 0.95vw, 2.2rem);
  max-width: 70rem;
}

.learner-dashboard__hero {
  display: grid;
  gap: 1.2rem;
  border: 1px solid rgba(0, 39, 76, 0.18);
  border-radius: var(--ct-radius-lg);
  padding: clamp(1.25rem, 1rem + 1vw, 2rem);
  background: linear-gradient(144deg, rgba(8, 32, 53, 0.97), rgba(14, 70, 112, 0.94));
  color: #f8fcff;
  box-shadow: 0 16px 30px rgba(0, 39, 76, 0.14);
}

@media (min-width: 48rem) {
  .learner-dashboard__hero {
    grid-template-columns: minmax(0, 1.6fr) minmax(16rem, 0.8fr);
    align-items: end;
  }
}

.learner-dashboard__eyebrow {
  margin: 0 0 0.55rem 0;
  color: #f6d87d;
  font-size: 0.77rem;
  font-weight: 700;
  letter-spacing: 0.14em;
  text-transform: uppercase;
}

.learner-dashboard__eyebrow--section {
  color: #8a6520;
}

.learner-dashboard__hero h1 {
  margin: 0;
  max-width: 12ch;
  color: #f8fcff;
  font-size: clamp(2rem, 1.5rem + 1.7vw, 3.15rem);
  line-height: 1.04;
}

.learner-dashboard__hero-lead {
  margin: 0.6rem 0 0 0;
  max-width: 42rem;
  color: rgba(248, 252, 255, 0.94);
  font-size: clamp(1rem, 0.93rem + 0.45vw, 1.22rem);
}

.learner-dashboard__hero-note {
  margin: 0.75rem 0 0 0;
  max-width: 40rem;
  color: rgba(248, 252, 255, 0.88);
}

.learner-dashboard__hero-note--switch {
  margin-top: 0.95rem;
}

.learner-dashboard__hero-note--record {
  margin-top: 0.95rem;
}

.learner-dashboard__hero-chips {
  display: flex;
  flex-wrap: wrap;
  gap: 0.55rem;
  margin: 1rem 0 0 0;
  padding: 0;
  list-style: none;
}

.learner-dashboard__hero-chip {
  display: inline-flex;
  align-items: center;
  min-height: 2.2rem;
  padding: 0.45rem 0.8rem;
  border: 1px solid rgba(246, 216, 125, 0.24);
  border-radius: 999px;
  background: rgba(255, 255, 255, 0.08);
  color: #f8fcff;
  font-size: 0.88rem;
  font-weight: 600;
}

.learner-dashboard__switch-link {
  display: inline-flex;
  align-items: center;
  min-height: 2.4rem;
  padding: 0.2rem 0;
  color: #f6d87d;
  font-weight: 700;
  text-decoration: none;
}

.learner-dashboard__record-link {
  display: inline-flex;
  align-items: center;
  min-height: 2.4rem;
  padding: 0.2rem 0;
  color: #f8fcff;
  font-weight: 700;
  text-decoration: none;
}

.learner-dashboard__switch-link:hover {
  text-decoration: underline;
}

.learner-dashboard__record-link:hover {
  text-decoration: underline;
}

.learner-dashboard__hero-card {
  display: grid;
  gap: 0.45rem;
  align-self: stretch;
  border: 1px solid rgba(245, 198, 75, 0.34);
  border-radius: 1.15rem;
  padding: 1rem;
  background: rgba(255, 252, 244, 0.96);
  color: var(--learner-ink);
  box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.45);
}

.learner-dashboard__hero-card-label {
  margin: 0;
  color: #73511a;
  font-size: 0.75rem;
  font-weight: 700;
  letter-spacing: 0.12em;
  text-transform: uppercase;
}

.learner-dashboard__hero-card-value {
  margin: 0;
  color: var(--learner-ink);
  font-size: 1.22rem;
  font-weight: 700;
  line-height: 1.2;
  overflow-wrap: anywhere;
}

.learner-dashboard__hero-card-note {
  margin: 0;
  color: #415f7c;
}

.learner-dashboard__subtle {
  margin: 0;
  color: var(--learner-ink-soft);
}

.learner-dashboard__subtle--break {
  overflow-wrap: anywhere;
}

.learner-dashboard__danger {
  margin: 0;
  color: #9c1f15;
  font-weight: 600;
}

.learner-dashboard__collection,
.learner-dashboard__profile {
  display: grid;
  gap: 1rem;
}

.learner-dashboard__section-heading {
  display: flex;
  justify-content: space-between;
  gap: 1rem;
  align-items: end;
}

.learner-dashboard__section-heading--compact {
  align-items: start;
}

.learner-dashboard__section-heading h2 {
  margin: 0;
  color: var(--learner-ink);
}

.learner-dashboard__section-copy {
  margin: 0.35rem 0 0 0;
  max-width: 44rem;
  color: var(--learner-ink-soft);
}

.learner-dashboard__empty-state {
  display: grid;
  gap: 0.55rem;
  border: 1px dashed rgba(0, 39, 76, 0.18);
  border-radius: 1.15rem;
  padding: 1.15rem;
  background: var(--learner-surface);
}

.learner-dashboard__notice {
  margin: 0;
  font-weight: 600;
  border-radius: 0.7rem;
  padding: 0.55rem 0.65rem;
}

.learner-dashboard__notice--success {
  color: #0a6f47;
  background: #eafbf1;
  border: 1px solid #bfead0;
}

.learner-dashboard__notice--info {
  color: #214363;
  background: #edf6ff;
  border: 1px solid #c7dff9;
}

.learner-dashboard__notice--danger {
  color: #932618;
  background: #fff1ef;
  border: 1px solid #f7ccc7;
}

.learner-dashboard__did-form {
  display: grid;
  gap: 0.6rem;
}

.learner-dashboard__profile-details {
  border: 1px solid var(--learner-line);
  border-radius: 1.15rem;
  background: var(--ct-theme-surface-card-strong);
  box-shadow: var(--learner-shadow);
}

.learner-dashboard__details-summary {
  display: flex;
  justify-content: space-between;
  gap: 1rem;
  align-items: center;
  padding: 1rem 1.05rem;
  cursor: pointer;
  list-style: none;
}

.learner-dashboard__details-summary::-webkit-details-marker {
  display: none;
}

.learner-dashboard__details-copy {
  display: grid;
  gap: 0.18rem;
}

.learner-dashboard__details-title {
  color: var(--learner-ink);
  font-weight: 700;
}

.learner-dashboard__details-subtitle {
  color: var(--learner-ink-soft);
}

.learner-dashboard__summary-pill {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  min-height: 2rem;
  padding: 0.3rem 0.7rem;
  border: 1px solid rgba(11, 90, 169, 0.16);
  border-radius: 999px;
  background: rgba(237, 246, 255, 0.9);
  color: #20476c;
  font-size: 0.82rem;
  font-weight: 700;
  white-space: nowrap;
}

.learner-dashboard__summary-pill--configured {
  border-color: #bfead0;
  background: #eafbf1;
  color: #0a6f47;
}

.learner-dashboard__details-panel {
  display: grid;
  gap: 0.75rem;
  padding: 0 1.05rem 1.05rem;
  border-top: 1px solid rgba(0, 39, 76, 0.08);
}

.learner-dashboard__did-label {
  color: var(--learner-ink);
}

.learner-dashboard__did-input {
  color: var(--learner-ink);
  background: rgba(255, 255, 255, 0.96);
}

.learner-dashboard__button-row {
  display: flex;
  gap: 0.5rem;
  flex-wrap: wrap;
}

.learner-dashboard__button {
  flex: 0 0 auto;
}

.learner-dashboard__badge-grid {
  display: grid;
  gap: 1rem;
  grid-template-columns: repeat(auto-fit, minmax(min(19rem, 100%), 1fr));
}

.learner-dashboard__badge-card {
  position: relative;
  display: grid;
  gap: 0.8rem;
  border: 1px solid var(--learner-line);
  border-radius: var(--ct-radius-lg);
  padding: 1.15rem;
  background: var(--learner-surface);
  box-shadow: var(--learner-shadow);
  overflow: hidden;
}

.learner-dashboard__badge-card::before {
  content: '';
  position: absolute;
  inset: 0 0 auto 0;
  height: 0.32rem;
  background: linear-gradient(90deg, rgba(236, 183, 43, 0.96), rgba(73, 118, 176, 0.82));
}

.learner-dashboard__badge-card--revoked {
  background: linear-gradient(180deg, rgba(255, 245, 243, 0.98), rgba(249, 247, 247, 0.96));
  border-color: rgba(148, 38, 24, 0.16);
}

.learner-dashboard__badge-card--revoked::before {
  background: linear-gradient(90deg, rgba(173, 70, 52, 0.82), rgba(120, 45, 33, 0.96));
}

.learner-dashboard__badge-topline {
  display: flex;
  justify-content: space-between;
  gap: 0.75rem;
  align-items: center;
  flex-wrap: wrap;
}

.learner-dashboard__badge-eyebrow {
  color: #7b5a22;
  font-size: 0.75rem;
  font-weight: 700;
  letter-spacing: 0.11em;
  text-transform: uppercase;
}

.learner-dashboard__badge-card--revoked .learner-dashboard__badge-eyebrow {
  color: #8a463d;
}

.learner-dashboard__badge-card h3 {
  margin: 0;
  color: var(--learner-ink);
  line-height: 1.2;
}

.learner-dashboard__claim-form {
  margin: 0;
}

.learner-dashboard__claim-state {
  margin: 0;
  font-weight: 700;
}

.learner-dashboard__claim-state--claimed {
  color: #0f5b84;
}

.learner-dashboard__claim-state--accepted {
  color: #0a6f47;
}

.learner-dashboard__badge-description {
  margin: 0;
  color: var(--learner-ink-soft);
}

.learner-dashboard__badge-status {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  min-height: 1.9rem;
  padding: 0.35rem 0.8rem;
  border: 1px solid transparent;
  border-radius: 999px;
  font-size: 0.78rem;
  font-weight: 700;
  letter-spacing: 0.03em;
  text-transform: uppercase;
  white-space: nowrap;
}

.learner-dashboard__badge-status--verified {
  color: #0a6f47;
  background: #eafbf1;
  border-color: #bfead0;
}

.learner-dashboard__badge-status--revoked {
  color: #932618;
  background: #fff1ef;
  border-color: #f7ccc7;
}

.learner-dashboard__badge-meta {
  display: grid;
  gap: 0.8rem;
  grid-template-columns: repeat(auto-fit, minmax(10rem, 1fr));
}

.learner-dashboard__meta-label {
  margin: 0;
  color: #7a5c24;
  font-size: 0.74rem;
  font-weight: 700;
  letter-spacing: 0.09em;
  text-transform: uppercase;
}

.learner-dashboard__badge-card--revoked .learner-dashboard__meta-label {
  color: #8a463d;
}

.learner-dashboard__meta-value {
  margin: 0.18rem 0 0 0;
  color: var(--learner-ink);
  font-weight: 600;
}

.learner-dashboard__badge-link {
  display: inline-flex;
  align-items: center;
  min-height: 2.75rem;
  padding: 0.2rem 0;
  color: #0e4f87;
  font-weight: 700;
  text-decoration: none;
}

.learner-dashboard__badge-link:hover {
  text-decoration: underline;
}

.learner-dashboard__badge-url {
  margin: 0;
  color: #577089;
  font-size: 0.87rem;
  overflow-wrap: anywhere;
}`;

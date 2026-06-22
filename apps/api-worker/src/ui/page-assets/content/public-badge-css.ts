export const PUBLIC_BADGE_CSS = `
.public-badge-not-found {
  display: grid;
  gap: 1rem;
  max-width: 42rem;
}

.public-badge-not-found__card {
  display: grid;
  gap: 0.8rem;
  padding: 1.25rem;
  border: 1px solid var(--ct-theme-border-default);
  border-radius: 1rem;
  background: linear-gradient(
    155deg,
    var(--ct-theme-surface-card-strong),
    var(--ct-theme-surface-soft)
  );
  box-shadow: var(--ct-theme-shadow-soft);
}

.public-badge-not-found__eyebrow {
  margin: 0;
  font-size: 0.8rem;
  letter-spacing: 0.11em;
  text-transform: uppercase;
  color: var(--ct-theme-link);
  font-weight: 700;
}

.public-badge-not-found__title {
  margin: 0;
}

.public-badge-not-found__copy {
  margin: 0;
  color: var(--ct-theme-text-muted);
}

.public-badge {
  display: grid;
  gap: 1rem;
  color: var(--ct-theme-text-title);
  --public-badge-card-radius: var(--ct-radius-lg);
  --public-badge-card-padding: 1.1rem;
  --public-badge-status-radius: 1.35rem;
  --public-badge-frame-padding: 0.72rem;
  --public-badge-frame-inner-radius: 1rem;
  --public-badge-frame-radius: calc(
    var(--public-badge-frame-inner-radius) + var(--public-badge-frame-padding)
  );
  --public-badge-panel-padding: 0.56rem;
  --public-badge-panel-inner-radius: 0.8rem;
  --public-badge-panel-radius: calc(
    var(--public-badge-panel-inner-radius) + var(--public-badge-panel-padding)
  );
}
  
.public-badge__card {
  background: var(--ct-theme-surface-card-strong);
  border: 1px solid var(--ct-theme-border-soft);
  border-radius: var(--public-badge-card-radius);
  box-shadow: var(--ct-theme-shadow-soft);
  padding: var(--public-badge-card-padding);
  animation: public-badge-enter 420ms ease-out both;
}

.public-badge__card:nth-child(2) {
  animation-delay: 45ms;
}

.public-badge__card:nth-child(3) {
  animation-delay: 95ms;
}

.public-badge__card:nth-child(4) {
  animation-delay: 140ms;
}
  
.public-badge__stack-sm {
  display: grid;
  gap: 0.65rem;
}
  
.public-badge__status {
  display: flex;
  justify-content: space-between;
  gap: 1rem;
  align-items: center;
  border-radius: var(--public-badge-status-radius);
  color: var(--ct-theme-text-on-brand);
  font-weight: 700;
  letter-spacing: 0.015em;
}
  
.public-badge__status--verified {
  border-color: color-mix(in srgb, var(--ct-brand-lake-500) 26%, var(--ct-theme-border-soft));
  background: linear-gradient(
    118deg,
    var(--ct-brand-midnight-900) 0%,
    var(--ct-brand-lake-700) 84%
  );
  box-shadow:
    inset 0 1px 0 rgba(255, 255, 255, 0.14),
    0 10px 20px rgba(8, 38, 74, 0.12);
}
  
.public-badge__status--revoked {
  background: var(--ct-theme-gradient-danger);
}

.public-badge__status--suspended {
  background: var(--ct-theme-gradient-warning);
}

.public-badge__status--expired {
  background: var(--ct-theme-gradient-neutral);
}

.public-badge__status-note {
  margin: 0;
  color: var(--ct-theme-text-body);
  font-size: 0.95rem;
}

.public-badge__status-note--revoked {
  color: var(--ct-theme-state-danger);
}

.public-badge__status-note--suspended {
  color: var(--ct-theme-state-warning);
}

.public-badge__status-note--expired {
  color: var(--ct-theme-text-muted);
}
  
.public-badge__hero {
  display: grid;
  gap: 1.1rem;
}

.public-badge__hero-image-frame {
  position: relative;
  display: grid;
  place-items: center;
  width: 100%;
  max-width: 420px;
  border: 1px solid var(--ct-theme-border-soft);
  border-radius: var(--public-badge-frame-radius);
  padding: var(--public-badge-frame-padding);
  box-sizing: border-box;
  background: linear-gradient(
    180deg,
    color-mix(in srgb, var(--ct-theme-surface-card-strong) 94%, var(--ct-theme-surface-soft)),
    color-mix(in srgb, var(--ct-theme-surface-soft) 88%, var(--ct-theme-surface-card-strong))
  );
  box-shadow:
    inset 0 1px 0 rgba(255, 255, 255, 0.8),
    0 1px 0 rgba(13, 46, 84, 0.04);
}
  
.public-badge__hero-image {
  display: block;
  width: 100%;
  box-sizing: border-box;
  border-radius: var(--public-badge-frame-inner-radius);
  aspect-ratio: 21 / 16;
  padding: clamp(0.8rem, 2.8vw, 1.1rem);
  object-fit: contain;
  object-position: center;
  background: linear-gradient(
    180deg,
    var(--ct-theme-surface-card-strong),
    color-mix(in srgb, var(--ct-theme-surface-soft) 84%, var(--ct-theme-surface-card-strong))
  );
}

.public-badge__hero-image-fallback {
  position: absolute;
  inset: var(--public-badge-frame-padding);
  display: none;
  align-items: center;
  justify-content: center;
  border-radius: var(--public-badge-frame-inner-radius);
  background: var(--ct-theme-gradient-hero);
  color: var(--ct-theme-text-on-brand);
  font-size: clamp(2rem, 5vw, 3.5rem);
  font-weight: 700;
  letter-spacing: 0.06em;
  text-transform: uppercase;
}

.public-badge__hero-image-frame[data-fallback='true'] .public-badge__hero-image-fallback {
  display: flex;
}
  
.public-badge__hero-meta {
  display: grid;
  gap: 0.5rem;
}
  
.public-badge__eyebrow {
  margin: 0;
  text-transform: uppercase;
  letter-spacing: 0.11em;
  font-size: 0.8rem;
  color: var(--ct-theme-link);
  font-weight: 700;
}
  
.public-badge__title {
  margin: 0;
  font-size: clamp(1.4rem, 3vw, 1.85rem);
  line-height: 1.2;
}
  
.public-badge__issuer,
.public-badge__issued-at,
.public-badge__recipient-meta {
  margin: 0;
  color: var(--ct-theme-text-muted);
}

.public-badge__issuer a,
.public-badge__achievement-copy a,
.public-badge__evidence-item a {
  display: inline-flex;
  align-items: center;
  min-height: 2.75rem;
}
  
.public-badge__recipient-name {
  margin: 0;
  font-size: 1.08rem;
  font-weight: 700;
}
  
.public-badge__recipient-header {
  display: flex;
  gap: 0.8rem;
  align-items: center;
}
  
.public-badge__recipient-avatar {
  width: 3rem;
  height: 3rem;
  border-radius: 999px;
  border: 2px solid var(--ct-theme-border-soft);
  object-fit: cover;
  background: var(--ct-theme-surface-soft);
}
  
.public-badge__section-title {
  margin: 0;
  font-size: 1rem;
}

.public-badge__section-heading-row {
  display: flex;
  flex-wrap: wrap;
  gap: 0.5rem;
  align-items: center;
  justify-content: space-between;
}

.public-badge__metadata-badge {
  display: inline-flex;
  align-items: center;
  min-height: 1.75rem;
  padding: 0.18rem 0.58rem;
  border: 1px solid color-mix(in srgb, var(--ct-brand-lake-500) 28%, var(--ct-theme-border-soft));
  border-radius: 999px;
  background: color-mix(in srgb, var(--ct-brand-lake-500) 8%, var(--ct-theme-surface-card-strong));
  color: var(--ct-brand-lake-700);
  font-size: 0.78rem;
  font-weight: 700;
}

.public-badge__share {
  gap: 0.72rem;
}

.public-badge__share-feed-link {
  margin: 0;
}

.public-badge__share-actions {
  display: grid;
  gap: 0.45rem;
  justify-items: start;
}

.public-badge__share-actions .public-badge__button--primary {
  width: auto;
}

.public-badge__text-link {
  color: var(--ct-theme-link);
  font-weight: 600;
  text-decoration: underline;
  text-decoration-color: color-mix(in srgb, var(--ct-theme-link) 35%, transparent);
  text-underline-offset: 0.14em;
}

.public-badge__text-link:hover {
  color: var(--ct-theme-link-hover, var(--ct-theme-link));
  text-decoration-color: currentColor;
}

.public-badge__text-button {
  margin: 0;
  padding: 0;
  border: 0;
  background: transparent;
  color: var(--ct-theme-link);
  font: inherit;
  font-weight: 600;
  text-decoration: underline;
  text-decoration-color: color-mix(in srgb, var(--ct-theme-link) 35%, transparent);
  text-underline-offset: 0.14em;
  cursor: pointer;
}

.public-badge__text-button:hover {
  color: var(--ct-theme-link-hover, var(--ct-theme-link));
  text-decoration-color: currentColor;
}

.public-badge__link-row {
  margin: 0;
  color: var(--ct-theme-text-muted);
  font-size: 0.88rem;
  line-height: 1.45;
}
  
.public-badge__achievement-copy {
  margin: 0;
  color: var(--ct-theme-text-muted);
}

.public-badge__actions {
  display: flex;
  flex-wrap: wrap;
  gap: 0.52rem;
  align-items: center;
}

.public-badge__button {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  border: 1px solid var(--ct-theme-border-default);
  border-radius: 0.7rem;
  min-height: 2.75rem;
  padding: 0.6rem 0.9rem;
  text-decoration: none;
  font-size: 0.84rem;
  line-height: 1.2;
  font-weight: 600;
  color: var(--ct-theme-text-body);
  background: linear-gradient(
    180deg,
    var(--ct-theme-surface-card-strong),
    var(--ct-theme-surface-info)
  );
  cursor: pointer;
  transition:
    transform var(--ct-duration-fast) var(--ct-ease-standard),
    box-shadow var(--ct-duration-fast) var(--ct-ease-standard),
    border-color var(--ct-duration-fast) var(--ct-ease-standard);
}

.public-badge__button:hover {
  color: var(--ct-theme-text-body);
  transform: translateY(-1px);
  box-shadow: var(--ct-theme-shadow-soft);
  border-color: var(--ct-theme-border-strong);
}
  
.public-badge__button--primary {
  border-color: transparent;
  background: var(--ct-theme-gradient-action);
  color: var(--ct-theme-text-on-brand);
}

.public-badge__button--primary:hover {
  background: var(--ct-theme-gradient-action-hover);
  color: var(--ct-theme-text-on-brand);
}

.public-badge__button--compact {
  min-height: 2.35rem;
  padding: 0.45rem 0.75rem;
  font-size: 0.82rem;
}
  
.public-badge__copy-status {
  margin: 0;
  color: var(--ct-theme-text-muted);
  font-size: 0.88rem;
}

.public-badge__share-more {
  margin-top: 0.15rem;
  padding-top: 0.7rem;
  border-top: 1px solid var(--ct-theme-border-soft);
}

.public-badge__share-more summary {
  display: flex;
  align-items: center;
  min-height: 2.75rem;
  cursor: pointer;
  font-weight: 700;
  color: var(--ct-theme-text-body);
  font-size: 0.92rem;
}

.public-badge__share-groups {
  display: grid;
  gap: 1rem;
  margin-top: 0.55rem;
}

.public-badge__share-group-title {
  margin: 0 0 0.55rem;
  font-size: 0.88rem;
  font-weight: 700;
  color: var(--ct-theme-text-body);
}

.public-badge__wallet-paths {
  display: grid;
  gap: 1rem;
}

.public-badge__wallet-path-title {
  margin: 0 0 0.55rem;
  font-size: 0.88rem;
  font-weight: 700;
  color: var(--ct-theme-text-body);
}

.public-badge__wallet-path-copy {
  margin: 0 0 0.55rem;
  color: var(--ct-theme-text-muted);
  font-size: 0.88rem;
  line-height: 1.45;
}

.public-badge__wallet-path--phone {
  display: grid;
  gap: 0.55rem;
}

.public-badge__wallet-path--device {
  display: grid;
  gap: 0.45rem;
  justify-items: start;
}

.public-badge__wallet-browser-row {
  margin-top: 0.1rem;
}

.public-badge__wallet-panel {
  display: grid;
  gap: 0.85rem;
}

.public-badge__wallet-actions {
  display: grid;
  gap: 0.45rem;
  justify-items: start;
}

.public-badge__validator-note {
  margin: 0;
  color: var(--ct-theme-text-muted);
  font-size: 0.88rem;
  line-height: 1.35;
}

.public-badge__technical-url-row {
  display: grid;
  gap: 0.35rem;
}

.public-badge__technical-url-row .public-badge__text-button {
  justify-self: start;
}
  
.public-badge__qr {
  margin: 0;
  display: grid;
  gap: 0.55rem;
  width: fit-content;
  max-width: 100%;
  justify-items: start;
}
  
.public-badge__qr-image {
  box-sizing: border-box;
  width: 11.5rem;
  height: 11.5rem;
  padding: 0.55rem;
  border-radius: var(--public-badge-panel-inner-radius);
  border: 1px solid var(--ct-theme-border-default);
  background: var(--ct-theme-surface-card-strong);
  object-fit: contain;
}
  
.public-badge__qr-caption {
  margin: 0;
  color: var(--ct-theme-text-muted);
  font-size: 0.84rem;
  line-height: 1.45;
  max-width: 16rem;
}
  
.public-badge__evidence-list {
  margin: 0;
  padding-left: 1.2rem;
  display: grid;
  gap: 0.5rem;
}
  
.public-badge__evidence-item a {
  font-weight: 600;
}
  
.public-badge__evidence-description {
  margin: 0.2rem 0 0 0;
  color: var(--ct-theme-text-muted);
}

.public-badge__trust-grid {
  margin: 0;
  display: grid;
  grid-template-columns: minmax(8rem, max-content) 1fr;
  gap: 0.55rem 0.8rem;
}

.public-badge__trust-grid dt {
  color: var(--ct-theme-text-body);
  font-weight: 700;
}

.public-badge__trust-grid dd {
  margin: 0;
  color: var(--ct-theme-text-muted);
  overflow-wrap: anywhere;
}

.public-badge__trust-list {
  margin: 0;
  padding-left: 1.1rem;
  display: grid;
  gap: 0.35rem;
}

.public-badge__trust-muted {
  color: var(--ct-theme-text-muted);
}
  
.public-badge__technical summary {
  display: flex;
  align-items: center;
  min-height: 2.75rem;
  cursor: pointer;
  font-weight: 700;
}
  
.public-badge__technical-grid {
  margin: 0.85rem 0 0 0;
  display: grid;
  grid-template-columns: minmax(9rem, max-content) 1fr;
  gap: 0.45rem 0.8rem;
}
  
.public-badge__technical-grid dt {
  font-weight: 600;
  color: var(--ct-theme-text-body);
}
  
.public-badge__technical-grid dd {
  margin: 0;
  overflow-wrap: anywhere;
}

.public-badge__technical-tools {
  margin-top: 1rem;
  padding-top: 0.9rem;
  border-top: 1px solid var(--ct-theme-border-soft);
  display: grid;
  gap: 0.55rem;
}

.public-badge__technical-tools-title {
  margin: 0;
  font-size: 0.92rem;
  font-weight: 700;
  color: var(--ct-theme-text-body);
}

.public-badge__technical-link-list {
  margin: 0;
  padding-left: 1.15rem;
  display: grid;
  gap: 0.35rem;
}

.public-badge__technical-link-list a {
  font-weight: 600;
  color: var(--ct-theme-link);
}

@keyframes public-badge-enter {
  from {
    opacity: 0;
    transform: translateY(7px);
  }
  to {
    opacity: 1;
    transform: translateY(0);
  }
}
  
@media (min-width: 760px) {
  .public-badge__hero {
    grid-template-columns: minmax(260px, 340px) 1fr;
    align-items: start;
  }

  .public-badge__wallet-path--device {
    display: none;
  }

  .public-badge__qr {
    grid-template-columns: auto minmax(0, 1fr);
    align-items: center;
    gap: 0.85rem 1rem;
    width: auto;
    max-width: 28rem;
  }

  .public-badge__qr-image {
    width: 9rem;
    height: 9rem;
  }

  .public-badge__qr-caption {
    max-width: none;
  }
}

@media (max-width: 759px) {
  .public-badge__status {
    flex-direction: column;
    align-items: flex-start;
  }

  .public-badge__trust-grid {
    grid-template-columns: minmax(0, 1fr);
  }
}

@media (prefers-reduced-motion: reduce) {
  .public-badge__card {
    animation: none;
  }
  .public-badge__button {
    transition: none;
  }
}

.badge-wall {
  display: grid;
  gap: 1rem;
  color: var(--ct-theme-text-title);
}

.badge-wall__hero {
  display: flex;
  flex-wrap: wrap;
  gap: clamp(1rem, 2vw, 1.4rem);
  align-items: center;
  padding: clamp(0.95rem, 2vw, 1.25rem);
  border: 1px solid var(--ct-theme-border-soft);
  border-radius: 1.25rem;
  background: var(--ct-theme-surface-card-strong);
  color: var(--ct-theme-text-title);
  box-shadow: var(--ct-theme-shadow-soft);
}

.badge-wall__hero-copy {
  display: grid;
  flex: 1 1 22rem;
  min-width: min(100%, 18rem);
  gap: 0.58rem;
  align-content: center;
}

.badge-wall__hero h1 {
  margin: 0;
  color: var(--ct-theme-text-title);
  font-size: clamp(1.3rem, 2.5vw, 1.65rem);
  line-height: 1.2;
}

.badge-wall__hero-image-frame {
  display: grid;
  flex: 0 0 clamp(10rem, 21vw, 13rem);
  place-items: center;
  width: clamp(10rem, 21vw, 13rem);
  border: 1px solid var(--ct-theme-border-soft);
  border-radius: 1.15rem;
  padding: 0.5rem;
  background: linear-gradient(
    180deg,
    var(--ct-theme-surface-card-strong),
    color-mix(in srgb, var(--ct-theme-surface-soft) 86%, var(--ct-theme-surface-card-strong))
  );
  box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.82);
}

.badge-wall__hero-image {
  display: block;
  box-sizing: border-box;
  width: 100%;
  aspect-ratio: 1;
  border: 1px solid var(--ct-theme-border-default);
  border-radius: 0.88rem;
  padding: clamp(0.4rem, 1.2vw, 0.58rem);
  object-fit: contain;
  background: var(--ct-theme-surface-card-strong);
}

.badge-wall__hero-image--placeholder {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  color: var(--ct-theme-text-on-brand);
  font-size: clamp(3rem, 10vw, 5.5rem);
  font-weight: 700;
  background: var(--ct-theme-gradient-hero);
}

.badge-wall__lead {
  margin: 0;
  max-width: 48rem;
  color: var(--ct-theme-text-muted);
  font-size: 0.92rem;
  line-height: 1.55;
}

.badge-wall__description {
  margin: 0;
  max-width: 54rem;
  color: var(--ct-theme-text-body);
  font-size: 0.96rem;
  line-height: 1.5;
}

.badge-wall__hero-actions {
  display: flex;
  flex-wrap: wrap;
  gap: 0.55rem;
  align-items: center;
}

.badge-wall__count {
  display: inline-flex;
  align-items: center;
  width: fit-content;
  margin: 0;
  padding: 0.25rem 0.65rem;
  border: 1px solid var(--ct-theme-border-soft);
  border-radius: 999px;
  background: var(--ct-theme-surface-soft);
  color: var(--ct-theme-text-muted);
  font-size: 0.82rem;
  font-weight: 600;
}

.badge-wall__hero-link {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  width: fit-content;
  min-height: 2.5rem;
  padding: 0.5rem 0.88rem;
  border: 1px solid var(--ct-theme-border-default);
  border-radius: 0.6rem;
  color: var(--ct-theme-text-body);
  text-decoration: none;
  font-size: 0.88rem;
  font-weight: 600;
  background: linear-gradient(
    180deg,
    var(--ct-theme-surface-card-strong),
    var(--ct-theme-surface-info)
  );
  transition:
    transform var(--ct-duration-fast) var(--ct-ease-standard),
    box-shadow var(--ct-duration-fast) var(--ct-ease-standard),
    border-color var(--ct-duration-fast) var(--ct-ease-standard);
}

.badge-wall__hero-link:hover,
.badge-wall__hero-link:focus-visible {
  color: var(--ct-theme-text-body);
  transform: translateY(-1px);
  box-shadow: var(--ct-theme-shadow-soft);
  border-color: var(--ct-theme-border-strong);
}
  
.badge-wall__list {
  margin: 0;
  padding: 0;
  list-style: none;
  border: 1px solid var(--ct-theme-border-soft);
  border-radius: 1rem;
  background: color-mix(
    in srgb,
    var(--ct-theme-surface-card-strong) 92%,
    var(--ct-theme-surface-soft)
  );
  box-shadow: var(--ct-theme-shadow-soft);
  overflow: hidden;
}
  
.badge-wall__item {
  padding: 0.95rem 1rem;
  background: transparent;
  animation: badge-wall-item-enter 420ms ease-out both;
}

.badge-wall__item + .badge-wall__item {
  border-top: 1px solid var(--ct-theme-border-soft);
}

.badge-wall__item:nth-child(2n) {
  animation-delay: 60ms;
}

.badge-wall__identity {
  display: flex;
  align-items: center;
  gap: 0.8rem;
  min-width: 0;
}
  
.badge-wall__recipient {
  display: flex;
  gap: 0.55rem;
  align-items: center;
  min-width: 0;
}

.badge-wall__summary {
  display: flex;
  gap: 1rem;
  align-items: center;
  justify-content: space-between;
}

.badge-wall__badge-image {
  width: 2.9rem;
  height: 2.9rem;
  border-radius: 0.65rem;
  border: 1px solid var(--ct-theme-border-default);
  object-fit: cover;
  background: var(--ct-theme-surface-info);
  flex: 0 0 auto;
}

.badge-wall__badge-image--placeholder {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  color: var(--ct-theme-text-on-brand);
  font-weight: 700;
  font-size: 1.3rem;
  text-transform: uppercase;
  background: var(--ct-theme-gradient-hero);
}
  
.badge-wall__avatar {
  width: 1.75rem;
  height: 1.75rem;
  border-radius: 999px;
  border: 1px solid var(--ct-theme-border-soft);
  object-fit: cover;
  background: var(--ct-theme-surface-info);
  flex: 0 0 auto;
}
  
.badge-wall__stack {
  display: grid;
  gap: 0.14rem;
  min-width: 0;
}
  
.badge-wall__name {
  margin: 0;
  font-weight: 700;
  font-size: 1rem;
  min-width: 0;
}
  
.badge-wall__badge-title {
  margin: 0;
  color: var(--ct-theme-text-body);
  font-size: 0.96rem;
}
  
.badge-wall__meta {
  margin: 0;
  color: var(--ct-theme-text-muted);
  font-size: 0.84rem;
}

.badge-wall__meta--verified {
  color: var(--ct-theme-text-body);
}

.badge-wall__meta--suspended {
  color: var(--ct-theme-state-warning);
}

.badge-wall__meta--revoked {
  color: var(--ct-theme-state-danger);
}

.badge-wall__meta--expired {
  color: var(--ct-theme-text-muted);
}

.badge-wall__meta--reason {
  color: var(--ct-theme-text-subtle);
  font-size: 0.82rem;
}
  
.badge-wall__url {
  margin: 0.42rem 0 0 0;
  font-size: 0.83rem;
  color: var(--ct-theme-text-subtle);
  font-family: var(--ct-font-mono);
  display: block;
  max-width: 100%;
  line-height: 1.3;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.badge-wall__actions {
  display: flex;
  flex-wrap: wrap;
  gap: 0.35rem;
  align-items: center;
  justify-content: flex-end;
  flex: 0 0 auto;
}

.badge-wall__button {
  display: inline-flex;
  flex: 0 0 auto;
  align-items: center;
  justify-content: center;
  appearance: none;
  border: 1px solid var(--ct-theme-border-default);
  border-radius: 0.55rem;
  min-height: 2.2rem;
  height: 2.2rem;
  padding: 0 0.7rem;
  font-size: 0.78rem;
  font-weight: 600;
  line-height: 1.2;
  color: var(--ct-theme-text-muted);
  background: var(--ct-theme-surface-card-strong);
  cursor: pointer;
  text-decoration: none;
  transition:
    transform var(--ct-duration-fast) var(--ct-ease-standard),
    box-shadow var(--ct-duration-fast) var(--ct-ease-standard),
    border-color var(--ct-duration-fast) var(--ct-ease-standard),
    color var(--ct-duration-fast) var(--ct-ease-standard);
}

.badge-wall__button:hover {
  color: var(--ct-theme-text-body);
  transform: translateY(-1px);
  box-shadow: var(--ct-theme-shadow-soft);
  border-color: var(--ct-theme-border-strong);
}

.badge-wall__button--primary {
  color: var(--ct-theme-link);
  border-color: var(--ct-theme-border-info);
  background: var(--ct-theme-surface-info);
  font-weight: 700;
}

.badge-wall__button--primary:hover {
  color: var(--ct-theme-link-hover);
  border-color: var(--ct-theme-link);
}

.badge-wall__copy-status {
  margin: 0;
  width: 100%;
  font-size: 0.75rem;
  color: var(--ct-theme-text-subtle);
  min-height: 1rem;
  text-align: right;
}
  
.badge-wall__empty {
  margin: 0;
  color: var(--ct-theme-text-muted);
}

@keyframes badge-wall-item-enter {
  from {
    opacity: 0;
    transform: translateY(6px);
  }
  to {
    opacity: 1;
    transform: translateY(0);
  }
}

@media (prefers-reduced-motion: reduce) {
  .badge-wall__item {
    animation: none;
  }
}

@media (max-width: 640px) {
  .badge-wall__hero {
    align-items: flex-start;
  }

  .badge-wall__hero-image-frame {
    flex-basis: 9.5rem;
    width: 9.5rem;
  }

  .badge-wall__summary {
    display: grid;
    grid-template-columns: minmax(0, 1fr);
    align-items: start;
  }

  .badge-wall__actions {
    justify-content: flex-start;
  }

  .badge-wall__copy-status {
    text-align: left;
  }
}

.criteria-registry {
  display: grid;
  gap: 1rem;
  color: var(--ct-theme-text-title);
}

.criteria-registry__hero {
  border: none;
  border-bottom: 1px solid var(--ct-theme-border-default);
  border-radius: 0;
  padding: 0 0 1rem 0;
  background: transparent;
  color: var(--ct-theme-text-title);
  box-shadow: none;
  display: grid;
  gap: 0.45rem;
}

.criteria-registry__hero h1 {
  margin: 0;
  color: var(--ct-theme-text-title);
}

.criteria-registry__hero p {
  margin: 0;
  color: var(--ct-theme-text-muted);
}

.criteria-registry__hero-link {
  display: inline-flex;
  align-items: center;
  min-height: 2.75rem;
  width: fit-content;
  color: var(--ct-theme-link);
  font-weight: 600;
}

.criteria-registry__hero-link:hover,
.criteria-registry__hero-link:focus-visible {
  color: var(--ct-theme-link-hover);
}

.criteria-registry__template-grid {
  display: grid;
  gap: 0.9rem;
}

.criteria-registry__template-card {
  border: 1px solid var(--ct-theme-border-default);
  border-radius: 0.95rem;
  padding: 0.9rem;
  background: linear-gradient(
    165deg,
    var(--ct-theme-surface-card-strong),
    var(--ct-theme-surface-soft)
  );
  box-shadow: var(--ct-theme-shadow-soft);
  display: grid;
  gap: 0.55rem;
}

.criteria-registry__template-header {
  display: grid;
  grid-template-columns: auto 1fr;
  gap: 0.66rem;
  align-items: center;
}

.criteria-registry__template-header h2 {
  margin: 0;
}

.criteria-registry__template-image {
  width: 3.25rem;
  height: 3.25rem;
  border-radius: 0.58rem;
  border: 1px solid var(--ct-theme-border-default);
  object-fit: cover;
  background: var(--ct-theme-surface-info);
}

.criteria-registry__template-image--placeholder {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  color: var(--ct-theme-text-on-brand);
  font-weight: 700;
  font-size: 1.2rem;
  background: var(--ct-theme-gradient-hero);
}

.criteria-registry__template-meta {
  display: grid;
  gap: 0.2rem;
}

.criteria-registry__description {
  margin: 0;
  color: var(--ct-theme-text-body);
  line-height: 1.45;
}

.criteria-registry__facts {
  margin: 0;
  padding: 0;
  display: grid;
  gap: 0.45rem;
  grid-template-columns: repeat(auto-fit, minmax(14rem, 1fr));
}

.criteria-registry__fact {
  margin: 0;
  padding: 0.44rem 0.56rem;
  border: 1px solid var(--ct-theme-border-soft);
  border-radius: 0.62rem;
  background: var(--ct-theme-surface-info);
  display: grid;
  gap: 0.15rem;
}

.criteria-registry__fact dt {
  margin: 0;
  font-size: 0.74rem;
  text-transform: uppercase;
  letter-spacing: 0.08em;
  color: var(--ct-theme-text-muted);
  font-weight: 700;
}

.criteria-registry__fact dd {
  margin: 0;
  color: var(--ct-theme-text-body);
  word-break: break-word;
}

.criteria-registry__fact dd a {
  display: inline-flex;
  align-items: center;
  min-height: 2.75rem;
  max-width: 100%;
}

.criteria-registry__muted {
  margin: 0;
  color: var(--ct-theme-text-muted);
  font-size: 0.9rem;
}

.criteria-registry__section {
  border-top: 1px solid var(--ct-theme-border-soft);
  padding-top: 0.6rem;
  display: grid;
  gap: 0.48rem;
}

.criteria-registry__section h3 {
  margin: 0;
  font-size: 1rem;
}

.criteria-registry__actions {
  margin: 0;
  display: inline-flex;
  width: fit-content;
}

.criteria-registry__actions a {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  min-height: 2.75rem;
  font-weight: 700;
}

.criteria-registry__rule {
  border: 1px solid var(--ct-theme-border-soft);
  border-radius: 0.72rem;
  padding: 0.58rem;
  background: var(--ct-theme-surface-info);
  display: grid;
  gap: 0.5rem;
}

.criteria-registry__rule h3 {
  margin: 0;
  font-size: 0.98rem;
}

.criteria-registry__stack-sm {
  display: grid;
  gap: 0.36rem;
}

.criteria-registry__stack-sm p {
  margin: 0;
}

.criteria-registry__conditions,
.criteria-registry__conditions ul,
.criteria-registry__approval-steps,
.criteria-registry__approval-events,
.criteria-registry__timeline {
  margin: 0;
  padding-left: 1.2rem;
  display: grid;
  gap: 0.3rem;
}

.criteria-registry__approval-steps p,
.criteria-registry__timeline p {
  margin: 0;
}

.criteria-registry__details {
  border: 1px solid var(--ct-theme-border-default);
  border-radius: 0.64rem;
  padding: 0.52rem 0.6rem;
  background: var(--ct-theme-surface-soft);
}

.criteria-registry__details summary {
  display: flex;
  align-items: center;
  min-height: 2.75rem;
  cursor: pointer;
  font-weight: 700;
  color: var(--ct-theme-text-body);
}

.criteria-registry__details-body {
  margin-top: 0.55rem;
}

.criteria-registry__pre {
  margin: 0.55rem 0 0 0;
  padding: 0.55rem;
  border-radius: 0.58rem;
  border: 1px solid var(--ct-theme-border-default);
  background: var(--ct-theme-surface-info);
  color: var(--ct-theme-text-body);
  font-size: 0.8rem;
  overflow: auto;
  max-height: 14rem;
}

.criteria-registry__empty {
  margin: 0;
  color: var(--ct-theme-text-muted);
  border: 1px solid var(--ct-theme-border-default);
  border-radius: 0.82rem;
  padding: 0.75rem;
  background: var(--ct-theme-surface-shell);
}

@media (max-width: 640px) {
  .criteria-registry__actions {
    width: 100%;
  }

  .criteria-registry__actions a {
    width: 100%;
  }

  .criteria-registry__template-header {
    grid-template-columns: 1fr;
    align-items: start;
  }
}
`;

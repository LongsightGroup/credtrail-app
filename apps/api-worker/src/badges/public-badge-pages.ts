import type { JsonObject } from '@credtrail/core-domain';
import type { AssertionRecord, PublicBadgeWallEntryRecord } from '@credtrail/db';
import { renderPageShell } from '@credtrail/ui-components';
import type { VerificationViewModel } from './public-badge-model';

interface AchievementDetails {
  badgeClassUri: string | null;
  description: string | null;
  criteriaUri: string | null;
  imageUri: string | null;
}

interface EvidenceDetails {
  uri: string;
  name: string | null;
  description: string | null;
}

interface CreatePublicBadgePageRenderersInput {
  asString: (value: unknown) => string | null;
  achievementDetailsFromCredential: (credential: JsonObject) => AchievementDetails;
  badgeHeroImageMarkup: (badgeName: string, imageUri: string | null) => string;
  badgeNameFromCredential: (credential: JsonObject) => string;
  evidenceDetailsFromCredential: (credential: JsonObject) => EvidenceDetails[];
  escapeHtml: (value: string) => string;
  formatIsoTimestamp: (timestampIso: string) => string;
  githubAvatarUrlForUsername: (username: string) => string;
  githubUsernameFromUrl: (value: string) => string | null;
  imsOb2ValidatorUrl: (targetUrl: string) => string;
  isWebUrl: (value: string) => boolean;
  issuerIdentifierFromCredential: (credential: JsonObject) => string | null;
  issuerNameFromCredential: (credential: JsonObject) => string;
  issuerUrlFromCredential: (credential: JsonObject) => string | null;
  linkedInAddToProfileUrl: (input: {
    badgeName: string;
    issuerName: string;
    issuedAtIso: string;
    credentialUrl: string;
    credentialId: string;
  }) => string;
  publicBadgePathForAssertion: (assertion: AssertionRecord) => string;
  recipientAvatarUrlFromAssertion: (assertion: AssertionRecord) => string | null;
  recipientDisplayNameFromAssertion: (assertion: AssertionRecord) => string | null;
  recipientFromCredential: (credential: JsonObject) => string;
}

interface PublicBadgePageRenderers {
  publicBadgeNotFoundPage: () => string;
  publicBadgePage: (requestUrl: string, model: VerificationViewModel) => string;
  tenantBadgeWallPage: (
    requestUrl: string,
    tenantId: string,
    entries: readonly PublicBadgeWallEntryRecord[],
    filterBadgeTemplateId: string | null,
  ) => string;
}

export const createPublicBadgePageRenderers = (
  input: CreatePublicBadgePageRenderersInput,
): PublicBadgePageRenderers => {
  const {
    asString,
    achievementDetailsFromCredential,
    badgeHeroImageMarkup,
    badgeNameFromCredential,
    evidenceDetailsFromCredential,
    escapeHtml,
    formatIsoTimestamp,
    githubAvatarUrlForUsername,
    githubUsernameFromUrl,
    imsOb2ValidatorUrl,
    isWebUrl,
    issuerIdentifierFromCredential,
    issuerNameFromCredential,
    issuerUrlFromCredential,
    linkedInAddToProfileUrl,
    publicBadgePathForAssertion,
    recipientAvatarUrlFromAssertion,
    recipientDisplayNameFromAssertion,
    recipientFromCredential,
  } = input;
  const publicBadgeNotFoundPage = (): string => {
    return renderPageShell(
      'Badge not found',
      `<section style="display:grid;gap:1rem;max-width:40rem;">
        <h1 style="margin:0;">Badge not found</h1>
        <p style="margin:0;">The shared badge URL is invalid or the credential does not exist.</p>
      </section>`,
    );
  };
  
  const publicBadgePage = (requestUrl: string, model: VerificationViewModel): string => {
    const badgeName = badgeNameFromCredential(model.credential);
    const issuerName = issuerNameFromCredential(model.credential);
    const issuerUrl = issuerUrlFromCredential(model.credential);
    const issuerIdentifier = issuerIdentifierFromCredential(model.credential);
    const recipientIdentifier = recipientFromCredential(model.credential);
    const recipientName =
      model.recipientDisplayName ??
      recipientDisplayNameFromAssertion(model.assertion) ??
      'Badge recipient';
    const recipientAvatarUrl = recipientAvatarUrlFromAssertion(model.assertion);
    const achievementDetails = achievementDetailsFromCredential(model.credential);
    const evidenceDetails = evidenceDetailsFromCredential(model.credential);
    const achievementImage = badgeHeroImageMarkup(badgeName, achievementDetails.imageUri);
    const credentialUri = asString(model.credential.id) ?? model.assertion.id;
    const isRevoked = model.assertion.revokedAt !== null;
    const verificationLabel = isRevoked ? 'Revoked' : 'Verified';
    const publicBadgePath = publicBadgePathForAssertion(model.assertion);
    const publicBadgeUrl = new URL(publicBadgePath, requestUrl).toString();
    const verificationApiPath = `/credentials/v1/${encodeURIComponent(model.assertion.id)}`;
    const verificationApiUrl = new URL(verificationApiPath, requestUrl).toString();
    const ob3JsonPath = `/credentials/v1/${encodeURIComponent(model.assertion.id)}/jsonld`;
    const ob3JsonUrl = new URL(ob3JsonPath, requestUrl).toString();
    const credentialDownloadPath = `/credentials/v1/${encodeURIComponent(model.assertion.id)}/download`;
    const credentialDownloadUrl = new URL(credentialDownloadPath, requestUrl).toString();
    const credentialPdfDownloadPath = `/credentials/v1/${encodeURIComponent(model.assertion.id)}/download.pdf`;
    const credentialPdfDownloadUrl = new URL(credentialPdfDownloadPath, requestUrl).toString();
    const assertionValidationTargetUrl = ob3JsonUrl;
    const badgeClassValidationTargetUrl = achievementDetails.badgeClassUri ?? publicBadgeUrl;
    const issuerValidationTargetUrl =
      issuerUrl ??
      (issuerIdentifier !== null && isWebUrl(issuerIdentifier) ? issuerIdentifier : publicBadgeUrl);
    const assertionValidatorUrl = imsOb2ValidatorUrl(assertionValidationTargetUrl);
    const badgeClassValidatorUrl = imsOb2ValidatorUrl(badgeClassValidationTargetUrl);
    const issuerValidatorUrl = imsOb2ValidatorUrl(issuerValidationTargetUrl);
    const qrCodeImageUrl = new URL('https://api.qrserver.com/v1/create-qr-code/');
    qrCodeImageUrl.searchParams.set('size', '220x220');
    qrCodeImageUrl.searchParams.set('format', 'svg');
    qrCodeImageUrl.searchParams.set('margin', '0');
    qrCodeImageUrl.searchParams.set('data', publicBadgeUrl);
    const linkedInAddProfileUrl = linkedInAddToProfileUrl({
      badgeName,
      issuerName,
      issuedAtIso: model.assertion.issuedAt,
      credentialUrl: publicBadgeUrl,
      credentialId: credentialUri,
    });
    const linkedInShareUrl = new URL('https://www.linkedin.com/sharing/share-offsite/');
    linkedInShareUrl.searchParams.set('url', publicBadgeUrl);
    const issuedAt = `${formatIsoTimestamp(model.assertion.issuedAt)} UTC`;
    const issuerLine =
      issuerUrl === null
        ? `<span>${escapeHtml(issuerName)}</span>`
        : `<a href="${escapeHtml(issuerUrl)}" target="_blank" rel="noopener noreferrer">${escapeHtml(
            issuerName,
          )}</a>`;
    const recipientIdentifierLine = '';
    const recipientAvatarSection =
      recipientAvatarUrl === null
        ? ''
        : `<img
            class="public-badge__recipient-avatar"
            src="${escapeHtml(recipientAvatarUrl)}"
            alt="${escapeHtml(`${recipientName} GitHub avatar`)}"
            loading="lazy"
          />`;
    const criteriaSection =
      achievementDetails.criteriaUri === null
        ? ''
        : `<p class="public-badge__achievement-copy">
            Criteria:
            <a href="${escapeHtml(achievementDetails.criteriaUri)}" target="_blank" rel="noopener noreferrer">
              ${escapeHtml(achievementDetails.criteriaUri)}
            </a>
          </p>`;
    const revokedDetails =
      model.assertion.revokedAt === null
        ? ''
        : `<p class="public-badge__status-note">Revoked at ${escapeHtml(
            formatIsoTimestamp(model.assertion.revokedAt),
          )} UTC</p>`;
    const achievementDescriptionSection =
      achievementDetails.description === null
        ? '<p class="public-badge__achievement-copy">No additional description provided.</p>'
        : `<p class="public-badge__achievement-copy">${escapeHtml(achievementDetails.description)}</p>`;
    const evidenceSection =
      evidenceDetails.length === 0
        ? ''
        : `<section class="public-badge__card public-badge__stack-sm">
            <h2 class="public-badge__section-title">Evidence</h2>
            <ul class="public-badge__evidence-list">
              ${evidenceDetails
                .map((entry) => {
                  const label = entry.name ?? entry.uri;
                  const description =
                    entry.description === null
                      ? ''
                      : `<p class="public-badge__evidence-description">${escapeHtml(
                          entry.description,
                        )}</p>`;
  
                  return `<li class="public-badge__evidence-item">
                    <a href="${escapeHtml(entry.uri)}" target="_blank" rel="noopener noreferrer">
                      ${escapeHtml(label)}
                    </a>
                    ${description}
                  </li>`;
                })
                .join('')}
            </ul>
          </section>`;
  
    return renderPageShell(
      `${badgeName} | CredTrail`,
      `<style>
        .public-badge {
          display: grid;
          gap: 1.2rem;
          color: #0f172a;
        }
  
        .public-badge__card {
          background: #ffffff;
          border: 1px solid #d6dfeb;
          border-radius: 1rem;
          box-shadow: 0 16px 36px rgba(15, 23, 42, 0.07);
          padding: 1.25rem;
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
          color: #f8fafc;
          font-weight: 600;
        }
  
        .public-badge__status--verified {
          background: linear-gradient(135deg, #166534 0%, #14532d 65%);
        }
  
        .public-badge__status--revoked {
          background: linear-gradient(135deg, #b42318 0%, #8f1c13 65%);
        }
  
        .public-badge__status-note {
          margin: 0;
          color: #7f1d1d;
          font-size: 0.95rem;
        }
  
        .public-badge__hero {
          display: grid;
          gap: 1.1rem;
        }
  
        .public-badge__hero-image {
          display: block;
          width: 100%;
          max-width: 420px;
          border: 1px solid #d6dfeb;
          border-radius: 1rem;
          box-shadow: 0 14px 28px rgba(20, 83, 45, 0.18);
        }
  
        .public-badge__hero-meta {
          display: grid;
          gap: 0.5rem;
        }
  
        .public-badge__eyebrow {
          margin: 0;
          text-transform: uppercase;
          letter-spacing: 0.08em;
          font-size: 0.8rem;
          color: #166534;
          font-weight: 700;
        }
  
        .public-badge__title {
          margin: 0;
          font-size: clamp(1.65rem, 3.7vw, 2.45rem);
          line-height: 1.15;
        }
  
        .public-badge__issuer,
        .public-badge__issued-at,
        .public-badge__recipient-meta {
          margin: 0;
          color: #334155;
        }
  
        .public-badge__recipient-name {
          margin: 0;
          font-size: 1.35rem;
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
          border: 1px solid #d6dfeb;
          object-fit: cover;
          background: #f8fafc;
        }
  
        .public-badge__section-title {
          margin: 0;
          font-size: 1.12rem;
        }
  
        .public-badge__achievement-copy {
          margin: 0;
          color: #334155;
        }
  
        .public-badge__actions {
          display: flex;
          flex-wrap: wrap;
          gap: 0.6rem;
          align-items: center;
        }
  
        .public-badge__button {
          border: 1px solid #166534;
          border-radius: 0.75rem;
          padding: 0.48rem 0.86rem;
          text-decoration: none;
          font-weight: 600;
          color: #166534;
          background: #f8fafc;
          cursor: pointer;
        }
  
        .public-badge__button--primary {
          background: #166534;
          color: #f8fafc;
        }
  
        .public-badge__button--accent {
          border-color: #fbbf24;
          background: #fffbeb;
        }
  
        .public-badge__copy-status {
          margin: 0;
          color: #334155;
          font-size: 0.92rem;
        }
  
        .public-badge__validator-links {
          display: flex;
          flex-wrap: wrap;
          gap: 0.6rem;
        }
  
        .public-badge__validator-note {
          margin: 0;
          color: #475569;
          font-size: 0.92rem;
        }
  
        .public-badge__qr {
          margin: 0;
          display: grid;
          justify-items: start;
          gap: 0.45rem;
        }
  
        .public-badge__qr-image {
          width: 11rem;
          height: 11rem;
          border-radius: 0.9rem;
          border: 1px solid #d6dfeb;
          background: #ffffff;
        }
  
        .public-badge__qr-caption {
          color: #475569;
          font-size: 0.9rem;
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
          color: #3d4b66;
        }
  
        .public-badge__technical summary {
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
        }
  
        .public-badge__technical-grid dd {
          margin: 0;
          overflow-wrap: anywhere;
        }
  
        @media (min-width: 760px) {
          .public-badge__hero {
            grid-template-columns: minmax(260px, 340px) 1fr;
            align-items: start;
          }
        }
      </style>
      <article class="public-badge">
        <section class="public-badge__card public-badge__status public-badge__status--${
          isRevoked ? 'revoked' : 'verified'
        }">
          <span>${escapeHtml(verificationLabel)}</span>
          <span>${escapeHtml(issuedAt)}</span>
        </section>
  
        <section class="public-badge__card public-badge__hero">
          ${achievementImage}
          <div class="public-badge__hero-meta">
            <p class="public-badge__eyebrow">Open Badges 3.0 Credential</p>
            <h1 class="public-badge__title">${escapeHtml(badgeName)}</h1>
            <p class="public-badge__issuer">Issued by ${issuerLine}</p>
            <p class="public-badge__issued-at">Issued ${escapeHtml(issuedAt)}</p>
            ${revokedDetails}
          </div>
        </section>
  
        <section class="public-badge__card public-badge__stack-sm">
          <h2 class="public-badge__section-title">Recipient</h2>
          <div class="public-badge__recipient-header">
            ${recipientAvatarSection}
            <p class="public-badge__recipient-name">${escapeHtml(recipientName)}</p>
          </div>
          ${recipientIdentifierLine}
        </section>
  
        <section class="public-badge__card public-badge__stack-sm">
          <h2 class="public-badge__section-title">Achievement</h2>
          ${achievementDescriptionSection}
          ${criteriaSection}
        </section>
  
        ${evidenceSection}
  
        <section class="public-badge__card public-badge__stack-sm">
          <h2 class="public-badge__section-title">Share and verify</h2>
          <div class="public-badge__actions">
            <button
              id="copy-badge-url-button"
              class="public-badge__button public-badge__button--primary"
              type="button"
              data-copy-value="${escapeHtml(publicBadgeUrl)}"
            >
              Copy URL
            </button>
            <a class="public-badge__button" href="${escapeHtml(ob3JsonPath)}">Open Badges 3.0 JSON</a>
            <a class="public-badge__button" href="${escapeHtml(credentialDownloadPath)}">Download VC</a>
            <a class="public-badge__button" href="${escapeHtml(credentialPdfDownloadPath)}">Download PDF</a>
            <a
              class="public-badge__button public-badge__button--accent"
              href="${escapeHtml(linkedInAddProfileUrl)}"
              target="_blank"
              rel="noopener noreferrer"
            >
              Add to LinkedIn Profile
            </a>
            <a
              class="public-badge__button"
              href="${escapeHtml(linkedInShareUrl.toString())}"
              target="_blank"
              rel="noopener noreferrer"
            >
              Share on LinkedIn Feed
            </a>
          </div>
          <p id="copy-badge-url-status" class="public-badge__copy-status" aria-live="polite"></p>
          <div class="public-badge__validator-links">
            <a
              class="public-badge__button"
              href="${escapeHtml(assertionValidatorUrl)}"
              target="_blank"
              rel="noopener noreferrer"
            >
              Validate Assertion (IMS)
            </a>
            <a
              class="public-badge__button"
              href="${escapeHtml(badgeClassValidatorUrl)}"
              target="_blank"
              rel="noopener noreferrer"
            >
              Validate Badge Class (IMS)
            </a>
            <a
              class="public-badge__button"
              href="${escapeHtml(issuerValidatorUrl)}"
              target="_blank"
              rel="noopener noreferrer"
            >
              Validate Issuer (IMS)
            </a>
          </div>
          <p class="public-badge__validator-note">
            Opens IMS Global OB2 validator with pre-filled URLs for assertion, badge class, and issuer checks.
          </p>
          <figure class="public-badge__qr">
            <img
              class="public-badge__qr-image"
              src="${escapeHtml(qrCodeImageUrl.toString())}"
              alt="QR code for this badge URL"
              loading="lazy"
            />
            <figcaption class="public-badge__qr-caption">Scan to open the public badge URL.</figcaption>
          </figure>
        </section>
  
        <details class="public-badge__card public-badge__technical">
          <summary>Technical details</summary>
          <dl class="public-badge__technical-grid">
            <dt>Issuer ID</dt>
            <dd>${escapeHtml(issuerIdentifier ?? 'Not available')}</dd>
            <dt>Recipient identity</dt>
            <dd>${escapeHtml(model.assertion.recipientIdentity)}</dd>
            <dt>Recipient identity type</dt>
            <dd>${escapeHtml(model.assertion.recipientIdentityType)}</dd>
            <dt>Credential ID</dt>
            <dd>${escapeHtml(credentialUri)}</dd>
            <dt>Assertion ID</dt>
            <dd>${escapeHtml(model.assertion.id)}</dd>
            <dt>Recipient ID</dt>
            <dd>${escapeHtml(recipientIdentifier)}</dd>
            <dt>Verification JSON</dt>
            <dd><a href="${escapeHtml(verificationApiPath)}">${escapeHtml(verificationApiUrl)}</a></dd>
            <dt>Open Badges 3.0 JSON</dt>
            <dd><a href="${escapeHtml(ob3JsonPath)}">${escapeHtml(ob3JsonUrl)}</a></dd>
            <dt>Credential download</dt>
            <dd><a href="${escapeHtml(credentialDownloadPath)}">${escapeHtml(credentialDownloadUrl)}</a></dd>
            <dt>Credential PDF download</dt>
            <dd><a href="${escapeHtml(credentialPdfDownloadPath)}">${escapeHtml(credentialPdfDownloadUrl)}</a></dd>
            <dt>IMS assertion validation</dt>
            <dd><a href="${escapeHtml(assertionValidatorUrl)}">${escapeHtml(assertionValidatorUrl)}</a></dd>
            <dt>IMS badge class validation</dt>
            <dd><a href="${escapeHtml(badgeClassValidatorUrl)}">${escapeHtml(badgeClassValidatorUrl)}</a></dd>
            <dt>IMS issuer validation</dt>
            <dd><a href="${escapeHtml(issuerValidatorUrl)}">${escapeHtml(issuerValidatorUrl)}</a></dd>
          </dl>
        </details>
  
        <script>
          (() => {
            const button = document.getElementById('copy-badge-url-button');
            const status = document.getElementById('copy-badge-url-status');
  
            if (!(button instanceof HTMLButtonElement) || !(status instanceof HTMLElement)) {
              return;
            }
  
            const value = button.dataset.copyValue;
  
            if (typeof value !== 'string' || value.length === 0) {
              return;
            }
  
            button.addEventListener('click', async () => {
              try {
                await navigator.clipboard.writeText(value);
                status.textContent = 'Badge URL copied';
              } catch {
                status.textContent = 'Unable to copy URL automatically';
              }
            });
          })();
        </script>
      </article>`,
      `<link rel="canonical" href="${escapeHtml(publicBadgeUrl)}" />
      <link rel="alternate" type="application/ld+json" href="${escapeHtml(ob3JsonPath)}" />`,
    );
  };

  const tenantBadgeWallPage = (
    requestUrl: string,
    tenantId: string,
    entries: readonly PublicBadgeWallEntryRecord[],
    filterBadgeTemplateId: string | null,
  ): string => {
    const title =
      filterBadgeTemplateId === null ? `Badge Wall · ${tenantId}` : `Badge Wall · ${tenantId}`;
    const subtitle =
      filterBadgeTemplateId === null
        ? `Public badge URLs issued under tenant "${tenantId}".`
        : `Public badge URLs issued under tenant "${tenantId}" for badge template "${filterBadgeTemplateId}".`;
    const cards =
      entries.length === 0
        ? ''
        : entries
            .map((entry) => {
              const username = githubUsernameFromUrl(entry.recipientIdentity);
              const recipientLabel = username === null ? entry.recipientIdentity : `@${username}`;
              const avatarUrl = username === null ? null : githubAvatarUrlForUsername(username);
              const badgePath = `/badges/${encodeURIComponent(entry.assertionPublicId)}`;
              const badgeUrl = new URL(badgePath, requestUrl).toString();
              const issuedAt = `${formatIsoTimestamp(entry.issuedAt)} UTC`;
              const statusLabel = entry.revokedAt === null ? 'Verified' : 'Revoked';
              const revokedLine =
                entry.revokedAt === null
                  ? ''
                  : `<p class="badge-wall__meta">Revoked ${escapeHtml(
                      formatIsoTimestamp(entry.revokedAt),
                    )} UTC</p>`;
              const avatarMarkup =
                avatarUrl === null
                  ? ''
                  : `<img
                      class="badge-wall__avatar"
                      src="${escapeHtml(avatarUrl)}"
                      alt="${escapeHtml(`${recipientLabel} GitHub avatar`)}"
                      loading="lazy"
                    />`;
  
              return `<li class="badge-wall__item">
                <div class="badge-wall__recipient">
                  ${avatarMarkup}
                  <div class="badge-wall__stack">
                    <p class="badge-wall__name">${escapeHtml(recipientLabel)}</p>
                    <p class="badge-wall__badge-title">${escapeHtml(entry.badgeTitle)}</p>
                    <p class="badge-wall__meta">${escapeHtml(statusLabel)} · Issued ${escapeHtml(issuedAt)}</p>
                    ${revokedLine}
                  </div>
                </div>
                <p class="badge-wall__url">
                  <a href="${escapeHtml(badgePath)}">${escapeHtml(badgeUrl)}</a>
                </p>
              </li>`;
            })
            .join('');
    const listMarkup =
      entries.length === 0
        ? '<p class="badge-wall__empty">No public badges found for this showcase.</p>'
        : `<ol class="badge-wall__list">${cards}</ol>`;
  
    return renderPageShell(
      `${title} | CredTrail`,
      `<style>
        .badge-wall {
          display: grid;
          gap: 1rem;
          color: #0f172a;
        }
  
        .badge-wall__lead {
          margin: 0;
          color: #475569;
        }
  
        .badge-wall__count {
          margin: 0;
          font-weight: 600;
        }
  
        .badge-wall__list {
          margin: 0;
          padding: 0;
          list-style: none;
          display: grid;
          gap: 0.75rem;
        }
  
        .badge-wall__item {
          border: 1px solid #d6dfeb;
          border-radius: 0.9rem;
          background: #ffffff;
          box-shadow: 0 10px 24px rgba(15, 23, 42, 0.05);
          padding: 0.9rem;
          display: grid;
          gap: 0.65rem;
        }
  
        .badge-wall__recipient {
          display: flex;
          gap: 0.75rem;
          align-items: center;
        }
  
        .badge-wall__avatar {
          width: 2.7rem;
          height: 2.7rem;
          border-radius: 999px;
          border: 1px solid #d6dfeb;
          object-fit: cover;
          background: #f8fafc;
        }
  
        .badge-wall__stack {
          display: grid;
          gap: 0.2rem;
        }
  
        .badge-wall__name {
          margin: 0;
          font-weight: 700;
        }
  
        .badge-wall__badge-title {
          margin: 0;
          color: #334155;
        }
  
        .badge-wall__meta {
          margin: 0;
          color: #475569;
          font-size: 0.92rem;
        }
  
        .badge-wall__url {
          margin: 0;
          overflow-wrap: anywhere;
        }
  
        .badge-wall__empty {
          margin: 0;
          color: #475569;
        }
      </style>
      <section class="badge-wall">
        <h1 style="margin:0;">${escapeHtml(title)}</h1>
        <p class="badge-wall__lead">${escapeHtml(subtitle)}</p>
        <p class="badge-wall__count">${escapeHtml(String(entries.length))} issued badges</p>
        ${listMarkup}
      </section>`,
    );
  };

  return {
    publicBadgeNotFoundPage,
    publicBadgePage,
    tenantBadgeWallPage,
  };
};

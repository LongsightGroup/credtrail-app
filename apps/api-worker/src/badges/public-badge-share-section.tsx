import type { HonoElement } from "./public-badge-ui";
import {
  PublicBadgeButtonLink,
  PublicBadgeTextButton,
  PublicBadgeTextLink,
} from "./public-badge-ui";

export type PublicBadgeClaimStatusNotice = "recorded" | "already_recorded";

const claimStatusLabel = (notice: PublicBadgeClaimStatusNotice): string => {
  return notice === "recorded" ? "Claim recorded" : "Claim already recorded";
};

const claimStatusCopy = (notice: PublicBadgeClaimStatusNotice): string => {
  return notice === "recorded"
    ? "Credential claim recorded in CredTrail. You can share this public verification page now."
    : "Credential claim was already recorded in CredTrail. You can keep sharing this public verification page.";
};

export const PublicBadgeShareSection = (input: {
  linkedInProfileSharePath: string;
  linkedInFeedSharePath: string;
  walletQrCodePath: string;
  walletDeepLinkUrl: string;
  ob3JsonPath: string;
  claimStatusNotice: PublicBadgeClaimStatusNotice | null;
}): HonoElement => {
  const claimStatusNotice = input.claimStatusNotice;

  return (
    <section
      id="share-this-credential"
      class="public-badge__card public-badge__stack-sm public-badge__share"
    >
      <header class="public-badge__section-heading-row">
        <h2 class="public-badge__section-title">Share this credential</h2>
        {claimStatusNotice === null ? null : (
          <span class="public-badge__metadata-badge" role="status" aria-live="polite">
            {claimStatusLabel(claimStatusNotice)}
          </span>
        )}
      </header>
      {claimStatusNotice === null ? null : (
        <p class="public-badge__achievement-copy">{claimStatusCopy(claimStatusNotice)}</p>
      )}
      <p class="public-badge__achievement-copy">
        Add it to your LinkedIn profile so recruiters can find it.
      </p>
      <div class="public-badge__share-actions">
        <PublicBadgeButtonLink
          href={input.linkedInProfileSharePath}
          variant="primary"
          target="_blank"
          rel="noopener noreferrer"
        >
          Add to LinkedIn Profile
        </PublicBadgeButtonLink>
        <p class="public-badge__share-feed-link">
          <PublicBadgeTextLink
            href={input.linkedInFeedSharePath}
            target="_blank"
            rel="noopener noreferrer"
          >
            Share to LinkedIn feed
          </PublicBadgeTextLink>
        </p>
      </div>
      <details class="public-badge__share-more">
        <summary>Wallet &amp; downloads</summary>
        <div class="public-badge__share-groups">
          <div class="public-badge__wallet-paths">
            <section class="public-badge__wallet-path public-badge__wallet-path--phone">
              <h3 class="public-badge__wallet-path-title">On your phone</h3>
              <figure class="public-badge__qr">
                <img
                  class="public-badge__qr-image"
                  src={input.walletQrCodePath}
                  alt="QR code to import this credential into your wallet"
                  loading="lazy"
                />
                <figcaption class="public-badge__qr-caption">
                  Scan with your phone camera or wallet app.
                </figcaption>
              </figure>
            </section>
            <section class="public-badge__wallet-path public-badge__wallet-path--device">
              <h3 class="public-badge__wallet-path-title">On this device</h3>
              <p class="public-badge__wallet-path-copy">
                Open your wallet app to import this credential.
              </p>
              <p class="public-badge__link-row">
                <PublicBadgeTextLink
                  href={input.walletDeepLinkUrl}
                  target="_blank"
                  rel="noopener noreferrer"
                >
                  Open in wallet app
                </PublicBadgeTextLink>
              </p>
              <p
                id="chapi-store-row"
                class="public-badge__link-row public-badge__wallet-browser-row"
                hidden
              >
                <PublicBadgeTextButton
                  id="chapi-store-link"
                  type="button"
                  dataCredentialJsonUrl={input.ob3JsonPath}
                >
                  Save in this browser
                </PublicBadgeTextButton>
              </p>
              <p id="chapi-store-status" class="public-badge__copy-status" aria-live="polite"></p>
            </section>
          </div>
        </div>
      </details>
    </section>
  );
};

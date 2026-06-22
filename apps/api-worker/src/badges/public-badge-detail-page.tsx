import { VC_JSON_LD_MEDIA_TYPE } from "../http/vc-media-types";
import { appPage, type AppPage } from "../ui/render-page";
import { badgeTemplateCriteriaRegistryHref } from "./badge-template-public-links";
import { badgeInitialsFromName } from "./pdf";
import {
  buildSeoHeadContent,
  hasContextUrl,
  nonEmptyText,
  resolveAbsoluteWebUrl,
  VC_DATA_MODEL_V2_CONTEXT_URL,
} from "./public-badge-renderer-helpers";
import type {
  CreatePublicBadgePageRenderersInput,
  PublicBadgePageRenderers,
} from "./public-badge-renderer-types";
import type { VerificationViewModel } from "./public-badge-model";
import { PublicBadgeTrustEdCredentialSection } from "./public-badge-trusted-credential-section";
import { PublicBadgeButton, PublicBadgeButtonLink, PublicBadgeTextLink } from "./public-badge-ui";

export const createPublicBadgePage = (
  input: CreatePublicBadgePageRenderersInput,
): PublicBadgePageRenderers["publicBadgePage"] => {
  const {
    asString,
    achievementDetailsFromCredential,
    badgeNameFromCredential,
    evidenceDetailsFromCredential,
    formatIsoTimestamp,
    imsOb3ValidatorUrl,
    isWebUrl,
    issuerIdentifierFromCredential,
    issuerNameFromCredential,
    issuerUrlFromCredential,
    publicBadgePathForAssertion,
    recipientAvatarUrlFromAssertion,
    recipientDisplayNameFromAssertion,
    recipientFromCredential,
    trustEdCredentialDetailsFromCredential,
  } = input;
  const toAbsoluteWebUrl = (requestUrl: string, value: string | null): string | null => {
    return resolveAbsoluteWebUrl({ requestUrl, value, isWebUrl });
  };

  return (requestUrl: string, model: VerificationViewModel): AppPage => {
    const badgeName = badgeNameFromCredential(model.credential);
    const issuerName = issuerNameFromCredential(model.credential);
    const issuerUrl = issuerUrlFromCredential(model.credential);
    const issuerIdentifier = issuerIdentifierFromCredential(model.credential);
    const recipientIdentifier = recipientFromCredential(model.credential);
    const recipientName =
      model.recipientDisplayName ??
      recipientDisplayNameFromAssertion(model.assertion) ??
      "Badge recipient";
    const recipientAvatarUrl = recipientAvatarUrlFromAssertion(model.assertion);
    const achievementDetails = achievementDetailsFromCredential(model.credential);
    const evidenceDetails = evidenceDetailsFromCredential(model.credential);
    const trustEdCredentialDetails = trustEdCredentialDetailsFromCredential(model.credential);
    const displayBadgeImageUri = model.badgeTemplateImageUri ?? achievementDetails.imageUri;
    const fallbackBadgeImageUri =
      model.badgeTemplateImageUri === null ? null : achievementDetails.imageUri;
    const achievementInitials = badgeInitialsFromName(badgeName);
    const fallbackImageUri =
      fallbackBadgeImageUri === null || fallbackBadgeImageUri === displayBadgeImageUri
        ? undefined
        : fallbackBadgeImageUri;
    const achievementImage =
      displayBadgeImageUri === null ? (
        <svg
          class="public-badge__hero-image public-badge__hero-image--placeholder"
          viewBox="0 0 420 320"
          role="img"
          aria-label={`Placeholder image for ${badgeName}`}
        >
          <defs>
            <linearGradient id="badge-placeholder-gradient" x1="0" x2="1" y1="0" y2="1">
              <stop offset="0%" stop-color="#166534" />
              <stop offset="100%" stop-color="#14532d" />
            </linearGradient>
          </defs>
          <rect
            x="0"
            y="0"
            width="420"
            height="320"
            rx="28"
            fill="url(#badge-placeholder-gradient)"
          />
          <circle cx="338" cy="80" r="42" fill="#fbbf24" fill-opacity="0.22" />
          <circle cx="86" cy="232" r="56" fill="#fbbf24" fill-opacity="0.16" />
          <path
            d="M116 168l42 42 106-106"
            fill="none"
            stroke="#fbbf24"
            stroke-width="20"
            stroke-linecap="round"
            stroke-linejoin="round"
          />
          <text
            x="210"
            y="148"
            text-anchor="middle"
            dominant-baseline="middle"
            font-size="54"
            fill="#f8fafc"
            font-weight="700"
          >
            {achievementInitials}
          </text>
        </svg>
      ) : (
        <div class="public-badge__hero-image-frame">
          <img
            class="public-badge__hero-image"
            src={displayBadgeImageUri}
            alt={badgeName}
            loading="lazy"
            data-fallback-src={fallbackImageUri}
          />
          <span class="public-badge__hero-image-fallback" aria-hidden="true">
            {achievementInitials}
          </span>
        </div>
      );
    const credentialUri = asString(model.credential.id) ?? model.assertion.id;
    const lifecycleState = model.lifecycle.state;
    const verificationLabel =
      lifecycleState === "active"
        ? "Verified"
        : lifecycleState.slice(0, 1).toUpperCase() + lifecycleState.slice(1);
    const verificationStatusClass = lifecycleState === "active" ? "verified" : lifecycleState;
    const publicBadgePath = publicBadgePathForAssertion(model.assertion);
    const publicBadgeUrl = new URL(publicBadgePath, requestUrl).toString();
    const summaryPath = `${publicBadgePath}/summary`;
    const summaryUrl = new URL(summaryPath, requestUrl).toString();
    const verificationApiPath = `${publicBadgePath}/verification`;
    const verificationApiUrl = new URL(verificationApiPath, requestUrl).toString();
    const ob3JsonPath = `${publicBadgePath}/jsonld`;
    const ob3JsonUrl = new URL(ob3JsonPath, requestUrl).toString();
    const credentialDownloadPath = `${publicBadgePath}/download`;
    const credentialDownloadUrl = new URL(credentialDownloadPath, requestUrl).toString();
    const credentialPdfDownloadPath = `${publicBadgePath}/download.pdf`;
    const credentialPdfDownloadUrl = new URL(credentialPdfDownloadPath, requestUrl).toString();
    const walletOfferBadgeIdentifier = model.assertion.publicId ?? model.assertion.id;
    const walletOfferPath = `/credentials/v1/offers/${encodeURIComponent(walletOfferBadgeIdentifier)}`;
    const walletOfferUrl = new URL(walletOfferPath, requestUrl).toString();
    const walletDeepLinkUrl = new URL("openid-credential-offer://");
    walletDeepLinkUrl.searchParams.set("credential_offer_uri", walletOfferUrl);
    const dccExchangePath = `/credentials/v1/dcc/exchanges/${encodeURIComponent(walletOfferBadgeIdentifier)}`;
    const dccExchangeUrl = new URL(dccExchangePath, requestUrl).toString();
    const dccInvitationRequest = {
      credentialRequestOrigin: new URL(requestUrl).origin,
      protocols: {
        vcapi: dccExchangeUrl,
      },
    };
    const dccWalletDeepLinkUrl = new URL("https://lcw.app/request");
    dccWalletDeepLinkUrl.searchParams.set("request", JSON.stringify(dccInvitationRequest));
    const isVcV2Credential = hasContextUrl(
      model.credential["@context"],
      VC_DATA_MODEL_V2_CONTEXT_URL,
    );
    const assertionValidationTargetUrl = ob3JsonUrl;
    const badgeClassValidationTargetUrl =
      achievementDetails.badgeClassUri !== null && isWebUrl(achievementDetails.badgeClassUri)
        ? achievementDetails.badgeClassUri
        : null;
    const issuerValidationTargetUrlFromIdentifier =
      issuerIdentifier !== null && isWebUrl(issuerIdentifier) ? issuerIdentifier : null;
    const issuerValidationTargetUrl = issuerUrl ?? issuerValidationTargetUrlFromIdentifier;
    const assertionValidatorUrl = isVcV2Credential
      ? null
      : imsOb3ValidatorUrl(assertionValidationTargetUrl);
    const badgeClassValidatorUrl =
      isVcV2Credential || badgeClassValidationTargetUrl === null
        ? null
        : imsOb3ValidatorUrl(badgeClassValidationTargetUrl);
    const issuerValidatorUrl =
      isVcV2Credential || issuerValidationTargetUrl === null
        ? null
        : imsOb3ValidatorUrl(issuerValidationTargetUrl);
    const validatorToolsMarkup =
      assertionValidatorUrl === null ? null : (
        <div class="public-badge__technical-tools">
          <h3 class="public-badge__technical-tools-title">IMS validation tools</h3>
          <p class="public-badge__validator-note">
            Use IMS tools to validate the published JSON and issuer records.
          </p>
          <ul class="public-badge__technical-link-list">
            <li>
              <a href={assertionValidatorUrl} target="_blank" rel="noopener noreferrer">
                Validate Assertion (IMS)
              </a>
            </li>
            {badgeClassValidatorUrl === null ? null : (
              <li>
                <a href={badgeClassValidatorUrl} target="_blank" rel="noopener noreferrer">
                  Validate Badge Class (IMS)
                </a>
              </li>
            )}
            {issuerValidatorUrl === null ? null : (
              <li>
                <a href={issuerValidatorUrl} target="_blank" rel="noopener noreferrer">
                  Validate Issuer (IMS)
                </a>
              </li>
            )}
          </ul>
          <p class="public-badge__validator-note">
            IMS validator expects JSON/image targets. Validate using the Open Badges 3.0 JSON URL,
            not this HTML page URL.
          </p>
        </div>
      );
    const badgeClassValidationTechnicalDetail =
      badgeClassValidatorUrl === null ? (
        <span>Not available (badge class URI is not a web URL).</span>
      ) : (
        <a href={badgeClassValidatorUrl}>{badgeClassValidatorUrl}</a>
      );
    const issuerValidationTechnicalDetail =
      issuerValidatorUrl === null ? (
        <span>Not available (issuer URL is not published).</span>
      ) : (
        <a href={issuerValidatorUrl}>{issuerValidatorUrl}</a>
      );
    const imsTechnicalDetailRows =
      assertionValidatorUrl === null ? null : (
        <>
          <dt>IMS assertion validation</dt>
          <dd>
            <a href={assertionValidatorUrl}>{assertionValidatorUrl}</a>
          </dd>
          <dt>IMS badge class validation</dt>
          <dd>{badgeClassValidationTechnicalDetail}</dd>
          <dt>IMS issuer validation</dt>
          <dd>{issuerValidationTechnicalDetail}</dd>
        </>
      );
    const qrCodeImageUrl = new URL("https://api.qrserver.com/v1/create-qr-code/");
    qrCodeImageUrl.searchParams.set("size", "220x220");
    qrCodeImageUrl.searchParams.set("format", "svg");
    qrCodeImageUrl.searchParams.set("margin", "0");
    qrCodeImageUrl.searchParams.set("data", dccWalletDeepLinkUrl.toString());
    const linkedInProfileSharePath = `/badges/${encodeURIComponent(
      walletOfferBadgeIdentifier,
    )}/share/linkedin-profile`;
    const linkedInFeedSharePath = `/badges/${encodeURIComponent(
      walletOfferBadgeIdentifier,
    )}/share/linkedin-feed`;
    const moreWaysSection = (
      <details class="public-badge__share-more">
        <summary>More ways to save and share</summary>
        <div class="public-badge__share-groups">
          <section class="public-badge__share-group">
            <h3 class="public-badge__share-group-title">Save to a wallet</h3>
            <div class="public-badge__wallet-panel">
              <figure class="public-badge__qr">
                <img
                  class="public-badge__qr-image"
                  src={qrCodeImageUrl.toString()}
                  alt="QR code for DCC Learner Wallet claim request"
                  loading="lazy"
                />
                <figcaption class="public-badge__qr-caption">
                  Scan to claim in a compatible wallet.
                </figcaption>
              </figure>
              <div class="public-badge__actions public-badge__actions--grid">
                <PublicBadgeButtonLink href={walletDeepLinkUrl.toString()}>
                  Claim in Wallet
                </PublicBadgeButtonLink>
                <PublicBadgeButtonLink href={dccWalletDeepLinkUrl.toString()}>
                  DCC Learner Wallet
                </PublicBadgeButtonLink>
                <PublicBadgeButton
                  id="chapi-store-button"
                  type="button"
                  dataCredentialJsonUrl={ob3JsonPath}
                  hidden
                >
                  Add to Browser Wallet
                </PublicBadgeButton>
              </div>
            </div>
          </section>
          <section class="public-badge__share-group">
            <h3 class="public-badge__share-group-title">Downloads</h3>
            <div class="public-badge__actions public-badge__actions--grid public-badge__actions--pair">
              <PublicBadgeButtonLink href={credentialPdfDownloadPath}>
                Download PDF
              </PublicBadgeButtonLink>
              <PublicBadgeButtonLink href={credentialDownloadPath}>
                JSON-LD download
              </PublicBadgeButtonLink>
            </div>
          </section>
        </div>
      </details>
    );
    const issuedAt = `${formatIsoTimestamp(model.assertion.issuedAt)} UTC`;
    const issuerLine =
      issuerUrl === null ? (
        <span>{issuerName}</span>
      ) : (
        <a href={issuerUrl} target="_blank" rel="noopener noreferrer">
          {issuerName}
        </a>
      );
    const pageTitle = `${badgeName} | CredTrail`;
    const pageDescription =
      nonEmptyText(achievementDetails.description) ??
      `${badgeName} credential issued by ${issuerName}.`;
    const socialImageUrl = toAbsoluteWebUrl(requestUrl, displayBadgeImageUri);
    const recipientAvatarSection =
      recipientAvatarUrl === null ? null : (
        <img
          class="public-badge__recipient-avatar"
          src={recipientAvatarUrl}
          alt={`${recipientName} GitHub avatar`}
          loading="lazy"
        />
      );
    const criteriaSection =
      achievementDetails.criteriaUri === null ? null : (
        <p class="public-badge__achievement-copy">
          Criteria:{" "}
          <a href={achievementDetails.criteriaUri} target="_blank" rel="noopener noreferrer">
            {achievementDetails.criteriaUri}
          </a>
        </p>
      );
    const criteriaRegistryPath = badgeTemplateCriteriaRegistryHref(
      model.assertion.tenantId,
      model.assertion.badgeTemplateId,
    );
    const criteriaRegistrySection = (
      <p class="public-badge__achievement-copy">
        Governance: <a href={criteriaRegistryPath}>View public criteria registry entry</a>
      </p>
    );
    const lifecycleDetails = (() => {
      if (lifecycleState === "active") {
        return null;
      }

      if (lifecycleState === "revoked" && model.lifecycle.revokedAt !== null) {
        return (
          <p class="public-badge__status-note public-badge__status-note--revoked">
            Revoked at {formatIsoTimestamp(model.lifecycle.revokedAt)} UTC
          </p>
        );
      }

      const transitionedAt =
        model.lifecycle.transitionedAt === null
          ? ""
          : ` since ${formatIsoTimestamp(model.lifecycle.transitionedAt)} UTC`;
      const reasonLine =
        model.lifecycle.reason === null ? null : (
          <p class={`public-badge__status-note public-badge__status-note--${lifecycleState}`}>
            {model.lifecycle.reason}
          </p>
        );
      const stateLabel = verificationLabel;

      return (
        <>
          <p class={`public-badge__status-note public-badge__status-note--${lifecycleState}`}>
            {stateLabel}
            {transitionedAt}
          </p>
          {reasonLine}
        </>
      );
    })();
    const achievementDescriptionSection =
      achievementDetails.description === null ? (
        <p class="public-badge__achievement-copy">No additional description provided.</p>
      ) : (
        <p class="public-badge__achievement-copy">{achievementDetails.description}</p>
      );
    const evidenceSection =
      evidenceDetails.length === 0 ? null : (
        <section class="public-badge__card public-badge__stack-sm">
          <h2 class="public-badge__section-title">Evidence</h2>
          <ul class="public-badge__evidence-list">
            {evidenceDetails.map((entry) => {
              const label = entry.name ?? entry.uri;

              return (
                <li class="public-badge__evidence-item" key={entry.uri}>
                  <a href={entry.uri} target="_blank" rel="noopener noreferrer">
                    {label}
                  </a>
                  {entry.description === null ? null : (
                    <p class="public-badge__evidence-description">{entry.description}</p>
                  )}
                </li>
              );
            })}
          </ul>
        </section>
      );
    const trustEdCredentialSection = (
      <PublicBadgeTrustEdCredentialSection details={trustEdCredentialDetails} />
    );

    return appPage({
      title: pageTitle,
      head: buildSeoHeadContent({
        title: pageTitle,
        description: pageDescription,
        canonicalUrl: publicBadgeUrl,
        ogType: "article",
        imageUrl: socialImageUrl,
        extraHeadContent: (
          <>
            <link rel="alternate" type={VC_JSON_LD_MEDIA_TYPE} href={ob3JsonUrl} />
            <link rel="alternate" type="application/json" href={summaryUrl} />
          </>
        ),
      }),
      assets: ["publicBadgeCss", "publicBadgeJs"],
      variant: "open",
      body: (
        <article class="public-badge">
          <section
            class={`public-badge__card public-badge__status public-badge__status--${verificationStatusClass}`}
          >
            <span>{verificationLabel}</span>
            <span>{issuedAt}</span>
          </section>

          <section class="public-badge__card public-badge__hero">
            {achievementImage}
            <div class="public-badge__hero-meta">
              <p class="public-badge__eyebrow">Open Badges 3.0 Credential</p>
              <h1 class="public-badge__title">{badgeName}</h1>
              <p class="public-badge__issuer">Issued by {issuerLine}</p>
              <p class="public-badge__issued-at">Issued {issuedAt}</p>
              {lifecycleDetails}
            </div>
          </section>

          <section class="public-badge__card public-badge__stack-sm">
            <h2 class="public-badge__section-title">Recipient</h2>
            <div class="public-badge__recipient-header">
              {recipientAvatarSection}
              <p class="public-badge__recipient-name">{recipientName}</p>
            </div>
          </section>

          <section class="public-badge__card public-badge__stack-sm">
            <h2 class="public-badge__section-title">Achievement</h2>
            {achievementDescriptionSection}
            {criteriaSection}
            {criteriaRegistrySection}
          </section>

          {evidenceSection}

          {trustEdCredentialSection}

          <section
            id="share-this-credential"
            class="public-badge__card public-badge__stack-sm public-badge__share"
          >
            <h2 class="public-badge__section-title">Share this credential</h2>
            <p class="public-badge__achievement-copy">
              Add it to your LinkedIn profile or copy the public link. Recruiters and other
              reviewers can verify the issuer, evidence, and technical details on this page.
            </p>
            <div class="public-badge__actions public-badge__actions--primary">
              <PublicBadgeButtonLink href={linkedInProfileSharePath} variant="primary">
                Add to LinkedIn Profile
              </PublicBadgeButtonLink>
              <PublicBadgeButton
                id="copy-badge-url-button"
                type="button"
                dataCopyValue={publicBadgeUrl}
              >
                Copy public URL
              </PublicBadgeButton>
            </div>
            <p class="public-badge__share-feed-link">
              <PublicBadgeTextLink
                href={linkedInFeedSharePath}
                target="_blank"
                rel="noopener noreferrer"
              >
                Share to LinkedIn feed
              </PublicBadgeTextLink>
            </p>
            {moreWaysSection}
            <p id="copy-badge-url-status" class="public-badge__copy-status" aria-live="polite"></p>
            <p id="chapi-store-status" class="public-badge__copy-status" aria-live="polite"></p>
          </section>

          <details class="public-badge__card public-badge__technical">
            <summary>Technical details</summary>
            <dl class="public-badge__technical-grid">
              <dt>Issuer ID</dt>
              <dd>{issuerIdentifier ?? "Not available"}</dd>
              <dt>Recipient identity</dt>
              <dd>{model.assertion.recipientIdentity}</dd>
              <dt>Recipient identity type</dt>
              <dd>{model.assertion.recipientIdentityType}</dd>
              <dt>Credential ID</dt>
              <dd>{credentialUri}</dd>
              <dt>Assertion ID</dt>
              <dd>{model.assertion.id}</dd>
              <dt>Recipient ID</dt>
              <dd>{recipientIdentifier}</dd>
              <dt>Verification JSON</dt>
              <dd>
                <a href={verificationApiPath}>{verificationApiUrl}</a>
              </dd>
              <dt>Summary JSON</dt>
              <dd>
                <a href={summaryPath}>{summaryUrl}</a>
              </dd>
              <dt>Open Badges 3.0 JSON</dt>
              <dd>
                <a href={ob3JsonPath}>{ob3JsonUrl}</a>
              </dd>
              <dt>Credential download</dt>
              <dd>
                <a href={credentialDownloadPath}>{credentialDownloadUrl}</a>
              </dd>
              <dt>OpenID4VCI offer</dt>
              <dd>
                <a href={walletOfferPath}>{walletOfferUrl}</a>
              </dd>
              <dt>DCC VC-API exchange</dt>
              <dd>
                <a href={dccExchangePath}>{dccExchangeUrl}</a>
              </dd>
              <dt>Credential PDF download</dt>
              <dd>
                <a href={credentialPdfDownloadPath}>{credentialPdfDownloadUrl}</a>
              </dd>
              {imsTechnicalDetailRows}
            </dl>
            {validatorToolsMarkup}
          </details>
        </article>
      ),
    });
  };
};

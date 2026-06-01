import type { JsonObject } from "@credtrail/core-domain";
import {
  parseBadgeIssuanceRuleDefinition,
  type BadgeIssuanceRuleCondition,
} from "@credtrail/validation";
import type {
  AssertionRecord,
  BadgeIssuanceRuleApprovalEventRecord,
  BadgeIssuanceRuleApprovalStepRecord,
  BadgeIssuanceRuleRecord,
  BadgeIssuanceRuleVersionRecord,
  BadgeTemplateOwnershipEventRecord,
  BadgeTemplateRecord,
  PublicBadgeWallEntryRecord,
  ResolveAssertionLifecycleStateResult,
  TenantOrgUnitRecord,
} from "@credtrail/db";
import type { PropsWithChildren } from "hono/jsx";
import type { HtmlEscapedString } from "hono/utils/html";
import { appPage, type AppPage } from "../ui/render-page";
import type { VerificationViewModel } from "./public-badge-model";
import { badgeInitialsFromName } from "./pdf";

type HonoElement = HtmlEscapedString | Promise<HtmlEscapedString>;

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

interface TrustEdAlignmentDetails {
  targetUrl: string;
  targetName: string | null;
  targetFramework: string | null;
  frameworkUri: string | null;
}

interface TrustEdResultDetails {
  value: string;
  resultDate: string;
}

interface TrustEdCredentialDetails {
  achievementType: string | null;
  criteriaUri: string | null;
  criteriaNarrative: string | null;
  alignments: TrustEdAlignmentDetails[];
  results: TrustEdResultDetails[];
}

interface CreatePublicBadgePageRenderersInput {
  asString: (value: unknown) => string | null;
  achievementDetailsFromCredential: (credential: JsonObject) => AchievementDetails;
  badgeNameFromCredential: (credential: JsonObject) => string;
  evidenceDetailsFromCredential: (credential: JsonObject) => EvidenceDetails[];
  formatIsoTimestamp: (timestampIso: string) => string;
  githubAvatarUrlForUsername: (username: string) => string;
  githubUsernameFromUrl: (value: string) => string | null;
  imsOb3ValidatorUrl: (targetUrl: string) => string;
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
  trustEdCredentialDetailsFromCredential: (credential: JsonObject) => TrustEdCredentialDetails;
}

interface PublicBadgePageRenderers {
  publicBadgeNotFoundPage: (requestUrl: string) => AppPage;
  publicBadgePage: (requestUrl: string, model: VerificationViewModel) => AppPage;
  tenantBadgeWallPage: (
    requestUrl: string,
    tenantId: string,
    entries: readonly PublicBadgeWallEntryViewRecord[],
    filterBadgeTemplateId: string | null,
  ) => AppPage;
  tenantBadgeCriteriaRegistryPage: (
    requestUrl: string,
    tenantId: string,
    model: PublicBadgeCriteriaRegistryViewModel,
    filterBadgeTemplateId: string | null,
  ) => AppPage;
}

type PublicBadgeButtonVariant = "primary" | "secondary";

const publicBadgeButtonClass = (variant: PublicBadgeButtonVariant = "secondary"): string => {
  return variant === "primary"
    ? "public-badge__button public-badge__button--primary"
    : "public-badge__button";
};

const PublicBadgeButtonLink = ({
  href,
  variant,
  target,
  rel,
  children,
}: PropsWithChildren<{
  href: string;
  variant?: PublicBadgeButtonVariant;
  target?: "_blank";
  rel?: string;
}>): HonoElement => {
  return (
    <a class={publicBadgeButtonClass(variant)} href={href} target={target} rel={rel}>
      {children}
    </a>
  );
};

const PublicBadgeButton = ({
  id,
  type = "button",
  variant,
  dataCopyValue,
  dataCredentialJsonUrl,
  children,
}: PropsWithChildren<{
  id?: string;
  type?: "button" | "submit";
  variant?: PublicBadgeButtonVariant;
  dataCopyValue?: string;
  dataCredentialJsonUrl?: string;
}>): HonoElement => {
  return (
    <button
      id={id}
      class={publicBadgeButtonClass(variant)}
      type={type}
      data-copy-value={dataCopyValue}
      data-credential-json-url={dataCredentialJsonUrl}
    >
      {children}
    </button>
  );
};

const BadgeWallButtonLink = ({
  href,
  variant,
  children,
}: PropsWithChildren<{
  href: string;
  variant?: PublicBadgeButtonVariant;
}>): HonoElement => {
  const className =
    variant === "primary" ? "badge-wall__button badge-wall__button--primary" : "badge-wall__button";

  return (
    <a class={className} href={href}>
      {children}
    </a>
  );
};

const BadgeWallCopyButton = (input: { value: string }): HonoElement => {
  return (
    <button class="badge-wall__button" type="button" data-copy-value={input.value}>
      Copy link
    </button>
  );
};

export interface PublicBadgeWallEntryViewRecord extends PublicBadgeWallEntryRecord {
  lifecycle: ResolveAssertionLifecycleStateResult;
}

export interface PublicBadgeCriteriaRuleViewRecord {
  rule: BadgeIssuanceRuleRecord;
  latestVersion: BadgeIssuanceRuleVersionRecord | null;
  activeVersion: BadgeIssuanceRuleVersionRecord | null;
  approvalSteps: readonly BadgeIssuanceRuleApprovalStepRecord[];
  approvalEvents: readonly BadgeIssuanceRuleApprovalEventRecord[];
}

export interface PublicBadgeCriteriaTemplateViewRecord {
  template: BadgeTemplateRecord;
  ownerOrgUnit: TenantOrgUnitRecord | null;
  ownershipEvents: readonly BadgeTemplateOwnershipEventRecord[];
  rules: readonly PublicBadgeCriteriaRuleViewRecord[];
}

export interface PublicBadgeCriteriaRegistryViewModel {
  orgUnits: readonly TenantOrgUnitRecord[];
  templates: readonly PublicBadgeCriteriaTemplateViewRecord[];
}

export const createPublicBadgePageRenderers = (
  input: CreatePublicBadgePageRenderersInput,
): PublicBadgePageRenderers => {
  const {
    asString,
    achievementDetailsFromCredential,
    badgeNameFromCredential,
    evidenceDetailsFromCredential,
    formatIsoTimestamp,
    githubAvatarUrlForUsername,
    githubUsernameFromUrl,
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
  const VC_DATA_MODEL_V2_CONTEXT_URL = "https://www.w3.org/ns/credentials/v2";
  const nonEmptyText = (value: string | null): string | null => {
    if (value === null) {
      return null;
    }

    const trimmed = value.trim();
    return trimmed.length === 0 ? null : trimmed;
  };

  const toAbsoluteWebUrl = (requestUrl: string, value: string | null): string | null => {
    const text = nonEmptyText(value);

    if (text === null) {
      return null;
    }

    try {
      const absoluteUrl = new URL(text, requestUrl).toString();
      return isWebUrl(absoluteUrl) ? absoluteUrl : null;
    } catch {
      return null;
    }
  };
  const hasContextUrl = (contextValue: unknown, expectedContextUrl: string): boolean => {
    if (typeof contextValue === "string") {
      return contextValue === expectedContextUrl;
    }

    if (!Array.isArray(contextValue)) {
      return false;
    }

    return contextValue.some((entry) => typeof entry === "string" && entry === expectedContextUrl);
  };

  const buildSeoHeadContent = (options: {
    title: string;
    description: string;
    canonicalUrl: string;
    ogType: "article" | "website";
    imageUrl?: string | null;
    robots?: string;
    extraHeadContent?: HonoElement | readonly HonoElement[];
  }): HonoElement => {
    const imageUrl = options.imageUrl ?? null;

    return (
      <>
        <meta name="description" content={options.description} />
        <meta name="robots" content={options.robots ?? "index, follow"} />
        <link rel="canonical" href={options.canonicalUrl} />
        <meta property="og:site_name" content="CredTrail" />
        <meta property="og:type" content={options.ogType} />
        <meta property="og:title" content={options.title} />
        <meta property="og:description" content={options.description} />
        <meta property="og:url" content={options.canonicalUrl} />
        {imageUrl === null ? null : <meta property="og:image" content={imageUrl} />}
        <meta name="twitter:card" content={imageUrl === null ? "summary" : "summary_large_image"} />
        <meta name="twitter:title" content={options.title} />
        <meta name="twitter:description" content={options.description} />
        {imageUrl === null ? null : <meta name="twitter:image" content={imageUrl} />}
        {options.extraHeadContent ?? null}
      </>
    );
  };

  const publicBadgeNotFoundPage = (requestUrl: string): AppPage => {
    const canonicalUrl = new URL(requestUrl).toString();

    return appPage({
      title: "Badge not found",
      head: buildSeoHeadContent({
        title: "Badge not found | CredTrail",
        description: "The shared badge URL is invalid or the credential does not exist.",
        canonicalUrl,
        ogType: "website",
        robots: "noindex, nofollow",
      }),
      assets: ["publicBadgeCss"],
      body: (
        <section class="public-badge-not-found">
          <article class="public-badge-not-found__card">
            <p class="public-badge-not-found__eyebrow">Public Badge Lookup</p>
            <h1 class="public-badge-not-found__title">Badge not found</h1>
            <p class="public-badge-not-found__copy">
              The shared badge URL is invalid or the credential does not exist.
            </p>
          </article>
        </section>
      ),
    });
  };

  const ruleConditionMarkup = (condition: BadgeIssuanceRuleCondition): HonoElement => {
    if ("all" in condition) {
      return (
        <li>
          <strong>All of these must be true:</strong>
          <ul>{condition.all.map((entry) => ruleConditionMarkup(entry))}</ul>
        </li>
      );
    }

    if ("any" in condition) {
      return (
        <li>
          <strong>At least one of these must be true:</strong>
          <ul>{condition.any.map((entry) => ruleConditionMarkup(entry))}</ul>
        </li>
      );
    }

    if ("not" in condition) {
      return (
        <li>
          <strong>None of these can be true:</strong>
          <ul>{ruleConditionMarkup(condition.not)}</ul>
        </li>
      );
    }

    switch (condition.type) {
      case "grade_threshold": {
        const scoreField = condition.scoreField ?? "final_score";
        const range =
          condition.minScore !== undefined && condition.maxScore !== undefined
            ? `between ${String(condition.minScore)} and ${String(condition.maxScore)}`
            : condition.minScore !== undefined
              ? `at least ${String(condition.minScore)}`
              : `at most ${String(condition.maxScore)}`;
        const courseLabel =
          condition.courseId ??
          (condition.courseListId === undefined
            ? "the selected course"
            : `course list ${condition.courseListId}`);
        return (
          <li>
            For course {courseLabel}, {scoreField} must be {range}.
          </li>
        );
      }
      case "course_completion": {
        const completionTarget =
          condition.minCompletionPercent === undefined
            ? ""
            : ` and reach at least ${String(condition.minCompletionPercent)}% completion`;
        const completionRequirement =
          condition.requireCompleted === false
            ? "Completion does not need to be marked complete"
            : "The course must be marked complete";
        const courseLabel =
          condition.courseId ??
          (condition.courseListId === undefined
            ? "the selected course"
            : `course list ${condition.courseListId}`);
        return (
          <li>
            For course {courseLabel}, {completionRequirement}
            {completionTarget}.
          </li>
        );
      }
      case "program_completion": {
        const programLabel =
          condition.courseIds === undefined
            ? `complete the courses in list ${condition.courseListId ?? "selected"}`
            : condition.minimumCompleted === undefined
              ? `complete all ${String(condition.courseIds.length)} listed courses`
              : `complete ${String(condition.minimumCompleted)} of ${String(condition.courseIds.length)} listed courses`;
        const courseList =
          condition.courseIds === undefined
            ? (condition.courseListId ?? "configured list")
            : condition.courseIds.join(", ");
        const minimumCompleted = programLabel;
        return (
          <li>
            Program requirement: {minimumCompleted} ({courseList}).
          </li>
        );
      }
      case "assignment_submission": {
        const scoreClause =
          condition.minScore === undefined
            ? ""
            : ` and earn at least ${String(condition.minScore)}`;
        const submissionClause =
          condition.requireSubmitted === false
            ? "submission is optional"
            : "submission is required";
        const workflowClause =
          condition.workflowStates === undefined
            ? ""
            : `, with workflow state in ${condition.workflowStates.join(", ")}`;
        return (
          <li>
            For assignment {condition.assignmentId} in {condition.courseId}, {submissionClause}
            {scoreClause}
            {workflowClause}.
          </li>
        );
      }
      case "survey_completion": {
        const sourceClause = condition.source === undefined ? "" : ` from ${condition.source}`;
        return (
          <li>
            Survey {condition.surveyId}
            {sourceClause} must be completed.
          </li>
        );
      }
      case "custom_field": {
        const operator = (condition.operator ?? "equals").replaceAll("_", " ");
        return (
          <li>
            Custom field {condition.fieldName} must {operator} {String(condition.expectedValue)}.
          </li>
        );
      }
      case "time_window": {
        const notBefore =
          condition.notBefore === undefined
            ? ""
            : ` on or after ${formatIsoTimestamp(condition.notBefore)} UTC`;
        const notAfter =
          condition.notAfter === undefined
            ? ""
            : ` on or before ${formatIsoTimestamp(condition.notAfter)} UTC`;
        return (
          <li>
            Qualifying activity must happen{notBefore}
            {notAfter}.
          </li>
        );
      }
      case "prerequisite_badge":
        return (
          <li>
            Requires earning this badge first:{" "}
            {condition.badgeTemplateId ??
              `badge template list ${condition.badgeTemplateListId ?? "selected"}`}
            .
          </li>
        );
    }
  };

  const ruleDefinitionSummaryMarkup = (ruleJson: string | null): HonoElement => {
    if (ruleJson === null) {
      return <p class="criteria-registry__muted">Rule definition unavailable.</p>;
    }

    try {
      const parsed = parseBadgeIssuanceRuleDefinition(JSON.parse(ruleJson));
      return (
        <ul class="criteria-registry__conditions">{ruleConditionMarkup(parsed.conditions)}</ul>
      );
    } catch {
      return <p class="criteria-registry__muted">Rule definition could not be parsed.</p>;
    }
  };

  const publicBadgePage = (requestUrl: string, model: VerificationViewModel): AppPage => {
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
    const validatorLinks =
      assertionValidatorUrl === null ? null : (
        <>
          <PublicBadgeButtonLink
            href={assertionValidatorUrl}
            target="_blank"
            rel="noopener noreferrer"
          >
            Validate Assertion (IMS)
          </PublicBadgeButtonLink>
          {badgeClassValidatorUrl === null ? null : (
            <PublicBadgeButtonLink
              href={badgeClassValidatorUrl}
              target="_blank"
              rel="noopener noreferrer"
            >
              Validate Badge Class (IMS)
            </PublicBadgeButtonLink>
          )}
          {issuerValidatorUrl === null ? null : (
            <PublicBadgeButtonLink
              href={issuerValidatorUrl}
              target="_blank"
              rel="noopener noreferrer"
            >
              Validate Issuer (IMS)
            </PublicBadgeButtonLink>
          )}
        </>
      );
    const validatorToolsMarkup =
      assertionValidatorUrl === null ? null : (
        <div class="public-badge__validator-block">
          <p class="public-badge__validator-note">
            Use IMS tools to validate the published JSON and issuer records.
          </p>
          <div class="public-badge__validator-links">{validatorLinks}</div>
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
    qrCodeImageUrl.searchParams.set("data", walletOfferUrl);
    const linkedInProfileSharePath = `/badges/${encodeURIComponent(
      walletOfferBadgeIdentifier,
    )}/share/linkedin-profile`;
    const linkedInFeedSharePath = `/badges/${encodeURIComponent(
      walletOfferBadgeIdentifier,
    )}/share/linkedin-feed`;
    const advancedActionsSection = (
      <details class="public-badge__actions-details">
        <summary>Wallet, downloads, and advanced tools</summary>
        <div class="public-badge__actions public-badge__actions--secondary">
          <PublicBadgeButtonLink href={walletDeepLinkUrl.toString()}>
            Claim in Wallet
          </PublicBadgeButtonLink>
          <PublicBadgeButtonLink href={dccWalletDeepLinkUrl.toString()}>
            Open in DCC Learner Wallet
          </PublicBadgeButtonLink>
          <PublicBadgeButtonLink
            href={linkedInFeedSharePath}
            target="_blank"
            rel="noopener noreferrer"
          >
            Share on LinkedIn Feed
          </PublicBadgeButtonLink>
          <PublicBadgeButtonLink href={ob3JsonPath}>Open Badges 3.0 JSON</PublicBadgeButtonLink>
          <PublicBadgeButtonLink href={summaryPath}>Summary JSON</PublicBadgeButtonLink>
          <PublicBadgeButtonLink href={credentialDownloadPath}>
            Download .jsonld VC
          </PublicBadgeButtonLink>
          <PublicBadgeButtonLink href={credentialPdfDownloadPath}>
            Download PDF
          </PublicBadgeButtonLink>
          <PublicBadgeButtonLink href={walletOfferPath}>OpenID4VCI Offer</PublicBadgeButtonLink>
          <PublicBadgeButton
            id="chapi-store-button"
            type="button"
            dataCredentialJsonUrl={ob3JsonPath}
          >
            Add to Browser Wallet
          </PublicBadgeButton>
        </div>
        {validatorToolsMarkup}
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
    const criteriaRegistryPath = `/showcase/${encodeURIComponent(
      model.assertion.tenantId,
    )}/criteria?badgeTemplateId=${encodeURIComponent(model.assertion.badgeTemplateId)}`;
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
    const hasTrustEdCredentialDetails =
      trustEdCredentialDetails.achievementType !== null ||
      trustEdCredentialDetails.criteriaNarrative !== null ||
      trustEdCredentialDetails.alignments.length > 0 ||
      trustEdCredentialDetails.results.length > 0;
    const trustEdCredentialSection = !hasTrustEdCredentialDetails ? null : (
      <section class="public-badge__card public-badge__stack-sm">
        <div class="public-badge__section-heading-row">
          <h2 class="public-badge__section-title">Trust metadata</h2>
          <span class="public-badge__metadata-badge">TrustEd-aligned</span>
        </div>
        <p class="public-badge__achievement-copy">
          Structured credential data published inside this Open Badges 3.0 record.
        </p>
        <dl class="public-badge__trust-grid">
          {trustEdCredentialDetails.achievementType === null ? null : (
            <>
              <dt>Achievement type</dt>
              <dd>{trustEdCredentialDetails.achievementType}</dd>
            </>
          )}
          {trustEdCredentialDetails.criteriaNarrative === null ? null : (
            <>
              <dt>Criteria</dt>
              <dd>
                {trustEdCredentialDetails.criteriaNarrative}
                {trustEdCredentialDetails.criteriaUri === null ? null : (
                  <>
                    {" "}
                    <a
                      href={trustEdCredentialDetails.criteriaUri}
                      target="_blank"
                      rel="noopener noreferrer"
                    >
                      View criteria
                    </a>
                  </>
                )}
              </dd>
            </>
          )}
          {trustEdCredentialDetails.results.length === 0 ? null : (
            <>
              <dt>Results</dt>
              <dd>
                <ul class="public-badge__trust-list">
                  {trustEdCredentialDetails.results.map((result) => (
                    <li key={`${result.value}:${result.resultDate}`}>
                      {result.value} on {result.resultDate}
                    </li>
                  ))}
                </ul>
              </dd>
            </>
          )}
          {trustEdCredentialDetails.alignments.length === 0 ? null : (
            <>
              <dt>Framework alignment</dt>
              <dd>
                <ul class="public-badge__trust-list">
                  {trustEdCredentialDetails.alignments.map((alignment) => {
                    const label = alignment.targetName ?? alignment.targetUrl;
                    const framework =
                      alignment.targetFramework === null ? null : (
                        <span class="public-badge__trust-muted">
                          {" "}
                          ({alignment.targetFramework})
                        </span>
                      );

                    return (
                      <li key={alignment.targetUrl}>
                        <a href={alignment.targetUrl} target="_blank" rel="noopener noreferrer">
                          {label}
                        </a>
                        {framework}
                      </li>
                    );
                  })}
                </ul>
              </dd>
            </>
          )}
        </dl>
      </section>
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
            <link rel="alternate" type="application/ld+json" href={ob3JsonUrl} />
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

          <section class="public-badge__card public-badge__stack-sm public-badge__share">
            <div class="public-badge__share-main">
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
              <p class="public-badge__achievement-copy">
                Prefer a wallet? Scan the QR code or use the wallet tools below.
              </p>
              {advancedActionsSection}
              <p
                id="copy-badge-url-status"
                class="public-badge__copy-status"
                aria-live="polite"
              ></p>
              <p id="chapi-store-status" class="public-badge__copy-status" aria-live="polite"></p>
            </div>
            <figure class="public-badge__qr">
              <img
                class="public-badge__qr-image"
                src={qrCodeImageUrl.toString()}
                alt="QR code for OpenID4VCI credential offer endpoint"
                loading="lazy"
              />
              <figcaption class="public-badge__qr-caption">
                Scan to claim this credential in a compatible wallet.
              </figcaption>
            </figure>
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
          </details>
        </article>
      ),
    });
  };

  const tenantBadgeWallPage = (
    requestUrl: string,
    tenantId: string,
    entries: readonly PublicBadgeWallEntryViewRecord[],
    filterBadgeTemplateId: string | null,
  ): AppPage => {
    const displayTenantName = tenantId;
    const firstBadgeTitle = entries.length > 0 ? (entries[0]?.badgeTitle ?? null) : null;
    const filterLabel = firstBadgeTitle ?? filterBadgeTemplateId;
    const heroEntry = filterBadgeTemplateId === null ? null : (entries[0] ?? null);
    const heroBadgeInitial = (filterLabel ?? "Badge").trim().slice(0, 1).toUpperCase() || "B";
    const title =
      filterBadgeTemplateId === null
        ? `Issued Credentials · ${displayTenantName}`
        : `${filterLabel ?? "Credentials"} · ${displayTenantName}`;
    const badgeWallPath =
      filterBadgeTemplateId === null
        ? `/showcase/${encodeURIComponent(tenantId)}`
        : `/showcase/${encodeURIComponent(tenantId)}?badgeTemplateId=${encodeURIComponent(
            filterBadgeTemplateId,
          )}`;
    const canonicalUrl = new URL(badgeWallPath, requestUrl).toString();
    const subtitle =
      filterBadgeTemplateId === null
        ? `Publicly verified credentials issued by this institution.`
        : `Publicly verified credentials for ${filterLabel ?? "this badge"}.`;
    const criteriaRegistryPath =
      filterBadgeTemplateId === null
        ? `/showcase/${encodeURIComponent(tenantId)}/criteria`
        : `/showcase/${encodeURIComponent(tenantId)}/criteria?badgeTemplateId=${encodeURIComponent(
            filterBadgeTemplateId,
          )}`;
    const pageTitle = `${title} | CredTrail`;
    const socialImageUrl =
      entries
        .map((entry) => toAbsoluteWebUrl(requestUrl, entry.badgeImageUri))
        .find((value): value is string => value !== null) ?? null;

    return appPage({
      title: pageTitle,
      head: buildSeoHeadContent({
        title: pageTitle,
        description: subtitle,
        canonicalUrl,
        ogType: "website",
        imageUrl: socialImageUrl,
      }),
      assets: ["publicBadgeCss", "publicBadgeJs"],
      variant: "open",
      body: (
        <section class="badge-wall">
          <header class="badge-wall__hero">
            {heroEntry === null ? null : (
              <div class="badge-wall__hero-image-frame">
                {heroEntry.badgeImageUri === null ? (
                  <span class="badge-wall__hero-image badge-wall__hero-image--placeholder">
                    {heroBadgeInitial}
                  </span>
                ) : (
                  <img
                    class="badge-wall__hero-image"
                    src={heroEntry.badgeImageUri}
                    alt={`${heroEntry.badgeTitle} badge artwork`}
                  />
                )}
              </div>
            )}
            <div class="badge-wall__hero-copy">
              <h1>{title}</h1>
              <p class="badge-wall__lead">{subtitle}</p>
              {heroEntry?.badgeDescription === null ||
              heroEntry?.badgeDescription === undefined ? null : (
                <p class="badge-wall__description">{heroEntry.badgeDescription}</p>
              )}
              <div class="badge-wall__hero-actions">
                <p class="badge-wall__count">{String(entries.length)} issued badges</p>
                <a class="badge-wall__hero-link" href={criteriaRegistryPath}>
                  View criteria registry
                </a>
              </div>
            </div>
          </header>
          {entries.length === 0 ? (
            <p class="badge-wall__empty">No public badges found for this showcase.</p>
          ) : (
            <ol class="badge-wall__list">
              {entries.map((entry) => {
                const username = githubUsernameFromUrl(entry.recipientIdentity);
                const recipientLabel = username === null ? entry.recipientIdentity : `@${username}`;
                const avatarUrl = username === null ? null : githubAvatarUrlForUsername(username);
                const badgePath = `/badges/${encodeURIComponent(entry.assertionPublicId)}`;
                const badgeUrl = new URL(badgePath, requestUrl).toString();
                const issuedAt = `${formatIsoTimestamp(entry.issuedAt)} UTC`;
                const lifecycleState = entry.lifecycle.state;
                const statusLabel =
                  lifecycleState === "active"
                    ? "Verified"
                    : lifecycleState.slice(0, 1).toUpperCase() + lifecycleState.slice(1);
                const statusClass = lifecycleState === "active" ? "verified" : lifecycleState;
                const transitionedAt =
                  lifecycleState === "revoked"
                    ? (entry.lifecycle.revokedAt ?? entry.lifecycle.transitionedAt)
                    : entry.lifecycle.transitionedAt;
                const reasonText = entry.lifecycle.reason ?? entry.lifecycle.reasonCode;
                const badgeInitial = entry.badgeTitle.trim().slice(0, 1).toUpperCase() || "B";

                return (
                  <li class="badge-wall__item" key={entry.assertionPublicId}>
                    <div class="badge-wall__summary">
                      <div class="badge-wall__identity">
                        {entry.badgeImageUri === null ? (
                          <span
                            class="badge-wall__badge-image badge-wall__badge-image--placeholder"
                            aria-hidden="true"
                          >
                            {badgeInitial}
                          </span>
                        ) : (
                          <img
                            class="badge-wall__badge-image"
                            src={entry.badgeImageUri}
                            alt={entry.badgeTitle}
                            loading="lazy"
                          />
                        )}
                        <div class="badge-wall__stack">
                          <div class="badge-wall__recipient">
                            {avatarUrl === null ? null : (
                              <img
                                class="badge-wall__avatar"
                                src={avatarUrl}
                                alt={`${recipientLabel} GitHub avatar`}
                                loading="lazy"
                              />
                            )}
                            <p class="badge-wall__name">{recipientLabel}</p>
                          </div>
                          <p class="badge-wall__badge-title">{entry.badgeTitle}</p>
                          <p class={`badge-wall__meta badge-wall__meta--${statusClass}`}>
                            {statusLabel} · Issued {issuedAt}
                          </p>
                          {transitionedAt === null || lifecycleState === "active" ? null : (
                            <p class={`badge-wall__meta badge-wall__meta--${statusClass}`}>
                              {statusLabel} {formatIsoTimestamp(transitionedAt)} UTC
                            </p>
                          )}
                          {reasonText === null || lifecycleState === "active" ? null : (
                            <p class="badge-wall__meta badge-wall__meta--reason">{reasonText}</p>
                          )}
                        </div>
                      </div>
                      <div class="badge-wall__actions">
                        <BadgeWallButtonLink href={badgePath} variant="primary">
                          View credential
                        </BadgeWallButtonLink>
                        <BadgeWallCopyButton value={badgeUrl} />
                        <p class="badge-wall__copy-status" aria-live="polite"></p>
                      </div>
                    </div>
                  </li>
                );
              })}
            </ol>
          )}
        </section>
      ),
    });
  };

  const tenantBadgeCriteriaRegistryPage = (
    requestUrl: string,
    tenantId: string,
    model: PublicBadgeCriteriaRegistryViewModel,
    filterBadgeTemplateId: string | null,
  ): AppPage => {
    const title = `Badge Criteria Registry · ${tenantId}`;
    const criteriaRegistryPath =
      filterBadgeTemplateId === null
        ? `/showcase/${encodeURIComponent(tenantId)}/criteria`
        : `/showcase/${encodeURIComponent(tenantId)}/criteria?badgeTemplateId=${encodeURIComponent(
            filterBadgeTemplateId,
          )}`;
    const canonicalUrl = new URL(criteriaRegistryPath, requestUrl).toString();
    const subtitle =
      filterBadgeTemplateId === null
        ? `Public criteria and governance metadata for badge templates under tenant "${tenantId}".`
        : `Public criteria and governance metadata for tenant "${tenantId}" badge template "${filterBadgeTemplateId}".`;
    const heroLead =
      filterBadgeTemplateId === null
        ? "Use this page to understand what each public badge recognizes, who publishes it, and how qualification rules are reviewed."
        : "Use this page to understand what this public badge recognizes, who publishes it, and how qualification rules are reviewed.";
    const badgeWallPath =
      filterBadgeTemplateId === null
        ? `/showcase/${encodeURIComponent(tenantId)}`
        : `/showcase/${encodeURIComponent(tenantId)}?badgeTemplateId=${encodeURIComponent(
            filterBadgeTemplateId,
          )}`;
    const orgUnitById = new Map(model.orgUnits.map((orgUnit) => [orgUnit.id, orgUnit]));
    const templateCards =
      model.templates.length === 0 ? (
        <p class="criteria-registry__empty">No public badge templates matched this view.</p>
      ) : (
        model.templates.map((entry) => {
          const template = entry.template;
          const ownerOrgUnit = entry.ownerOrgUnit;
          const ownerLabel =
            ownerOrgUnit === null
              ? template.ownerOrgUnitId
              : `${ownerOrgUnit.displayName} (${ownerOrgUnit.unitType})`;
          const templateShowcasePath = `/showcase/${encodeURIComponent(
            tenantId,
          )}?badgeTemplateId=${encodeURIComponent(template.id)}`;
          const criteriaLink =
            template.criteriaUri === null ? (
              <span class="criteria-registry__muted">
                No public criteria link is published for this badge.
              </span>
            ) : (
              <a href={template.criteriaUri} target="_blank" rel="noopener noreferrer">
                {template.criteriaUri}
              </a>
            );
          const templateRecordDetails = (
            <details class="criteria-registry__details">
              <summary>
                {template.governanceMetadataJson === null
                  ? "Badge record details"
                  : "Badge record details and raw metadata"}
              </summary>
              <div class="criteria-registry__details-body criteria-registry__stack-sm">
                <p class="criteria-registry__muted">Template ID: {template.id}</p>
              </div>
              {template.governanceMetadataJson === null ? null : (
                <pre class="criteria-registry__pre">{template.governanceMetadataJson}</pre>
              )}
            </details>
          );
          const ownershipHistorySection =
            entry.ownershipEvents.length === 0 ? (
              <p class="criteria-registry__muted">
                No published ownership changes are recorded for this badge yet.
              </p>
            ) : (
              <details class="criteria-registry__details">
                <summary>View ownership transfer history</summary>
                <ol class="criteria-registry__timeline">
                  {entry.ownershipEvents.map((event) => {
                    const fromOrgUnit =
                      event.fromOrgUnitId === null
                        ? null
                        : (orgUnitById.get(event.fromOrgUnitId) ?? null);
                    const toOrgUnit = orgUnitById.get(event.toOrgUnitId) ?? null;
                    const fromLabel =
                      fromOrgUnit === null ? "No previous owner recorded" : fromOrgUnit.displayName;
                    const toLabel = toOrgUnit === null ? event.toOrgUnitId : toOrgUnit.displayName;
                    const actor = event.transferredByUserId ?? "system";
                    const reason =
                      event.reason === null
                        ? event.reasonCode
                        : `${event.reasonCode}: ${event.reason}`;

                    return (
                      <li key={`${event.toOrgUnitId}:${event.transferredAt}`}>
                        <p>
                          <strong>{fromLabel}</strong> → <strong>{toLabel}</strong>
                        </p>
                        <p class="criteria-registry__muted">
                          Why it changed: {reason} · Recorded by {actor} ·{" "}
                          {formatIsoTimestamp(event.transferredAt)} UTC
                        </p>
                      </li>
                    );
                  })}
                </ol>
              </details>
            );
          const rulesSection =
            entry.rules.length === 0 ? (
              <p class="criteria-registry__muted">
                No published qualification rules are available for this badge yet.
              </p>
            ) : (
              entry.rules.map((ruleEntry) => {
                const latestVersion = ruleEntry.latestVersion;
                const activeVersion = ruleEntry.activeVersion;
                const effectiveVersion = activeVersion ?? latestVersion;
                const latestVersionLabel =
                  latestVersion === null
                    ? "No recorded version"
                    : `v${String(latestVersion.versionNumber)} (${latestVersion.status})`;
                const activeVersionLabel =
                  activeVersion === null
                    ? "No published version"
                    : `v${String(activeVersion.versionNumber)}`;
                const changeSummary =
                  effectiveVersion?.changeSummary === null ||
                  effectiveVersion?.changeSummary === undefined ? (
                    <span class="criteria-registry__muted">
                      No public summary was provided for the latest rule update.
                    </span>
                  ) : (
                    effectiveVersion.changeSummary
                  );
                const approvalStepsMarkup =
                  ruleEntry.approvalSteps.length === 0 ? (
                    <p class="criteria-registry__muted">
                      No review steps are published for this rule version.
                    </p>
                  ) : (
                    <ol class="criteria-registry__approval-steps">
                      {ruleEntry.approvalSteps.map((step) => {
                        const actor = step.decidedByUserId ?? "pending";
                        const decidedAt =
                          step.decidedAt === null
                            ? "Awaiting decision"
                            : `${formatIsoTimestamp(step.decidedAt)} UTC`;
                        const reviewLabel =
                          step.label === null || step.label.trim().length === 0
                            ? `Step ${String(step.stepNumber)}`
                            : step.label;

                        return (
                          <li key={step.id}>
                            <p>
                              <strong>{reviewLabel}</strong> · status <strong>{step.status}</strong>
                            </p>
                            <p class="criteria-registry__muted">
                              Required role: {step.requiredRole} · Reviewed by {actor} · {decidedAt}
                            </p>
                          </li>
                        );
                      })}
                    </ol>
                  );
                const approvalEventsMarkup =
                  ruleEntry.approvalEvents.length === 0 ? (
                    <p class="criteria-registry__muted">
                      No detailed approval history is published for this rule version.
                    </p>
                  ) : (
                    <ol class="criteria-registry__approval-events">
                      {ruleEntry.approvalEvents.map((event) => {
                        const actor = event.actorUserId ?? "system";
                        const role = event.actorRole ?? "unknown_role";

                        return (
                          <li key={`${event.action}:${event.occurredAt}`}>
                            {event.action} by {actor} ({role}) ·{" "}
                            {formatIsoTimestamp(event.occurredAt)} UTC
                            {event.comment === null ? "" : ` · ${event.comment}`}
                          </li>
                        );
                      })}
                    </ol>
                  );
                const ruleGovernanceDetails = (
                  <details class="criteria-registry__details">
                    <summary>Rule history and governance details</summary>
                    <div class="criteria-registry__details-body criteria-registry__stack-sm">
                      <p class="criteria-registry__muted">Rule ID: {ruleEntry.rule.id}</p>
                      <p class="criteria-registry__muted">
                        Source system: {ruleEntry.rule.lmsProviderKind}
                      </p>
                      <p class="criteria-registry__muted">
                        Current published version: {activeVersionLabel} · Most recent recorded
                        version: {latestVersionLabel}
                      </p>
                      <p>
                        <strong>Review steps</strong>
                      </p>
                      {approvalStepsMarkup}
                      <p>
                        <strong>Detailed approval history</strong>
                      </p>
                      {approvalEventsMarkup}
                    </div>
                  </details>
                );

                return (
                  <article class="criteria-registry__rule" key={ruleEntry.rule.id}>
                    <header>
                      <h3>{ruleEntry.rule.name}</h3>
                      <p class="criteria-registry__muted">
                        This published rule explains when a learner qualifies for this badge.
                      </p>
                    </header>
                    <div class="criteria-registry__stack-sm">
                      <p>
                        <strong>Learners qualify when these checks are met</strong>
                      </p>
                      {ruleDefinitionSummaryMarkup(effectiveVersion?.ruleJson ?? null)}
                      <p>
                        <strong>Latest published update</strong>
                      </p>
                      <p class="criteria-registry__muted">{changeSummary}</p>
                      {ruleGovernanceDetails}
                    </div>
                  </article>
                );
              })
            );

          return (
            <article class="criteria-registry__template-card" key={template.id}>
              <header class="criteria-registry__template-header">
                {template.imageUri === null ? (
                  <span
                    class="criteria-registry__template-image criteria-registry__template-image--placeholder"
                    aria-hidden="true"
                  >
                    B
                  </span>
                ) : (
                  <img
                    class="criteria-registry__template-image"
                    src={template.imageUri}
                    alt={template.title}
                    loading="lazy"
                  />
                )}
                <div class="criteria-registry__template-meta">
                  <h2>{template.title}</h2>
                </div>
              </header>
              <p class="criteria-registry__description">
                {template.description ?? "No public description is published for this badge yet."}
              </p>
              <dl class="criteria-registry__facts">
                <div class="criteria-registry__fact">
                  <dt>Published criteria</dt>
                  <dd>{criteriaLink}</dd>
                </div>
                <div class="criteria-registry__fact">
                  <dt>Current badge owner</dt>
                  <dd>{ownerLabel}</dd>
                </div>
                <div class="criteria-registry__fact">
                  <dt>Registry updated</dt>
                  <dd>{formatIsoTimestamp(template.updatedAt)} UTC</dd>
                </div>
              </dl>
              <p class="criteria-registry__actions">
                <a href={templateShowcasePath}>View public badge examples</a>
              </p>
              <section class="criteria-registry__section">
                <h3>How someone qualifies</h3>
                <p class="criteria-registry__muted">
                  These published rules explain how a learner becomes eligible for this badge.
                </p>
                {rulesSection}
              </section>
              <section class="criteria-registry__section">
                <h3>Governance and ownership</h3>
                <p class="criteria-registry__muted">
                  This section shows who is responsible for the badge and any published changes to
                  ownership.
                </p>
                {ownershipHistorySection}
                {templateRecordDetails}
              </section>
            </article>
          );
        })
      );
    const pageTitle = `${title} | CredTrail`;
    const socialImageUrl =
      model.templates
        .map((entry) => toAbsoluteWebUrl(requestUrl, entry.template.imageUri))
        .find((value): value is string => value !== null) ?? null;

    return appPage({
      title: pageTitle,
      head: buildSeoHeadContent({
        title: pageTitle,
        description: subtitle,
        canonicalUrl,
        ogType: "website",
        imageUrl: socialImageUrl,
      }),
      assets: ["publicBadgeCss"],
      variant: "open",
      body: (
        <section class="criteria-registry">
          <header class="criteria-registry__hero">
            <h1>{title}</h1>
            <p>{heroLead}</p>
            <a class="criteria-registry__hero-link" href={badgeWallPath}>
              Back to badge wall
            </a>
          </header>
          <div class="criteria-registry__template-grid">{templateCards}</div>
        </section>
      ),
    });
  };

  return {
    publicBadgeNotFoundPage,
    publicBadgePage,
    tenantBadgeWallPage,
    tenantBadgeCriteriaRegistryPage,
  };
};

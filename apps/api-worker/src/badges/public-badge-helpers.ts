import type { JsonObject } from '@credtrail/core-domain';
import type { AssertionRecord } from '@credtrail/db';
import { badgeInitialsFromName } from './pdf';
import { escapeHtml } from '../utils/display-format';
import { asJsonObject, asNonEmptyString } from '../utils/value-parsers';

const IMS_GLOBAL_OB2_VALIDATOR_BASE_URL = 'https://openbadgesvalidator.imsglobal.org/';

export interface AchievementDetails {
  badgeClassUri: string | null;
  description: string | null;
  criteriaUri: string | null;
  imageUri: string | null;
}

export interface EvidenceDetails {
  uri: string;
  name: string | null;
  description: string | null;
}

export const githubUsernameFromUrl = (value: string): string | null => {
  try {
    const parsedUrl = new URL(value);

    if (parsedUrl.hostname !== 'github.com' && parsedUrl.hostname !== 'www.github.com') {
      return null;
    }

    const firstPath = parsedUrl.pathname
      .split('/')
      .map((segment) => segment.trim())
      .find((segment) => segment.length > 0);

    if (firstPath === undefined) {
      return null;
    }

    return firstPath;
  } catch {
    return null;
  }
};

export const recipientDisplayNameFromAssertion = (assertion: AssertionRecord): string | null => {
  if (assertion.recipientIdentityType === 'email') {
    const email = assertion.recipientIdentity.trim();
    return email.length === 0 ? null : email;
  }

  if (assertion.recipientIdentityType === 'url') {
    const username = githubUsernameFromUrl(assertion.recipientIdentity);

    if (username !== null) {
      return `@${username}`;
    }

    try {
      const parsedUrl = new URL(assertion.recipientIdentity);
      return parsedUrl.hostname.replace(/^www\./, '');
    } catch {
      return null;
    }
  }

  return null;
};

export const githubAvatarUrlForUsername = (username: string): string => {
  return `https://github.com/${encodeURIComponent(username)}.png?size=256`;
};

export const recipientAvatarUrlFromAssertion = (assertion: AssertionRecord): string | null => {
  if (assertion.recipientIdentityType !== 'url') {
    return null;
  }

  const username = githubUsernameFromUrl(assertion.recipientIdentity);
  return username === null ? null : githubAvatarUrlForUsername(username);
};

export const linkedDataReferenceId = (value: unknown): string | null => {
  const stringValue = asNonEmptyString(value);

  if (stringValue !== null) {
    return stringValue;
  }

  const linkedDataObject = asJsonObject(value);
  return asNonEmptyString(linkedDataObject?.id);
};

export const achievementDetailsFromCredential = (credential: JsonObject): AchievementDetails => {
  const credentialSubject = asJsonObject(credential.credentialSubject);
  const achievement = asJsonObject(credentialSubject?.achievement);

  return {
    badgeClassUri: linkedDataReferenceId(achievement?.id),
    description: asNonEmptyString(achievement?.description),
    criteriaUri: linkedDataReferenceId(achievement?.criteria),
    imageUri: linkedDataReferenceId(achievement?.image),
  };
};

export const imsOb2ValidatorUrl = (targetUrl: string): string => {
  const validatorUrl = new URL(IMS_GLOBAL_OB2_VALIDATOR_BASE_URL);
  validatorUrl.searchParams.set('url', targetUrl);
  return validatorUrl.toString();
};

const evidenceDetailsFromValue = (value: unknown): EvidenceDetails | null => {
  const uri = linkedDataReferenceId(value);

  if (uri === null) {
    return null;
  }

  const evidenceObject = asJsonObject(value);

  return {
    uri,
    name: asNonEmptyString(evidenceObject?.name),
    description: asNonEmptyString(evidenceObject?.description),
  };
};

export const evidenceDetailsFromCredential = (credential: JsonObject): EvidenceDetails[] => {
  const credentialSubject = asJsonObject(credential.credentialSubject);
  const evidence = credentialSubject?.evidence;

  if (Array.isArray(evidence)) {
    const mappedEvidence = evidence.map((entry) => evidenceDetailsFromValue(entry));
    return mappedEvidence.filter((entry): entry is EvidenceDetails => entry !== null);
  }

  const singularEvidence = evidenceDetailsFromValue(evidence);
  return singularEvidence === null ? [] : [singularEvidence];
};

export const badgeHeroImageMarkup = (badgeName: string, imageUri: string | null): string => {
  if (imageUri !== null) {
    return `<img
      class="public-badge__hero-image"
      src="${escapeHtml(imageUri)}"
      alt="${escapeHtml(`${badgeName} image`)}"
      loading="lazy"
    />`;
  }

  const initials = badgeInitialsFromName(badgeName);

  return `<svg
    class="public-badge__hero-image public-badge__hero-image--placeholder"
    viewBox="0 0 420 320"
    role="img"
    aria-label="${escapeHtml(`Placeholder image for ${badgeName}`)}"
  >
    <defs>
      <linearGradient id="badge-placeholder-gradient" x1="0" x2="1" y1="0" y2="1">
        <stop offset="0%" stop-color="#166534" />
        <stop offset="100%" stop-color="#14532d" />
      </linearGradient>
    </defs>
    <rect x="0" y="0" width="420" height="320" rx="28" fill="url(#badge-placeholder-gradient)" />
    <circle cx="338" cy="80" r="42" fill="#fbbf24" fill-opacity="0.22" />
    <circle cx="86" cy="232" r="56" fill="#fbbf24" fill-opacity="0.16" />
    <path d="M116 168l42 42 106-106" fill="none" stroke="#fbbf24" stroke-width="20" stroke-linecap="round" stroke-linejoin="round" />
    <text x="210" y="148" text-anchor="middle" dominant-baseline="middle" font-size="54" fill="#f8fafc" font-weight="700">${escapeHtml(initials)}</text>
  </svg>`;
};

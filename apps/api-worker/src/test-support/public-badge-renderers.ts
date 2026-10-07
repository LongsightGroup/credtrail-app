import {
  createPublicBadgePageRenderers,
  type PublicBadgePageRenderers,
} from "../badges/public-badge-pages";
import {
  achievementDetailsFromCredential,
  evidenceDetailsFromCredential,
  githubAvatarUrlForUsername,
  githubUsernameFromUrl,
  imsOb3ValidatorUrl,
  recipientAvatarUrlFromAssertion,
  recipientDisplayNameFromAssertion,
  trustEdCredentialDetailsFromCredential,
} from "../badges/public-badge-helpers";
import {
  badgeNameFromCredential,
  isWebUrl,
  issuerIdentifierFromCredential,
  issuerNameFromCredential,
  issuerUrlFromCredential,
  recipientFromCredential,
} from "../badges/credential-display";
import { publicBadgePathForAssertion } from "../badges/public-badge-model";
import { asString } from "../utils/value-parsers";
import { formatIsoTimestamp } from "../utils/display-format";

/** Composes the real public page renderers with their production presentation policies. */
export const createPublicBadgeTestRenderers = (): PublicBadgePageRenderers =>
  createPublicBadgePageRenderers({
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
  });

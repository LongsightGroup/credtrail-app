import {
  achievementDetailsFromCredential,
  recipientAvatarUrlFromAssertion,
  recipientDisplayNameFromAssertion,
} from "./public-badge-helpers";
import {
  badgeNameFromCredential,
  issuerIdentifierFromCredential,
  issuerNameFromCredential,
  issuerUrlFromCredential,
  recipientFromCredential,
} from "./credential-display";
import {
  badgeTemplateCriteriaRegistryHref,
  badgeTemplateShowcaseHref,
} from "./badge-template-public-links";
import type { PublicBadgeViewModel } from "./public-badge-model";

export const publicBadgeSummaryPayload = (input: {
  requestUrl: string;
  model: PublicBadgeViewModel;
  formatIsoTimestamp: (timestampIso: string) => string;
}): Record<string, unknown> => {
  const requestBaseUrl = new URL(input.requestUrl);
  const assertion = input.model.assertion;
  const achievementDetails = achievementDetailsFromCredential(input.model.credential);
  const badgeName = badgeNameFromCredential(input.model.credential);
  const recipientDisplayName =
    input.model.recipientDisplayName ?? recipientDisplayNameFromAssertion(assertion);
  const recipientAvatarUrl = recipientAvatarUrlFromAssertion(assertion);
  const issuerName = issuerNameFromCredential(input.model.credential);
  const issuerId = issuerIdentifierFromCredential(input.model.credential);
  const issuerUrl = issuerUrlFromCredential(input.model.credential);
  const recipientId = recipientFromCredential(input.model.credential);
  const publicBadgePath = `/badges/${encodeURIComponent(assertion.publicId)}`;
  const summaryPath = `${publicBadgePath}/summary`;
  const verificationPath = `${publicBadgePath}/verification`;
  const ob3JsonPath = `${publicBadgePath}/jsonld`;
  const credentialDownloadPath = `${publicBadgePath}/download`;
  const credentialPdfDownloadPath = `${publicBadgePath}/download.pdf`;
  const walletOfferPath = `/credentials/v1/offers/${encodeURIComponent(assertion.publicId)}`;
  const showcasePath = badgeTemplateShowcaseHref(assertion.tenantId, assertion.badgeTemplateId);
  const criteriaRegistryPath = badgeTemplateCriteriaRegistryHref(
    assertion.tenantId,
    assertion.badgeTemplateId,
  );
  const verificationLabel =
    input.model.lifecycle.state === "active" ? "verified" : input.model.lifecycle.state;

  return {
    badge: {
      assertionId: assertion.id,
      publicBadgeId: assertion.publicId,
      tenantId: assertion.tenantId,
      badgeTemplateId: assertion.badgeTemplateId,
      name: badgeName,
      description: achievementDetails.description,
      badgeClassId: achievementDetails.badgeClassUri,
      criteriaUri: achievementDetails.criteriaUri,
      imageUri: achievementDetails.imageUri,
      issuedAt: assertion.issuedAt,
      issuedAtLabel: `${input.formatIsoTimestamp(assertion.issuedAt)} UTC`,
    },
    recipient: {
      identity: assertion.recipientIdentity,
      identityType: assertion.recipientIdentityType,
      id: recipientId,
      displayName: recipientDisplayName,
      avatarUrl: recipientAvatarUrl,
    },
    issuer: {
      name: issuerName,
      id: issuerId,
      url: issuerUrl,
    },
    lifecycle: {
      state: input.model.lifecycle.state,
      source: input.model.lifecycle.source,
      reasonCode: input.model.lifecycle.reasonCode,
      reason: input.model.lifecycle.reason,
      transitionedAt: input.model.lifecycle.transitionedAt,
      revokedAt: input.model.lifecycle.revokedAt,
    },
    verification: {
      label: verificationLabel,
      isValid: input.model.lifecycle.state === "active",
    },
    links: {
      badgePagePath: publicBadgePath,
      badgePageUrl: new URL(publicBadgePath, requestBaseUrl).toString(),
      summaryPath,
      summaryUrl: new URL(summaryPath, requestBaseUrl).toString(),
      verificationPath,
      verificationUrl: new URL(verificationPath, requestBaseUrl).toString(),
      ob3JsonPath,
      ob3JsonUrl: new URL(ob3JsonPath, requestBaseUrl).toString(),
      credentialDownloadPath,
      credentialDownloadUrl: new URL(credentialDownloadPath, requestBaseUrl).toString(),
      credentialPdfDownloadPath,
      credentialPdfDownloadUrl: new URL(credentialPdfDownloadPath, requestBaseUrl).toString(),
      walletOfferPath,
      walletOfferUrl: new URL(walletOfferPath, requestBaseUrl).toString(),
      showcasePath,
      showcaseUrl: new URL(showcasePath, requestBaseUrl).toString(),
      criteriaRegistryPath,
      criteriaRegistryUrl: new URL(criteriaRegistryPath, requestBaseUrl).toString(),
    },
  };
};

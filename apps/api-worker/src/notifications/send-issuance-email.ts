import { sendTransactionalEmail } from "./transactional-email";
import { publicHttpUrl } from "../http/public-http-url";
import { formatIsoTimestamp } from "../utils/display-format";

export interface SendIssuanceEmailNotificationInput {
  emailBinding?: SendEmail | undefined;
  fromEmail?: string | undefined;
  fromName?: string | undefined;
  recipientEmail: string;
  tenantDisplayName: string;
  badgeTitle: string;
  issuedAtIso: string;
  publicBadgeUrl: string;
  credentialDownloadUrl: string;
  badgeDescription?: string | null | undefined;
  badgeImageUrl?: string | null | undefined;
  /** Expiry of the credential, when it has one. */
  validUntilIso?: string | null | undefined;
}

export const sendIssuanceEmailNotification = async (
  input: SendIssuanceEmailNotificationInput,
): Promise<void> => {
  const subject = `You've earned a new badge: ${input.badgeTitle}`;
  const linkedInUrl = `${input.publicBadgeUrl}/share/linkedin-profile`;
  const description = input.badgeDescription?.trim() ?? "";
  const imageUrl =
    input.badgeImageUrl === undefined || input.badgeImageUrl === null
      ? null
      : (publicHttpUrl(input.badgeImageUrl, input.publicBadgeUrl)?.toString() ?? null);
  await sendTransactionalEmail({
    kind: "issuance",
    emailBinding: input.emailBinding,
    fromEmail: input.fromEmail,
    fromName: input.fromName,
    recipientEmail: input.recipientEmail,
    subject,
    content: {
      institution: input.tenantDisplayName.trim(),
      image:
        imageUrl === null ? undefined : { url: imageUrl, alt: `${input.badgeTitle} badge artwork` },
      title: `You have earned ${input.badgeTitle}`,
      paragraphs: [
        ...(description === "" ? [] : [description]),
        "View your badge to see your achievement and share it with others.",
      ],
      details: [
        { label: "Issued", value: `${formatIsoTimestamp(input.issuedAtIso)} UTC` },
        ...(input.validUntilIso === undefined || input.validUntilIso === null
          ? []
          : [{ label: "Valid until", value: `${formatIsoTimestamp(input.validUntilIso)} UTC` }]),
      ],
      action: { label: "View your badge", url: input.publicBadgeUrl },
      secondaryActions: [
        { label: "Add to LinkedIn", url: linkedInUrl },
        { label: "Download PDF", url: `${input.publicBadgeUrl}/download.pdf` },
        { label: "Download your credential", url: input.credentialDownloadUrl },
      ],
      footer: "Contact the issuing institution if you have questions about this badge.",
    },
    category: "Issuance Notification",
  });
};

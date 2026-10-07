import { sendTransactionalEmail } from "./transactional-email";

export interface SendIssuanceEmailNotificationInput {
  emailBinding?: SendEmail | undefined;
  fromEmail?: string | undefined;
  fromName?: string | undefined;
  recipientEmail: string;
  tenantDisplayName: string;
  badgeTitle: string;
  issuedAtIso: string;
  publicBadgeUrl: string;
  verificationUrl: string;
  credentialDownloadUrl: string;
  /** Expiry of the credential, when it has one. */
  validUntilIso?: string | null | undefined;
}

export const sendIssuanceEmailNotification = async (
  input: SendIssuanceEmailNotificationInput,
): Promise<void> => {
  const subject = `You've earned a new badge: ${input.badgeTitle}`;
  await sendTransactionalEmail({
    kind: "issuance",
    emailBinding: input.emailBinding,
    fromEmail: input.fromEmail,
    fromName: input.fromName,
    recipientEmail: input.recipientEmail,
    subject,
    content: {
      institution: input.tenantDisplayName.trim(),
      title: `You have earned ${input.badgeTitle}`,
      paragraphs: ["View your badge to see your achievement and share it with others."],
      details: [
        { label: "Issued", value: input.issuedAtIso },
        ...(input.validUntilIso === undefined || input.validUntilIso === null
          ? []
          : [{ label: "Valid until", value: input.validUntilIso }]),
      ],
      action: { label: "View your badge", url: input.publicBadgeUrl },
      secondaryActions: [
        { label: "Verify your badge", url: input.verificationUrl },
        { label: "Download your credential", url: input.credentialDownloadUrl },
      ],
      footer: "Contact the issuing institution if you have questions about this badge.",
    },
    category: "Issuance Notification",
  });
};

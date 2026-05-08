import { sendTransactionalEmail } from "./transactional-email";

export interface SendIssuanceEmailNotificationInput {
  emailBinding?: SendEmail | undefined;
  fromEmail?: string | undefined;
  fromName?: string | undefined;
  recipientEmail: string;
  badgeTitle: string;
  assertionId: string;
  tenantId: string;
  issuedAtIso: string;
  publicBadgeUrl: string;
  verificationUrl: string;
  credentialDownloadUrl: string;
}

export const sendIssuanceEmailNotification = async (
  input: SendIssuanceEmailNotificationInput,
): Promise<void> => {
  const subject = `You've earned a new badge: ${input.badgeTitle}`;
  const textBody = [
    `You have earned the "${input.badgeTitle}" badge.`,
    "",
    `Issued at: ${input.issuedAtIso}`,
    `Assertion ID: ${input.assertionId}`,
    `Tenant ID: ${input.tenantId}`,
    "",
    `Public badge page: ${input.publicBadgeUrl}`,
    `Verification JSON: ${input.verificationUrl}`,
    `Download VC: ${input.credentialDownloadUrl}`,
  ].join("\n");

  await sendTransactionalEmail({
    emailBinding: input.emailBinding,
    fromEmail: input.fromEmail,
    fromName: input.fromName,
    recipientEmail: input.recipientEmail,
    subject,
    text: textBody,
    category: "Issuance Notification",
  });
};

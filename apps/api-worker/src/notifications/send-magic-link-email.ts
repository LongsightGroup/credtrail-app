import { sendTransactionalEmail } from "./transactional-email";

export interface SendMagicLinkEmailNotificationInput {
  emailBinding?: SendEmail | undefined;
  fromEmail?: string | undefined;
  fromName?: string | undefined;
  recipientEmail: string;
  tenantId: string;
  magicLinkUrl: string;
  expiresAtIso: string;
}

export const sendMagicLinkEmailNotification = async (
  input: SendMagicLinkEmailNotificationInput,
): Promise<void> => {
  const subject = `Sign in to CredTrail (${input.tenantId})`;
  const textBody = [
    "Use the link below to sign in to CredTrail:",
    "",
    input.magicLinkUrl,
    "",
    `Tenant: ${input.tenantId}`,
    `Expires at: ${input.expiresAtIso}`,
  ].join("\n");

  await sendTransactionalEmail({
    emailBinding: input.emailBinding,
    fromEmail: input.fromEmail,
    fromName: input.fromName,
    recipientEmail: input.recipientEmail,
    subject,
    text: textBody,
    category: "Auth Magic Link",
  });
};

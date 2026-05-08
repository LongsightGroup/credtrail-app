import { sendTransactionalEmail } from "./transactional-email";

export interface SendPasswordResetEmailNotificationInput {
  emailBinding?: SendEmail | undefined;
  fromEmail?: string | undefined;
  fromName?: string | undefined;
  recipientEmail: string;
  tenantId: string;
  resetUrl: string;
}

export const sendPasswordResetEmailNotification = async (
  input: SendPasswordResetEmailNotificationInput,
): Promise<void> => {
  const subject = `Set up local CredTrail access (${input.tenantId})`;
  const textBody = [
    "Use the link below to set or reset your local CredTrail password for break-glass access:",
    "",
    input.resetUrl,
    "",
    `Tenant: ${input.tenantId}`,
    "",
    "After setting your password, complete local MFA enrollment before relying on break-glass access.",
  ].join("\n");

  await sendTransactionalEmail({
    emailBinding: input.emailBinding,
    fromEmail: input.fromEmail,
    fromName: input.fromName,
    recipientEmail: input.recipientEmail,
    subject,
    text: textBody,
    category: "Auth Password Reset",
  });
};

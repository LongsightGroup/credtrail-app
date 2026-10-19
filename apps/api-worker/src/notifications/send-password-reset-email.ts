import type { EmailTracking } from "./email-attempt-store";
import type { TransactionalEmailResult } from "./transactional-email";
import { sendTransactionalEmail } from "./transactional-email";

export interface SendPasswordResetEmailNotificationInput {
  readonly tracking: EmailTracking;
  emailBinding?: SendEmail | undefined;
  fromEmail?: string | undefined;
  fromName?: string | undefined;
  recipientEmail: string;
  tenantDisplayName: string;
  resetUrl: string;
}

export const sendPasswordResetEmailNotification = async (
  input: SendPasswordResetEmailNotificationInput,
): Promise<TransactionalEmailResult> => {
  const institution = input.tenantDisplayName.trim();
  const subject = `Set up local access to ${institution}`;
  return sendTransactionalEmail({
    tracking: input.tracking,
    kind: "password_reset",
    emailBinding: input.emailBinding,
    fromEmail: input.fromEmail,
    fromName: input.fromName,
    recipientEmail: input.recipientEmail,
    subject,
    content: {
      institution,
      title: subject,
      paragraphs: [
        "Set or reset your password for local emergency access.",
        "After setting your password, complete local MFA enrollment before relying on emergency access.",
      ],
      action: { label: "Set your password", url: input.resetUrl },
      footer: "If you did not request this change, you can ignore this email.",
    },
    category: "Auth Password Reset",
  });
};

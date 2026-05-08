import { sendTransactionalEmail } from "./transactional-email";

export interface SendMemberInviteEmailNotificationInput {
  emailBinding?: SendEmail | undefined;
  fromEmail?: string | undefined;
  fromName?: string | undefined;
  recipientEmail: string;
  tenantId: string;
  tenantDisplayName: string;
  role: string;
  signInUrl: string;
}

export const sendMemberInviteEmailNotification = async (
  input: SendMemberInviteEmailNotificationInput,
): Promise<void> => {
  const subject = `You have been added to ${input.tenantDisplayName} on CredTrail`;
  const textBody = [
    `You have been added to ${input.tenantDisplayName} on CredTrail.`,
    "",
    `Organization: ${input.tenantId}`,
    `Role: ${input.role}`,
    "",
    "Use the link below to sign in with your institution account:",
    "",
    input.signInUrl,
  ].join("\n");

  await sendTransactionalEmail({
    emailBinding: input.emailBinding,
    fromEmail: input.fromEmail,
    fromName: input.fromName,
    recipientEmail: input.recipientEmail,
    subject,
    text: textBody,
    category: "Tenant Member Invite",
  });
};

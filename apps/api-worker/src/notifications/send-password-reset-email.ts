import { buildMailtrapSendEndpoint, mailtrapConfigured } from "./mailtrap";

export interface SendPasswordResetEmailNotificationInput {
  mailtrapApiToken?: string | undefined;
  mailtrapInboxId?: string | undefined;
  mailtrapApiBaseUrl?: string | undefined;
  mailtrapFromEmail?: string | undefined;
  mailtrapFromName?: string | undefined;
  recipientEmail: string;
  tenantId: string;
  resetUrl: string;
}

export const sendPasswordResetEmailNotification = async (
  input: SendPasswordResetEmailNotificationInput,
): Promise<void> => {
  if (!mailtrapConfigured(input)) {
    return;
  }

  const endpoint = buildMailtrapSendEndpoint(input);
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

  const response = await fetch(endpoint, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${input.mailtrapApiToken}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      from: {
        email: input.mailtrapFromEmail ?? "no-reply@credtrail.org",
        name: input.mailtrapFromName ?? "CredTrail",
      },
      to: [
        {
          email: input.recipientEmail,
        },
      ],
      subject,
      text: textBody,
      category: "Auth Password Reset",
    }),
  });

  if (!response.ok) {
    const errorBody = await response.text();
    throw new Error(
      `Mailtrap API request failed: ${String(response.status)} ${response.statusText} ${errorBody}`,
    );
  }
};

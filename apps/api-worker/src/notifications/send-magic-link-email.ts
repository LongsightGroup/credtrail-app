import { buildMailtrapSendEndpoint, mailtrapConfigured } from "./mailtrap";

export interface SendMagicLinkEmailNotificationInput {
  mailtrapApiToken?: string | undefined;
  mailtrapInboxId?: string | undefined;
  mailtrapApiBaseUrl?: string | undefined;
  mailtrapFromEmail?: string | undefined;
  mailtrapFromName?: string | undefined;
  recipientEmail: string;
  tenantId: string;
  magicLinkUrl: string;
  expiresAtIso: string;
}

export const sendMagicLinkEmailNotification = async (
  input: SendMagicLinkEmailNotificationInput,
): Promise<void> => {
  if (!mailtrapConfigured(input)) {
    return;
  }

  const endpoint = buildMailtrapSendEndpoint(input);
  const subject = `Sign in to CredTrail (${input.tenantId})`;
  const textBody = [
    "Use the link below to sign in to CredTrail:",
    "",
    input.magicLinkUrl,
    "",
    `Tenant: ${input.tenantId}`,
    `Expires at: ${input.expiresAtIso}`,
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
      category: "Auth Magic Link",
    }),
  });

  if (!response.ok) {
    const errorBody = await response.text();
    throw new Error(
      `Mailtrap API request failed: ${String(response.status)} ${response.statusText} ${errorBody}`,
    );
  }
};

import { buildMailtrapSendEndpoint, mailtrapConfigured } from "./mailtrap";

export interface SendIssuanceEmailNotificationInput {
  mailtrapApiToken?: string | undefined;
  mailtrapInboxId?: string | undefined;
  mailtrapApiBaseUrl?: string | undefined;
  mailtrapFromEmail?: string | undefined;
  mailtrapFromName?: string | undefined;
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
  if (!mailtrapConfigured(input)) {
    return;
  }

  const endpoint = buildMailtrapSendEndpoint(input);
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
      category: "Issuance Notification",
    }),
  });

  if (!response.ok) {
    const errorBody = await response.text();
    throw new Error(
      `Mailtrap API request failed: ${String(response.status)} ${response.statusText} ${errorBody}`,
    );
  }
};

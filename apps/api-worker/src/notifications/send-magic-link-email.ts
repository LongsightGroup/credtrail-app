import { sendTransactionalEmail } from "./transactional-email";

export interface SendMagicLinkEmailNotificationInput {
  emailBinding?: SendEmail | undefined;
  fromEmail?: string | undefined;
  fromName?: string | undefined;
  recipientEmail: string;
  tenantId: string;
  magicLinkUrl: string;
  expiresAtIso: string;
  preferredLocale?: string | undefined;
  preferredTimeZone?: string | undefined;
}

const DEFAULT_EXPIRY_LOCALE = "en-US";
const DEFAULT_EXPIRY_TIME_ZONE = "UTC";

export const formatMagicLinkExpiry = (input: {
  expiresAtIso: string;
  preferredLocale?: string | undefined;
  preferredTimeZone?: string | undefined;
}): string => {
  const expiresAt = new Date(input.expiresAtIso);

  if (!Number.isFinite(expiresAt.getTime())) {
    return input.expiresAtIso;
  }

  const locale =
    input.preferredLocale === undefined || input.preferredLocale.trim().length === 0
      ? DEFAULT_EXPIRY_LOCALE
      : input.preferredLocale.trim();
  const timeZone =
    input.preferredTimeZone === undefined || input.preferredTimeZone.trim().length === 0
      ? DEFAULT_EXPIRY_TIME_ZONE
      : input.preferredTimeZone.trim();
  const formatterOptions: Intl.DateTimeFormatOptions = {
    timeZone,
    year: "numeric",
    month: "short",
    day: "numeric",
    hour: "numeric",
    minute: "2-digit",
    timeZoneName: "short",
  };

  try {
    return new Intl.DateTimeFormat(locale, formatterOptions).format(expiresAt);
  } catch {
    return new Intl.DateTimeFormat(DEFAULT_EXPIRY_LOCALE, {
      ...formatterOptions,
      timeZone: DEFAULT_EXPIRY_TIME_ZONE,
    }).format(expiresAt);
  }
};

export const sendMagicLinkEmailNotification = async (
  input: SendMagicLinkEmailNotificationInput,
): Promise<void> => {
  const subject = `Sign in to CredTrail (${input.tenantId})`;
  const formattedExpiresAt = formatMagicLinkExpiry({
    expiresAtIso: input.expiresAtIso,
    preferredLocale: input.preferredLocale,
    preferredTimeZone: input.preferredTimeZone,
  });
  const textBody = [
    "Use the link below to sign in to CredTrail:",
    "",
    input.magicLinkUrl,
    "",
    `Organization: ${input.tenantId}`,
    `Expires: ${formattedExpiresAt}`,
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

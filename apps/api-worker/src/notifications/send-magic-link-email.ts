import type { EmailTracking } from "./email-attempt-store";
import type { TransactionalEmailResult } from "./transactional-email";
import { sendTransactionalEmail } from "./transactional-email";

export interface SendMagicLinkEmailNotificationInput {
  readonly tracking: EmailTracking;
  readonly skipReason?: "development" | undefined;
  emailBinding?: SendEmail | undefined;
  fromEmail?: string | undefined;
  fromName?: string | undefined;
  recipientEmail: string;
  tenantDisplayName: string;
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
): Promise<TransactionalEmailResult> => {
  const institution = input.tenantDisplayName.trim();
  const subject = `Sign in to ${institution}`;
  const formattedExpiresAt = formatMagicLinkExpiry({
    expiresAtIso: input.expiresAtIso,
    preferredLocale: input.preferredLocale,
    preferredTimeZone: input.preferredTimeZone,
  });
  return sendTransactionalEmail({
    tracking: input.tracking,
    skipReason: input.skipReason,
    kind: "magic_link",
    emailBinding: input.emailBinding,
    fromEmail: input.fromEmail,
    fromName: input.fromName,
    recipientEmail: input.recipientEmail,
    subject,
    content: {
      institution,
      title: subject,
      paragraphs: ["Use this link to sign in. You can use it once."],
      details: [{ label: "Link expires", value: formattedExpiresAt }],
      action: { label: "Sign in", url: input.magicLinkUrl },
      footer: "If you did not request this link, you can ignore this email.",
    },
    category: "Auth Magic Link",
  });
};

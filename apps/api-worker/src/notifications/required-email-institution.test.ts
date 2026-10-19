import { createMemoryEmailTracking } from "../test-support/email-attempts";
import { expect, it } from "vitest";
import { createRecordingEmailBinding } from "../test-support/recording-email";
import { sendMagicLinkEmailNotification } from "./send-magic-link-email";
import { sendPasswordResetEmailNotification } from "./send-password-reset-email";
import { sendIssuanceEmailNotification } from "./send-issuance-email";
import { sendMemberInviteEmailNotification } from "./send-member-invite-email";

it("rejects blank institution names before sending any message", async () => {
  const { emailBinding, messages } = createRecordingEmailBinding();
  const common = { emailBinding, tenantDisplayName: " \n ", recipientEmail: "learner@example.edu" };
  const url = "https://badges.example.edu/access?token=disposable-private-token";
  const attempts = [
    () =>
      sendMagicLinkEmailNotification({
        tracking: createMemoryEmailTracking(),
        ...common,
        magicLinkUrl: url,
        expiresAtIso: "2026-10-05T12:00:00Z",
      }),
    () =>
      sendPasswordResetEmailNotification({
        tracking: createMemoryEmailTracking(),
        ...common,
        resetUrl: url,
      }),
    () =>
      sendMemberInviteEmailNotification({
        tracking: createMemoryEmailTracking(),
        ...common,
        role: "issuer",
        signInUrl: url,
      }),
    () =>
      sendIssuanceEmailNotification({
        tracking: createMemoryEmailTracking(),
        ...common,
        badgeTitle: "Completion",
        issuedAtIso: "2026-10-05",
        publicBadgeUrl: url,

        credentialDownloadUrl: url,
      }),
  ];
  for (const send of attempts)
    expect(await send()).toMatchObject({ status: "failed", reason: "render_failed" });
  expect(messages).toHaveLength(0);
});

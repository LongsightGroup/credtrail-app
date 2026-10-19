import { createMemoryEmailTracking } from "../test-support/email-attempts";
import { createRecordingEmailBinding } from "../test-support/recording-email";
import { describe, expect, it } from "vitest";

import { formatMagicLinkExpiry, sendMagicLinkEmailNotification } from "./send-magic-link-email";

describe("sendMagicLinkEmailNotification", () => {
  it("sends notification through Cloudflare Email Service when configured", async () => {
    const { emailBinding, messages } = createRecordingEmailBinding();

    await sendMagicLinkEmailNotification({
      tracking: createMemoryEmailTracking(),
      emailBinding,
      fromEmail: "no-reply@credtrail.org",
      fromName: "CredTrail",
      recipientEmail: "learner@example.edu",

      tenantDisplayName: "Example University",
      magicLinkUrl: "https://credtrail.test/auth/magic-link/verify?token=test-token",
      expiresAtIso: "2026-02-18T01:00:00.000Z",
      preferredLocale: "en-US",
      preferredTimeZone: "America/New_York",
    });

    expect(messages[0]?.html).toContain("Example University");
    expect(messages[0]).toEqual(
      expect.objectContaining({
        from: {
          email: "no-reply@credtrail.org",
          name: "CredTrail",
        },
        to: "learner@example.edu",
        subject: "Sign in to Example University",
        text: expect.stringContaining(
          "https://credtrail.test/auth/magic-link/verify?token=test-token",
        ),
        headers: {
          "X-CredTrail-Email-Kind": "magic_link",
          "X-CredTrail-Email-Category": "Auth Magic Link",
        },
      }),
    );
    expect(messages[0]).toEqual(
      expect.objectContaining({
        text: expect.stringContaining("Example University"),
      }),
    );
    expect(messages[0]).toEqual(
      expect.objectContaining({
        text: expect.stringContaining("Link expires: Feb 17, 2026, 8:00 PM EST"),
      }),
    );
    expect(messages[0]).toEqual(
      expect.objectContaining({
        text: expect.not.stringContaining("Expires at: 2026-02-18T01:00:00.000Z"),
      }),
    );
  });

  it("formats expiry timestamps with a UTC fallback when preferences are invalid", () => {
    expect(
      formatMagicLinkExpiry({
        expiresAtIso: "2026-02-18T01:00:00.000Z",
        preferredLocale: "not a locale",
        preferredTimeZone: "not/a-zone",
      }),
    ).toBe("Feb 18, 2026, 1:00 AM UTC");
  });

  it("keeps tenant details out of an unscoped sign-in email", async () => {
    const { emailBinding, messages } = createRecordingEmailBinding();

    await sendMagicLinkEmailNotification({
      tracking: createMemoryEmailTracking(),
      emailBinding,
      fromEmail: "no-reply@credtrail.org",
      recipientEmail: "learner@example.edu",
      tenantDisplayName: "CredTrail",
      magicLinkUrl: "https://credtrail.test/auth/magic-link/verify?token=test-token",
      expiresAtIso: "2026-02-18T01:00:00.000Z",
    });

    expect(messages[0]).toEqual(
      expect.objectContaining({
        subject: "Sign in to CredTrail",
        text: expect.not.stringContaining("Organization:"),
      }),
    );
  });

  it("skips sending when the Cloudflare Email binding is missing", async () => {
    await expect(
      sendMagicLinkEmailNotification({
        tracking: createMemoryEmailTracking(),
        recipientEmail: "learner@example.edu",

        tenantDisplayName: "Example University",
        magicLinkUrl: "https://credtrail.test/auth/magic-link/verify?token=test-token",
        expiresAtIso: "2026-02-18T01:00:00.000Z",
      }),
    ).resolves.toMatchObject({ status: "skipped", reason: "not_configured" });
  });
});

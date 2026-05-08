import { describe, expect, it, vi } from "vitest";

import { sendPasswordResetEmailNotification } from "./send-password-reset-email";

const createEmailBinding = (): { emailBinding: SendEmail; send: ReturnType<typeof vi.fn> } => {
  const send = vi.fn(async () => {
    return { messageId: "email_msg_123" };
  });

  return {
    emailBinding: { send } as unknown as SendEmail,
    send,
  };
};

describe("sendPasswordResetEmailNotification", () => {
  it("sends notification through Cloudflare Email Service when configured", async () => {
    const { emailBinding, send } = createEmailBinding();

    await sendPasswordResetEmailNotification({
      emailBinding,
      fromEmail: "no-reply@credtrail.org",
      fromName: "CredTrail",
      recipientEmail: "admin@example.edu",
      tenantId: "tenant_123",
      resetUrl: "https://credtrail.test/auth/reset-password?token=test-token",
    });

    expect(send).toHaveBeenCalledWith(
      expect.objectContaining({
        from: {
          email: "no-reply@credtrail.org",
          name: "CredTrail",
        },
        to: "admin@example.edu",
        subject: "Set up local CredTrail access (tenant_123)",
        text: expect.stringContaining(
          "https://credtrail.test/auth/reset-password?token=test-token",
        ),
        headers: {
          "X-CredTrail-Email-Category": "Auth Password Reset",
        },
      }),
    );
  });

  it("skips sending when the Cloudflare Email binding is missing", async () => {
    await expect(
      sendPasswordResetEmailNotification({
        recipientEmail: "admin@example.edu",
        tenantId: "tenant_123",
        resetUrl: "https://credtrail.test/auth/reset-password?token=test-token",
      }),
    ).resolves.toBeUndefined();
  });
});

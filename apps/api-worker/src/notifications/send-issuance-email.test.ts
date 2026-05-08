import { describe, expect, it, vi } from "vitest";

import { sendIssuanceEmailNotification } from "./send-issuance-email";

const createEmailBinding = (): { emailBinding: SendEmail; send: ReturnType<typeof vi.fn> } => {
  const send = vi.fn(async () => {
    return { messageId: "email_msg_123" };
  });

  return {
    emailBinding: { send } as unknown as SendEmail,
    send,
  };
};

describe("sendIssuanceEmailNotification", () => {
  it("sends notification through Cloudflare Email Service when configured", async () => {
    const { emailBinding, send } = createEmailBinding();

    await sendIssuanceEmailNotification({
      emailBinding,
      fromEmail: "no-reply@credtrail.org",
      fromName: "CredTrail",
      recipientEmail: "learner@example.edu",
      badgeTitle: "TypeScript Foundations",
      assertionId: "tenant_123:assertion_456",
      tenantId: "tenant_123",
      issuedAtIso: "2026-02-10T22:00:00.000Z",
      publicBadgeUrl: "https://credtrail.test/badges/40a6dc92-85ec-4cb0-8a50-afb2ae700e22",
      verificationUrl:
        "https://credtrail.test/badges/40a6dc92-85ec-4cb0-8a50-afb2ae700e22/verification",
      credentialDownloadUrl:
        "https://credtrail.test/badges/40a6dc92-85ec-4cb0-8a50-afb2ae700e22/download",
    });

    expect(send).toHaveBeenCalledWith(
      expect.objectContaining({
        from: {
          email: "no-reply@credtrail.org",
          name: "CredTrail",
        },
        to: "learner@example.edu",
        subject: "You've earned a new badge: TypeScript Foundations",
        text: expect.stringContaining(
          "https://credtrail.test/badges/40a6dc92-85ec-4cb0-8a50-afb2ae700e22",
        ),
        headers: {
          "X-CredTrail-Email-Category": "Issuance Notification",
        },
      }),
    );
  });

  it("skips sending when the Cloudflare Email binding is missing", async () => {
    const fetchSpy = vi.spyOn(globalThis, "fetch");

    await sendIssuanceEmailNotification({
      recipientEmail: "learner@example.edu",
      badgeTitle: "TypeScript Foundations",
      assertionId: "tenant_123:assertion_456",
      tenantId: "tenant_123",
      issuedAtIso: "2026-02-10T22:00:00.000Z",
      publicBadgeUrl: "https://credtrail.test/badges/40a6dc92-85ec-4cb0-8a50-afb2ae700e22",
      verificationUrl:
        "https://credtrail.test/badges/40a6dc92-85ec-4cb0-8a50-afb2ae700e22/verification",
      credentialDownloadUrl:
        "https://credtrail.test/badges/40a6dc92-85ec-4cb0-8a50-afb2ae700e22/download",
    });

    expect(fetchSpy).not.toHaveBeenCalled();

    fetchSpy.mockRestore();
  });
});

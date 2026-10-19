import { describe, expect, it } from "vitest";
import { createSesEmailBinding } from "./ses-email";
import { sendTransactionalEmail } from "./transactional-email";
import { createMemoryEmailTracking } from "../test-support/email-attempts";

const content = {
  institution: "University",
  title: "Your badge",
  paragraphs: ["Your badge is ready."],
  action: { label: "View badge", url: "https://credtrail.org/badges/test" },
  footer: "Contact your issuer.",
};

describe("provider backoff signals", () => {
  it.each([
    { name: "TooManyRequestsException", $metadata: { httpStatusCode: 429 } },
    { name: "ThrottlingException" },
    { $metadata: { httpStatusCode: 429 } },
  ])(
    "records explicit SES throttling as failed and asks the batch to slow down: %j",
    async (details) => {
      const tracking = createMemoryEmailTracking();
      const emailBinding = createSesEmailBinding(
        { region: "us-east-1" },
        {
          send: async () => {
            throw Object.assign(new Error("secret-provider-response"), details);
          },
        },
      );
      const result = await sendTransactionalEmail({
        tracking,
        emailBinding,
        kind: "issuance",
        recipientEmail: "learner@example.edu",
        subject: "Your badge",
        content,
        category: "Issuance Notification",
      });
      expect(result).toMatchObject({
        status: "failed",
        reason: "provider_rejected",
        providerBusy: true,
      });
      expect(tracking.attempts).toHaveLength(1);
      expect(tracking.attempts[0]?.outcome).toEqual({
        status: "failed",
        reason: "provider_rejected",
      });
      expect(JSON.stringify(result)).not.toContain("secret-provider-response");
    },
  );

  it("preserves uncertainty for a lost reply without treating it as an explicit throttle rejection", async () => {
    const tracking = createMemoryEmailTracking();
    const result = await sendTransactionalEmail({
      tracking,
      kind: "issuance",
      recipientEmail: "learner@example.edu",
      subject: "Your badge",
      content,
      category: "Issuance Notification",
      emailBinding: {
        send: async () => {
          throw new Error("Lost reply");
        },
      },
    });
    expect(result).toMatchObject({ status: "pending", reason: "provider_uncertain" });
    expect(result).not.toHaveProperty("providerBusy");
    expect(tracking.attempts).toHaveLength(1);
  });
});

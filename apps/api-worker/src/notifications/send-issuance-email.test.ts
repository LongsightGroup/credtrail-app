import { linkedinOrganizationIdSchema } from "@credtrail/validation";
import { createRecordingEmailBinding } from "../test-support/recording-email";
import { describe, expect, it } from "vitest";

import { sendIssuanceEmailNotification } from "./send-issuance-email";

describe("sendIssuanceEmailNotification", () => {
  it("sends notification through Cloudflare Email Service when configured", async () => {
    const { emailBinding, messages } = createRecordingEmailBinding();

    await sendIssuanceEmailNotification({
      emailBinding,
      fromEmail: "no-reply@credtrail.org",
      fromName: "CredTrail",
      recipientEmail: "learner@example.edu",
      badgeTitle: "TypeScript Foundations",

      tenantDisplayName: "Example University",
      issuedAtIso: "2026-02-10T22:00:00.000Z",
      publicBadgeUrl: "https://credtrail.test/badges/40a6dc92-85ec-4cb0-8a50-afb2ae700e22",
      verificationUrl:
        "https://credtrail.test/badges/40a6dc92-85ec-4cb0-8a50-afb2ae700e22/verification",
      credentialDownloadUrl:
        "https://credtrail.test/badges/40a6dc92-85ec-4cb0-8a50-afb2ae700e22/download",
    });

    expect(messages[0]?.html).toContain("Example University");
    expect(messages[0]).toEqual(
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
          "X-CredTrail-Email-Kind": "issuance",
          "X-CredTrail-Email-Category": "Issuance Notification",
        },
      }),
    );
  });

  it("skips sending when the Cloudflare Email binding is missing", async () => {
    await expect(
      sendIssuanceEmailNotification({
        recipientEmail: "learner@example.edu",
        badgeTitle: "TypeScript Foundations",

        tenantDisplayName: "Example University",
        issuedAtIso: "2026-02-10T22:00:00.000Z",
        publicBadgeUrl: "https://credtrail.test/badges/40a6dc92-85ec-4cb0-8a50-afb2ae700e22",
        verificationUrl:
          "https://credtrail.test/badges/40a6dc92-85ec-4cb0-8a50-afb2ae700e22/verification",
        credentialDownloadUrl:
          "https://credtrail.test/badges/40a6dc92-85ec-4cb0-8a50-afb2ae700e22/download",
      }),
    ).resolves.toBeUndefined();
  });
});

describe("issuance email expiry", () => {
  it("shows the expiry when the credential has one", async () => {
    const { emailBinding, messages } = createRecordingEmailBinding();

    await sendIssuanceEmailNotification({
      emailBinding,
      recipientEmail: "learner@example.edu",
      badgeTitle: "TypeScript Foundations",
      tenantDisplayName: "Example University",
      issuedAtIso: "2026-02-10T22:00:00.000Z",
      publicBadgeUrl: "https://credtrail.test/badges/40a6dc92-85ec-4cb0-8a50-afb2ae700e22",
      verificationUrl:
        "https://credtrail.test/badges/40a6dc92-85ec-4cb0-8a50-afb2ae700e22/verification",
      credentialDownloadUrl:
        "https://credtrail.test/badges/40a6dc92-85ec-4cb0-8a50-afb2ae700e22/download",
      validUntilIso: "2027-02-10T22:00:00.000Z",
    });

    expect(messages[0]?.html).toContain("Valid until");
    expect(messages[0]?.html).toContain("2027-02-10T22:00:00.000Z");
    expect(messages[0]?.text).toContain("Valid until: 2027-02-10T22:00:00.000Z");
  });

  describe("issuance email LinkedIn link", () => {
    const baseInput = {
      recipientEmail: "learner@example.edu",
      badgeTitle: "TypeScript Foundations",
      tenantDisplayName: "Example University",
      issuedAtIso: "2026-02-10T22:00:00.000Z",
      publicBadgeUrl: "https://credtrail.test/badges/40a6dc92-85ec-4cb0-8a50-afb2ae700e22",
      verificationUrl:
        "https://credtrail.test/badges/40a6dc92-85ec-4cb0-8a50-afb2ae700e22/verification",
      credentialDownloadUrl:
        "https://credtrail.test/badges/40a6dc92-85ec-4cb0-8a50-afb2ae700e22/download",
      credentialId: "urn:credtrail:assertion:tenant_123%3Aassertion_456",
    };

    it("offers Add to LinkedIn with the issuer name, credential and dates", async () => {
      const { emailBinding, messages } = createRecordingEmailBinding();

      await sendIssuanceEmailNotification({
        ...baseInput,
        emailBinding,
        validUntilIso: "2027-02-10T22:00:00.000Z",
      });

      const html = messages[0]?.html ?? "";
      expect(html).toContain("Add to LinkedIn");
      expect(html).toContain("https://www.linkedin.com/profile/add?");
      expect(html).toContain("organizationName=Example+University");
      expect(html).toContain("certId=urn%3Acredtrail%3Aassertion%3Atenant_123%253Aassertion_456");
      expect(html).toContain("issueYear=2026");
      expect(html).toContain("expirationYear=2027");
      expect(messages[0]?.text).toContain("Add to LinkedIn: https://www.linkedin.com/profile/add?");
    });

    it("links the certification to the issuer's LinkedIn organization when configured", async () => {
      const { emailBinding, messages } = createRecordingEmailBinding();

      await sendIssuanceEmailNotification({
        ...baseInput,
        emailBinding,
        linkedInOrganizationId: linkedinOrganizationIdSchema.parse("110806030"),
      });

      expect(messages[0]?.html).toContain("organizationId=110806030");
      expect(messages[0]?.html).not.toContain("organizationName=");
    });
  });
});

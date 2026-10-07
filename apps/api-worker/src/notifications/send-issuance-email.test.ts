import { createRecordingEmailBinding } from "../test-support/recording-email";
import { describe, expect, it } from "vitest";

import { sendIssuanceEmailNotification } from "./send-issuance-email";

describe("sendIssuanceEmailNotification", () => {
  it("delivers artwork, achievement content and public downloads with equivalent text actions", async () => {
    const { emailBinding, messages } = createRecordingEmailBinding();
    const publicBadgeUrl = "https://badges.example.edu/badges/event-123";
    await sendIssuanceEmailNotification({
      emailBinding,
      recipientEmail: "learner@example.edu",
      badgeTitle: "Community & <Research>",
      badgeDescription: 'Completed the event. <script>alert("unsafe")</script>',
      badgeImageUrl: "/badges/artwork/event.png",
      tenantDisplayName: "North University",
      issuedAtIso: "2026-10-07T17:00:00.000Z",
      validUntilIso: "2027-10-07T17:00:00.000Z",
      publicBadgeUrl,
      credentialDownloadUrl: `${publicBadgeUrl}/download`,
    });
    const message = messages[0];
    expect(message?.html).toContain('src="https://badges.example.edu/badges/artwork/event.png"');
    expect(message?.html).toContain("Community &amp; &lt;Research&gt; badge artwork");
    expect(message?.html).toContain("&lt;script&gt;");
    expect(message?.html).not.toContain("<script>");
    expect(message?.text).toContain('Completed the event. <script>alert("unsafe")</script>');
    for (const path of ["", "/download.pdf", "/download", "/share/linkedin-profile"]) {
      expect(message?.html).toContain(`href="${publicBadgeUrl}${path}"`);
      expect(message?.text).toContain(`${publicBadgeUrl}${path}`);
    }
    expect(message?.html).not.toContain("/verification");
    expect(message?.text).toContain("Issued: Oct 7, 2026, 5:00 PM UTC");
    expect(message?.text).toContain("Valid until: Oct 7, 2027, 5:00 PM UTC");
  });

  it.each([
    undefined,
    "",
    "javascript:alert(1)",
    "data:image/png;base64,AAAA",
    "http://127.0.0.1/image",
    "https://user:password@example.edu/image",
  ])("keeps notifications usable without public artwork (%s)", async (badgeImageUrl) => {
    const { emailBinding, messages } = createRecordingEmailBinding();
    await sendIssuanceEmailNotification({
      emailBinding,
      recipientEmail: "learner@example.edu",
      badgeTitle: "Participation",
      badgeImageUrl,
      badgeDescription: " ",
      tenantDisplayName: "Example University",
      issuedAtIso: "2026-10-07T17:00:00.000Z",
      publicBadgeUrl: "https://badges.example.edu/badges/123",
      credentialDownloadUrl: "https://badges.example.edu/badges/123/download",
    });
    expect(messages[0]?.html).not.toContain("<img");
    expect(messages[0]?.html).toContain("/badges/123/download.pdf");
    expect(messages[0]?.text).not.toContain("Valid until:");
  });

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

      credentialDownloadUrl:
        "https://credtrail.test/badges/40a6dc92-85ec-4cb0-8a50-afb2ae700e22/download",
      validUntilIso: "2027-02-10T22:00:00.000Z",
    });

    expect(messages[0]?.html).toContain("Valid until");
    expect(messages[0]?.html).toContain("Feb 10, 2027, 10:00 PM UTC");
    expect(messages[0]?.text).toContain("Valid until: Feb 10, 2027, 10:00 PM UTC");
  });

  it("routes LinkedIn sharing through the public credential record", async () => {
    const { emailBinding, messages } = createRecordingEmailBinding();
    const publicBadgeUrl = "https://credtrail.org/badges/40a6dc92-85ec-4cb0-8a50-afb2ae700e22";
    await sendIssuanceEmailNotification({
      emailBinding,
      recipientEmail: "learner@example.edu",
      badgeTitle: "TypeScript Foundations",
      tenantDisplayName: "Example University",
      issuedAtIso: "2026-02-10T22:00:00.000Z",
      validUntilIso: "2027-02-10T22:00:00.000Z",
      publicBadgeUrl,

      credentialDownloadUrl: `${publicBadgeUrl}/download`,
    });
    expect(messages[0]?.html).toContain(`href="${publicBadgeUrl}/share/linkedin-profile"`);
    expect(messages[0]?.text).toContain(
      `Add to LinkedIn: ${publicBadgeUrl}/share/linkedin-profile`,
    );
  });
});

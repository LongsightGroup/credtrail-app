import { describe, expect, it, vi } from "vitest";

import { sendIssuanceEmailNotification } from "./send-issuance-email";

describe("sendIssuanceEmailNotification", () => {
  it("sends notification through Mailtrap API when configured", async () => {
    const fetchSpy = vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response("", {
        status: 200,
      }),
    );

    await sendIssuanceEmailNotification({
      mailtrapApiToken: "token-123",
      mailtrapInboxId: "4374730",
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

    expect(fetchSpy).toHaveBeenCalledTimes(1);
    const firstCall = fetchSpy.mock.calls[0];
    expect(firstCall?.[0]).toBe("https://sandbox.api.mailtrap.io/api/send/4374730");

    const requestInit = firstCall?.[1];
    expect(requestInit?.method).toBe("POST");
    expect(requestInit?.headers).toEqual({
      Authorization: "Bearer token-123",
      "Content-Type": "application/json",
    });

    fetchSpy.mockRestore();
  });

  it("sends notification through Mailtrap production API without appending an inbox id", async () => {
    const fetchSpy = vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response("", {
        status: 200,
      }),
    );

    await sendIssuanceEmailNotification({
      mailtrapApiToken: "token-123",
      mailtrapApiBaseUrl: "https://send.api.mailtrap.io/api/send",
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

    expect(fetchSpy).toHaveBeenCalledTimes(1);
    const firstCall = fetchSpy.mock.calls[0];
    expect(firstCall?.[0]).toBe("https://send.api.mailtrap.io/api/send");

    fetchSpy.mockRestore();
  });

  it("skips sending when Mailtrap config is missing", async () => {
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

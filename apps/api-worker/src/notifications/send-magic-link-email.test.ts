import { describe, expect, it, vi } from "vitest";

import { sendMagicLinkEmailNotification } from "./send-magic-link-email";

describe("sendMagicLinkEmailNotification", () => {
  it("sends notification through Mailtrap API when configured", async () => {
    const fetchSpy = vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response("", {
        status: 200,
      }),
    );

    await sendMagicLinkEmailNotification({
      mailtrapApiToken: "token-123",
      mailtrapInboxId: "4374730",
      recipientEmail: "learner@example.edu",
      tenantId: "tenant_123",
      magicLinkUrl: "https://credtrail.test/auth/magic-link/verify?token=test-token",
      expiresAtIso: "2026-02-18T01:00:00.000Z",
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

    await sendMagicLinkEmailNotification({
      mailtrapApiToken: "token-123",
      mailtrapApiBaseUrl: "https://send.api.mailtrap.io/api/send",
      recipientEmail: "learner@example.edu",
      tenantId: "tenant_123",
      magicLinkUrl: "https://credtrail.test/auth/magic-link/verify?token=test-token",
      expiresAtIso: "2026-02-18T01:00:00.000Z",
    });

    expect(fetchSpy).toHaveBeenCalledTimes(1);
    const firstCall = fetchSpy.mock.calls[0];
    expect(firstCall?.[0]).toBe("https://send.api.mailtrap.io/api/send");

    fetchSpy.mockRestore();
  });

  it("skips sending when Mailtrap config is missing", async () => {
    const fetchSpy = vi.spyOn(globalThis, "fetch");

    await sendMagicLinkEmailNotification({
      recipientEmail: "learner@example.edu",
      tenantId: "tenant_123",
      magicLinkUrl: "https://credtrail.test/auth/magic-link/verify?token=test-token",
      expiresAtIso: "2026-02-18T01:00:00.000Z",
    });

    expect(fetchSpy).not.toHaveBeenCalled();

    fetchSpy.mockRestore();
  });
});

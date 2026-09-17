import { describe, expect, it } from "vitest";
import {
  attemptIssuanceEmail,
  issuanceEmailOutcomeMessage,
  issuanceEmailAvailability,
  issuanceEmailExpectation,
} from "./issuance-email-outcome";

describe("issuance email outcomes", () => {
  it("only reports acceptance after the sender resolves", async () => {
    let sent = false;
    const outcome = await attemptIssuanceEmail({
      isEmailRecipient: true,
      enabled: true,
      configured: true,
      suppressed: false,
      send: async () => {
        sent = true;
      },
    });
    expect(sent).toBe(true);
    expect(outcome).toBe("accepted");
    expect(issuanceEmailOutcomeMessage(outcome)).toContain("not confirmed");
  });
  it("returns failure without turning an issued credential into an issuance error", async () => {
    const outcome = await attemptIssuanceEmail({
      isEmailRecipient: true,
      enabled: true,
      configured: true,
      suppressed: false,
      send: async () => {
        throw new Error("provider unavailable");
      },
    });
    expect(outcome).toBe("failed");
    expect(issuanceEmailOutcomeMessage(outcome)).toContain("still issued");
  });
  it.each([
    {
      isEmailRecipient: false,
      enabled: true,
      configured: true,
      suppressed: false,
      expected: "not_applicable",
    },
    {
      isEmailRecipient: true,
      enabled: false,
      configured: true,
      suppressed: false,
      expected: "disabled",
    },
    {
      isEmailRecipient: true,
      enabled: true,
      configured: false,
      suppressed: false,
      expected: "not_configured",
    },
    {
      isEmailRecipient: true,
      enabled: true,
      configured: true,
      suppressed: true,
      expected: "suppressed",
    },
  ])("does not call the sender when $expected", async ({ expected, ...settings }) => {
    let sent = false;
    expect(
      await attemptIssuanceEmail({
        ...settings,
        send: async () => {
          sent = true;
        },
      }),
    ).toBe(expected);
    expect(sent).toBe(false);
  });
  it.each([
    { enabled: true, configured: true, status: "ready", message: "will attempt to email" },
    { enabled: false, configured: true, status: "disabled", message: "turned off" },
    { enabled: true, configured: false, status: "not_configured", message: "Email is unavailable" },
  ])("sets accurate expectations when $status", ({ enabled, configured, status, message }) => {
    const availability = issuanceEmailAvailability({ enabled, configured });
    expect(availability).toBe(status);
    expect(issuanceEmailExpectation(availability)).toContain(message);
  });
});

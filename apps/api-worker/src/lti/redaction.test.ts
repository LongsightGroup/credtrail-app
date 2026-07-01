import { describe, expect, it } from "vitest";
import { redactLtiProtocolSecrets } from "./redaction";

describe("redactLtiProtocolSecrets", () => {
  it("redacts id_token and state values from free-text messages", () => {
    expect(
      redactLtiProtocolSecrets("Launch config not found for issuer id_token=secret state=secret"),
    ).toBe("Launch config not found for issuer id_token=[redacted] state=[redacted]");
  });

  it("preserves query separators between redacted values", () => {
    expect(
      redactLtiProtocolSecrets(
        "https://tool.example/launch?id_token=secret-token&state=secret-state&next=course",
      ),
    ).toBe("https://tool.example/launch?id_token=[redacted]&state=[redacted]&next=course");
  });

  it("limits diagnostic length after redaction", () => {
    expect(redactLtiProtocolSecrets(`id_token=secret ${"x".repeat(600)}`)).toHaveLength(500);
  });
});

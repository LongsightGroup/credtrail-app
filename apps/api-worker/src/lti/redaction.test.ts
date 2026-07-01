import { describe, expect, it } from "vitest";
import { ltiErrorDetail, redactLtiProtocolSecrets } from "./redaction";

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

describe("ltiErrorDetail", () => {
  it("extracts and redacts Error messages", () => {
    expect(ltiErrorDetail(new Error("Launch failed id_token=secret"))).toBe(
      "Launch failed id_token=[redacted]",
    );
  });

  it("extracts and redacts string errors", () => {
    expect(ltiErrorDetail("Launch failed state=secret")).toBe("Launch failed state=[redacted]");
  });

  it("ignores unsupported thrown values", () => {
    expect(ltiErrorDetail({ message: "Launch failed id_token=secret" })).toBeUndefined();
  });
});

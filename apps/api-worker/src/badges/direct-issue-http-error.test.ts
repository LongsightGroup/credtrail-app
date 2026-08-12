import { describe, expect, it } from "vitest";
import { isIssueBadgeHttpError } from "./direct-issue";

describe("isIssueBadgeHttpError", () => {
  it("recognizes every supported issuance status, including service unavailability", () => {
    for (const statusCode of [400, 404, 409, 422, 500, 502, 503]) {
      expect(isIssueBadgeHttpError({ statusCode, payload: { error: "Issuance failed" } })).toBe(
        true,
      );
    }
  });

  it("rejects unsupported status codes and malformed payloads", () => {
    expect(isIssueBadgeHttpError({ statusCode: 504, payload: { error: "Timeout" } })).toBe(false);
    expect(isIssueBadgeHttpError({ statusCode: 503, payload: {} })).toBe(false);
  });
});

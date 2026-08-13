import { describe, expect, it } from "vitest";
import { buildLoginPath, parseLoginReason, type LoginReason } from "./login-path";

const supportedLoginReasons: readonly LoginReason[] = [
  "auth_required",
  "break_glass_unavailable",
  "google_failed",
  "google_unavailable",
  "signed_out",
  "sso_failed",
  "sso_required",
  "sso_unavailable",
];

describe("login path contract", () => {
  it.each(supportedLoginReasons)("parses the supported %s reason", (reason) => {
    expect(parseLoginReason(` ${reason} `)).toBe(reason);
  });

  it.each([undefined, "", "unknown_reason"])("rejects unsupported reason %s", (reason) => {
    expect(parseLoginReason(reason)).toBeUndefined();
  });

  it("builds an encoded login path in canonical query order", () => {
    expect(
      buildLoginPath({
        tenantId: "tenant 123",
        nextPath: "/tenants/tenant 123/admin",
        reason: "auth_required",
      }),
    ).toBe("/login?tenantId=tenant+123&next=%2Ftenants%2Ftenant+123%2Fadmin&reason=auth_required");
  });

  it("omits empty optional query parameters", () => {
    expect(buildLoginPath({ tenantId: " ", nextPath: "" })).toBe("/login");
  });
});

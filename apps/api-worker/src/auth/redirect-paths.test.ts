import { describe, expect, it } from "vitest";

import { isSafeRedirectPath, normalizeSafeRedirectPath } from "./redirect-paths";

describe("redirect path safety", () => {
  it("allows local absolute paths", () => {
    expect(isSafeRedirectPath("/tenants/tenant_123/admin")).toBe(true);
    expect(normalizeSafeRedirectPath("/auth/resolve", "/fallback")).toBe("/auth/resolve");
  });

  it("rejects protocol-relative and external paths", () => {
    expect(isSafeRedirectPath("//evil.example/path")).toBe(false);
    expect(isSafeRedirectPath("https://evil.example/path")).toBe(false);
    expect(normalizeSafeRedirectPath("//evil.example/path", "/fallback")).toBe("/fallback");
    expect(normalizeSafeRedirectPath("https://evil.example/path", "/fallback")).toBe("/fallback");
  });
});

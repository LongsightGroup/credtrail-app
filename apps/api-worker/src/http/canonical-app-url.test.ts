import { describe, expect, it } from "vitest";
import { canonicalAppUrl } from "./canonical-app-url";

describe("canonicalAppUrl", () => {
  it("uses the configured public domain for application links", () => {
    expect(canonicalAppUrl("credtrail.org", "/tenants/tenant_123/admin/rules")).toBe(
      "https://credtrail.org/tenants/tenant_123/admin/rules",
    );
  });

  it("rejects values that are not host configuration", () => {
    expect(() => canonicalAppUrl("private.workers.dev/path", "/rules")).toThrow("PLATFORM_DOMAIN");
  });
});

import { describe, expect, it } from "vitest";
import { canonicalAppOrigin, canonicalAppRequestUrl, canonicalAppUrl } from "./canonical-app-url";

describe("canonicalAppUrl", () => {
  it("uses the configured public domain for application links", () => {
    expect(canonicalAppUrl("https://credtrail.org", "/tenants/tenant_123/admin/rules")).toBe(
      "https://credtrail.org/tenants/tenant_123/admin/rules",
    );
  });

  it("preserves the explicit local development scheme and port", () => {
    expect(canonicalAppUrl("http://localhost:8787", "/badges/assets/example")).toBe(
      "http://localhost:8787/badges/assets/example",
    );
  });

  it("rebuilds request paths and queries without trusting the incoming origin", () => {
    expect(
      canonicalAppRequestUrl(
        "https://credtrail.org",
        "https://unexpected.example/badges/example?wallet=1",
      ),
    ).toBe("https://credtrail.org/badges/example?wallet=1");

    expect(
      canonicalAppRequestUrl(
        "https://credtrail.org",
        "https://unexpected.example//evil.example/badges?wallet=1",
      ),
    ).toBe("https://credtrail.org//evil.example/badges?wallet=1");
  });

  it("rejects absolute and protocol-relative application paths", () => {
    expect(() => canonicalAppUrl("https://credtrail.org", "https://evil.example/path")).toThrow(
      "root-relative",
    );
    expect(() => canonicalAppUrl("https://credtrail.org", "//evil.example/path")).toThrow(
      "root-relative",
    );
    expect(() => canonicalAppUrl("https://credtrail.org", "/\\evil.example/path")).toThrow(
      "remain on PUBLIC_APP_ORIGIN",
    );
  });

  it("rejects missing, path-bearing, credential-bearing, and insecure public origins", () => {
    expect(() => canonicalAppOrigin(" ")).toThrow("PUBLIC_APP_ORIGIN");
    expect(() => canonicalAppOrigin("credtrail.org")).toThrow("PUBLIC_APP_ORIGIN");
    expect(() => canonicalAppOrigin("https://credtrail.org/path")).toThrow("PUBLIC_APP_ORIGIN");
    expect(() => canonicalAppOrigin("https://user@credtrail.org")).toThrow("PUBLIC_APP_ORIGIN");
    expect(() => canonicalAppOrigin("http://credtrail.org")).toThrow("only for local development");
  });
});

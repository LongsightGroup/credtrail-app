import { describe, expect, it } from "vitest";
import { findLtiIssuerRegistryEntry, type LtiIssuerRegistry } from "./lti-helpers";

describe("findLtiIssuerRegistryEntry", () => {
  const registry: LtiIssuerRegistry = {
    "https://canvas.example.edu": {
      authorizationEndpoint: "https://canvas.example.edu/api/lti/authorize_redirect",
      clientId: "client-123",
      tenantId: "tenant-123",
    },
  };

  it("finds an issuer and client pair after normalizing issuer values", () => {
    expect(
      findLtiIssuerRegistryEntry(registry, "https://canvas.example.edu/", "client-123"),
    ).toEqual({
      issuer: "https://canvas.example.edu",
      entry: registry["https://canvas.example.edu"],
    });
  });

  it("returns null when the issuer exists with a different client", () => {
    expect(findLtiIssuerRegistryEntry(registry, "https://canvas.example.edu", "client-456")).toBe(
      null,
    );
  });
});

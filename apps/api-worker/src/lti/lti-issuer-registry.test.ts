import { describe, expect, it } from "vitest";
import {
  findLtiIssuerRegistryEntry,
  resolveLtiLoginIssuer,
  type LtiIssuerRegistry,
} from "./lti-issuer-registry";

const registry: LtiIssuerRegistry = {
  "https://canvas.example.edu": {
    authorizationEndpoint: "https://canvas.example.edu/api/lti/authorize_redirect",
    clientId: "client-123",
    tenantId: "tenant-123",
  },
};

describe("findLtiIssuerRegistryEntry", () => {
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

  it("finds the matching client across duplicate normalized issuer keys", () => {
    const duplicateIssuerRegistry: LtiIssuerRegistry = {
      "https://canvas.example.edu/": {
        authorizationEndpoint: "https://canvas.example.edu/api/lti/authorize_redirect",
        clientId: "client-123",
        tenantId: "tenant-123",
      },
      "https://canvas.example.edu": {
        authorizationEndpoint: "https://canvas.example.edu/api/lti/authorize_redirect",
        clientId: "client-456",
        tenantId: "tenant-456",
      },
    };

    expect(
      findLtiIssuerRegistryEntry(
        duplicateIssuerRegistry,
        "https://canvas.example.edu",
        "client-456",
      ),
    ).toEqual({
      issuer: "https://canvas.example.edu",
      entry: duplicateIssuerRegistry["https://canvas.example.edu"],
    });
  });
});

describe("resolveLtiLoginIssuer", () => {
  it("resolves a login issuer without client_id by using the registered client", () => {
    expect(
      resolveLtiLoginIssuer(registry, {
        iss: "https://canvas.example.edu/",
      }),
    ).toEqual({
      status: "resolved",
      issuer: "https://canvas.example.edu",
      entry: registry["https://canvas.example.edu"],
      clientId: "client-123",
    });
  });

  it("resolves a login issuer when client_id matches the registered client", () => {
    expect(
      resolveLtiLoginIssuer(registry, {
        iss: "https://canvas.example.edu",
        client_id: "client-123",
      }),
    ).toMatchObject({
      status: "resolved",
      clientId: "client-123",
    });
  });

  it("rejects a login issuer when client_id does not match the registered client", () => {
    expect(
      resolveLtiLoginIssuer(registry, {
        iss: "https://canvas.example.edu",
        client_id: "client-456",
      }),
    ).toMatchObject({
      status: "client_id_mismatch",
      issuer: "https://canvas.example.edu",
      requestedClientId: "client-456",
    });
  });

  it("returns unknown_issuer when the issuer is not registered", () => {
    expect(
      resolveLtiLoginIssuer(registry, {
        iss: "https://unknown.example.edu",
      }),
    ).toEqual({
      status: "unknown_issuer",
      issuer: "https://unknown.example.edu",
    });
  });
});

import type { LtiIssuerRegistrationRecord } from "@credtrail/db";
import { describe, expect, it } from "vitest";
import {
  ltiIssuerRegistryFromStoredRows,
  parseLtiIssuerRegistryFromEnv,
} from "./lti-issuer-registry-config";

const sampleStoredRow = (
  overrides?: Partial<LtiIssuerRegistrationRecord>,
): LtiIssuerRegistrationRecord => {
  return {
    issuer: "https://canvas.example.edu",
    tenantId: "tenant-123",
    authorizationEndpoint: "https://canvas.example.edu/api/lti/authorize_redirect",
    clientId: "client-123",
    platformJwksEndpoint: "https://canvas.example.edu/api/lti/security/jwks",
    tokenEndpoint: "https://canvas.example.edu/login/oauth2/token",
    clientSecret: null,
    createdAt: "2026-01-01T00:00:00.000Z",
    updatedAt: "2026-01-01T00:00:00.000Z",
    ...overrides,
  };
};

describe("parseLtiIssuerRegistryFromEnv", () => {
  it("returns an empty registry when env config is missing or blank", () => {
    expect(parseLtiIssuerRegistryFromEnv(undefined)).toEqual({});
    expect(parseLtiIssuerRegistryFromEnv("   ")).toEqual({});
  });

  it("parses a valid issuer registry from env JSON", () => {
    expect(
      parseLtiIssuerRegistryFromEnv(
        JSON.stringify({
          "https://canvas.example.edu/": {
            authorizationEndpoint: "https://canvas.example.edu/api/lti/authorize_redirect",
            clientId: "client-123",
            tenantId: "tenant-123",
            platformJwksEndpoint: "https://canvas.example.edu/api/lti/security/jwks",
            tokenEndpoint: "https://canvas.example.edu/login/oauth2/token",
          },
        }),
      ),
    ).toEqual({
      "https://canvas.example.edu": {
        authorizationEndpoint: "https://canvas.example.edu/api/lti/authorize_redirect",
        clientId: "client-123",
        tenantId: "tenant-123",
        platformJwksEndpoint: "https://canvas.example.edu/api/lti/security/jwks",
        tokenEndpoint: "https://canvas.example.edu/login/oauth2/token",
      },
    });
  });

  it("rejects invalid JSON", () => {
    expect(() => parseLtiIssuerRegistryFromEnv("{not-json")).toThrow(
      "LTI_ISSUER_REGISTRY_JSON is not valid JSON",
    );
  });

  it("rejects non-object JSON roots", () => {
    expect(() => parseLtiIssuerRegistryFromEnv("[]")).toThrow(
      "LTI_ISSUER_REGISTRY_JSON must be a JSON object keyed by issuer URL",
    );
  });

  it("rejects issuer entries that are not objects", () => {
    expect(() =>
      parseLtiIssuerRegistryFromEnv(
        JSON.stringify({
          "https://canvas.example.edu": "invalid",
        }),
      ),
    ).toThrow('LTI_ISSUER_REGISTRY_JSON["https://canvas.example.edu"] must be an object');
  });

  it("rejects invalid authorization endpoint URLs", () => {
    expect(() =>
      parseLtiIssuerRegistryFromEnv(
        JSON.stringify({
          "https://canvas.example.edu": {
            authorizationEndpoint: "not-a-url",
            clientId: "client-123",
            tenantId: "tenant-123",
          },
        }),
      ),
    ).toThrow(
      'LTI_ISSUER_REGISTRY_JSON["https://canvas.example.edu"].authorizationEndpoint must be an absolute http(s) URL',
    );
  });

  it("rejects missing clientId values", () => {
    expect(() =>
      parseLtiIssuerRegistryFromEnv(
        JSON.stringify({
          "https://canvas.example.edu": {
            authorizationEndpoint: "https://canvas.example.edu/api/lti/authorize_redirect",
            clientId: "",
            tenantId: "tenant-123",
          },
        }),
      ),
    ).toThrow(
      'LTI_ISSUER_REGISTRY_JSON["https://canvas.example.edu"].clientId must be a non-empty string',
    );
  });

  it("rejects invalid optional endpoint URLs", () => {
    expect(() =>
      parseLtiIssuerRegistryFromEnv(
        JSON.stringify({
          "https://canvas.example.edu": {
            authorizationEndpoint: "https://canvas.example.edu/api/lti/authorize_redirect",
            clientId: "client-123",
            tenantId: "tenant-123",
            tokenEndpoint: "ftp://bad.example/token",
          },
        }),
      ),
    ).toThrow(
      'LTI_ISSUER_REGISTRY_JSON["https://canvas.example.edu"].tokenEndpoint must be an absolute http(s) URL when provided',
    );
  });
});

describe("ltiIssuerRegistryFromStoredRows", () => {
  it("maps stored issuer rows into a normalized registry", () => {
    expect(ltiIssuerRegistryFromStoredRows([sampleStoredRow()])).toEqual({
      "https://canvas.example.edu": {
        authorizationEndpoint: "https://canvas.example.edu/api/lti/authorize_redirect",
        clientId: "client-123",
        tenantId: "tenant-123",
        platformJwksEndpoint: "https://canvas.example.edu/api/lti/security/jwks",
        tokenEndpoint: "https://canvas.example.edu/login/oauth2/token",
      },
    });
  });

  it("omits null optional endpoints from stored rows", () => {
    expect(
      ltiIssuerRegistryFromStoredRows([
        sampleStoredRow({
          platformJwksEndpoint: null,
          tokenEndpoint: null,
        }),
      ]),
    ).toEqual({
      "https://canvas.example.edu": {
        authorizationEndpoint: "https://canvas.example.edu/api/lti/authorize_redirect",
        clientId: "client-123",
        tenantId: "tenant-123",
      },
    });
  });

  it("rejects stored rows with invalid issuer URLs", () => {
    expect(() =>
      ltiIssuerRegistryFromStoredRows([
        sampleStoredRow({
          issuer: "not-a-url",
        }),
      ]),
    ).toThrow('Stored LTI issuer "not-a-url" is not a valid absolute http(s) URL');
  });

  it("rejects stored rows with empty clientId", () => {
    expect(() =>
      ltiIssuerRegistryFromStoredRows([
        sampleStoredRow({
          clientId: "   ",
        }),
      ]),
    ).toThrow('Stored LTI issuer "https://canvas.example.edu" has empty clientId');
  });

  it("rejects stored rows with invalid token endpoint URLs", () => {
    expect(() =>
      ltiIssuerRegistryFromStoredRows([
        sampleStoredRow({
          tokenEndpoint: "not-a-url",
        }),
      ]),
    ).toThrow('Stored LTI issuer "https://canvas.example.edu" has invalid token endpoint URL');
  });
});

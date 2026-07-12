import type { LTI13JwtPayload } from "@longsightgroup/lti-tool";
import { LtiLaunchVerificationError as CoreLtiLaunchVerificationError } from "@longsightgroup/lti-tool";
import { describe, expect, it } from "vitest";
import {
  authorizeVerifiedLaunchForRegistry,
  ltiLaunchVerificationErrorFromCoreError,
} from "./launch-verification";
import type { LtiIssuerRegistry } from "./lti-issuer-registry";

const issuer = "https://canvas.example.edu";
const clientId = "canvas-client-123";
const deploymentId = "deployment-123";
const targetLinkUri = "https://credtrail.example.edu/v1/lti/launch";

const signedLaunchRegistry: LtiIssuerRegistry = {
  [issuer]: {
    authorizationEndpoint: "https://canvas.example.edu/api/lti/authorize_redirect",
    clientId,
    tenantId: "tenant-123",
    platformJwksEndpoint: "https://canvas.example.edu/api/lti/security/jwks",
    tokenEndpoint: "https://canvas.example.edu/login/oauth2/token",
  },
};

const sampleLaunchPayload = (overrides?: { aud?: LTI13JwtPayload["aud"] }): LTI13JwtPayload => {
  const payload: LTI13JwtPayload = {
    iss: issuer,
    sub: "instructor-123",
    aud: clientId,
    exp: 1_800_000_000,
    iat: 1_700_000_000,
    nonce: "nonce-123",
    "https://purl.imsglobal.org/spec/lti/claim/deployment_id": deploymentId,
    "https://purl.imsglobal.org/spec/lti/claim/message_type": "LtiResourceLinkRequest",
    "https://purl.imsglobal.org/spec/lti/claim/version": "1.3.0",
    "https://purl.imsglobal.org/spec/lti/claim/target_link_uri": targetLinkUri,
    "https://purl.imsglobal.org/spec/lti/claim/resource_link": {
      id: "resource-link-123",
    },
  };

  if (overrides?.aud !== undefined) {
    payload.aud = overrides.aud;
  }

  return payload;
};

describe("authorizeVerifiedLaunchForRegistry", () => {
  it("authorizes a verified launch when the issuer and client are registered", () => {
    const authorization = authorizeVerifiedLaunchForRegistry(signedLaunchRegistry, {
      payload: sampleLaunchPayload(),
      issuer,
      clientId,
      deploymentId,
      targetLinkUri,
      launchConfig: {
        iss: issuer,
        clientId,
        deploymentId,
        authUrl: "https://canvas.example.edu/api/lti/authorize_redirect",
        tokenUrl: "https://canvas.example.edu/login/oauth2/token",
        jwksUrl: "https://canvas.example.edu/api/lti/security/jwks",
      },
    });

    expect(authorization).toEqual({
      success: true,
      data: {
        issuer,
        entry: signedLaunchRegistry[issuer],
        launchClaims: sampleLaunchPayload(),
      },
    });
  });

  it("rejects a verified launch when the issuer and client pair is not registered", () => {
    const authorization = authorizeVerifiedLaunchForRegistry(signedLaunchRegistry, {
      payload: sampleLaunchPayload({
        aud: "unexpected-client",
      }),
      issuer,
      clientId: "unexpected-client",
      deploymentId,
      targetLinkUri,
      launchConfig: {
        iss: issuer,
        clientId: "unexpected-client",
        deploymentId,
        authUrl: "https://canvas.example.edu/api/lti/authorize_redirect",
        tokenUrl: "https://canvas.example.edu/login/oauth2/token",
        jwksUrl: "https://canvas.example.edu/api/lti/security/jwks",
      },
    });

    expect(authorization).toEqual({
      success: false,
      code: "issuer_registration_not_configured",
      message: "No issuer registration configured for verified LTI launch",
    });
  });
});

describe("ltiLaunchVerificationErrorFromCoreError", () => {
  it("maps authorization failures to bad requests with the package-provided message", () => {
    const error = ltiLaunchVerificationErrorFromCoreError(
      new CoreLtiLaunchVerificationError(
        "verified_launch_authorization_failed",
        "No issuer registration configured for verified LTI launch",
      ),
    );

    expect(error).toMatchObject({
      status: 400,
      message: "No issuer registration configured for verified LTI launch",
    });
  });

  it("maps ambiguous launch config failures to a generic authentication failure", () => {
    const error = ltiLaunchVerificationErrorFromCoreError(
      new CoreLtiLaunchVerificationError(
        "launch_config_not_found",
        "Launch config not found for issuer id_token=secret state=secret",
      ),
    );

    expect(error).toMatchObject({
      status: 401,
      message: "LTI launch verification failed",
      detail: "Launch config not found for issuer id_token=[redacted] state=[redacted]",
    });
  });

  it("maps missing signed-launch endpoint configuration to setup errors", () => {
    const error = ltiLaunchVerificationErrorFromCoreError(
      new CoreLtiLaunchVerificationError(
        "launch_config_missing_jwks_endpoint",
        "Launch client is missing a JWKS endpoint",
      ),
    );

    expect(error).toMatchObject({
      status: 501,
      message:
        "LTI issuer requires platform JWKS and token endpoint configuration for signed launches",
    });
  });
});

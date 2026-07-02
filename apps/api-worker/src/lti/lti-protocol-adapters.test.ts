import type {
  LTI13JwtPayload,
  LtiAuthorizedLaunch,
  LtiLaunchVerificationResult,
  LtiToolPort,
  LtiVerifiedLaunch,
  LtiVerifyLaunchOptions,
} from "@longsightgroup/lti-tool";
import { LtiLaunchVerificationError as CoreLtiLaunchVerificationError } from "@longsightgroup/lti-tool";
import { createFakeLtiAdvantage, testSession } from "@longsightgroup/lti-tool/testing";
import { describe, expect, it, vi } from "vitest";
import { authorizeVerifiedLaunchForRegistry } from "./launch-verification";
import type { LtiIssuerRegistry } from "./lti-issuer-registry";
import { createVerificationThrowingLtiTool } from "./lti-protocol-adapters";

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

const verificationAuthorizationFailure = (input: {
  message?: string | undefined;
  code: string;
  cause: unknown;
}): LtiLaunchVerificationResult => {
  return {
    success: false,
    error: new CoreLtiLaunchVerificationError(
      "verified_launch_authorization_failed",
      input.message ?? `Verified launch authorization failed: ${input.code}`,
      input.cause,
    ),
  };
};

const fakeLtiTool = (input: { verificationResult: LtiLaunchVerificationResult }): LtiToolPort => {
  async function verifyLaunch(
    _idToken: string,
    _state: string,
  ): Promise<LtiLaunchVerificationResult>;
  async function verifyLaunch<TAuthorization>(
    _idToken: string,
    _state: string,
    options: LtiVerifyLaunchOptions<TAuthorization>,
  ): Promise<LtiLaunchVerificationResult<LtiAuthorizedLaunch<TAuthorization>>>;
  async function verifyLaunch<TAuthorization>(
    _idToken: string,
    _state: string,
    options?: LtiVerifyLaunchOptions<TAuthorization>,
  ): Promise<
    LtiLaunchVerificationResult | LtiLaunchVerificationResult<LtiAuthorizedLaunch<TAuthorization>>
  > {
    if (!input.verificationResult.success || options?.authorizeVerifiedLaunch === undefined) {
      return input.verificationResult;
    }

    const authorization = await options.authorizeVerifiedLaunch(input.verificationResult.launch);

    if (!authorization.success) {
      return verificationAuthorizationFailure({
        message: authorization.message,
        code: authorization.code,
        cause: authorization,
      });
    }

    const authorizedLaunch: LtiAuthorizedLaunch<TAuthorization> = {
      ...input.verificationResult.launch,
      authorization: authorization.data,
    };

    return {
      success: true,
      launch: authorizedLaunch,
    };
  }

  return {
    getJWKS: vi.fn(async () => ({ keys: [] })),
    handleLogin: vi.fn(async () => "https://canvas.example.edu/api/lti/authorize_redirect"),
    verifyLaunch,
    createSessionFromVerifiedLaunch: vi.fn(async () => testSession()),
    getSession: vi.fn(async () => undefined),
    createAdvantage: vi.fn(() => createFakeLtiAdvantage()),
  };
};

describe("createVerificationThrowingLtiTool", () => {
  it("returns authorized launches for multi-audience payloads", async () => {
    const payload = sampleLaunchPayload({
      aud: ["other-client", clientId],
    });
    const launch = {
      payload,
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
    } satisfies LtiVerifiedLaunch;
    const ltiTool = createVerificationThrowingLtiTool(
      fakeLtiTool({
        verificationResult: {
          success: true,
          launch,
        },
      }),
    );

    const verificationResult = await ltiTool.verifyLaunch("opaque-id-token", "opaque-state", {
      authorizeVerifiedLaunch: (verifiedLaunch) =>
        authorizeVerifiedLaunchForRegistry(signedLaunchRegistry, verifiedLaunch),
    });

    expect(verificationResult).toMatchObject({
      success: true,
      launch: {
        clientId,
      },
    });
  });

  it("rejects a verified launch when the issuer and client pair is not registered", async () => {
    const payload = sampleLaunchPayload({
      aud: "unexpected-client",
    });
    const ltiTool = createVerificationThrowingLtiTool(
      fakeLtiTool({
        verificationResult: {
          success: true,
          launch: {
            payload,
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
          },
        },
      }),
    );

    await expect(
      ltiTool.verifyLaunch("opaque-id-token", "opaque-state", {
        authorizeVerifiedLaunch: (verifiedLaunch) =>
          authorizeVerifiedLaunchForRegistry(signedLaunchRegistry, verifiedLaunch),
      }),
    ).rejects.toMatchObject({
      status: 400,
      message: "No issuer registration configured for verified LTI launch",
    });
  });

  it("maps ambiguous core launch config failures to a generic 401 verification failure", async () => {
    const ltiTool = createVerificationThrowingLtiTool(
      fakeLtiTool({
        verificationResult: {
          success: false,
          error: new CoreLtiLaunchVerificationError(
            "launch_config_not_found",
            "Launch config not found for issuer id_token=secret state=secret",
          ),
        },
      }),
    );

    await expect(ltiTool.verifyLaunch("opaque-id-token", "opaque-state")).rejects.toMatchObject({
      status: 401,
      message: "LTI launch verification failed",
      detail: "Launch config not found for issuer id_token=[redacted] state=[redacted]",
    });
  });

  it("maps core missing signed-launch endpoint failures to 501 setup errors", async () => {
    const ltiTool = createVerificationThrowingLtiTool(
      fakeLtiTool({
        verificationResult: {
          success: false,
          error: new CoreLtiLaunchVerificationError(
            "launch_config_missing_jwks_endpoint",
            "Launch client is missing a JWKS endpoint",
          ),
        },
      }),
    );

    await expect(ltiTool.verifyLaunch("opaque-id-token", "opaque-state")).rejects.toMatchObject({
      status: 501,
      message:
        "LTI issuer requires platform JWKS and token endpoint configuration for signed launches",
    });
  });
});

import type {
  LTI13JwtPayload,
  LTISession,
  LTITool,
  LtiLaunchVerificationResult,
} from "@lti-tool/core";
import { LtiLaunchVerificationError as CoreLtiLaunchVerificationError } from "@lti-tool/core";
import type { SqlDatabase } from "@credtrail/db";
import { describe, expect, it, vi } from "vitest";
import type { AppBindings } from "../app";
import type { LtiIssuerRegistry } from "./lti-helpers";
import { resolveLtiLaunch } from "./launch-verification";

const issuer = "https://canvas.example.edu";
const clientId = "canvas-client-123";
const deploymentId = "deployment-123";
const targetLinkUri = "https://credtrail.example.edu/v1/lti/launch";

const fakeDb = {} as SqlDatabase;
const fakeEnv = {
  APP_ENV: "test",
  PLATFORM_DOMAIN: "credtrail.example.edu",
  BADGE_OBJECTS: {},
} as AppBindings;

const signedLaunchRegistry: LtiIssuerRegistry = {
  [issuer]: {
    authorizationEndpoint: "https://canvas.example.edu/api/lti/authorize_redirect",
    clientId,
    tenantId: "tenant-123",
    platformJwksEndpoint: "https://canvas.example.edu/api/lti/security/jwks",
    tokenEndpoint: "https://canvas.example.edu/login/oauth2/token",
  },
};

const unsignedLaunchRegistry: LtiIssuerRegistry = {
  [issuer]: {
    authorizationEndpoint: "https://canvas.example.edu/api/lti/authorize_redirect",
    clientId,
    tenantId: "tenant-123",
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

const sampleSession = (payload: LTI13JwtPayload, verifiedClientId: string): LTISession => {
  return {
    jwtPayload: payload as LTISession["jwtPayload"],
    id: "lti-session-123",
    user: {
      id: "instructor-123",
      roles: [],
    },
    context: {
      id: "course-123",
      label: "COURSE123",
      title: "Course 123",
    },
    platform: {
      issuer,
      clientId: verifiedClientId,
      deploymentId,
      name: "Canvas",
    },
    launch: {
      target: targetLinkUri,
    },
    customParameters: {},
    isAdmin: false,
    isInstructor: true,
    isStudent: false,
    isAssignmentAndGradesAvailable: false,
    isDeepLinkingAvailable: false,
    isNameAndRolesAvailable: false,
  };
};

const fakeLtiTool = (input: {
  verificationResult: LtiLaunchVerificationResult;
  createSession?: LTITool["createSession"];
}): LTITool => {
  return {
    verifyLaunchDetailed: vi.fn(async () => input.verificationResult),
    createSession: input.createSession ?? vi.fn(),
  } as unknown as LTITool;
};

describe("resolveLtiLaunch", () => {
  it("passes the verified client id into session creation for multi-audience launches", async () => {
    const payload = sampleLaunchPayload({
      aud: ["other-client", clientId],
    });
    const createSession = vi.fn(
      async (sessionPayload: LTI13JwtPayload, verifiedClientId?: string) =>
        sampleSession(sessionPayload, verifiedClientId ?? "missing-client-id"),
    );
    const ltiTool = fakeLtiTool({
      verificationResult: {
        success: true,
        launch: {
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
        },
      },
      createSession,
    });

    const resolvedLaunch = await resolveLtiLaunch({
      idToken: "opaque-id-token",
      state: "opaque-state",
      registry: signedLaunchRegistry,
      db: fakeDb,
      env: fakeEnv,
      createLtiTool: vi.fn(async () => ltiTool),
    });

    expect(createSession).toHaveBeenCalledWith(payload, clientId);
    expect(resolvedLaunch.ltiLaunchSession.platform.clientId).toBe(clientId);
  });

  it("rejects a verified launch when the issuer and client pair is not registered", async () => {
    const payload = sampleLaunchPayload({
      aud: "unexpected-client",
    });
    const createSession = vi.fn();
    const ltiTool = fakeLtiTool({
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
      createSession,
    });

    await expect(
      resolveLtiLaunch({
        idToken: "opaque-id-token",
        state: "opaque-state",
        registry: signedLaunchRegistry,
        db: fakeDb,
        env: fakeEnv,
        createLtiTool: vi.fn(async () => ltiTool),
      }),
    ).rejects.toMatchObject({
      status: 400,
      message: "No issuer registration configured for verified LTI launch",
    });
    expect(createSession).not.toHaveBeenCalled();
  });

  it("maps ambiguous core launch config failures to a generic 401 verification failure", async () => {
    const ltiTool = fakeLtiTool({
      verificationResult: {
        success: false,
        error: new CoreLtiLaunchVerificationError(
          "launch_config_not_found",
          "Launch config not found for issuer id_token=secret state=secret",
        ),
      },
    });

    await expect(
      resolveLtiLaunch({
        idToken: "opaque-id-token",
        state: "opaque-state",
        registry: signedLaunchRegistry,
        db: fakeDb,
        env: fakeEnv,
        createLtiTool: vi.fn(async () => ltiTool),
      }),
    ).rejects.toMatchObject({
      status: 401,
      message: "LTI launch verification failed",
      detail: "Launch config not found for issuer id_token=[redacted] state=[redacted]",
    });
  });

  it("returns 501 only after a verified issuer is known to lack signed-launch endpoints", async () => {
    const payload = sampleLaunchPayload();
    const createSession = vi.fn();
    const ltiTool = fakeLtiTool({
      verificationResult: {
        success: true,
        launch: {
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
        },
      },
      createSession,
    });

    await expect(
      resolveLtiLaunch({
        idToken: "opaque-id-token",
        state: "opaque-state",
        registry: unsignedLaunchRegistry,
        db: fakeDb,
        env: fakeEnv,
        createLtiTool: vi.fn(async () => ltiTool),
      }),
    ).rejects.toMatchObject({
      status: 501,
      message:
        "LTI issuer requires platform JWKS and token endpoint configuration for signed launches",
    });
    expect(createSession).not.toHaveBeenCalled();
  });
});

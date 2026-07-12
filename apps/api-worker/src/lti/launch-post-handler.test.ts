import type { SqlDatabase } from "@credtrail/db";
import { parseTenantPathParams } from "@credtrail/validation";
import type {
  LTISession,
  LtiAuthorizedLaunch,
  LtiLaunchVerificationResult,
  LtiToolPort,
  LtiVerifyLaunchOptions,
} from "@longsightgroup/lti-tool";
import { LtiLaunchMessageResolutionError } from "@longsightgroup/lti-tool";
import {
  createFakeLtiAdvantage,
  testSession,
  testVerifiedLaunch,
} from "@longsightgroup/lti-tool/testing";
import { Hono } from "hono";
import { describe, expect, it, vi } from "vitest";
import type { AppBindings, AppEnv } from "../app";
import type { LtiAuthenticatedPrincipal } from "../auth/auth-provider";
import { handleLtiLaunchPost, renderLtiLaunchError } from "./launch-post-handler";
import type { LtiIssuerRegistry, LtiIssuerRegistryEntry } from "./lti-issuer-registry";

const issuer = "https://canvas.example.edu";
const issuerEntry: LtiIssuerRegistryEntry = {
  authorizationEndpoint: "https://canvas.example.edu/api/lti/authorize_redirect",
  clientId: "canvas-client-123",
  tenantId: "tenant-123",
  platformJwksEndpoint: "https://canvas.example.edu/api/lti/security/jwks",
  tokenEndpoint: "https://canvas.example.edu/login/oauth2/token",
};
const fakeRegistry: LtiIssuerRegistry = {
  [issuer]: issuerEntry,
};
const fakeDb = {} as SqlDatabase;
const fakeEnv: AppBindings = {
  APP_ENV: "test",
  BADGE_OBJECTS: {
    head: vi.fn(async () => null),
    get: vi.fn(async () => null),
    put: vi.fn(async () => null),
    delete: vi.fn(async () => undefined),
  },
  PLATFORM_DOMAIN: "credtrail.example.edu",
};
const tokenEndpoint = "https://canvas.example.edu/login/oauth2/token";
const platformJwksEndpoint = "https://canvas.example.edu/api/lti/security/jwks";
const validJwtForSchema =
  "eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJodHRwczovL2NhbnZhcy5leGFtcGxlLmVkdSIsImF1ZCI6ImNhbnZhcy1jbGllbnQtMTIzIn0.c2lnbmF0dXJl";

const verifiedLaunch = testVerifiedLaunch({
  launchConfig: {
    iss: issuer,
    clientId: issuerEntry.clientId,
    deploymentId: "deployment-123",
    authUrl: issuerEntry.authorizationEndpoint,
    tokenUrl: tokenEndpoint,
    jwksUrl: platformJwksEndpoint,
  },
});
const fakeLtiSession = testSession({
  id: "lti-session-123",
  // SAFETY: testVerifiedLaunch returns a parsed LTI payload. LTISession stores it
  // behind jose's broader JWTPayload shape, whose optional fields are stricter
  // under exactOptionalPropertyTypes than the package fixture type.
  jwtPayload: verifiedLaunch.payload as LTISession["jwtPayload"],
  platform: {
    issuer,
    clientId: issuerEntry.clientId,
    deploymentId: verifiedLaunch.deploymentId,
    name: "Canvas",
  },
  launch: {
    target: verifiedLaunch.targetLinkUri,
  },
});

const createFakeLtiTool = (): LtiToolPort => {
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
    if (options?.authorizeVerifiedLaunch === undefined) {
      return {
        success: true,
        launch: verifiedLaunch,
      };
    }

    const authorization = await options.authorizeVerifiedLaunch(verifiedLaunch);

    if (!authorization.success) {
      throw new Error(authorization.message ?? "Verified launch authorization failed");
    }

    return {
      success: true,
      launch: {
        ...verifiedLaunch,
        authorization: authorization.data,
      },
    };
  }

  return {
    getJWKS: vi.fn(async () => ({ keys: [] })),
    handleLogin: vi.fn(async () => "https://canvas.example.edu/login"),
    verifyLaunch,
    createSessionFromVerifiedLaunch: vi.fn(async () => fakeLtiSession),
    getSession: vi.fn(async () => undefined),
    createAdvantage: vi.fn(() => createFakeLtiAdvantage()),
  };
};

describe("handleLtiLaunchPost", () => {
  it("delegates verified launches to the injected product flow handler", async () => {
    const app = new Hono<AppEnv>();
    const handleVerifiedLtiLaunch = vi.fn(
      async () => new Response("product-flow", { status: 202 }),
    );
    const createLtiSession = vi.fn(async () => ({}) as LtiAuthenticatedPrincipal);
    const sha256Hex = vi.fn(async (value: string) => value);

    app.post("/v1/lti/launch", (c) =>
      handleLtiLaunchPost({
        c,
        resolveLtiIssuerRegistry: vi.fn(async () => fakeRegistry),
        resolveDatabase: vi.fn(() => fakeDb),
        sha256Hex,
        createLtiSession,
        handleVerifiedLtiLaunch,
        createLtiTool: vi.fn(async () => createFakeLtiTool()),
      }),
    );

    const response = await app.request(
      "https://credtrail.example.edu/v1/lti/launch",
      {
        method: "POST",
        headers: {
          "content-type": "application/x-www-form-urlencoded",
        },
        body: new URLSearchParams({
          id_token: validJwtForSchema,
          state: "opaque-state",
        }).toString(),
      },
      fakeEnv,
    );

    expect(handleVerifiedLtiLaunch).toHaveBeenCalledWith({
      c: expect.anything(),
      db: fakeDb,
      tenantId: "tenant-123",
      resolvedLaunch: {
        issuer,
        issuerEntry,
        launchClaims: verifiedLaunch.payload,
        ltiLaunchSession: fakeLtiSession,
        ltiTool: expect.anything(),
      },
      launchMessage: expect.objectContaining({
        kind: "resource-link",
      }),
      sha256Hex,
      createLtiSession,
    });
    expect(response.status).toBe(202);
    await expect(response.text()).resolves.toBe("product-flow");
  });

  it("maps package launch message resolution failures to a bad request response", async () => {
    const app = new Hono<AppEnv>();

    app.get("/failure", (c) =>
      renderLtiLaunchError(
        c,
        new LtiLaunchMessageResolutionError(
          "missing_resource_link",
          "LtiResourceLinkRequest requires resource_link.id",
        ),
      ),
    );

    const response = await app.request("https://credtrail.example.edu/failure", undefined, fakeEnv);
    const body = await response.json<{ error: string }>();

    expect(response.status).toBe(400);
    expect(body).toEqual({
      error: "LtiResourceLinkRequest requires resource_link.id",
    });
  });

  it("maps validation parse failures to invalid launch parameters", async () => {
    const app = new Hono<AppEnv>();
    let parseFailure: unknown;

    try {
      parseTenantPathParams({});
    } catch (error: unknown) {
      parseFailure = error;
    }

    if (parseFailure === undefined) {
      throw new Error("Expected tenant path params parsing to fail");
    }

    app.get("/failure", (c) => renderLtiLaunchError(c, parseFailure));

    const response = await app.request("https://credtrail.example.edu/failure", undefined, fakeEnv);
    const body = await response.json<{ error: string }>();

    expect(response.status).toBe(400);
    expect(body).toEqual({
      error: "Invalid launch parameters",
    });
  });
});

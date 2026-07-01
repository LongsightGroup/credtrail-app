import type { SqlDatabase } from "@credtrail/db";
import { LTI_MESSAGE_TYPE_DEEP_LINKING_REQUEST, type LtiToolPort } from "@longsightgroup/lti-tool";
import {
  createFakeLtiAdvantage,
  testSession,
  testVerifiedLaunch,
} from "@longsightgroup/lti-tool/testing";
import { Hono } from "hono";
import { describe, expect, it, vi } from "vitest";
import type { AppBindings, AppEnv } from "../app";
import type { LtiAuthenticatedPrincipal } from "../auth/auth-provider";
import { handleLtiLaunchPost } from "./launch-post-handler";
import type { ResolvedLtiLaunchMessage } from "./launch-message";
import type { ResolvedLtiLaunch } from "./launch-verification";
import type { LtiIssuerRegistry, LtiIssuerRegistryEntry } from "./lti-helpers";

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

const fakeLtiTool: LtiToolPort = {
  getJWKS: vi.fn(async () => ({ keys: [] })),
  handleLogin: vi.fn(async () => "https://canvas.example.edu/login"),
  verifyLaunch: vi.fn(),
  createSessionFromVerifiedLaunch: vi.fn(async () => testSession()),
  getSession: vi.fn(async () => undefined),
  createAdvantage: vi.fn(() => createFakeLtiAdvantage()),
};

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
const fakeResolvedLaunch: ResolvedLtiLaunch = {
  issuer,
  issuerEntry,
  launchClaims: verifiedLaunch.payload,
  ltiLaunchSession: testSession({
    platform: {
      issuer,
      clientId: issuerEntry.clientId,
      deploymentId: verifiedLaunch.deploymentId,
      name: "Canvas",
    },
  }),
  ltiTool: fakeLtiTool,
};
const fakeLaunchMessage: ResolvedLtiLaunchMessage = {
  kind: "deep-linking",
  messageType: LTI_MESSAGE_TYPE_DEEP_LINKING_REQUEST,
  roleKind: "instructor",
  resolvedTargetLinkUri: "https://credtrail.example.edu/v1/lti/launch",
  deepLinkingSettings: {
    deepLinkReturnUrl: "https://canvas.example.edu/deep-linking/return",
    acceptTypes: ["ltiResourceLink"],
  },
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
        protocolHandlers: {
          readLaunchForm: vi.fn(async () => ({
            idToken: "opaque-id-token",
            state: "opaque-state",
          })),
          resolveLaunch: vi.fn(async () => fakeResolvedLaunch),
          resolveLaunchMessage: vi.fn(() => fakeLaunchMessage),
        },
      }),
    );

    const response = await app.request(
      "https://credtrail.example.edu/v1/lti/launch",
      { method: "POST" },
      fakeEnv,
    );

    expect(handleVerifiedLtiLaunch).toHaveBeenCalledWith({
      c: expect.anything(),
      db: fakeDb,
      tenantId: "tenant-123",
      resolvedLaunch: fakeResolvedLaunch,
      launchMessage: fakeLaunchMessage,
      sha256Hex,
      createLtiSession,
    });
    expect(response.status).toBe(202);
    await expect(response.text()).resolves.toBe("product-flow");
  });
});

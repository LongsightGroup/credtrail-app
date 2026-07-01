import { Hono } from "hono";
import { describe, expect, it, vi } from "vitest";
import type { SqlDatabase } from "@credtrail/db";
import type { AppBindings, AppEnv } from "./app";
import { registerLtiRoutes } from "./routes/lti-routes";

const { mockedCreateCredTrailLtiTool } = vi.hoisted(() => {
  return {
    mockedCreateCredTrailLtiTool: vi.fn(),
  };
});

vi.mock("./lti/credtrail-lti-tool", () => {
  return {
    createCredTrailLtiTool: mockedCreateCredTrailLtiTool,
  };
});

const fakeDb = {} as SqlDatabase;
const fakeEnv: AppBindings = {
  APP_ENV: "test",
  BADGE_OBJECTS: {
    head: vi.fn(async () => null),
    get: vi.fn(async () => null),
    put: vi.fn(async () => null),
    delete: vi.fn(async () => undefined),
  },
  PLATFORM_DOMAIN: "credtrail.test",
};

const createRouteApp = (): Hono<AppEnv> => {
  const app = new Hono<AppEnv>();

  registerLtiRoutes({
    app,
    resolveLtiIssuerRegistry: async () => ({}),
    resolveDatabase: () => fakeDb,
    sha256Hex: async () => "hash",
    createLtiSession: async () => {
      throw new Error("createLtiSession is not used by JWKS tests");
    },
    issueBadgeForTenant: async () => {
      throw new Error("issueBadgeForTenant is not used by JWKS tests");
    },
  });

  return app;
};

describe("LTI JWKS route", () => {
  it("serves the CredTrail LTI tool JWKS through the package Hono handler", async () => {
    const jwks = {
      keys: [
        {
          kty: "RSA",
          kid: "credtrail-lti-main",
          use: "sig",
          alg: "RS256",
          n: "test-modulus",
          e: "AQAB",
        },
      ],
    };
    const getJWKS = vi.fn(async () => jwks);
    mockedCreateCredTrailLtiTool.mockResolvedValue({
      getJWKS,
    });

    const response = await createRouteApp().request("/v1/lti/jwks", undefined, fakeEnv);
    const body = await response.json<typeof jwks>();

    expect(response.status).toBe(200);
    expect(body).toEqual(jwks);
    expect(mockedCreateCredTrailLtiTool).toHaveBeenCalledWith({
      db: fakeDb,
      env: fakeEnv,
    });
    expect(getJWKS).toHaveBeenCalledOnce();
  });
});

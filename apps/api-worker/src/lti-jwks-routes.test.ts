import { Hono } from "hono";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { SqlDatabase } from "@credtrail/db";
import type { AppBindings, AppContext, AppEnv } from "./app";
import { createAppLogger } from "./app/observability";
import { LTI_JWKS_PATH } from "./lti/constants";
import { registerLtiRoutes } from "./routes/lti-routes";

const { mockedCreateCredTrailLtiTool } = vi.hoisted(() => {
  return {
    mockedCreateCredTrailLtiTool: vi.fn(),
  };
});

vi.mock("./lti/credtrail-lti-tool", () => {
  return {
    createCredTrailLtiTool: mockedCreateCredTrailLtiTool,
    resolveCredTrailLtiTool: async (
      c: AppContext,
      resolveDatabase: (bindings: AppBindings) => SqlDatabase,
    ) => {
      return mockedCreateCredTrailLtiTool({
        db: resolveDatabase(c.env),
        env: c.env,
      });
    },
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

  app.use("*", async (c, next) => {
    c.set("requestId", "test-request");
    c.set(
      "appLogger",
      createAppLogger({
        context: {
          service: "api-worker",
          environment: "test",
        },
        fields: {
          requestId: "test-request",
          method: c.req.method,
          path: new URL(c.req.url).pathname,
        },
      }),
    );
    await next();
  });

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
  let consoleError: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    mockedCreateCredTrailLtiTool.mockReset();
    consoleError = vi.spyOn(console, "error").mockImplementation(() => undefined);
  });

  afterEach(() => {
    consoleError.mockRestore();
  });

  it("serves the CredTrail LTI tool JWKS", async () => {
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

    const response = await createRouteApp().request(LTI_JWKS_PATH, undefined, fakeEnv);
    const body = await response.json<typeof jwks>();

    expect(response.status).toBe(200);
    expect(body).toEqual(jwks);
    expect(mockedCreateCredTrailLtiTool).toHaveBeenCalledWith({
      db: fakeDb,
      env: fakeEnv,
    });
    expect(getJWKS).toHaveBeenCalledOnce();
  });

  it("returns a generic 500 response when JWKS resolution fails", async () => {
    mockedCreateCredTrailLtiTool.mockRejectedValue(new Error("key storage unavailable"));

    const response = await createRouteApp().request(LTI_JWKS_PATH, undefined, fakeEnv);
    const body = await response.json<{ error: string }>();

    expect(response.status).toBe(500);
    expect(body).toEqual({
      error: "Internal server error",
    });
    const errorRecord = JSON.parse(String(consoleError.mock.calls[0]?.[0])) as Record<
      string,
      unknown
    >;
    expect(errorRecord).toMatchObject({
      level: "error",
      message: "lti_jwks_failed",
      requestId: "test-request",
      component: "lti",
      detail: "key storage unavailable",
    });
  });
});

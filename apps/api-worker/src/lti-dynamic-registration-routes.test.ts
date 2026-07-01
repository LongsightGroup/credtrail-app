import { describe, expect, it, beforeEach, vi } from "vitest";
import { Hono } from "hono";
import { LtiServiceError, type LTIConfig } from "@longsightgroup/lti-tool";
import { LtiIssuerTenantConflictError, type SqlDatabase } from "@credtrail/db";
import type { AppBindings, AppEnv } from "./app";
import { registerLtiRoutes } from "./routes/lti-routes";
import {
  createLtiDynamicRegistrationInviteToken,
  ltiDynamicRegistrationPath,
} from "./lti/dynamic-registration-invite";

type DynamicRegistrationConfig = NonNullable<LTIConfig["dynamicRegistration"]>;

const { mockedCreateCredTrailLtiDynamicRegistration } = vi.hoisted(() => {
  return {
    mockedCreateCredTrailLtiDynamicRegistration: vi.fn(),
  };
});

vi.mock("./lti/credtrail-lti-tool", () => {
  return {
    createCredTrailLtiDynamicRegistration: mockedCreateCredTrailLtiDynamicRegistration,
  };
});

interface ErrorBody {
  error: string;
}

interface DynamicRegistrationToolMock {
  initiateDynamicRegistration: ReturnType<typeof vi.fn>;
  completeDynamicRegistration: ReturnType<typeof vi.fn>;
}

const fakeDb = {} as SqlDatabase;

const createEnv = (): AppBindings => {
  return {
    APP_ENV: "test",
    DATABASE_URL: "postgres://credtrail-test.local/db",
    BADGE_OBJECTS: {} as AppBindings["BADGE_OBJECTS"],
    PLATFORM_DOMAIN: "credtrail.test",
    LTI_STATE_SIGNING_SECRET: "test-lti-state-signing-secret",
  };
};

const createRouteApp = (): Hono<AppEnv> => {
  const app = new Hono<AppEnv>();

  registerLtiRoutes({
    app,
    resolveLtiIssuerRegistry: async () => ({}),
    resolveDatabase: () => fakeDb,
    sha256Hex: async () => "hash",
    createLtiSession: async () => {
      throw new Error("createLtiSession is not used by dynamic registration tests");
    },
    issueBadgeForTenant: async () => {
      throw new Error("issueBadgeForTenant is not used by dynamic registration tests");
    },
  });

  return app;
};

const createToolMock = (): DynamicRegistrationToolMock => {
  return {
    initiateDynamicRegistration: vi.fn(async () => ({
      success: true,
      data: "<form>registration</form>",
    })),
    completeDynamicRegistration: vi.fn(async () => ({
      success: true,
      data: {
        html: "<html>complete</html>",
      },
    })),
  };
};

const createInviteUrl = async (input: {
  env: AppBindings;
  tenantId: string;
  pathTenantId?: string;
}): Promise<string> => {
  const token = await createLtiDynamicRegistrationInviteToken(input.env, {
    tenantId: input.tenantId,
  });
  const path = ltiDynamicRegistrationPath(input.pathTenantId ?? input.tenantId, token);
  const url = new URL(path, "https://credtrail.test");
  url.searchParams.set(
    "openid_configuration",
    "https://canvas.test/.well-known/openid-configuration",
  );
  url.searchParams.set("registration_token", "registration-token");
  return url.toString();
};

const createCompletionUrl = async (
  env: AppBindings,
  input?: {
    tenantId?: string;
    pathTenantId?: string;
  },
): Promise<string> => {
  const token = await createLtiDynamicRegistrationInviteToken(env, {
    tenantId: input?.tenantId ?? "tenant-a",
  });

  return new URL(
    `${ltiDynamicRegistrationPath(input?.pathTenantId ?? "tenant-a", token)}/complete`,
    "https://credtrail.test",
  ).toString();
};

const createCompletionBody = (): FormData => {
  const body = new FormData();
  body.set("sessionToken", "registration-session-1");
  body.append("services", "ags");
  body.append("services", "nrps");
  body.append("services", "deep_linking");
  return body;
};

describe("LTI dynamic registration routes", () => {
  beforeEach(() => {
    mockedCreateCredTrailLtiDynamicRegistration.mockReset();
  });

  it("rejects missing or invalid invite tokens", async () => {
    const app = createRouteApp();
    const env = createEnv();
    const response = await app.request(
      "https://credtrail.test/v1/tenants/tenant-a/lti/dynamic-registration/not-a-token?openid_configuration=https%3A%2F%2Fcanvas.test%2F.well-known%2Fopenid-configuration",
      undefined,
      env,
    );
    const body = await response.json<ErrorBody>();

    expect(response.status).toBe(403);
    expect(body.error).toBe("Invalid or expired LTI dynamic registration link");
    expect(mockedCreateCredTrailLtiDynamicRegistration).not.toHaveBeenCalled();
  });

  it("rejects valid invites used for the wrong tenant path", async () => {
    const app = createRouteApp();
    const env = createEnv();
    const response = await app.request(
      await createInviteUrl({
        env,
        tenantId: "tenant-a",
        pathTenantId: "tenant-b",
      }),
      undefined,
      env,
    );
    const body = await response.json<ErrorBody>();

    expect(response.status).toBe(403);
    expect(body.error).toBe("Invalid or expired LTI dynamic registration link");
    expect(mockedCreateCredTrailLtiDynamicRegistration).not.toHaveBeenCalled();
  });

  it("initiates dynamic registration with tenant-scoped canonical URLs", async () => {
    const app = createRouteApp();
    const env = createEnv();
    const tool = createToolMock();
    mockedCreateCredTrailLtiDynamicRegistration.mockResolvedValue(tool);
    const requestUrl = await createInviteUrl({
      env,
      tenantId: "tenant-a",
    });

    const response = await app.request(requestUrl, undefined, env);
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(response.headers.get("content-type")).toContain("text/html");
    expect(body).toBe("<form>registration</form>");
    expect(tool.initiateDynamicRegistration).toHaveBeenCalledWith(
      {
        openid_configuration: "https://canvas.test/.well-known/openid-configuration",
        registration_token: "registration-token",
      },
      new URL(requestUrl).pathname,
    );
    expect(mockedCreateCredTrailLtiDynamicRegistration).toHaveBeenCalledTimes(1);

    const toolInput = mockedCreateCredTrailLtiDynamicRegistration.mock.calls[0]?.[0] as {
      defaultTenantId: string;
      dynamicRegistration: DynamicRegistrationConfig;
    };

    expect(toolInput.defaultTenantId).toBe("tenant-a");
    expect(toolInput.dynamicRegistration.url).toBe("https://credtrail.test/v1/lti/launch");
    expect(toolInput.dynamicRegistration.loginUri).toBe("https://credtrail.test/v1/lti/oidc/login");
    expect(toolInput.dynamicRegistration.launchUri).toBe("https://credtrail.test/v1/lti/launch");
    expect(toolInput.dynamicRegistration.jwksUri).toBe("https://credtrail.test/v1/lti/jwks");
    expect(toolInput.dynamicRegistration.deepLinkingUri).toBe(
      "https://credtrail.test/v1/lti/launch",
    );
  });

  it("completes dynamic registration with selected services", async () => {
    const app = createRouteApp();
    const env = createEnv();
    const tool = createToolMock();
    mockedCreateCredTrailLtiDynamicRegistration.mockResolvedValue(tool);

    const response = await app.request(
      await createCompletionUrl(env),
      {
        method: "POST",
        body: createCompletionBody(),
      },
      env,
    );
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(response.headers.get("content-type")).toContain("text/html");
    expect(body).toBe("<html>complete</html>");
    expect(tool.completeDynamicRegistration).toHaveBeenCalledWith({
      sessionToken: "registration-session-1",
      services: ["ags", "nrps", "deep_linking"],
    });
  });

  it("rejects registration completion replay", async () => {
    const app = createRouteApp();
    const env = createEnv();
    const tool = createToolMock();
    tool.completeDynamicRegistration
      .mockResolvedValueOnce({
        success: true,
        data: {
          html: "<html>complete</html>",
        },
      })
      .mockResolvedValueOnce({
        success: false,
        error: new LtiServiceError({
          code: "platform_request_failed",
          serviceKind: "dynamic_registration",
          operation: "completeDynamicRegistration",
          message: "Invalid or expired registration session",
        }),
      });
    mockedCreateCredTrailLtiDynamicRegistration.mockResolvedValue(tool);
    const requestUrl = await createCompletionUrl(env);

    const firstResponse = await app.request(
      requestUrl,
      {
        method: "POST",
        body: createCompletionBody(),
      },
      env,
    );
    const secondResponse = await app.request(
      requestUrl,
      {
        method: "POST",
        body: createCompletionBody(),
      },
      env,
    );
    const body = await secondResponse.json<ErrorBody>();

    expect(firstResponse.status).toBe(200);
    expect(secondResponse.status).toBe(400);
    expect(body.error).toBe("Invalid or expired registration session");
  });

  it("returns a clear conflict when an issuer belongs to another tenant", async () => {
    const app = createRouteApp();
    const env = createEnv();
    const tool = createToolMock();
    const conflict = new LtiIssuerTenantConflictError(
      "https://canvas.test",
      "tenant-b",
      "tenant-a",
    );
    tool.completeDynamicRegistration.mockResolvedValueOnce({
      success: false,
      error: new LtiServiceError({
        code: "platform_request_failed",
        serviceKind: "dynamic_registration",
        operation: "completeDynamicRegistration",
        message: conflict.message,
        cause: conflict,
      }),
    });
    mockedCreateCredTrailLtiDynamicRegistration.mockResolvedValue(tool);

    const response = await app.request(
      await createCompletionUrl(env),
      {
        method: "POST",
        body: createCompletionBody(),
      },
      env,
    );
    const body = await response.json<ErrorBody>();

    expect(response.status).toBe(409);
    expect(body.error).toContain("already registered to a different tenant");
  });
});

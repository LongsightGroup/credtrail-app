import { Hono } from "hono";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { AppBindings, AppEnv } from "../app/types";
import { observabilityContext } from "../app/observability";
import { registerCommonMiddleware } from "./common-middleware";

const fakeEnv: AppBindings = {
  APP_ENV: "test",
  BADGE_OBJECTS: {
    head: vi.fn(async () => null),
    get: vi.fn(async () => null),
    put: vi.fn(async () => null),
    delete: vi.fn(async () => undefined),
  },
  PLATFORM_DOMAIN: "credtrail.test",
  PUBLIC_APP_ORIGIN: "https://credtrail.test",
};

const createMiddlewareApp = (): Hono<AppEnv> => {
  const app = new Hono<AppEnv>();

  registerCommonMiddleware({
    app,
    observabilityContext,
  });

  app.get("/ok", (c) => {
    return c.json({
      requestId: c.get("requestId"),
    });
  });

  app.get("/boom", () => {
    throw new Error("route failed");
  });

  return app;
};

describe("registerCommonMiddleware", () => {
  let consoleLog: ReturnType<typeof vi.spyOn>;
  let consoleError: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    consoleLog = vi.spyOn(console, "log").mockImplementation(() => undefined);
    consoleError = vi.spyOn(console, "error").mockImplementation(() => undefined);
  });

  afterEach(() => {
    consoleLog.mockRestore();
    consoleError.mockRestore();
  });

  it("preserves an incoming request id and logs the completed request", async () => {
    const response = await createMiddlewareApp().request(
      "/ok",
      {
        headers: {
          "x-request-id": "request-inbound",
        },
      },
      fakeEnv,
    );
    const body = await response.json<{ requestId: string }>();

    expect(response.headers.get("x-request-id")).toBe("request-inbound");
    expect(body).toEqual({
      requestId: "request-inbound",
    });

    const logRecord = JSON.parse(String(consoleLog.mock.calls[0]?.[0])) as Record<string, unknown>;
    expect(logRecord).toMatchObject({
      level: "info",
      service: "api-worker",
      environment: "test",
      message: "http_request",
      requestId: "request-inbound",
      method: "GET",
      path: "/ok",
      status: 200,
    });
    expect(typeof logRecord.elapsedMs).toBe("number");
  });

  it("generates a request id when the request does not provide one", async () => {
    const response = await createMiddlewareApp().request("/ok", undefined, fakeEnv);
    const body = await response.json<{ requestId: string }>();

    expect(response.headers.get("x-request-id")).toBe(body.requestId);
    expect(body.requestId.length).toBeGreaterThan(0);
  });

  it("redirects aliases to PUBLIC_APP_ORIGIN independently of the issuer domain", async () => {
    const response = await createMiddlewareApp().request(
      "https://www.app.credtrail.test/ok?source=alias",
      undefined,
      {
        ...fakeEnv,
        APP_ENV: "production",
        PLATFORM_DOMAIN: "issuer.credtrail.test",
        PUBLIC_APP_ORIGIN: "https://app.credtrail.test",
      },
    );

    expect(response.status).toBe(308);
    expect(response.headers.get("location")).toBe("https://app.credtrail.test/ok?source=alias");
  });

  it("redirects unknown production origins without exposing them to application routes", async () => {
    const response = await createMiddlewareApp().request(
      "https://unexpected.example/ok?source=proxy",
      undefined,
      {
        ...fakeEnv,
        APP_ENV: "production",
        PLATFORM_DOMAIN: "issuer.credtrail.test",
        PUBLIC_APP_ORIGIN: "https://app.credtrail.test",
      },
    );

    expect(response.status).toBe(308);
    expect(response.headers.get("location")).toBe("https://app.credtrail.test/ok?source=proxy");
  });

  it("keeps protocol-relative-looking request paths on PUBLIC_APP_ORIGIN", async () => {
    const response = await createMiddlewareApp().request(
      "https://unexpected.example//evil.example/ok?source=proxy",
      undefined,
      {
        ...fakeEnv,
        APP_ENV: "production",
        PLATFORM_DOMAIN: "issuer.credtrail.test",
        PUBLIC_APP_ORIGIN: "https://app.credtrail.test",
      },
    );

    expect(response.status).toBe(308);
    expect(response.headers.get("location")).toBe(
      "https://app.credtrail.test//evil.example/ok?source=proxy",
    );
  });

  it("allows issuer identity documents on the configured platform domain", async () => {
    const app = createMiddlewareApp();
    app.get("/.well-known/did.json", (c) => c.json({ id: "did:web:issuer.credtrail.test" }));
    const response = await app.request(
      "https://issuer.credtrail.test/.well-known/did.json",
      undefined,
      {
        ...fakeEnv,
        APP_ENV: "production",
        PLATFORM_DOMAIN: "issuer.credtrail.test",
        PUBLIC_APP_ORIGIN: "https://app.credtrail.test",
      },
    );

    expect(response.status).toBe(200);
  });

  it("rejects malformed platform identity configuration before routing", async () => {
    const response = await createMiddlewareApp().request("/ok", undefined, {
      ...fakeEnv,
      PLATFORM_DOMAIN: "https://credtrail.test",
    });

    expect(response.status).toBe(500);
  });

  it("logs unhandled route errors with the request id", async () => {
    const response = await createMiddlewareApp().request(
      "/boom",
      {
        headers: {
          "x-request-id": "request-error",
        },
      },
      fakeEnv,
    );
    const body = await response.json<{ error: string }>();

    expect(response.status).toBe(500);
    expect(response.headers.get("x-request-id")).toBe("request-error");
    expect(body).toEqual({
      error: "Internal server error",
    });

    const errorRecord = JSON.parse(String(consoleError.mock.calls[0]?.[0])) as Record<
      string,
      unknown
    >;
    expect(errorRecord).toMatchObject({
      level: "error",
      service: "api-worker",
      environment: "test",
      message: "api_error",
      requestId: "request-error",
      method: "GET",
      path: "/boom",
      detail: "route failed",
    });
  });
});

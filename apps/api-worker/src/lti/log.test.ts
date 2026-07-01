import type {
  ObservabilityContext,
  ObservabilityFields,
  ObservabilityLevel,
} from "@credtrail/core-domain";
import { Hono } from "hono";
import { describe, expect, it, vi } from "vitest";
import type { AppBindings, AppEnv } from "../app";
import { createAppLogger } from "../app/observability";
import { ltiLogger } from "./log";

interface RecordedLog {
  level: ObservabilityLevel;
  context: ObservabilityContext;
  message: string;
  fields: ObservabilityFields;
}

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

describe("ltiLogger", () => {
  it("scopes warnings to the lti component", async () => {
    const records: RecordedLog[] = [];
    const app = new Hono<AppEnv>();

    app.use("*", async (c, next) => {
      c.set("requestId", "request-1");
      c.set(
        "appLogger",
        createAppLogger({
          context: {
            service: "api-worker",
            environment: "test",
          },
          fields: {
            requestId: "request-1",
          },
          writer: (level, context, message, fields) => {
            records.push({
              level,
              context,
              message,
              fields,
            });
          },
        }),
      );
      await next();
    });

    app.get("/lti", (c) => {
      ltiLogger(c)?.warn("lti_warning", {
        tenantId: "tenant_123",
      });
      return c.text("ok");
    });

    const response = await app.request("/lti", undefined, fakeEnv);

    expect(response.status).toBe(200);
    expect(records).toEqual([
      {
        level: "warn",
        context: {
          service: "api-worker",
          environment: "test",
        },
        message: "lti_warning",
        fields: {
          requestId: "request-1",
          component: "lti",
          tenantId: "tenant_123",
        },
      },
    ]);
  });

  it("returns undefined when request logging is not registered", async () => {
    const app = new Hono<AppEnv>();

    app.get("/lti", (c) => {
      expect(ltiLogger(c)).toBeUndefined();
      return c.text("ok");
    });

    const response = await app.request("/lti", undefined, fakeEnv);

    expect(response.status).toBe(200);
  });
});

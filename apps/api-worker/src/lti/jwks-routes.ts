import type { SqlDatabase } from "@credtrail/db";
import type { Hono } from "hono";
import type { AppBindings, AppContext, AppEnv } from "../app";
import type { AppLogger } from "../app/observability";
import { LTI_JWKS_PATH } from "./constants";
import { resolveCredTrailLtiTool } from "./credtrail-lti-tool";

interface RegisterLtiJwksRouteInput {
  app: Hono<AppEnv>;
  resolveDatabase: (bindings: AppBindings) => SqlDatabase;
}

const isAppLogger = (value: unknown): value is AppLogger => {
  return (
    typeof value === "object" &&
    value !== null &&
    "error" in value &&
    typeof value.error === "function"
  );
};

const appLoggerFromContext = (c: AppContext): AppLogger | undefined => {
  const logger: unknown = c.get("appLogger");
  return isAppLogger(logger) ? logger : undefined;
};

const serveLtiJwks = async (
  c: AppContext,
  resolveDatabase: (bindings: AppBindings) => SqlDatabase,
): Promise<Response> => {
  try {
    const ltiTool = await resolveCredTrailLtiTool(c, resolveDatabase);

    return c.json(await ltiTool.getJWKS());
  } catch (error) {
    appLoggerFromContext(c)?.error("lti_jwks_failed", {
      component: "lti",
      detail: error instanceof Error ? error.message : "unknown error",
    });

    return c.json(
      {
        error: "Internal server error",
      },
      500,
    );
  }
};

export const registerLtiJwksRoute = (input: RegisterLtiJwksRouteInput): void => {
  const { app, resolveDatabase } = input;

  app.get(LTI_JWKS_PATH, async (c): Promise<Response> => {
    return serveLtiJwks(c, resolveDatabase);
  });
};

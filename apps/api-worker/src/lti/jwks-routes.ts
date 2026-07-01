import type { SqlDatabase } from "@credtrail/db";
import type { Hono } from "hono";
import type { AppBindings, AppContext, AppEnv } from "../app";
import { LTI_JWKS_PATH } from "./constants";
import { createCredTrailLtiTool } from "./credtrail-lti-tool";
import { ltiLogger } from "./log";

interface RegisterLtiJwksRouteInput {
  app: Hono<AppEnv>;
  resolveDatabase: (bindings: AppBindings) => SqlDatabase;
}

const serveLtiJwks = async (
  c: AppContext,
  resolveDatabase: (bindings: AppBindings) => SqlDatabase,
): Promise<Response> => {
  try {
    const ltiTool = await createCredTrailLtiTool({
      db: resolveDatabase(c.env),
      env: c.env,
    });

    return c.json(await ltiTool.getJWKS());
  } catch (error) {
    ltiLogger(c)?.error("lti_jwks_failed", {
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

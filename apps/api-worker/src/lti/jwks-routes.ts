import type { SqlDatabase } from "@credtrail/db";
import type { Hono } from "hono";
import type { AppBindings, AppContext, AppEnv } from "../app";
import { createCredTrailLtiTool } from "./credtrail-lti-tool";

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
  } catch {
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

  app.get("/v1/lti/jwks", async (c): Promise<Response> => {
    return serveLtiJwks(c, resolveDatabase);
  });
};

import type { SqlDatabase } from "@credtrail/db";
import { jwksRouteHandler } from "@longsightgroup/lti-tool/hono";
import type { Hono } from "hono";
import type { AppBindings, AppContext, AppEnv } from "../app";
import { LTI_JWKS_PATH } from "./constants";
import { createCredTrailLtiTool } from "./credtrail-lti-tool";
import { createLtiHonoLogger } from "./hono-logger";

interface RegisterLtiJwksRouteInput {
  app: Hono<AppEnv>;
  resolveDatabase: (bindings: AppBindings) => SqlDatabase;
}

const serveLtiJwks = async (
  c: AppContext,
  resolveDatabase: (bindings: AppBindings) => SqlDatabase,
): Promise<Response> => {
  return jwksRouteHandler({
    getJWKS: async () => {
      const ltiTool = await createCredTrailLtiTool({
        db: resolveDatabase(c.env),
        env: c.env,
      });

      return ltiTool.getJWKS();
    },
    logger: createLtiHonoLogger({
      c,
      messageOverrides: {
        "JWKS endpoint error": "lti_jwks_failed",
      },
    }),
  })(c, async () => undefined);
};

export const registerLtiJwksRoute = (input: RegisterLtiJwksRouteInput): void => {
  const { app, resolveDatabase } = input;

  app.get(LTI_JWKS_PATH, async (c): Promise<Response> => {
    return serveLtiJwks(c, resolveDatabase);
  });
};

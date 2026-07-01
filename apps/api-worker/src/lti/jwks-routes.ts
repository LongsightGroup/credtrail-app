import type { SqlDatabase } from "@credtrail/db";
import type { JWKS } from "@longsightgroup/lti-tool";
import { jwksRouteHandler } from "@longsightgroup/lti-tool/hono";
import type { Hono } from "hono";
import type { AppBindings, AppContext, AppEnv } from "../app";
import { LTI_JWKS_PATH } from "./constants";
import { getCredTrailLtiToolJwks } from "./credtrail-lti-tool";
import { createLtiHonoLogger } from "./hono-logger";

interface RegisterLtiJwksRouteInput {
  app: Hono<AppEnv>;
  resolveDatabase: (bindings: AppBindings) => SqlDatabase;
}

const LTI_JWKS_CACHE_TTL_MS = 5 * 60 * 1000;

interface LtiJwksCacheEntry {
  readonly expiresAtMs: number;
  readonly jwks: Promise<JWKS>;
}

const createLtiJwksResolver = (
  resolveDatabase: (bindings: AppBindings) => SqlDatabase,
): ((c: AppContext) => Promise<JWKS>) => {
  let cacheEntry: LtiJwksCacheEntry | undefined;

  return async (c: AppContext): Promise<JWKS> => {
    const nowMs = Date.now();

    if (cacheEntry !== undefined && cacheEntry.expiresAtMs > nowMs) {
      return cacheEntry.jwks;
    }

    const jwks = getCredTrailLtiToolJwks(resolveDatabase(c.env));
    cacheEntry = {
      expiresAtMs: nowMs + LTI_JWKS_CACHE_TTL_MS,
      jwks,
    };

    try {
      return await jwks;
    } catch (error: unknown) {
      if (cacheEntry?.jwks === jwks) {
        cacheEntry = undefined;
      }

      throw error;
    }
  };
};

const serveLtiJwks = async (
  c: AppContext,
  getJWKS: (c: AppContext) => Promise<JWKS>,
): Promise<Response> => {
  return jwksRouteHandler({
    getJWKS: () => getJWKS(c),
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
  const getJWKS = createLtiJwksResolver(resolveDatabase);

  app.get(LTI_JWKS_PATH, async (c): Promise<Response> => {
    return serveLtiJwks(c, getJWKS);
  });
};

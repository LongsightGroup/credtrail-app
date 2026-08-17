import type { Hono } from "hono";
import type { AppContext, AppEnv } from "../app/types";
import { buildLoginPath } from "../auth/login-path";

/** Registers the browser and JSON logout protocol adapters. */
export const registerLogoutRoutes = (input: {
  readonly app: Hono<AppEnv>;
  readonly revokeCurrentSession: (context: AppContext) => Promise<void>;
}): void => {
  input.app.post("/auth/logout", async (c) => {
    await input.revokeCurrentSession(c);

    return c.redirect(buildLoginPath({ reason: "signed_out" }), 303);
  });

  input.app.post("/v1/auth/logout", async (c) => {
    await input.revokeCurrentSession(c);

    return c.json({ status: "signed_out" });
  });
};

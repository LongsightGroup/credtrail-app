import { Hono } from "hono";
import { deleteCookie } from "hono/cookie";
import { describe, expect, it } from "vitest";
import type { AppEnv } from "../app/types";
import { registerLogoutRoutes } from "./logout-routes";

const createHarness = (): Hono<AppEnv> => {
  const app = new Hono<AppEnv>();

  registerLogoutRoutes({
    app,
    revokeCurrentSession: (context) => {
      deleteCookie(context, "better-auth.session_token", { path: "/" });
      return Promise.resolve();
    },
  });

  return app;
};

describe("logout routes", () => {
  it("clears the browser session before redirecting to the signed-out login page", async () => {
    const response = await createHarness().request("/auth/logout", { method: "POST" });

    expect(response.status).toBe(303);
    expect(response.headers.get("location")).toBe("/login?reason=signed_out");
    expect(response.headers.get("set-cookie")).toContain("better-auth.session_token=");
  });

  it("clears the API session before confirming the signed-out state", async () => {
    const response = await createHarness().request("/v1/auth/logout", { method: "POST" });

    expect(response.status).toBe(200);
    await expect(response.json()).resolves.toEqual({ status: "signed_out" });
    expect(response.headers.get("set-cookie")).toContain("better-auth.session_token=");
  });
});

import { Hono } from "hono";
import { setCookie } from "hono/cookie";
import { describe, expect, it } from "vitest";
import type { AppEnv } from "../app/types";
import { registerAppPageRenderer } from "../ui/render-page";
import { registerMagicLinkBrowserRoutes } from "./magic-link-browser-routes";

const createHarness = (input?: { rejectToken?: boolean }) => {
  const app = new Hono<AppEnv>();
  const consumedTokens: string[] = [];
  registerAppPageRenderer(app);
  registerMagicLinkBrowserRoutes({
    app,
    createMagicLinkSession: (c, token) => {
      consumedTokens.push(token);

      if (input?.rejectToken === true) {
        return Promise.resolve(null);
      }

      setCookie(c, "better-auth.session_token", "better-session", {
        httpOnly: true,
        sameSite: "Lax",
        path: "/",
      });
      return Promise.resolve({
        userId: "usr_better",
        authSessionId: "ba_ses_123",
        authMethod: "better_auth",
        expiresAt: "2026-02-18T22:00:00.000Z",
      });
    },
  });
  return { app, consumedTokens };
};

describe("browser magic-link routes", () => {
  it("renders repeated GET confirmations without consuming the token", async () => {
    const { app, consumedTokens } = createHarness();
    const path = "/auth/magic-link/verify?token=better-token-1234567890&next=%2Fauth%2Fresolve";

    const firstResponse = await app.request(path);
    const secondResponse = await app.request(path);
    const body = await secondResponse.text();

    expect(firstResponse.status).toBe(200);
    expect(secondResponse.status).toBe(200);
    expect(body).toContain('action="/auth/magic-link/verify"');
    expect(body).toContain('name="token" type="hidden" value="better-token-1234567890"');
    expect(body).toContain('name="next" type="hidden" value="/auth/resolve"');
    expect(body).toContain("Continue to CredTrail");
    expect(consumedTokens).toEqual([]);
  });

  it("rejects a malformed token before rendering or session creation", async () => {
    const { app, consumedTokens } = createHarness();

    const response = await app.request("/auth/magic-link/verify?token=short");
    const body = await response.text();

    expect(response.status).toBe(400);
    expect(body).toContain("Invalid magic link");
    expect(consumedTokens).toEqual([]);
  });

  it("consumes an unscoped token and sets the session before organization resolution", async () => {
    const { app, consumedTokens } = createHarness();

    const response = await app.request("/auth/magic-link/verify", {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: new URLSearchParams({
        token: "better-token-1234567890",
        next: "/auth/resolve",
      }).toString(),
    });

    expect(response.status).toBe(302);
    expect(response.headers.get("location")).toBe("/auth/resolve");
    expect(response.headers.get("set-cookie")).toContain(
      "better-auth.session_token=better-session",
    );
    expect(consumedTokens).toEqual(["better-token-1234567890"]);
  });

  it("normalizes unsafe redirect paths", async () => {
    const { app } = createHarness();

    const response = await app.request(
      "/auth/magic-link/verify?token=better-token-1234567890&next=https%3A%2F%2Fattacker.example",
    );
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(body).toContain('name="next" type="hidden" value="/auth/resolve"');
  });

  it("renders an expired-link response when session creation rejects the token", async () => {
    const { app } = createHarness({ rejectToken: true });

    const response = await app.request("/auth/magic-link/verify", {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: new URLSearchParams({
        token: "better-token-1234567890",
        next: "/auth/resolve",
      }).toString(),
    });
    const body = await response.text();

    expect(response.status).toBe(400);
    expect(body).toContain("Magic link expired");
  });
});

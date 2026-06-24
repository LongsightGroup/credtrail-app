import type { ImmutableCredentialStore } from "@credtrail/core-domain";
import { Hono } from "hono";
import { describe, expect, it } from "vitest";
import type { AppBindings, AppEnv } from "../app/types";
import { registerDesignSystemRoutes } from "./design-system-routes";
import { registerAppPageRenderer } from "../ui/render-page";

const createEnv = (appEnv: string): AppBindings => {
  return {
    APP_ENV: appEnv,
    BADGE_OBJECTS: {} as ImmutableCredentialStore,
    PLATFORM_DOMAIN: "credtrail.org",
  };
};

const createApp = (): Hono<AppEnv> => {
  const app = new Hono<AppEnv>();

  registerAppPageRenderer(app);
  registerDesignSystemRoutes({ app });

  return app;
};

describe("design system routes", () => {
  it("serves the design system gallery in development", async () => {
    const response = await createApp().request("/design-system", {}, createEnv("development"));
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(body).toContain("Design System | CredTrail");
    expect(body).toContain('id="actions"');
  });

  it("does not expose the design system gallery outside development", async () => {
    const response = await createApp().request("/design-system", {}, createEnv("test"));

    expect(response.status).toBe(404);
  });
});

import type { Hono } from "hono";
import type { AppEnv } from "../app/types";
import { renderDesignSystemPage } from "../ui/design-system-page";
import { renderAppPage } from "../ui/render-page";

export const registerDesignSystemRoutes = (input: { app: Hono<AppEnv> }): void => {
  input.app.get("/design-system", (c) => {
    if (c.env.APP_ENV !== "development") {
      return c.notFound();
    }

    return renderAppPage(c, renderDesignSystemPage());
  });
};

import type { ObservabilityContext } from "@credtrail/core-domain";
import { logWarn } from "@credtrail/core-domain";
import type { Hono } from "hono";
import type { AppBindings, AppEnv } from "../app/types";
import type { ResolveDatabase } from "../app/route-deps";

interface RegisterHealthRoutesInput {
  app: Hono<AppEnv>;
  observabilityContext: (bindings: AppBindings) => ObservabilityContext;
  resolveDatabase: ResolveDatabase;
  serviceName: string;
  storageReadinessProbeKey: string;
}

export const registerHealthRoutes = (input: RegisterHealthRoutesInput): void => {
  input.app.get("/healthz/dependencies", async (c) => {
    try {
      await input.resolveDatabase(c.env).prepare("SELECT 1 AS ready").first<{ ready: number }>();
      await c.env.BADGE_OBJECTS.head(input.storageReadinessProbeKey);
    } catch (error: unknown) {
      const detail = error instanceof Error ? error.message : "Unknown dependency check failure";

      logWarn(input.observabilityContext(c.env), "dependency_healthcheck_failed", {
        detail,
      });

      return c.json(
        {
          service: input.serviceName,
          status: "degraded",
          detail,
        },
        503,
      );
    }

    return c.json({
      service: input.serviceName,
      status: "ok",
    });
  });
};

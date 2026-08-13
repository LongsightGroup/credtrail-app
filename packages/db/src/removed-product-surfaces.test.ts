import { readFileSync } from "node:fs";

import { describe, expect, it } from "vitest";

describe("removed product surfaces", () => {
  it("drops superseded provisioning and Canvas tables through forward migrations", () => {
    const dedicatedDbSql = readFileSync(
      new URL("../migrations/0070_drop_dedicated_db_provisioning.sql", import.meta.url),
      "utf8",
    );
    const canvasSql = readFileSync(
      new URL("../migrations/0071_drop_superseded_canvas_integration.sql", import.meta.url),
      "utf8",
    );

    expect(dedicatedDbSql).toContain(
      "DROP TABLE IF EXISTS tenant_dedicated_db_provisioning_requests",
    );
    expect(canvasSql).toContain("DROP TABLE IF EXISTS tenant_canvas_gradebook_integrations");
  });

  it("does not expose the removed database workflows", async () => {
    const dbModule = await import("./index");

    expect(dbModule).not.toHaveProperty("createDedicatedDbProvisioningRequest");
    expect(dbModule).not.toHaveProperty("listDedicatedDbProvisioningRequests");
    expect(dbModule).not.toHaveProperty("resolveDedicatedDbProvisioningRequest");
    expect(dbModule).not.toHaveProperty("findTenantCanvasGradebookIntegration");
    expect(dbModule).not.toHaveProperty("upsertTenantCanvasGradebookIntegration");
    expect(dbModule).not.toHaveProperty("updateTenantCanvasGradebookIntegrationTokens");
  });
});

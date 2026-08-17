import { expect, it } from "vitest";

import { listActiveTenants, upsertTenant } from "./index";
import {
  cleanupTestResources,
  createTestPostgresDatabase,
  describeDbIntegration,
  uniqueTestId,
} from "./postgres-test-support";

describeDbIntegration("tenant helpers", () => {
  it("lists integer-backed active tenants and excludes inactive tenants", async () => {
    const db = createTestPostgresDatabase();
    const activeTenantId = uniqueTestId("tenant_active");
    const inactiveTenantId = uniqueTestId("tenant_inactive");

    try {
      await upsertTenant(db, {
        id: activeTenantId,
        slug: uniqueTestId("active").replace(/_/g, "-"),
        displayName: "Active Tenant",
        planTier: "institution",
        issuerDomain: `${activeTenantId}.issuer.test`,
        didWeb: `did:web:${activeTenantId}.issuer.test`,
        isActive: true,
      });
      await upsertTenant(db, {
        id: inactiveTenantId,
        slug: uniqueTestId("inactive").replace(/_/g, "-"),
        displayName: "Inactive Tenant",
        planTier: "institution",
        issuerDomain: `${inactiveTenantId}.issuer.test`,
        didWeb: `did:web:${inactiveTenantId}.issuer.test`,
        isActive: false,
      });

      const activeTenantIds = (await listActiveTenants(db)).map((tenant) => tenant.id);

      expect(activeTenantIds).toContain(activeTenantId);
      expect(activeTenantIds).not.toContain(inactiveTenantId);
    } finally {
      await cleanupTestResources(db, {
        tenantIds: [activeTenantId, inactiveTenantId],
      });
    }
  });
});

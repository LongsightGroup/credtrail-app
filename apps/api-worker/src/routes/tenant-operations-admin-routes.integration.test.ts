import { findTenantById } from "@credtrail/db";
import { Hono } from "hono";
import { afterEach, expect, it } from "vitest";
import {
  cleanupTestResources,
  createBadgeRuleIntegrationFixture,
  createTestPostgresDatabase,
  describeDbIntegration,
  seedAssertion,
  type BadgeRuleIntegrationFixture,
} from "../../../../packages/db/src/postgres-test-support";
import type { AppEnv } from "../app/types";
import { registerAppPageRenderer } from "../ui/render-page";
import { issuanceReceiptPath } from "../admin/issuance-receipt-page";
import { registerTenantOperationsAdminRoutes } from "./tenant-operations-admin-routes";

const tenantIds: string[] = [];
const userIds: string[] = [];
afterEach(async () => {
  if (tenantIds.length === 0) return;
  await cleanupTestResources(createTestPostgresDatabase(), { tenantIds, userIds });
  tenantIds.length = 0;
  userIds.length = 0;
});

const fixture = async (): Promise<BadgeRuleIntegrationFixture> => {
  const result = await createBadgeRuleIntegrationFixture();
  tenantIds.push(result.tenantId);
  userIds.push(result.userId);
  return result;
};

const routeApp = (data: BadgeRuleIntegrationFixture, allowAccess = true): Hono<AppEnv> => {
  const app = new Hono<AppEnv>();
  registerAppPageRenderer(app);
  registerTenantOperationsAdminRoutes({
    app,
    resolveDatabase: () => data.db,
    resolveInstitutionAdminAdminRole: async (_c, tenantId) =>
      allowAccess && tenantId === data.tenantId
        ? { principal: { userId: data.userId }, membershipRole: "admin" }
        : new Response("Forbidden", { status: 403 }),
    requireDelegatedIssuingAuthorityPermission: async () => null,
    issueBadgeForTenant: async (_c, tenantId, request) => {
      const assertionId = await seedAssertion(data.db, {
        tenantId,
        badgeTemplateId: data.badgeTemplateId,
        recipientIdentity: request.recipientIdentity,
        issuedAt: "2026-09-16T12:00:00.000Z",
        publicId: `public_${crypto.randomUUID()}`,
      });
      return {
        status: "issued",
        assertionId,
        tenantId,
        idempotencyKey: request.idempotencyKey ?? "receipt-test",
        vcR2Key: `assertions/${assertionId}.jsonld`,
        credential: {},
      };
    },
    loadInstitutionAdminShellData: async (_c, tenantId) => {
      const tenant = await findTenantById(data.db, tenantId);
      if (tenant === null) return new Response("Not found", { status: 404 });
      return { tenant, userId: data.userId, membershipRole: "admin", switchOrganizationPath: null };
    },
  });
  return app;
};

describeDbIntegration("persisted issuance receipts", () => {
  it("redirects issuance to a receipt that survives refresh without a flash cookie", async () => {
    const data = await fixture();
    const app = routeApp(data);
    const response = await app.request(`/tenants/${data.tenantId}/admin/operations/issue`, {
      method: "POST",
      body: new URLSearchParams({
        badgeTemplateId: data.badgeTemplateId,
        recipientIdentity: "learner@example.edu",
      }),
    });
    expect(response.status).toBe(303);
    expect(response.headers.get("set-cookie")).toBeNull();
    const location = response.headers.get("location");
    expect(location).toMatch(/\/receipt$/);
    if (location === null) throw new Error("Missing receipt redirect");
    for (let visit = 0; visit < 2; visit++) {
      const receipt = await app.request(location);
      expect(receipt.status).toBe(200);
      expect(receipt.headers.get("cache-control")).toBe("no-store");
      const html = await receipt.text();
      expect(html).toContain("Issuance receipt");
      expect(html).toContain("learner@example.edu");
      expect(html).toContain("View badge record");
      expect(html).toContain("Issue another badge");
      expect(html).toContain("/verification");
      expect(html).toContain("/jsonld");
      expect(html).not.toContain('id="manual-issue-form"');
    }
  });

  it("does not expose another tenant's receipt or a missing assertion", async () => {
    const owner = await fixture();
    const visitor = await fixture();
    const assertionId = await seedAssertion(owner.db, {
      tenantId: owner.tenantId,
      badgeTemplateId: owner.badgeTemplateId,
      recipientIdentity: "private@example.edu",
      issuedAt: "2026-09-16T12:00:00.000Z",
    });
    const app = routeApp(visitor);
    for (const id of [assertionId, "missing_assertion"]) {
      const response = await app.request(issuanceReceiptPath(visitor.tenantId, id));
      expect(response.status).toBe(404);
      expect(await response.text()).not.toContain("private@example.edu");
    }
    const denied = await routeApp(owner, false).request(
      issuanceReceiptPath(owner.tenantId, assertionId),
    );
    expect(denied.status).toBe(403);
    expect(await denied.text()).not.toContain("private@example.edu");
  });
});

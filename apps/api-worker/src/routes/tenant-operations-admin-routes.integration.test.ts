import {
  recordIssuanceEmailOutcome,
  loadIssuanceEmailState,
} from "../notifications/issuance-email-outcome";
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
    renderManualIssueCorrection: async (c, _tenantId, _nextPath, correction) =>
      c.json(correction, 422),
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
        idempotencyKey: request.idempotencyKey,
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
  it("offers a retry tied to the saved failed notification on the existing receipt", async () => {
    const f = await fixture();
    const assertionId = await seedAssertion(f.db, {
      tenantId: f.tenantId,
      badgeTemplateId: f.badgeTemplateId,
      recipientIdentity: "receipt@example.edu",
      publicId: `public_${crypto.randomUUID()}`,
      issuedAt: "2026-09-01T00:00:00.000Z",
    });
    await recordIssuanceEmailOutcome({
      db: f.db,
      tenantId: f.tenantId,
      assertionId,
      status: "failed",
    });
    const state = await loadIssuanceEmailState(f.db, f.tenantId, assertionId);
    const returnHref = `/tenants/${f.tenantId}/admin/operations/issued-badges?notificationStatus=failed&recipientQuery=receipt&limit=100`;
    const response = await routeApp(f).request(
      `${issuanceReceiptPath(f.tenantId, assertionId)}?${new URLSearchParams({ returnTo: returnHref })}`,
      undefined,
      { PUBLIC_APP_ORIGIN: "https://credtrail.test" },
    );
    expect(response.status).toBe(200);
    const body = await response.text();
    expect(body).toContain("Retry notification email");
    expect(body).toContain(`name="failedAttemptId" type="hidden" value="${state.attemptId}"`);
    expect(body).toContain("Copy public badge link");
    expect(body).toContain("Back to failed emails");
    expect(body).toContain('name="returnTo"');
    expect(body).toContain("recipientQuery=receipt");
    for (const returnTo of [
      "https://external.example",
      "/tenants/other/admin/operations/issued-badges?notificationStatus=failed",
    ]) {
      const response = await routeApp(f).request(
        `${issuanceReceiptPath(f.tenantId, assertionId)}?${new URLSearchParams({ returnTo })}`,
        undefined,
        { PUBLIC_APP_ORIGIN: "https://credtrail.test" },
      );
      expect(await response.text()).not.toContain("Back to failed emails");
    }
  });

  it("returns the same receipt for simultaneous submissions and a later retry", async () => {
    const data = await fixture();
    const app = routeApp(data);
    const form = {
      issuanceRequestId: crypto.randomUUID(),
      badgeTemplateId: data.badgeTemplateId,
      recipientIdentity: "retry@example.edu",
    };
    const submit = async (): Promise<Response> =>
      app.request(`/tenants/${data.tenantId}/admin/operations/issue`, {
        method: "POST",
        body: new URLSearchParams(form),
      });
    const responses = await Promise.all([submit(), submit()]);
    responses.push(await submit());
    expect(responses.map((response) => response.status)).toEqual([303, 303, 303]);
    expect(new Set(responses.map((response) => response.headers.get("location"))).size).toBe(1);
    const count = await data.db
      .prepare(
        "SELECT COUNT(*) AS count FROM assertions WHERE tenant_id = ? AND recipient_identity = ?",
      )
      .bind(data.tenantId, form.recipientIdentity)
      .first<{ count: number | string }>();
    expect(Number(count?.count)).toBe(1);
  });

  it("requires a choice-bound confirmation for a previous award and keeps retries safe", async () => {
    const data = await fixture();
    const app = routeApp(data);
    const existingId = await seedAssertion(data.db, {
      tenantId: data.tenantId,
      badgeTemplateId: data.badgeTemplateId,
      recipientIdentity: "ALREADY@example.edu",
      issuedAt: "2026-09-16T12:00:00.000Z",
    });
    const form = {
      issuanceRequestId: crypto.randomUUID(),
      badgeTemplateId: data.badgeTemplateId,
      recipientIdentity: "already@example.edu",
    };
    const submit = async (values: Record<string, string>): Promise<Response> =>
      app.request(`/tenants/${data.tenantId}/admin/operations/issue`, {
        method: "POST",
        body: new URLSearchParams(values),
      });
    const review = await submit(form);
    const warning = await review.json<{
      previousAward: { assertionId: string; confirmationKey: string };
    }>();
    expect(warning.previousAward.assertionId).toBe(existingId);
    const confirmed = { ...form, previousAwardConfirmation: warning.previousAward.confirmationKey };
    // Confirmation from a different form cannot silently authorize another award.
    const stale = await submit({ ...confirmed, issuanceRequestId: crypto.randomUUID() });
    expect(stale.status).toBe(422);
    expect(await stale.json()).toHaveProperty("previousAward.assertionId", existingId);
    const issued = await submit(confirmed);
    expect(issued.status).toBe(303);
    expect(issued.headers.get("location")).not.toContain(encodeURIComponent(existingId));
    const retry = await submit(confirmed);
    expect(retry.status).toBe(303);
    expect(retry.headers.get("location")).toBe(issued.headers.get("location"));
    const count = await data.db
      .prepare(
        "SELECT COUNT(*) AS count FROM assertions WHERE tenant_id = ? AND LOWER(recipient_identity) = ?",
      )
      .bind(data.tenantId, form.recipientIdentity)
      .first<{ count: number | string }>();
    expect(Number(count?.count)).toBe(2);
  });

  it("preserves the recipient and selected badge when validation fails", async () => {
    const data = await fixture();
    const response = await routeApp(data).request(
      `/tenants/${data.tenantId}/admin/operations/issue`,
      {
        method: "POST",
        body: new URLSearchParams({
          issuanceRequestId: crypto.randomUUID(),
          badgeTemplateId: data.badgeTemplateId,
          recipientIdentity: "learner@",
        }),
      },
    );
    expect(response.status).toBe(422);
    expect(response.headers.get("location")).toBeNull();
    expect(await response.json()).toMatchObject({
      recipientIdentity: "learner@",
      badgeTemplateId: data.badgeTemplateId,
    });
  });
  it("redirects issuance to a receipt that survives refresh without a flash cookie", async () => {
    const data = await fixture();
    const app = routeApp(data);
    const response = await app.request(`/tenants/${data.tenantId}/admin/operations/issue`, {
      method: "POST",
      body: new URLSearchParams({
        issuanceRequestId: crypto.randomUUID(),
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
      const receipt = await app.request(location, undefined, {
        PUBLIC_APP_ORIGIN: "https://credtrail.test",
      });
      expect(receipt.status).toBe(200);
      expect(receipt.headers.get("cache-control")).toBe("no-store");
      const html = await receipt.text();
      expect(html).toContain("Issuance receipt");
      expect(html).toContain("learner@example.edu");
      expect(html).toContain("View badge record");
      expect(html).toContain("Issue this badge to another learner");
      expect(html).toContain(`/operations/issue?badgeTemplateId=${data.badgeTemplateId}`);
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

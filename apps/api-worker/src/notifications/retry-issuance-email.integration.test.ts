import { expect, it } from "vitest";
import { Hono } from "hono";
import { findAssertionById, listAuditLogs } from "@credtrail/db";
import {
  cleanupTestResources,
  createBadgeRuleIntegrationFixture,
  describeDbIntegration,
  seedAssertion,
} from "../../../../packages/db/src/postgres-test-support";
import { loadIssuanceEmailState, recordIssuanceEmailOutcome } from "./issuance-email-outcome";
import { retryFailedIssuanceEmail } from "./retry-issuance-email";
import { registerTenantNotificationRetryAdminRoutes } from "../routes/tenant-notification-retry-admin-routes";
import type { AppEnv } from "../app/types";

describeDbIntegration("notification retry", () => {
  it("claims each failed attempt once, records outcomes, and leaves the credential untouched", async () => {
    const f = await createBadgeRuleIntegrationFixture();
    try {
      const assertionId = await seedAssertion(f.db, {
        tenantId: f.tenantId,
        badgeTemplateId: f.badgeTemplateId,
        recipientIdentity: "retry@example.edu",
        issuedAt: "2026-09-01T00:00:00.000Z",
      });
      const original = await findAssertionById(f.db, f.tenantId, assertionId);
      await recordIssuanceEmailOutcome({
        db: f.db,
        tenantId: f.tenantId,
        assertionId,
        status: "failed",
      });
      const initial = await loadIssuanceEmailState(f.db, f.tenantId, assertionId);
      let sends = 0;
      const input = {
        db: f.db,
        tenantId: f.tenantId,
        assertionId,
        actorUserId: f.userId,
        failedAttemptId: initial.attemptId ?? "missing",
        send: async (): Promise<void> => {
          sends += 1;
          expect((await loadIssuanceEmailState(f.db, f.tenantId, assertionId)).outcome).toBe(
            "pending",
          );
          throw new Error("provider unavailable");
        },
      };
      const concurrent = await Promise.all([
        retryFailedIssuanceEmail(input),
        retryFailedIssuanceEmail(input),
      ]);
      expect(concurrent.sort()).toEqual(["already_handled", "failed"]);
      expect(sends).toBe(1);
      expect(await retryFailedIssuanceEmail(input)).toBe("already_handled");
      const failed = await loadIssuanceEmailState(f.db, f.tenantId, assertionId);
      expect(failed.outcome).toBe("failed");
      expect(failed.attemptId).not.toBe(initial.attemptId);
      expect(
        await retryFailedIssuanceEmail({
          ...input,
          failedAttemptId: failed.attemptId ?? "missing",
          send: async () => {
            sends += 1;
          },
        }),
      ).toBe("accepted");
      expect(sends).toBe(2);
      expect((await loadIssuanceEmailState(f.db, f.tenantId, assertionId)).outcome).toBe(
        "accepted",
      );
      expect(await retryFailedIssuanceEmail({ ...input, tenantId: "other-tenant" })).toBe(
        "already_handled",
      );
      expect(await findAssertionById(f.db, f.tenantId, assertionId)).toEqual(original);
      const audits = await listAuditLogs(f.db, {
        tenantId: f.tenantId,
        action: "assertion.issuance_email",
        targetType: "assertion",
        targetId: assertionId,
      });
      expect(audits).toHaveLength(5);
      expect(audits[0]?.actorUserId).toBe(f.userId);
    } finally {
      await cleanupTestResources(f.db, { tenantIds: [f.tenantId], userIds: [f.userId] });
    }
  });

  it("authorizes retry requests, validates the attempt, and sends existing credential links", async () => {
    const f = await createBadgeRuleIntegrationFixture();
    try {
      const assertionId = await seedAssertion(f.db, {
        tenantId: f.tenantId,
        badgeTemplateId: f.badgeTemplateId,
        recipientIdentity: "retry@example.edu",
        publicId: `public_${crypto.randomUUID()}`,
        issuedAt: "2026-09-01T00:00:00.000Z",
      });
      await recordIssuanceEmailOutcome({
        db: f.db,
        tenantId: f.tenantId,
        assertionId,
        status: "failed",
      });
      const failed = await loadIssuanceEmailState(f.db, f.tenantId, assertionId);
      let sends = 0;
      let allowed = false;
      const app = new Hono<AppEnv>();
      registerTenantNotificationRetryAdminRoutes({
        app,
        resolveDatabase: () => f.db,
        resolveInstitutionAdminAdminRole: async (_c, tenantId) =>
          tenantId === f.tenantId
            ? { principal: { userId: f.userId }, membershipRole: "admin" }
            : new Response("Forbidden", { status: 403 }),
        requireDelegatedIssuingAuthorityPermission: async () =>
          allowed ? null : new Response("Forbidden", { status: 403 }),
        send: async (email) => {
          sends += 1;
          expect(email.recipientEmail).toBe("retry@example.edu");
          expect(email.assertionId).toBe(assertionId);
          expect(email.publicBadgeUrl).toMatch(/^https:\/\/credtrail.org\/badges\//);
        },
      });
      const env = {
        BETTER_AUTH_SECRET: "test-notification-secret",
        ISSUANCE_EMAIL_NOTIFICATIONS_ENABLED: "true",
        EMAIL: { send: async () => {} },
        PUBLIC_APP_ORIGIN: "https://credtrail.org",
      };
      const submit = async (
        tenantId: string,
        attemptId: string,
        returnTo = "",
      ): Promise<Response> =>
        app.request(
          `/tenants/${tenantId}/admin/operations/issue/${encodeURIComponent(assertionId)}/retry-notification`,
          { method: "POST", body: new URLSearchParams({ failedAttemptId: attemptId, returnTo }) },
          env,
        );
      expect((await submit(f.tenantId, failed.attemptId ?? "missing")).status).toBe(403);
      allowed = true;
      expect((await submit("other-tenant", failed.attemptId ?? "missing")).status).toBe(403);
      expect((await submit(f.tenantId, "")).status).toBe(303);
      expect(sends).toBe(0);
      expect((await submit(f.tenantId, failed.attemptId ?? "missing")).status).toBe(303);
      expect((await submit(f.tenantId, failed.attemptId ?? "missing")).status).toBe(303);
      expect(sends).toBe(1);
      const returnHref = `/tenants/${f.tenantId}/admin/operations/issued-badges?notificationStatus=failed&recipientQuery=retry&limit=100`;
      const response = await submit(f.tenantId, failed.attemptId ?? "missing", returnHref);
      const location = new URL(response.headers.get("location") ?? "", "https://example.edu");
      expect(location.searchParams.get("returnTo")).toContain("notificationStatus=failed");
      expect(location.searchParams.get("returnTo")).toContain("recipientQuery=retry");
      const external = await submit(
        f.tenantId,
        failed.attemptId ?? "missing",
        "https://external.example",
      );
      expect(external.headers.get("location")).not.toContain("returnTo");
    } finally {
      await cleanupTestResources(f.db, { tenantIds: [f.tenantId], userIds: [f.userId] });
    }
  });
});

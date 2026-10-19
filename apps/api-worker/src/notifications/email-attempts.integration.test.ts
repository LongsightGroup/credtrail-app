import { processBadgeRuleApprovalNotificationJob } from "../badges/badge-rule-approval-notification-queue";
import { createBetterAuthSessionForCredtrailUser } from "../auth/better-auth-runtime";
import { createBetterAuthRuntimeConfig } from "../auth/better-auth-config";
import { afterEach, expect, it } from "vitest";
import { Hono } from "hono";
import {
  upsertTenantAuthPolicy,
  upsertTenantBreakGlassAccount,
  upsertTenantMembershipRole,
  upsertUserByEmail,
  type SqlDatabase,
} from "@credtrail/db";
import { createFixtureRule } from "../../../../packages/db/src/badge-issuance-rule-test-fixtures";
import {
  cleanupTestResources,
  createBadgeRuleIntegrationFixture,
  createTestPostgresDatabase,
  describeDbIntegration,
  requireTestDatabaseUrl,
} from "../../../../packages/db/src/postgres-test-support";
import { createSmtpTestServer, type SmtpTestServer } from "../test-support/smtp-test-server";
import { createNodeEmail } from "../runtime/node-email";
import { processBadgeRuleLifecycleForTenant } from "../badges/badge-rule-lifecycle-processor";
import {
  betterAuthProvider,
  breakGlassPolicyAdapter,
  requestTenantMemberInvite,
} from "../app/auth-runtime";
import type { AppBindings, AppEnv } from "../app/types";
import { emailTracking } from "./email-attempt-store";
import { sendTransactionalEmail } from "./transactional-email";

const tenantIds: string[] = [];
const userIds: string[] = [];
const authUserIds: string[] = [];
const relays: SmtpTestServer[] = [];
afterEach(async () => {
  for (const relay of relays.splice(0)) await relay.close();
  await cleanupTestResources(createTestPostgresDatabase(), {
    tenantIds,
    userIds,
    betterAuthUserIds: authUserIds,
  });
  tenantIds.length = 0;
  userIds.length = 0;
  authUserIds.length = 0;
});
const fixture = async (): ReturnType<typeof createBadgeRuleIntegrationFixture> => {
  const f = await createBadgeRuleIntegrationFixture();
  tenantIds.push(f.tenantId);
  userIds.push(f.userId);
  return f;
};
const relayFor = async (
  options: Parameters<typeof createSmtpTestServer>[0] = {},
): Promise<SmtpTestServer> => {
  const relay = await createSmtpTestServer(options);
  relays.push(relay);
  return relay;
};
const message = {
  kind: "issuance" as const,
  recipientEmail: "learner@example.edu",
  subject: "Your badge",
  content: {
    institution: "Example University",
    title: "Your badge",
    paragraphs: ["An achievement."],
    footer: "Contact your issuer.",
    action: { label: "View", url: "https://credtrail.org/badges/example" },
  },
  category: "Issuance Notification",
};
const attempts = async (db: SqlDatabase, tenantId: string): Promise<unknown[]> => {
  const rows = await db
    .prepare("SELECT * FROM email_attempts WHERE tenant_id = ? ORDER BY created_at, id")
    .bind(tenantId)
    .all<unknown>();
  return rows.results;
};
const bindings = (email: SendEmail | undefined): AppBindings => ({
  APP_ENV: "production",
  RUNTIME: "node",
  DATABASE_URL: requireTestDatabaseUrl(),
  BETTER_AUTH_SECRET: "disposable-test-secret-with-at-least-32-characters",
  PLATFORM_DOMAIN: "badges.example.edu",
  PUBLIC_APP_ORIGIN: "https://badges.example.edu",
  BADGE_OBJECTS: {
    head: async () => null,
    get: async () => null,
    put: async () => null,
    delete: async () => undefined,
  },
  ...(email === undefined ? {} : { EMAIL: email }),
});

describeDbIntegration("durable email attempts", () => {
  it("records missing-provider skips and definitive rejection, then deduplicates successful recovery", async () => {
    const f = await fixture();
    const tracking = emailTracking(f.db, f.tenantId, "award", "recovery");
    expect(await sendTransactionalEmail({ ...message, tracking })).toMatchObject({
      status: "skipped",
      reason: "not_configured",
    });
    const rejecting = await relayFor({ rejectRecipients: [message.recipientEmail] });
    expect(
      await sendTransactionalEmail({
        ...message,
        tracking,
        emailBinding: createNodeEmail(rejecting.env).binding,
      }),
    ).toMatchObject({ status: "failed", reason: "provider_rejected" });
    const relay = await relayFor();
    const input = { ...message, tracking, emailBinding: createNodeEmail(relay.env).binding };
    const results = await Promise.all([
      sendTransactionalEmail(input),
      sendTransactionalEmail(input),
    ]);
    expect(results.filter((result) => result.status === "accepted")).toHaveLength(1);
    expect(await sendTransactionalEmail(input)).toMatchObject({ status: "accepted" });
    expect(relay.messages).toHaveLength(1);
    expect(await attempts(f.db, f.tenantId)).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ status: "skipped", reason: "not_configured" }),
        expect.objectContaining({ status: "failed", reason: "provider_rejected" }),
        expect.objectContaining({
          status: "accepted",
          reason: null,
          provider_message_id: expect.any(String),
        }),
      ]),
    );
    expect(await attempts(f.db, "other-tenant")).toHaveLength(0);
  });

  it("persists the pending claim while SMTP is in flight and preserves unknown acceptance after disconnect", async () => {
    const f = await fixture();
    const relay = await relayFor({ disconnectAfterData: true });
    const smtp = createNodeEmail(relay.env).binding;
    if (smtp === undefined) throw new Error("SMTP missing");
    const tracking = emailTracking(f.db, f.tenantId, "award", "uncertain");
    const emailBinding: SendEmail = {
      send: async (input) => {
        expect(await attempts(f.db, f.tenantId)).toEqual([
          expect.objectContaining({ status: "pending", completed_at: null }),
        ]);
        if (!("subject" in input)) throw new Error("Expected structured email");
        return smtp.send(input);
      },
    };
    const input = { ...message, tracking, emailBinding };
    expect(await sendTransactionalEmail(input)).toMatchObject({
      status: "pending",
      reason: "provider_uncertain",
    });
    expect(relay.messages).toHaveLength(1);
    expect(await sendTransactionalEmail(input)).toMatchObject({ status: "pending" });
    expect(relay.messages).toHaveLength(1);
    expect(await attempts(f.db, f.tenantId)).toEqual([
      expect.objectContaining({ status: "pending", completed_at: null }),
    ]);
  });

  it("does not send without a durable claim or report success when saving acceptance fails", async () => {
    const f = await fixture();
    const relay = await relayFor();
    const tracking = emailTracking(f.db, f.tenantId, "award", "storage-outage");
    const emailBinding = createNodeEmail(relay.env).binding;
    const blocked = {
      ...tracking,
      store: {
        ...tracking.store,
        begin: async (): Promise<never> => {
          throw new Error("Database unavailable");
        },
      },
    };
    expect(
      await sendTransactionalEmail({ ...message, emailBinding, tracking: blocked }),
    ).toMatchObject({ status: "tracking_failed", attemptId: null });
    expect(relay.messages).toHaveLength(0);
    const interrupted = {
      ...tracking,
      store: {
        ...tracking.store,
        complete: async (): Promise<never> => {
          throw new Error("Database unavailable");
        },
      },
    };
    expect(
      await sendTransactionalEmail({ ...message, emailBinding, tracking: interrupted }),
    ).toMatchObject({ status: "tracking_failed", attemptId: expect.any(String) });
    expect(relay.messages).toHaveLength(1);
    expect(await attempts(f.db, f.tenantId)).toEqual([
      expect.objectContaining({ status: "pending", completed_at: null }),
    ]);
    expect(await sendTransactionalEmail({ ...message, emailBinding, tracking })).toMatchObject({
      status: "pending",
    });
    expect(relay.messages).toHaveLength(1);
  });

  it("tracks authentication skips without reporting sent or persisting sign-in secrets", async () => {
    const f = await fixture();
    const user = await f.db
      .prepare("SELECT email FROM users WHERE id = ?")
      .bind(f.userId)
      .first<{ email: string }>();
    if (user === null) throw new Error("Fixture user missing");
    const app = new Hono<AppEnv>();
    app.post("/attempt", async (c) =>
      c.json(
        await betterAuthProvider.requestMagicLink(c, { tenantId: f.tenantId, email: user.email }),
      ),
    );
    app.post("/invite", async (c) =>
      c.json(
        await requestTenantMemberInvite(c, {
          tenantId: f.tenantId,
          email: user.email,
          role: "admin",
        }),
      ),
    );
    for (const path of ["/attempt", "/invite"]) {
      const response = await app.request(path, { method: "POST" }, bindings(undefined));
      expect(response.status).toBe(200);
      expect(await response.json()).toMatchObject({ deliveryStatus: "skipped" });
    }
    const recorded = await attempts(f.db, f.tenantId);
    expect(recorded).toHaveLength(2);
    expect(recorded).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ status: "skipped", reason: "not_configured" }),
      ]),
    );
    expect(JSON.stringify(recorded)).not.toMatch(/token=|magicLink|disposable-test-secret/u);
    const authUser = await f.db
      .prepare("SELECT id FROM auth.user WHERE email = ?")
      .bind(user.email)
      .first<{ id: string }>();
    if (authUser !== null) authUserIds.push(authUser.id);
  });

  it("keeps partial lifecycle reminders incomplete and recovers only rejected recipients", async () => {
    const f = await fixture();
    const extra = await upsertUserByEmail(f.db, `reminder-${crypto.randomUUID()}@example.edu`);
    userIds.push(extra.id);
    await upsertTenantMembershipRole(f.db, {
      tenantId: f.tenantId,
      userId: extra.id,
      role: "admin",
    });
    const rule = await createFixtureRule(f);
    await f.db
      .prepare(
        "UPDATE badge_issuance_rule_versions SET status = 'active', expires_at = ? WHERE id = ?",
      )
      .bind("2026-10-07T12:00:00Z", rule.version.id)
      .run();
    const rejecting = await relayFor({ rejectRecipients: [extra.email] });
    const input = {
      db: f.db,
      tenantId: f.tenantId,
      nowIso: "2026-10-05T12:00:00Z",
      observability: { service: "api-worker", environment: "test" },
      env: bindings(createNodeEmail(rejecting.env).binding),
      adminUrlForTenant: () => "https://badges.example.edu/admin/rules",
    };
    expect((await processBadgeRuleLifecycleForTenant(input)).expiryRemindersSent).toBe(0);
    const state = await f.db
      .prepare("SELECT expiry_reminder_sent_at FROM badge_issuance_rule_versions WHERE id = ?")
      .bind(rule.version.id)
      .first<{ expiry_reminder_sent_at: string | null }>();
    expect(state?.expiry_reminder_sent_at).toBeNull();
    expect(rejecting.messages).toHaveLength(1);
    const healthy = await relayFor();
    const recovery = { ...input, env: bindings(createNodeEmail(healthy.env).binding) };
    expect((await processBadgeRuleLifecycleForTenant(recovery)).expiryRemindersSent).toBe(1);
    expect(healthy.messages).toHaveLength(1);
    expect(healthy.messages[0]?.recipients).toEqual([extra.email]);
    expect((await processBadgeRuleLifecycleForTenant(recovery)).expiryRemindersSent).toBe(0);
    expect(healthy.messages).toHaveLength(1);
  });
  it("requires provider acceptance before completing approval email jobs, and replays without duplicates", async () => {
    const f = await fixture();
    const rule = await createFixtureRule(f);
    const payload = {
      notificationType: "approval_decision" as const,
      ruleId: rule.rule.id,
      versionId: rule.version.id,
      decision: "approved" as const,
      comment: null,
      nextStepNumber: null,
    };
    const input = { db: f.db, tenantId: f.tenantId, payload, env: bindings(undefined) };
    await f.db.prepare("UPDATE tenants SET display_name = ' ' WHERE id = ?").bind(f.tenantId).run();
    await expect(processBadgeRuleApprovalNotificationJob(input)).rejects.toThrow(
      "without confirmed provider acceptance",
    );
    expect(await attempts(f.db, f.tenantId)).toHaveLength(0);
    await f.db
      .prepare("UPDATE tenants SET display_name = 'Example University' WHERE id = ?")
      .bind(f.tenantId)
      .run();
    await expect(processBadgeRuleApprovalNotificationJob(input)).rejects.toThrow(
      "without confirmed provider acceptance",
    );
    expect(await attempts(f.db, f.tenantId)).toEqual([
      expect.objectContaining({ status: "skipped" }),
    ]);
    const relay = await relayFor();
    const recovery = { ...input, env: bindings(createNodeEmail(relay.env).binding) };
    await processBadgeRuleApprovalNotificationJob(recovery);
    await processBadgeRuleApprovalNotificationJob(recovery);
    expect(relay.messages).toHaveLength(1);
    expect(await attempts(f.db, f.tenantId)).toEqual(
      expect.arrayContaining([expect.objectContaining({ status: "accepted" })]),
    );
  });

  it("reports SSO invitations accepted only after the relay accepts them, and records unavailable email as skipped", async () => {
    const f = await fixture();
    await f.db
      .prepare("UPDATE tenants SET plan_tier = 'enterprise' WHERE id = ?")
      .bind(f.tenantId)
      .run();
    await upsertTenantAuthPolicy(f.db, { tenantId: f.tenantId, loginMode: "sso_required" });
    const app = new Hono<AppEnv>();
    app.post("/invite", async (c) =>
      c.json(
        await requestTenantMemberInvite(c, {
          tenantId: f.tenantId,
          email: message.recipientEmail,
          role: "admin",
        }),
      ),
    );
    const skipped = await app.request("/invite", { method: "POST" }, bindings(undefined));
    expect(await skipped.json()).toMatchObject({
      deliveryStatus: "skipped",
      inviteKind: "sso_notice",
    });
    const relay = await relayFor();
    const accepted = await app.request(
      "/invite",
      { method: "POST" },
      bindings(createNodeEmail(relay.env).binding),
    );
    expect(await accepted.json()).toMatchObject({
      deliveryStatus: "sent",
      inviteKind: "sso_notice",
    });
    expect(relay.messages).toHaveLength(1);
    expect(relay.messages[0]?.mail.text).toContain(
      `https://badges.example.edu/login?tenantId=${f.tenantId}`,
    );
    expect(await attempts(f.db, f.tenantId)).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ kind: "member_invite", status: "skipped" }),
        expect.objectContaining({ kind: "member_invite", status: "accepted" }),
      ]),
    );
  });

  it("only marks password-reset enrollment sent after an actual accepted reset email", async () => {
    const f = await fixture();
    const user = await f.db
      .prepare("SELECT email FROM users WHERE id = ?")
      .bind(f.userId)
      .first<{ email: string }>();
    if (user === null) throw new Error("Fixture user missing");
    await f.db
      .prepare("UPDATE tenants SET plan_tier = 'enterprise' WHERE id = ?")
      .bind(f.tenantId)
      .run();
    await upsertTenantAuthPolicy(f.db, {
      tenantId: f.tenantId,
      loginMode: "hybrid",
      breakGlassEnabled: true,
      localMfaRequired: true,
    });
    await upsertTenantBreakGlassAccount(f.db, { tenantId: f.tenantId, userId: f.userId });
    const env = bindings(undefined);
    const session = await createBetterAuthSessionForCredtrailUser({
      db: f.db,
      runtimeConfig: createBetterAuthRuntimeConfig(env),
      credtrailUserId: f.userId,
    });
    authUserIds.push(session.session.userId);
    const app = new Hono<AppEnv>();
    app.post("/reset", async (c) =>
      c.json({
        status: await breakGlassPolicyAdapter.requestPasswordReset(c, {
          tenantId: f.tenantId,
          email: user.email,
          nextPath: "/auth/resolve",
        }),
      }),
    );
    const checkEnrollment = async (): Promise<string | null | undefined> =>
      (
        await f.db
          .prepare(
            "SELECT last_enrollment_email_sent_at AS sent FROM tenant_break_glass_accounts WHERE tenant_id = ? AND user_id = ?",
          )
          .bind(f.tenantId, f.userId)
          .first<{ sent: string | null }>()
      )?.sent;
    expect(
      await (await app.request("https://badges.example.edu/reset", { method: "POST" }, env)).json(),
    ).toEqual({ status: "unavailable" });
    expect(await checkEnrollment()).toBeNull();
    const relay = await relayFor();
    const accepted = await app.request(
      "https://badges.example.edu/reset",
      { method: "POST" },
      bindings(createNodeEmail(relay.env).binding),
    );
    expect(await accepted.json()).toEqual({ status: "sent" });
    expect(await checkEnrollment()).toEqual(expect.any(String));
    expect(relay.messages).toHaveLength(1);
    const recorded = await attempts(f.db, f.tenantId);
    expect(recorded).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ kind: "password_reset", status: "skipped" }),
        expect.objectContaining({ kind: "password_reset", status: "accepted" }),
      ]),
    );
    expect(JSON.stringify(recorded)).not.toContain("token=");
  });
});

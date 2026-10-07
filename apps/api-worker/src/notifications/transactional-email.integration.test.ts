import { createFixtureRule } from "../../../../packages/db/src/badge-issuance-rule-test-fixtures";
import { processBadgeRuleLifecycleForTenant } from "../badges/badge-rule-lifecycle-processor";
import { createRecordingEmailBinding } from "../test-support/recording-email";
import { afterEach, expect, it } from "vitest";
import {
  cleanupTestResources,
  createBadgeRuleIntegrationFixture,
  createTestPostgresDatabase,
  describeDbIntegration,
} from "../../../../packages/db/src/postgres-test-support";
import { createSmtpTestServer, type SmtpTestServer } from "../test-support/smtp-test-server";
import { createNodeEmail } from "../runtime/node-email";
import { sendMagicLinkEmailNotification } from "./send-magic-link-email";
import { sendPasswordResetEmailNotification } from "./send-password-reset-email";
import { sendMemberInviteEmailNotification } from "./send-member-invite-email";
import { sendIssuanceEmailNotification } from "./send-issuance-email";
import {
  sendBadgeRuleApprovalSubmittedEmail,
  sendBadgeRuleApprovalDecisionEmail,
} from "./send-badge-rule-approval-email";
import { sendBadgeRuleLifecycleReminderNotifications } from "./send-badge-rule-lifecycle-email";

const tenantIds: string[] = [];
const userIds: string[] = [];
let relay: SmtpTestServer | undefined;
afterEach(async () => {
  await relay?.close();
  relay = undefined;
  if (tenantIds.length)
    await cleanupTestResources(createTestPostgresDatabase(), { tenantIds, userIds });
  tenantIds.length = 0;
  userIds.length = 0;
});

describeDbIntegration("shared transactional email delivery", () => {
  it("delivers every notification builder as HTML plus text through TLS SMTP", async () => {
    const fixture = await createBadgeRuleIntegrationFixture();
    tenantIds.push(fixture.tenantId);
    userIds.push(fixture.userId);
    relay = await createSmtpTestServer();
    const emailBinding = createNodeEmail(relay.env).binding;
    const common = {
      emailBinding,
      tenantDisplayName: "Example University",
      recipientEmail: "learner@example.edu",
    };
    const url = "https://badges.example.edu/access?token=disposable-private-token";
    await sendMagicLinkEmailNotification({
      ...common,
      magicLinkUrl: url,
      expiresAtIso: "2026-10-05T12:00:00Z",
    });
    await sendPasswordResetEmailNotification({ ...common, resetUrl: url });
    await sendMemberInviteEmailNotification({ ...common, role: "issuer", signInUrl: url });
    const approval = {
      ...common,
      tenantId: fixture.tenantId,
      ruleName: "Graduation",
      versionNumber: 1,
      reviewUrl: "https://badges.example.edu/review",
    };
    await sendBadgeRuleApprovalSubmittedEmail({ ...approval, stepLabel: "Registrar review" });
    await sendBadgeRuleApprovalDecisionEmail({
      ...approval,
      decisionLabel: "Approved",
      comment: '<script>alert("unsafe")</script>',
    });
    await sendBadgeRuleLifecycleReminderNotifications(fixture.db, {
      ...approval,
      tenantId: fixture.tenantId,
      dueAt: "2026-10-06",
      reminderType: "expiry",
      adminUrl: approval.reviewUrl,
    });
    await sendIssuanceEmailNotification({
      ...common,
      badgeTitle: "Graduation",
      badgeDescription: "Completed the community program.",
      badgeImageUrl: "https://badges.example.edu/artwork/graduation.png",
      issuedAtIso: "2026-10-05",
      publicBadgeUrl: "https://badges.example.edu/badges/123",

      credentialDownloadUrl: "https://badges.example.edu/badges/123/download",
    });
    expect(relay.messages).toHaveLength(7);
    for (const message of relay.messages) {
      expect(message.secure).toBe(true);
      expect(message.mail.text).toContain("Example University");
      expect(message.mail.html).toContain("Example University");
      expect(message.mail.html).toContain("<!DOCTYPE html>");
      expect(message.mail.html).not.toContain("<script>");
      expect(message.mail.replyTo?.value[0]?.address).toBe("support@example.edu");
      expect(message.mail.headers.has("bcc")).toBe(false);
    }
    for (const message of relay.messages.filter(
      (message) => message.mail.headers.get("x-credtrail-email-kind") !== "issuance",
    )) {
      expect(message.recipients).not.toContain("records@example.edu");
    }
    expect(relay.messages.at(-1)?.recipients).toContain("records@example.edu");
    expect(relay.messages.at(-1)?.mail.html).not.toContain("disposable-private-token");
    expect(relay.messages.at(-1)?.mail.html).toContain(
      'src="https://badges.example.edu/artwork/graduation.png"',
    );
    expect(relay.messages.at(-1)?.mail.text).toContain(
      "https://badges.example.edu/badges/123/download.pdf",
    );
    expect(relay.messages[0]?.mail.html).toContain(url);
    expect(relay.messages[0]?.mail.text).toContain(url);
  });
  it("keeps lifecycle reminders pending until the institution has a display name", async () => {
    const fixture = await createBadgeRuleIntegrationFixture();
    tenantIds.push(fixture.tenantId);
    userIds.push(fixture.userId);
    const created = await createFixtureRule(fixture);
    await fixture.db
      .prepare(
        "UPDATE badge_issuance_rule_versions SET status = 'active', expires_at = ? WHERE id = ?",
      )
      .bind("2026-10-07T12:00:00Z", created.version.id)
      .run();
    await fixture.db
      .prepare("UPDATE tenants SET display_name = ? WHERE id = ?")
      .bind(" ", fixture.tenantId)
      .run();
    const { emailBinding, messages } = createRecordingEmailBinding();
    const input = {
      db: fixture.db,
      tenantId: fixture.tenantId,
      nowIso: "2026-10-05T12:00:00Z",
      observability: { service: "api-worker", environment: "test" },
      env: {
        APP_ENV: "test",
        PLATFORM_DOMAIN: "badges.example.edu",
        PUBLIC_APP_ORIGIN: "https://badges.example.edu",
        EMAIL: emailBinding,
        BADGE_OBJECTS: {
          head: async () => null,
          get: async () => null,
          put: async () => null,
          delete: async () => undefined,
        },
      },
      adminUrlForTenant: () => "https://badges.example.edu/admin/rules",
    };
    expect((await processBadgeRuleLifecycleForTenant(input)).expiryRemindersSent).toBe(0);
    expect(messages).toHaveLength(0);
    await fixture.db
      .prepare("UPDATE tenants SET display_name = ? WHERE id = ?")
      .bind("Example University", fixture.tenantId)
      .run();
    expect((await processBadgeRuleLifecycleForTenant(input)).expiryRemindersSent).toBe(1);
    expect(messages).toHaveLength(1);
    expect(messages[0]?.html).toContain("Example University");
    expect(messages[0]?.text).not.toContain(fixture.tenantId);
  });
});

import { SendEmailCommand } from "@aws-sdk/client-sesv2";
import { expect, it } from "vitest";
import { createConfiguredEmailBinding } from "./configured-email-binding";
import { createSesEmailBinding } from "./ses-email";
import { sendMagicLinkEmailNotification } from "./send-magic-link-email";
import { sendPasswordResetEmailNotification } from "./send-password-reset-email";
import { sendMemberInviteEmailNotification } from "./send-member-invite-email";
import { sendBadgeRuleApprovalSubmittedEmail } from "./send-badge-rule-approval-email";
import { sendIssuanceEmailNotification } from "./send-issuance-email";

it("applies the same reply and copy policy to real notification builders through SES", async () => {
  const commands: SendEmailCommand[] = [];
  const emailBinding = createConfiguredEmailBinding(
    createSesEmailBinding(
      { region: "us-east-1" },
      {
        send: async (command) => {
          commands.push(command);
          return { MessageId: "accepted-by-recording-client", $metadata: {} };
        },
      },
    ),
    {
      fromAddress: "badges@example.edu",
      fromName: "Example",
      replyTo: "support@example.edu",
      issuanceBcc: ["records@example.edu"],
    },
  );
  const common = {
    emailBinding,
    recipientEmail: "learner@example.edu",
    tenantDisplayName: "Example",
  };
  const accessLink = "https://badges.example.edu/access?token=private-disposable-token";
  await sendMagicLinkEmailNotification({
    ...common,
    magicLinkUrl: accessLink,
    expiresAtIso: "2026-10-04T12:00:00Z",
  });
  await sendPasswordResetEmailNotification({ ...common, resetUrl: accessLink });
  await sendMemberInviteEmailNotification({
    ...common,
    tenantDisplayName: "Example",
    role: "issuer",
    signInUrl: accessLink,
  });
  await sendBadgeRuleApprovalSubmittedEmail({
    ...common,
    tenantId: "example",
    ruleName: "Completion",
    versionNumber: 1,
    reviewUrl: accessLink,
    stepLabel: "Review",
  });
  await sendIssuanceEmailNotification({
    ...common,
    badgeTitle: "Completion",
    issuedAtIso: "2026-10-04T12:00:00Z",
    publicBadgeUrl: "https://badges.example.edu/badge",

    credentialDownloadUrl: "https://badges.example.edu/credential",
  });
  expect(commands).toHaveLength(5);
  expect(
    commands.every((command) =>
      command.input.Content?.Simple?.Body?.Html?.Data?.startsWith("<!DOCTYPE html>"),
    ),
  ).toBe(true);
  expect(commands.map((command) => command.input.ReplyToAddresses)).toEqual(
    Array.from({ length: 5 }, () => ["support@example.edu"]),
  );
  expect(commands.map((command) => command.input.Destination?.BccAddresses)).toEqual([
    undefined,
    undefined,
    undefined,
    undefined,
    ["records@example.edu"],
  ]);
  expect(
    commands
      .slice(0, 4)
      .every((command) => command.input.Content?.Simple?.Body?.Text?.Data?.includes(accessLink)),
  ).toBe(true);
  expect(commands.at(-1)?.input.Content?.Simple?.Body?.Text?.Data).not.toContain(
    "private-disposable-token",
  );
});

import { SendEmailCommand, type SendEmailCommandOutput } from "@aws-sdk/client-sesv2";
import { describe, expect, it, vi } from "vitest";

import { buildSesSendEmailInput, createSesEmailBinding } from "./ses-email";

describe("buildSesSendEmailInput", () => {
  it("maps SendEmail builder messages to SES v2 simple email input", () => {
    const input = buildSesSendEmailInput(
      {
        from: {
          email: "no-reply@example.edu",
          name: "CredTrail",
        },
        to: ["learner@example.edu"],
        cc: "registrar@example.edu",
        subject: "Sign in",
        text: "Use this link.",
        headers: {
          "X-CredTrail-Email-Category": "Auth Magic Link",
        },
      },
      {
        configurationSetName: "credtrail-transactional",
      },
    );

    expect(input).toEqual({
      FromEmailAddress: '"CredTrail" <no-reply@example.edu>',
      Destination: {
        ToAddresses: ["learner@example.edu"],
        CcAddresses: ["registrar@example.edu"],
        BccAddresses: undefined,
      },
      ReplyToAddresses: undefined,
      ConfigurationSetName: "credtrail-transactional",
      Content: {
        Simple: {
          Subject: {
            Charset: "UTF-8",
            Data: "Sign in",
          },
          Body: {
            Text: {
              Charset: "UTF-8",
              Data: "Use this link.",
            },
          },
          Headers: [
            {
              Name: "X-CredTrail-Email-Category",
              Value: "Auth Magic Link",
            },
          ],
        },
      },
    });
  });
});

describe("createSesEmailBinding", () => {
  it("sends builder messages through SES", async () => {
    const send = vi.fn<(command: SendEmailCommand) => Promise<SendEmailCommandOutput>>(async () => {
      return { MessageId: "ses-message-123", $metadata: {} };
    });
    const emailBinding = createSesEmailBinding(
      {
        region: "us-east-1",
      },
      {
        send,
      },
    );

    const result = await emailBinding.send({
      from: "no-reply@example.edu",
      to: "learner@example.edu",
      subject: "Hello",
      text: "Body",
    });
    const command = send.mock.calls[0]?.[0];

    expect(result.messageId).toBe("ses-message-123");
    expect(command).toBeInstanceOf(SendEmailCommand);
    expect(command?.input.FromEmailAddress).toBe("no-reply@example.edu");
  });
});

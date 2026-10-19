import { createMemoryEmailTracking } from "../test-support/email-attempts";
import { afterEach, describe, expect, it } from "vitest";
import { createNodeEmail } from "../runtime/node-email";
import { createSmtpTestServer, type SmtpTestServer } from "../test-support/smtp-test-server";
import { checkNodeEmail } from "../runtime/node-email-check";
import { sendTransactionalEmail } from "./transactional-email";

const relays: SmtpTestServer[] = [];
afterEach(async () => {
  for (const relay of relays.splice(0)) await relay.close();
});
const start = async (
  options: Parameters<typeof createSmtpTestServer>[0] = {},
): Promise<SmtpTestServer> => {
  const relay = await createSmtpTestServer(options);
  relays.push(relay);
  return relay;
};
const input = {
  from: "badges@example.edu",
  to: "learner@example.edu",
  subject: "Congratulations – 学習",
  text: "Badge link: https://badges.example.edu/example",
  html: "<p>Congratulations – 学習</p>",
};

describe("SMTP wire delivery", () => {
  it.each(["starttls", "tls"] as const)(
    "verifies without delivery, then sends MIME over %s",
    async (security) => {
      const relay = await start({ security });
      expect((await checkNodeEmail(relay.env, [])).exitCode).toBe(0);
      expect(relay.messages).toHaveLength(0);
      const email = createNodeEmail(relay.env);
      const accepted = await email.binding?.send({
        ...input,
        headers: { "X-CredTrail-Email-Kind": "issuance" },
      });
      expect(accepted?.messageId).toBeTruthy();
      const capture = relay.messages[0];
      expect(capture?.secure).toBe(true);
      expect(capture?.recipients).toEqual(["learner@example.edu", "records@example.edu"]);
      expect(capture?.mail.subject).toBe(input.subject);
      expect(capture?.mail.text).toContain(input.text);
      expect(capture?.mail.html).toContain("学習");
      expect(capture?.mail.replyTo).toMatchObject({ value: [{ address: "support@example.edu" }] });
      expect(capture?.mail.headers.has("bcc")).toBe(false);
    },
  );
  it.each([
    { rejectAuth: true },
    { noStarttls: true },
    { rejectSender: true },
    { rejectRecipients: ["learner@example.edu"] },
  ])("fails safely without delivering or leaking access links: %j", async (options) => {
    const relay = await start(options);
    const email = createNodeEmail(relay.env);
    await expect(email.binding?.send({ ...input, text: "secret-access-token" })).rejects.toThrow(
      /SMTP/u,
    );
    expect(relay.messages).toHaveLength(0);
    const output = await checkNodeEmail(relay.env, ["--to", "learner@example.edu"]);
    expect(output.exitCode).toBe(1);
    expect(output.message).not.toContain(" secret ");
    expect(output.message).not.toContain("secret-access-token");
  });
  it.each([
    { rejectionCode: 451 as const, copy: false, temporary: true },
    { rejectionCode: 451 as const, copy: true, temporary: true },
    { rejectionCode: 550 as const, copy: true, temporary: false },
  ])(
    "distinguishes temporary SMTP rejection from uncertain acceptance: %j",
    async ({ rejectionCode, copy, temporary }) => {
      const relay = await start({ rejectRecipients: ["learner@example.edu"], rejectionCode });
      const tracking = createMemoryEmailTracking();
      const result = await sendTransactionalEmail({
        tracking,
        emailBinding: createNodeEmail(relay.env).binding,
        kind: copy ? "issuance" : "member_invite",
        recipientEmail: "learner@example.edu",
        subject: "Your badge",
        category: "test",
        content: {
          institution: "University",
          title: "Your badge",
          paragraphs: ["Your badge is ready."],
          action: { label: "View", url: "https://credtrail.org/badges/test" },
          footer: "Contact your issuer.",
        },
      });
      expect(result).toMatchObject({ status: "failed", reason: "provider_rejected" });
      expect(result.status === "failed" && result.providerBusy === true).toBe(temporary);
      expect(tracking.attempts).toHaveLength(1);
      expect(tracking.attempts[0]?.outcome.status).toBe("failed");
      expect(relay.messages).toHaveLength(copy ? 1 : 0);
      expect(relay.messages.map((message) => message.recipients)).toEqual(
        copy ? [["records@example.edu"]] : [],
      );
    },
  );
  it("rejects untrusted and mismatched certificates", async () => {
    const relay = await start();
    expect((await checkNodeEmail({ ...relay.env, SMTP_TLS_CA_FILE: undefined }, [])).exitCode).toBe(
      1,
    );
    const mismatched = await start({ mismatchedCertificate: true });
    expect((await checkNodeEmail(mismatched.env, [])).exitCode).toBe(1);
    expect(mismatched.messages).toHaveLength(0);
    expect(relay.messages).toHaveLength(0);
  });
  it("accepts the learner even if the optional copy recipient rejects", async () => {
    const relay = await start({ rejectRecipients: ["records@example.edu"] });
    const email = createNodeEmail(relay.env);
    await expect(
      email.binding?.send({ ...input, headers: { "X-CredTrail-Email-Kind": "issuance" } }),
    ).resolves.toHaveProperty("messageId");
    expect(relay.messages[0]?.recipients).toEqual(["learner@example.edu"]);
  });
  it("does not resend after an uncertain disconnect following DATA", async () => {
    const relay = await start({ disconnectAfterData: true });
    const email = createNodeEmail(relay.env);
    await expect(email.binding?.send(input)).rejects.toThrow(/SMTP/u);
    expect(relay.messages).toHaveLength(1);
  });
  it("copies only issuance across every application message kind", async () => {
    const relay = await start({ auth: "none" });
    const email = createNodeEmail(relay.env);
    for (const kind of [
      "magic_link",
      "password_reset",
      "member_invite",
      "rule_approval",
      "rule_lifecycle",
      "issuance",
    ] as const) {
      await sendTransactionalEmail({
        tracking: createMemoryEmailTracking(),
        kind,
        emailBinding: email.binding,
        recipientEmail: "learner@example.edu",
        subject: kind,
        content: {
          institution: "Example University",
          title: kind,
          paragraphs: ["access-link-for-sensitive-messages"],
          details: [],
          action: {
            label: "Continue",
            url: "https://badges.example.edu/access?token=private-disposable-token",
          },
          secondaryActions: [],
          footer: "Keep this link private.",
        },
        category: "test",
      });
    }
    expect(
      relay.messages.every(
        (message) =>
          message.mail.text?.includes("Example University") &&
          typeof message.mail.html === "string" &&
          message.mail.html.includes("Example University"),
      ),
    ).toBe(true);
    expect(relay.messages.map((message) => message.recipients)).toEqual([
      ...Array.from({ length: 5 }, () => ["learner@example.edu"]),
      ["learner@example.edu", "records@example.edu"],
    ]);
    expect((await checkNodeEmail(relay.env, ["--to", "operator@example.edu"])).exitCode).toBe(0);
    expect(relay.messages.at(-1)?.recipients).toEqual(["operator@example.edu"]);
    expect((await checkNodeEmail(relay.env, ["--to", "invalid"])).exitCode).toBe(1);
    expect((await checkNodeEmail({}, [])).exitCode).toBe(1);
  });
  it("bounds a stalled greeting without sending or leaking credentials", async () => {
    const relay = await start({ stallGreeting: true });
    const output = await checkNodeEmail(relay.env, []);
    expect(output.exitCode).toBe(1);
    expect(output.message).toContain("timed out");
    expect(output.message).not.toContain(" secret ");
    expect(relay.messages).toHaveLength(0);
  }, 15_000);
  it("strips caller copies for missing and unknown kinds", async () => {
    const relay = await start();
    const email = createNodeEmail(relay.env);
    await email.binding?.send({ ...input, bcc: "victim@example.edu" });
    await email.binding?.send({
      ...input,
      bcc: "victim@example.edu",
      headers: { "X-CredTrail-Email-Kind": "unknown" },
    });
    expect(relay.messages.map((message) => message.recipients)).toEqual([
      ["learner@example.edu"],
      ["learner@example.edu"],
    ]);
  });
  it("rejects raw messages, attachments, and multiple primary recipients", async () => {
    const relay = await start();
    const email = createNodeEmail(relay.env);
    await expect(email.binding?.send({ from: input.from, to: input.to })).rejects.toThrow(
      "builder",
    );
    await expect(
      email.binding?.send({
        ...input,
        attachments: [
          { disposition: "attachment", filename: "file.txt", type: "text/plain", content: "file" },
        ],
      }),
    ).rejects.toThrow("invalid");
    await expect(
      email.binding?.send({ ...input, to: [input.to, "second@example.edu"] }),
    ).rejects.toThrow("invalid");
    expect(relay.messages).toHaveLength(0);
  });
  it("rejects header injection before delivery", async () => {
    const relay = await start();
    const email = createNodeEmail(relay.env);
    await expect(
      email.binding?.send({ ...input, subject: "safe\r\nBCC: victim@example.edu" }),
    ).rejects.toThrow("invalid");
    expect(relay.messages).toHaveLength(0);
  });
});

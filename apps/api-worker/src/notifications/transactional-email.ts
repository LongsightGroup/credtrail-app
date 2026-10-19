import type { TransactionalEmailContent } from "./transactional-email-content";
import { renderTransactionalEmail } from "./transactional-email-renderer";
import { z } from "zod";
import type { EmailAttemptCompletion, EmailKind, EmailTracking } from "./email-attempt-store";

/** Bound SMTP sockets and leave database-pool capacity for recording results. */
export const EMAIL_PROVIDER_CONCURRENCY = 4;

const DEFAULT_FROM_EMAIL = "no-reply@credtrail.org";
const DEFAULT_FROM_NAME = "CredTrail";

/** Explicit application message kinds used by the operator copy policy. */
export type TransactionalEmailKind = EmailKind;

export type TransactionalEmailResult =
  | ({ readonly attemptId: string } & EmailAttemptCompletion)
  | { readonly status: "tracking_failed"; readonly attemptId: string | null };

export interface SendTransactionalEmailInput {
  tracking: EmailTracking;
  skipReason?: "development" | undefined;
  kind: TransactionalEmailKind;
  emailBinding?: SendEmail | undefined;
  fromEmail?: string | undefined;
  fromName?: string | undefined;
  recipientEmail: string;
  subject: string;
  content: TransactionalEmailContent;
  category: string;
}

const rejectedSmtpError = z.object({
  name: z.literal("SmtpFailure"),
  kind: z.enum(["authentication", "tls", "rejected", "invalid_message"]),
});
const rejectedSesError = z.object({
  $metadata: z.object({ httpStatusCode: z.number().min(400).max(499) }),
});
const acceptanceSchema = z.object({ messageId: z.string().trim().min(1).max(2048) });

/** Commit before provider I/O; a missing completion remains pending and must not be blindly resent. */
export const sendTransactionalEmail = async (
  input: SendTransactionalEmailInput,
): Promise<TransactionalEmailResult> => {
  let attemptId: string;
  try {
    const claim = await input.tracking.store.begin({
      id: `email_${crypto.randomUUID()}`,
      tenantId: input.tracking.tenantId,
      targetId: input.tracking.targetId ?? null,
      kind: input.kind,
      recipientEmail: input.recipientEmail,
      deduplicationKey:
        input.tracking.deduplicationKey === undefined
          ? null
          : JSON.stringify([
              input.tracking.tenantId,
              input.kind,
              input.tracking.targetId ?? null,
              input.tracking.deduplicationKey,
              input.recipientEmail.trim().toLowerCase(),
            ]),
      createdAt: new Date().toISOString(),
    });
    attemptId = claim.attemptId;
    if (claim.status === "accepted")
      return { status: "accepted", attemptId, messageId: claim.messageId };
    if (claim.status === "pending")
      return { status: "pending", attemptId, reason: "provider_uncertain" };
  } catch {
    console.error(
      JSON.stringify({
        message: "email_attempt_tracking_failed",
        phase: "begin",
        kind: input.kind,
        tenantId: input.tracking.tenantId,
      }),
    );
    return { status: "tracking_failed", attemptId: null };
  }

  const complete = async (outcome: EmailAttemptCompletion): Promise<TransactionalEmailResult> => {
    try {
      await input.tracking.store.complete(attemptId, outcome, new Date().toISOString());
      if (outcome.status === "failed" || outcome.status === "pending") {
        console.warn(
          JSON.stringify({
            message: "email_attempt_not_accepted",
            kind: input.kind,
            tenantId: input.tracking.tenantId,
            attemptId,
            status: outcome.status,
            reason: outcome.reason,
          }),
        );
      }
      return { ...outcome, attemptId };
    } catch {
      console.error(
        JSON.stringify({
          message: "email_attempt_tracking_failed",
          phase: "complete",
          kind: input.kind,
          tenantId: input.tracking.tenantId,
          attemptId,
        }),
      );
      return { status: "tracking_failed", attemptId };
    }
  };
  if (input.skipReason !== undefined || input.emailBinding === undefined) {
    return complete({ status: "skipped", reason: input.skipReason ?? "not_configured" });
  }
  let rendered: Awaited<ReturnType<typeof renderTransactionalEmail>>;
  try {
    rendered = await renderTransactionalEmail(input.content);
  } catch {
    return complete({ status: "failed", reason: "render_failed" });
  }
  try {
    const result = acceptanceSchema.safeParse(
      await input.emailBinding.send({
        from: {
          email: input.fromEmail?.trim() || DEFAULT_FROM_EMAIL,
          name: input.fromName?.trim() || DEFAULT_FROM_NAME,
        },
        to: input.recipientEmail,
        subject: input.subject,
        text: rendered.text,
        html: rendered.html,
        headers: {
          "X-CredTrail-Email-Category": input.category,
          "X-CredTrail-Email-Kind": input.kind,
        },
      }),
    );
    return complete(
      result.success
        ? { status: "accepted", messageId: result.data.messageId }
        : { status: "pending", reason: "provider_uncertain" },
    );
  } catch (cause: unknown) {
    return complete(
      rejectedSmtpError.safeParse(cause).success || rejectedSesError.safeParse(cause).success
        ? { status: "failed", reason: "provider_rejected" }
        : { status: "pending", reason: "provider_uncertain" },
    );
  }
};

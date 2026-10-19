import type { SqlDatabase } from "@credtrail/db";
import { z } from "zod";

export type EmailKind =
  | "magic_link"
  | "password_reset"
  | "member_invite"
  | "issuance"
  | "rule_approval"
  | "rule_lifecycle";

export interface BeginEmailAttempt {
  readonly id: string;
  readonly tenantId: string | null;
  readonly targetId: string | null;
  readonly kind: EmailKind;
  readonly recipientEmail: string;
  readonly deduplicationKey: string | null;
  readonly createdAt: string;
}

export type EmailAttemptCompletion =
  | { readonly status: "accepted"; readonly messageId: string }
  | { readonly status: "failed"; readonly reason: "render_failed" | "provider_rejected" }
  | { readonly status: "skipped"; readonly reason: "not_configured" | "development" }
  | { readonly status: "pending"; readonly reason: "provider_uncertain" };

/** Storage seam for committing a send claim and its result independently of provider I/O. */
export interface EmailAttemptStore {
  begin(
    input: BeginEmailAttempt,
  ): Promise<
    | { readonly status: "created"; readonly attemptId: string }
    | { readonly status: "accepted"; readonly attemptId: string; readonly messageId: string }
    | { readonly status: "pending"; readonly attemptId: string }
  >;
  complete(id: string, outcome: EmailAttemptCompletion, completedAt: string): Promise<void>;
}

export interface EmailTracking {
  readonly store: EmailAttemptStore;
  readonly tenantId: string | null;
  readonly targetId?: string | undefined;
  /** Stable logical reminder ID; the sender scopes this to tenant, kind and recipient. */
  readonly deduplicationKey?: string | undefined;
}

const existingAttemptSchema = z.discriminatedUnion("status", [
  z.object({ id: z.string(), status: z.literal("accepted"), messageId: z.string().min(1) }),
  z.object({ id: z.string(), status: z.literal("pending") }),
]);

/** Database adapter. Records contain routing metadata, never message bodies or sign-in links. */
export const emailTracking = (
  db: SqlDatabase,
  tenantId: string | null,
  targetId?: string,
  deduplicationKey?: string,
): EmailTracking => ({
  tenantId,
  targetId,
  deduplicationKey,
  store: {
    begin: async (input) => {
      const row = await db
        .prepare(`
        INSERT INTO email_attempts
          (id, tenant_id, target_id, kind, recipient_email, status, deduplication_key, created_at)
        VALUES (?, ?, ?, ?, ?, 'pending', ?, ?)
        ON CONFLICT DO NOTHING RETURNING id
      `)
        .bind(
          input.id,
          input.tenantId,
          input.targetId,
          input.kind,
          input.recipientEmail,
          input.deduplicationKey,
          input.createdAt,
        )
        .first<unknown>();
      if (row !== null) return { status: "created", attemptId: input.id };
      const existing = existingAttemptSchema.parse(
        await db
          .prepare(`
        SELECT id, status, provider_message_id AS "messageId" FROM email_attempts
        WHERE deduplication_key = ? AND tenant_id IS NOT DISTINCT FROM ? AND status IN ('pending', 'accepted')
        LIMIT 1
      `)
          .bind(input.deduplicationKey, tenantId)
          .first<unknown>(),
      );
      return existing.status === "accepted"
        ? { status: "accepted", attemptId: existing.id, messageId: existing.messageId }
        : { status: "pending", attemptId: existing.id };
    },
    complete: async (id, outcome, completedAt) => {
      const result = await db
        .prepare(`
        UPDATE email_attempts SET status = ?, reason = ?, provider_message_id = ?, completed_at = ?
        WHERE id = ? AND status = 'pending' AND tenant_id IS NOT DISTINCT FROM ?
        RETURNING id
      `)
        .bind(
          outcome.status,
          "reason" in outcome ? outcome.reason : null,
          outcome.status === "accepted" ? outcome.messageId : null,
          outcome.status === "pending" ? null : completedAt,
          id,
          tenantId,
        )
        .first<unknown>();
      if (result === null) throw new Error("Email attempt could not be completed");
    },
  },
});

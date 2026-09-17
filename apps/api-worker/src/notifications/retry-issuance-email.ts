import { createAuditLog, runSqlTransaction, type SqlDatabase } from "@credtrail/db";
import { loadIssuanceEmailState } from "./issuance-email-outcome";

const after = (timestamp: string): string =>
  new Date(Math.max(Date.now(), Date.parse(timestamp) + 1)).toISOString();

/** Commit the claim before contacting the provider; an uncertain send must never be retried automatically. */
export const retryFailedIssuanceEmail = async (input: {
  db: SqlDatabase;
  tenantId: string;
  assertionId: string;
  actorUserId: string;
  failedAttemptId: string;
  send: () => Promise<void>;
}): Promise<"accepted" | "failed" | "already_handled"> => {
  const pending = await runSqlTransaction(input.db, async (db) => {
    await db
      .prepare("SELECT pg_advisory_xact_lock(hashtextextended(?, 0))")
      .bind(JSON.stringify(["issuance-email-retry", input.tenantId, input.assertionId]))
      .run();
    const current = await loadIssuanceEmailState(db, input.tenantId, input.assertionId);
    if (
      current.outcome !== "failed" ||
      current.attemptId !== input.failedAttemptId ||
      current.occurredAt === null
    )
      return null;
    return createAuditLog(db, {
      tenantId: input.tenantId,
      actorUserId: input.actorUserId,
      action: "assertion.issuance_email",
      targetType: "assertion",
      targetId: input.assertionId,
      occurredAt: after(current.occurredAt),
      metadata: { status: "pending", retriesAttemptId: input.failedAttemptId },
    });
  });
  if (pending === null) return "already_handled";
  let status: "accepted" | "failed";
  try {
    await input.send();
    status = "accepted";
  } catch {
    status = "failed";
  }
  await createAuditLog(input.db, {
    tenantId: input.tenantId,
    actorUserId: input.actorUserId,
    action: "assertion.issuance_email",
    targetType: "assertion",
    targetId: input.assertionId,
    occurredAt: after(pending.occurredAt),
    metadata: { status, retriesAttemptId: input.failedAttemptId, pendingAttemptId: pending.id },
  });
  return status;
};

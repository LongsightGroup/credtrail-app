import {
  createAuditLog,
  listAuditLogs,
  type SqlDatabase,
  type AuditLogRecord,
} from "@credtrail/db";
import { z } from "zod";

const outcomeSchema = z.object({
  status: z.enum([
    "accepted",
    "pending",
    "failed",
    "disabled",
    "suppressed",
    "not_applicable",
    "not_configured",
  ]),
});
export type IssuanceEmailOutcome = z.infer<typeof outcomeSchema>["status"] | "unrecorded";
const auditAction = "assertion.issuance_email";

/** Availability shared by issuance and its pre-submit expectations. */
export const issuanceEmailAvailability = (input: {
  enabled: boolean;
  configured: boolean;
}): "ready" | "disabled" | "not_configured" =>
  !input.enabled ? "disabled" : input.configured ? "ready" : "not_configured";

/** Describes planned notification behavior without promising delivery. */
export const issuanceEmailExpectation = (
  availability: ReturnType<typeof issuanceEmailAvailability>,
): string => {
  switch (availability) {
    case "ready":
      return "After issuance, CredTrail will attempt to email the learner their badge link. The receipt will show whether the email provider accepted it; delivery is not guaranteed.";
    case "disabled":
      return "Email notifications are turned off. No email will be sent. After issuance, copy the public badge link from the receipt and share it with the learner.";
    case "not_configured":
      return "Email is unavailable. No email will be sent. After issuance, copy the public badge link from the receipt and share it with the learner.";
  }
};

export const attemptIssuanceEmail = async (input: {
  readonly isEmailRecipient: boolean;
  readonly enabled: boolean;
  readonly suppressed: boolean;
  readonly configured: boolean;
  readonly send: () => Promise<void>;
}): Promise<Exclude<IssuanceEmailOutcome, "unrecorded">> => {
  if (!input.isEmailRecipient) return "not_applicable";
  if (input.suppressed) return "suppressed";
  const availability = issuanceEmailAvailability(input);
  if (availability !== "ready") return availability;
  try {
    await input.send();
    return "accepted";
  } catch {
    return "failed";
  }
};

export const recordIssuanceEmailOutcome = async (input: {
  readonly db: SqlDatabase;
  readonly tenantId: string;
  readonly assertionId: string;
  readonly status: Exclude<IssuanceEmailOutcome, "unrecorded">;
}): Promise<void> => {
  await createAuditLog(input.db, {
    tenantId: input.tenantId,
    action: auditAction,
    targetType: "assertion",
    targetId: input.assertionId,
    metadata: { status: input.status },
  });
};

/** Safe, public notification state from an audit entry. */
export interface IssuanceEmailState {
  outcome: IssuanceEmailOutcome;
  attemptId: string | null;
  occurredAt: string | null;
}

const emailStateFromAudit = (record: AuditLogRecord | undefined): IssuanceEmailState => {
  let outcome: IssuanceEmailOutcome = "unrecorded";
  if (record?.metadataJson) {
    try {
      const parsed = outcomeSchema.safeParse(JSON.parse(record.metadataJson));
      if (parsed.success) outcome = parsed.data.status;
    } catch {
      /* Malformed historical metadata has no trustworthy outcome. */
    }
  }
  return { outcome, attemptId: record?.id ?? null, occurredAt: record?.occurredAt ?? null };
};

/** Loads the latest notification events, never exposing provider errors or metadata. */
export const loadIssuanceEmailHistory = async (
  db: SqlDatabase,
  tenantId: string,
  assertionId: string,
): Promise<{
  latest: IssuanceEmailState;
  events: IssuanceEmailState[];
  hasMore: boolean;
}> => {
  const records = await listAuditLogs(db, {
    tenantId,
    action: auditAction,
    targetType: "assertion",
    targetId: assertionId,
    limit: 21,
  });
  return {
    latest: emailStateFromAudit(records[0]),
    events: records.slice(0, 20).map(emailStateFromAudit),
    hasMore: records.length > 20,
  };
};

export const loadIssuanceEmailState = async (
  db: SqlDatabase,
  tenantId: string,
  assertionId: string,
): Promise<{
  outcome: IssuanceEmailOutcome;
  attemptId: string | null;
  occurredAt: string | null;
}> => {
  const [record] = await listAuditLogs(db, {
    tenantId,
    action: auditAction,
    targetType: "assertion",
    targetId: assertionId,
    limit: 1,
  });
  return emailStateFromAudit(record);
};

export const loadIssuanceEmailOutcome = async (
  db: SqlDatabase,
  tenantId: string,
  assertionId: string,
): Promise<IssuanceEmailOutcome> =>
  (await loadIssuanceEmailState(db, tenantId, assertionId)).outcome;

export const issuanceEmailOutcomeMessage = (outcome: IssuanceEmailOutcome): string => {
  switch (outcome) {
    case "pending":
      return "A notification retry has started. Its result is not recorded yet. Refresh this page to check the outcome.";
    case "accepted":
      return "The email service accepted the notification. Delivery to the recipient is not confirmed.";
    case "failed":
      return "The notification could not be sent. The credential is still issued.";
    case "disabled":
      return "Email notifications are turned off.";
    case "not_configured":
      return "Email is not configured.";
    case "suppressed":
      return "No email notification was requested for this issuance.";
    case "not_applicable":
      return "This credential was issued without an email recipient.";
    case "unrecorded":
      return "No notification result is recorded.";
  }
};

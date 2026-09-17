import { createAuditLog, listAuditLogs, type SqlDatabase } from "@credtrail/db";
import { z } from "zod";

const outcomeSchema = z.object({
  status: z.enum([
    "accepted",
    "failed",
    "disabled",
    "suppressed",
    "not_applicable",
    "not_configured",
  ]),
});
export type IssuanceEmailOutcome = z.infer<typeof outcomeSchema>["status"] | "unrecorded";
const auditAction = "assertion.issuance_email";

export const attemptIssuanceEmail = async (input: {
  readonly isEmailRecipient: boolean;
  readonly enabled: boolean;
  readonly suppressed: boolean;
  readonly configured: boolean;
  readonly send: () => Promise<void>;
}): Promise<Exclude<IssuanceEmailOutcome, "unrecorded">> => {
  if (!input.isEmailRecipient) return "not_applicable";
  if (input.suppressed) return "suppressed";
  if (!input.enabled) return "disabled";
  if (!input.configured) return "not_configured";
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

export const loadIssuanceEmailOutcome = async (
  db: SqlDatabase,
  tenantId: string,
  assertionId: string,
): Promise<IssuanceEmailOutcome> => {
  const [record] = await listAuditLogs(db, {
    tenantId,
    action: auditAction,
    targetType: "assertion",
    targetId: assertionId,
    limit: 1,
  });
  if (!record?.metadataJson) return "unrecorded";
  let metadata: unknown;
  try {
    metadata = JSON.parse(record.metadataJson);
  } catch {
    return "unrecorded";
  }
  const parsed = outcomeSchema.safeParse(metadata);
  return parsed.success ? parsed.data.status : "unrecorded";
};

export const issuanceEmailOutcomeMessage = (outcome: IssuanceEmailOutcome): string => {
  switch (outcome) {
    case "accepted":
      return "The email service accepted the notification. Delivery to the recipient is not confirmed.";
    case "failed":
      return "The notification could not be sent. The credential is still issued. Share its public badge link with the learner.";
    case "disabled":
      return "Email notifications are turned off. Share the public badge link with the learner.";
    case "not_configured":
      return "Email is not configured. Share the public badge link with the learner.";
    case "suppressed":
      return "No email notification was requested for this issuance.";
    case "not_applicable":
      return "This credential was issued without an email recipient.";
    case "unrecorded":
      return "No notification result is recorded. You can share the public badge link with the learner.";
  }
};

import type {
  BeginEmailAttempt,
  EmailAttemptCompletion,
  EmailAttemptStore,
  EmailTracking,
} from "../notifications/email-attempt-store";

export interface RecordedEmailAttempt extends BeginEmailAttempt {
  outcome: EmailAttemptCompletion;
}

/** In-memory implementation of the persistence seam for notification content/workflow tests. */
export const createMemoryEmailTracking = (): EmailTracking & {
  readonly attempts: RecordedEmailAttempt[];
} => {
  const attempts: RecordedEmailAttempt[] = [];
  const store: EmailAttemptStore = {
    begin: async (input) => {
      const existing =
        input.deduplicationKey === null
          ? undefined
          : attempts.find(
              (attempt) =>
                attempt.deduplicationKey === input.deduplicationKey &&
                (attempt.outcome.status === "accepted" || attempt.outcome.status === "pending"),
            );
      if (existing?.outcome.status === "accepted")
        return {
          status: "accepted",
          attemptId: existing.id,
          messageId: existing.outcome.messageId,
        };
      if (existing?.outcome.status === "pending")
        return { status: "pending", attemptId: existing.id };
      attempts.push({ ...input, outcome: { status: "pending", reason: "provider_uncertain" } });
      return { status: "created", attemptId: input.id };
    },
    complete: async (id, outcome) => {
      const attempt = attempts.find((candidate) => candidate.id === id);
      if (attempt === undefined) throw new Error("Unknown email attempt");
      attempt.outcome = outcome;
    },
  };
  return { store, tenantId: "tenant_123", attempts };
};

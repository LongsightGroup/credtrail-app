import { mapConcurrentBounded } from "../utils/map-concurrent-bounded";
import type { TransactionalEmailResult } from "./transactional-email";

interface EmailBatchClock {
  readonly now: () => number;
  readonly pause: (milliseconds: number) => Promise<void>;
}

const runtimeClock: EmailBatchClock = {
  now: Date.now,
  pause: (milliseconds) => new Promise((resolve) => setTimeout(resolve, milliseconds)),
};

/** Local batch pacing; no shared state or coordination between requests/workers. */
export const sendEmailBatch = async <Recipient>(
  recipients: readonly Recipient[],
  send: (recipient: Recipient) => Promise<TransactionalEmailResult>,
  clock: EmailBatchClock = runtimeClock,
): Promise<readonly TransactionalEmailResult[]> => {
  // Keep SMTP connections small and smooth starts instead of releasing simultaneous bursts.
  const concurrency = 2;
  const intervalMs = 500;
  const maximumBackoffMs = 10_000;
  let backoffMs = 2_000;
  let nextStartAt = 0;

  return mapConcurrentBounded(recipients, { concurrency }, async (recipient) => {
    // Recheck after waking: another send may have extended the pause after a temporary rejection.
    while (nextStartAt > clock.now()) await clock.pause(nextStartAt - clock.now());
    // This check/reservation is synchronous, so only one callback reserves each start time.
    nextStartAt = clock.now() + intervalMs;
    const result = await send(recipient);
    if (result.status === "failed" && result.providerBusy === true) {
      nextStartAt = Math.max(nextStartAt, clock.now() + backoffMs);
      backoffMs = Math.min(backoffMs * 2, maximumBackoffMs);
    }
    return result;
  });
};

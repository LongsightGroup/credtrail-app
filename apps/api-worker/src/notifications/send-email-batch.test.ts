import { describe, expect, it } from "vitest";
import { sendEmailBatch } from "./send-email-batch";
import type { TransactionalEmailResult } from "./transactional-email";

const settle = async (): Promise<void> => new Promise((resolve) => setImmediate(resolve));
const manualClock = (): {
  now: () => number;
  pause: (milliseconds: number) => Promise<void>;
  advance: (milliseconds: number) => Promise<void>;
} => {
  let now = 0;
  const waiters: { due: number; resolve: () => void }[] = [];
  return {
    now: () => now,
    pause: (milliseconds) =>
      new Promise((resolve) => waiters.push({ due: now + milliseconds, resolve })),
    advance: async (milliseconds) => {
      now += milliseconds;
      const ready = waiters.filter((waiter) => waiter.due <= now);
      for (const waiter of ready) {
        waiters.splice(waiters.indexOf(waiter), 1);
        waiter.resolve();
      }
      await settle();
    },
  };
};
const accepted = (id: number): TransactionalEmailResult => ({
  status: "accepted",
  attemptId: String(id),
  messageId: String(id),
});

describe("local email batch pacing", () => {
  it("spaces fast sends by half a second and preserves recipient/result order", async () => {
    const clock = manualClock();
    const starts: number[] = [];
    const results = sendEmailBatch(
      [1, 2, 3],
      async (id) => {
        starts.push(clock.now());
        return accepted(id);
      },
      clock,
    );
    await settle();
    expect(starts).toEqual([0]);
    await clock.advance(499);
    expect(starts).toEqual([0]);
    await clock.advance(1);
    expect(starts).toEqual([0, 500]);
    await clock.advance(500);
    expect(starts).toEqual([0, 500, 1_000]);
    expect(await results).toEqual([accepted(1), accepted(2), accepted(3)]);
  });

  it("never has more than two sends in flight, even when provider replies are slow", async () => {
    const clock = manualClock();
    const finish: (() => void)[] = [];
    const starts: number[] = [];
    let active = 0;
    let maximumActive = 0;
    const results = sendEmailBatch(
      [1, 2, 3],
      (id) =>
        new Promise((resolve) => {
          starts.push(clock.now());
          active += 1;
          maximumActive = Math.max(active, maximumActive);
          finish.push(() => {
            active -= 1;
            resolve(accepted(id));
          });
        }),
      clock,
    );
    await settle();
    await clock.advance(500);
    await clock.advance(500);
    expect(starts).toEqual([0, 500]);
    finish.shift()?.();
    await settle();
    expect(starts).toEqual([0, 500, 1_000]);
    for (const complete of finish) complete();
    expect(await results).toEqual([accepted(1), accepted(2), accepted(3)]);
    expect(maximumActive).toBe(2);
  });

  it("extends already-waiting sends after temporary rejection and caps repeated backoff at ten seconds", async () => {
    const clock = manualClock();
    const starts: number[] = [];
    const results = sendEmailBatch(
      [1, 2, 3, 4, 5, 6],
      async (id) => {
        starts.push(clock.now());
        return {
          status: "failed",
          reason: "provider_rejected",
          providerBusy: true,
          attemptId: String(id),
        };
      },
      clock,
    );
    await settle();
    const expectedStarts = [0];
    for (const delay of [2_000, 4_000, 8_000, 10_000, 10_000]) {
      await clock.advance(delay - 1);
      expect(starts).toEqual(expectedStarts);
      await clock.advance(1);
      expectedStarts.push(clock.now());
      expect(starts).toEqual(expectedStarts);
    }
    expect(await results).toHaveLength(6);
  });

  it("keeps a temporary-rejection pause when an earlier in-flight message succeeds", async () => {
    const clock = manualClock();
    const starts: number[] = [];
    let finishFirst = (): void => {
      throw new Error("First send has not started");
    };
    const results = sendEmailBatch(
      [1, 2, 3],
      async (id) => {
        starts.push(clock.now());
        if (id === 1)
          return new Promise<TransactionalEmailResult>((resolve) => {
            finishFirst = () => resolve(accepted(id));
          });
        return id === 2
          ? { status: "failed", reason: "provider_rejected", providerBusy: true, attemptId: "2" }
          : accepted(id);
      },
      clock,
    );
    await settle();
    await clock.advance(500);
    finishFirst();
    await settle();
    await clock.advance(1_999);
    expect(starts).toEqual([0, 500]);
    await clock.advance(1);
    expect(starts).toEqual([0, 500, 2_500]);
    expect((await results).map((result) => result.status)).toEqual([
      "accepted",
      "failed",
      "accepted",
    ]);
  });

  it.each<TransactionalEmailResult>([
    { status: "failed", reason: "provider_rejected", attemptId: "first" },
    { status: "pending", reason: "provider_uncertain", attemptId: "first" },
    { status: "skipped", reason: "not_configured", attemptId: "first" },
  ])("does not retry or report $status as accepted", async (first) => {
    const clock = manualClock();
    const ids: number[] = [];
    const results = sendEmailBatch(
      [1, 2],
      async (id) => {
        ids.push(id);
        return id === 1 ? first : accepted(id);
      },
      clock,
    );
    await settle();
    await clock.advance(500);
    expect(ids).toEqual([1, 2]);
    expect(await results).toEqual([first, accepted(2)]);
  });
});

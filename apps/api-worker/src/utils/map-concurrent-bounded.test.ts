import { describe, expect, it } from "vitest";
import { mapConcurrentBounded } from "./map-concurrent-bounded";

describe("mapConcurrentBounded", () => {
  it("limits concurrent work and preserves input order", async () => {
    let activeCount = 0;
    let highestActiveCount = 0;
    const releaseWork: Array<() => void> = [];

    const resultPromise = mapConcurrentBounded(
      [1, 2, 3, 4],
      { concurrency: 2 },
      async (value) => {
        activeCount += 1;
        highestActiveCount = Math.max(highestActiveCount, activeCount);
        await new Promise<void>((resolve) => {
          releaseWork.push(resolve);
        });
        activeCount -= 1;
        return value * 10;
      },
    );

    await Promise.resolve();
    expect(activeCount).toBe(2);
    releaseWork.shift()?.();
    await Promise.resolve();
    releaseWork.shift()?.();
    await Promise.resolve();
    releaseWork.shift()?.();
    await Promise.resolve();
    releaseWork.shift()?.();

    await expect(resultPromise).resolves.toEqual([10, 20, 30, 40]);
    expect(highestActiveCount).toBe(2);
  });
});

import { describe, expect, it } from "vitest";

import { isoTimestampSchema } from "./primitives.js";

describe("isoTimestampSchema", () => {
  it("accepts UTC timestamps with seconds", () => {
    expect(isoTimestampSchema.safeParse("2026-09-01T12:30:00Z").success).toBe(true);
    expect(isoTimestampSchema.safeParse("2026-09-01T12:30:00.123Z").success).toBe(true);
  });

  it("rejects UTC timestamps without seconds", () => {
    expect(isoTimestampSchema.safeParse("2026-09-01T12:30Z").success).toBe(false);
  });
});

import { describe, expect, it } from "vitest";

import { expiryTimestampFromFormDate } from "./tenant-operations-admin-routes";

describe("expiryTimestampFromFormDate", () => {
  const now = Date.parse("2026-10-07T12:00:00.000Z");

  it("turns a calendar date into the end of that day in UTC", () => {
    expect(expiryTimestampFromFormDate("2027-01-31", now)).toBe("2027-01-31T23:59:59.000Z");
    expect(expiryTimestampFromFormDate(" 2026-10-08 ", now)).toBe("2026-10-08T23:59:59.000Z");
    expect(expiryTimestampFromFormDate("2026-10-07", now)).toBe("2026-10-07T23:59:59.000Z"); // today still ends later than now
  });

  it("rejects dates that are not real, not in the form's format, or not in the future", () => {
    for (const value of [
      "2027-02-30",
      "31/01/2027",
      "2027-1-31",
      "soon",
      "",

      "2020-01-01",
    ]) {
      expect(expiryTimestampFromFormDate(value, now)).toBeNull();
    }
  });
});

import { describe, expect, it } from "vitest";

import { expiryTimestampFromFormDate } from "./manual-issue-expiry";

describe("expiryTimestampFromFormDate", () => {
  it("turns a calendar date into the end of that day in UTC", () => {
    expect(expiryTimestampFromFormDate("2027-01-31")).toBe("2027-01-31T23:59:59.000Z");
    expect(expiryTimestampFromFormDate(" 2026-10-08 ")).toBe("2026-10-08T23:59:59.000Z");
    expect(expiryTimestampFromFormDate("2026-10-07")).toBe("2026-10-07T23:59:59.000Z");
  });

  it("converts past dates so a saved command can still be replayed", () => {
    expect(expiryTimestampFromFormDate("2020-01-01")).toBe("2020-01-01T23:59:59.000Z");
  });

  it("rejects impossible dates and malformed calendar values", () => {
    for (const value of ["2027-02-30", "31/01/2027", "2027-1-31", "soon", ""]) {
      expect(expiryTimestampFromFormDate(value)).toBeNull();
    }
  });
});

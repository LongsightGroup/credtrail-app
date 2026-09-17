import { describe, expect, it } from "vitest";
import { parseReviewQueuePageQuery, reviewQueuePageUrl } from "./review-queue-page-query";
import { reviewWaitingLabel } from "./components";

describe("review filters and waiting expectations", () => {
  it("round-trips outcome, sort and selection and drops outcomes for pending reviews", () => {
    const query = parseReviewQueuePageQuery({
      reviewStatus: "resolved",
      sort: "oldest",
      decision: "dismiss",
      q: "science",
      review: "e1",
    });
    const url = new URL(reviewQueuePageUrl("tenant", query), "https://example.edu");
    expect(parseReviewQueuePageQuery(Object.fromEntries(url.searchParams))).toEqual(query);
    expect(parseReviewQueuePageQuery({ decision: "issue" }).decision).toBe("all");
    expect(() => parseReviewQueuePageQuery({ sort: "arbitrary" })).toThrow(/Invalid option/);
    expect(() => parseReviewQueuePageQuery({ decision: "arbitrary" })).toThrow(/Invalid option/);
  });
  it("describes elapsed days without negative time or misleading deadlines", () => {
    const now = Date.parse("2026-09-17T12:00:00Z");
    expect(reviewWaitingLabel("2026-09-14T12:00:00Z", now)).toBe("Waiting 3 days");
    expect(reviewWaitingLabel("2026-09-16T12:00:00Z", now)).toBe("Waiting 1 day");
    expect(reviewWaitingLabel("2026-09-18T12:00:00Z", now)).toBe("Waiting less than a day");
    expect(reviewWaitingLabel("invalid", now)).toBe("Waiting time unavailable");
  });
});

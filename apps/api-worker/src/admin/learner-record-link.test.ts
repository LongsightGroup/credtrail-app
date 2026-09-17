import { expect, it } from "vitest";
import { badgeRecordsReturnHref } from "./learner-record-link";
import { buildIssuedBadgesPagePath } from "./issued-badges-admin-helpers";

it("preserves validated filters and page position for the same tenant", () => {
  const cursor = JSON.stringify({
    issuedAt: "2026-09-10T12:00:00.000Z",
    assertionId: "badge_1",
    direction: "older",
  });
  const path = buildIssuedBadgesPagePath("tenant_1");
  const query = new URLSearchParams({
    recipientQuery: "learner@example.edu",
    state: "active",
    limit: "25",
    cursor,
  });
  const result = new URL(
    badgeRecordsReturnHref("tenant_1", `${path}?${query}`)!,
    "https://test.invalid",
  );
  expect(result.searchParams.get("cursor")).toBe(cursor);
  expect(result.searchParams.get("recipientQuery")).toBe("learner@example.edu");
  expect(result.searchParams.get("state")).toBe("active");
});
it("rejects external, malformed, cross-tenant, and invalid cursor returns", () => {
  for (const value of [
    "https://example.org",
    "//example.org",
    "//[",
    buildIssuedBadgesPagePath("tenant_2"),
    `${buildIssuedBadgesPagePath("tenant_1")}?cursor=invalid`,
  ]) {
    expect(badgeRecordsReturnHref("tenant_1", value)).toBeNull();
  }
});

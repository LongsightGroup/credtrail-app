import { expect, it } from "vitest";
import { badgeRecordReturnLink } from "./badge-record-return-link";
import { parseReviewQueuePageQuery, reviewQueuePageUrl } from "./review-queue-page-query";

it("preserves the learner lookup and nested badge-record filter", () => {
  const base = "/tenants/tenant_1/admin/operations";
  const learner = `${base}/learner-records?${new URLSearchParams({ learner: "learner@example.edu", returnTo: `${base}/issued-badges?notificationStatus=failed&limit=100` })}`;
  expect(badgeRecordReturnLink("tenant_1", learner)).toEqual({
    href: learner,
    label: "Back to learner record",
  });
});
it("preserves review search, page position, and selected decision", () => {
  const query = parseReviewQueuePageQuery({
    q: "Badge",
    sort: "oldest",
    decision: "dismiss",
    reviewStatus: "resolved",
    review: "evaluation_1",
    cursor: JSON.stringify({
      at: "2026-09-01T00:00:00.000Z",
      id: "evaluation_3",
      direction: "older",
    }),
  });
  const href = reviewQueuePageUrl("tenant_1", query);
  expect(badgeRecordReturnLink("tenant_1", href)).toEqual({ href, label: "Back to review queue" });
});
it("rejects external and cross-tenant return links and invalid cursors", () => {
  for (const path of [
    "https://example.org",
    "//example.org",
    "/tenants/tenant_2/admin/operations/learner-records?learner=x",
    "/tenants/tenant_1/admin/operations/review-queue?cursor=oops",
    "/tenants/tenant_1/admin/operations/learner-records?learner=",
  ])
    expect(badgeRecordReturnLink("tenant_1", path)).toBeNull();
});

import type { BadgeIssuanceRuleApprovalEventRecord } from "@credtrail/db";
import { describe, expect, it } from "vitest";
import { BadgeRuleApprovalReviewHistory } from "./badge-rule-approval-review-history";

const event = (actorUserId: string | null): BadgeIssuanceRuleApprovalEventRecord => ({
  id: "brae_submitted",
  tenantId: "tenant_123",
  versionId: "brv_123",
  stepNumber: null,
  action: "submitted",
  actorUserId,
  actorRole: null,
  comment: "Ready for review.",
  occurredAt: "2026-09-22T17:31:00.000Z",
  createdAt: "2026-09-22T17:31:00.000Z",
});

describe("approval audit history identities", () => {
  it("shows email addresses for every recorded actor and preserves system and unresolved identities", async () => {
    const html = String(
      await BadgeRuleApprovalReviewHistory({
        steps: [],
        events: [event("usr_author"), event("usr_reviewer"), event(null), event("usr_missing")],
        actors: new Map([
          ["usr_author", { id: "usr_author", email: "author@example.edu" }],
          ["usr_reviewer", { id: "usr_reviewer", email: "reviewer@example.edu" }],
        ]),
      }),
    );

    expect(html).toContain("author@example.edu");
    expect(html).toContain("reviewer@example.edu");
    expect(html).not.toContain("usr_author");
    expect(html).not.toContain("usr_reviewer");
    expect(html).toContain("System");
    expect(html).toContain("usr_missing");
    expect(html).toContain("Ready for review.");
    expect(html).toContain("Show full audit history (4 events)");
  });

  it("escapes user-controlled email text", async () => {
    const html = String(
      await BadgeRuleApprovalReviewHistory({
        steps: [],
        events: [event("usr_author")],
        actors: new Map([
          ["usr_author", { id: "usr_author", email: "<script>alert(1)</script>@example.edu" }],
        ]),
      }),
    );

    expect(html).not.toContain("<script>");
    expect(html).toContain("&lt;script&gt;");
  });
});

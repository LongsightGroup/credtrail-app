import { describe, expect, it } from "vitest";

import {
  assertionBadgeTemplateJoinSql,
  bindLearnerProfileOrEmailAccessParams,
  buildLearnerProfileOrEmailAccessFilter,
  buildLegacyLearnerEmailAccessFilter,
} from "./learner-assertion-access-sql";

describe("learner assertion access SQL helpers", () => {
  it("builds the shared assertion and badge template join", () => {
    expect(assertionBadgeTemplateJoinSql).toContain("FROM assertions");
    expect(assertionBadgeTemplateJoinSql).toContain("INNER JOIN badge_templates");
  });

  it("builds legacy email-only access filters", () => {
    expect(buildLegacyLearnerEmailAccessFilter()).toContain("recipient_identity_type = 'email'");
    expect(buildLegacyLearnerEmailAccessFilter()).toContain(
      "LOWER(assertions.recipient_identity) = ?",
    );
  });

  it("builds profile or email access filters with alias placeholders", () => {
    const filter = buildLearnerProfileOrEmailAccessFilter(["a@example.edu", "b@example.edu"]);

    expect(filter).toContain("assertions.learner_profile_id = ?");
    expect(filter).toContain("IN (?, ?)");
  });

  it("builds profile-only access filters when there are no email aliases", () => {
    expect(buildLearnerProfileOrEmailAccessFilter([])).toBe("assertions.learner_profile_id = ?");
  });

  it("binds profile and alias params in query order", () => {
    expect(
      bindLearnerProfileOrEmailAccessParams("profile_1", ["a@example.edu", "b@example.edu"]),
    ).toEqual(["profile_1", "a@example.edu", "b@example.edu"]);
  });
});

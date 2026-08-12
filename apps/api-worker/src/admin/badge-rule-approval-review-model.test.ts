import { describe, expect, it } from "vitest";
import { buildBadgeRuleVersionRecord } from "../test-support/badge-rule-version";
import {
  buildBadgeRuleReviewAction,
  buildBadgeRuleReviewComparison,
} from "./badge-rule-approval-review-model";

describe("badge rule approval-review model", () => {
  it("does not count unchanged requirements as a visible change", () => {
    const baseVersion = buildBadgeRuleVersionRecord({
      id: "brv_base",
      versionNumber: 1,
      snapshot: { name: "Original rule" },
    });
    const selectedVersion = buildBadgeRuleVersionRecord({
      id: "brv_selected",
      versionNumber: 2,
      snapshot: { name: "Renamed rule" },
    });

    expect(
      buildBadgeRuleReviewComparison({
        baseVersion,
        selectedVersion,
      }),
    ).toMatchObject({
      kind: "available",
      baseVersionNumber: 1,
      changeCount: 1,
      requirementChanges: [],
    });
  });

  it("represents a first version as unavailable for comparison", () => {
    const selectedVersion = buildBadgeRuleVersionRecord();

    expect(buildBadgeRuleReviewComparison({ baseVersion: null, selectedVersion })).toEqual({
      kind: "unavailable",
    });
  });

  it("rejects contradictory reviewer action capabilities", () => {
    expect(() => buildBadgeRuleReviewAction({ canDecide: true, canReopen: true })).toThrow(
      "cannot be both decidable and reopenable",
    );
    expect(buildBadgeRuleReviewAction({ canDecide: true, canReopen: false })).toEqual({
      kind: "decide",
    });
    expect(buildBadgeRuleReviewAction({ canDecide: false, canReopen: true })).toEqual({
      kind: "reopen",
    });
    expect(buildBadgeRuleReviewAction({ canDecide: false, canReopen: false })).toEqual({
      kind: "read_only",
    });
  });
});

import { describe, expect, it } from "vitest";
import { parseDecideBadgeIssuanceRuleVersionRequest } from "@credtrail/validation";
import {
  adminApprovalDecisionRequestFailureMessage,
  apiDecideBadgeRuleVersionErrorMessage,
} from "./badge-rule-approval-outcomes";

describe("badge rule approval outcome messages", () => {
  it("describes the comment requirement for both non-approval decisions", () => {
    expect(apiDecideBadgeRuleVersionErrorMessage({ status: "comment_required" })).toBe(
      "comment is required when returning or rejecting a version",
    );
  });

  it("maps structured request issues to precise recovery copy", () => {
    let missingCommentError: unknown;
    let overlongCommentError: unknown;

    try {
      parseDecideBadgeIssuanceRuleVersionRequest({ decision: "rejected" });
    } catch (error: unknown) {
      missingCommentError = error;
    }

    try {
      parseDecideBadgeIssuanceRuleVersionRequest({
        decision: "rejected",
        comment: "x".repeat(2001),
      });
    } catch (error: unknown) {
      overlongCommentError = error;
    }

    expect(adminApprovalDecisionRequestFailureMessage(missingCommentError)).toBe(
      "Add a reviewer comment before returning or rejecting this version.",
    );
    expect(adminApprovalDecisionRequestFailureMessage(overlongCommentError)).toBe(
      "Keep the reviewer comment to 2,000 characters or fewer.",
    );
  });
});

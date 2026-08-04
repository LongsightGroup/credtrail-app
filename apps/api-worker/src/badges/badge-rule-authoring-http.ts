import {
  BADGE_ISSUANCE_RULE_BUILDER_EDIT_DENIED_MESSAGE,
  type BadgeIssuanceRuleAuthoringFailureReason,
} from "@credtrail/db";
import {
  apiSubmitBadgeRuleVersionStatusCode,
  submitBadgeRuleVersionForApprovalFailureMessage,
} from "./badge-rule-approval-outcomes";

/** HTTP error details for one rejected badge-rule authoring command. */
export type BadgeRuleAuthoringHttpFailure = {
  readonly error: string;
  readonly statusCode: 404 | 409 | 500;
};

/** Maps a domain authoring failure into the public HTTP contract. */
export const badgeRuleAuthoringHttpFailure = (
  reason: BadgeIssuanceRuleAuthoringFailureReason,
): BadgeRuleAuthoringHttpFailure => {
  switch (reason) {
    case "unavailable":
      return {
        error: "That unfinished draft is no longer available.",
        statusCode: 409,
      };
    case "replay_conflict":
      return {
        error: "This unfinished rule has already been promoted. Continue from the saved rule.",
        statusCode: 409,
      };
    case "not_found":
      return {
        error: "Badge rule not found",
        statusCode: 404,
      };
    case "not_editable":
      return {
        error: BADGE_ISSUANCE_RULE_BUILDER_EDIT_DENIED_MESSAGE,
        statusCode: 409,
      };
    case "self_certification_required":
    case "policy_missing_steps":
      return {
        error: submitBadgeRuleVersionForApprovalFailureMessage({ status: reason }),
        statusCode: apiSubmitBadgeRuleVersionStatusCode({ status: reason }),
      };
  }
};

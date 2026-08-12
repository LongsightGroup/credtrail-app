import { BADGE_ISSUANCE_RULE_BUILDER_EDIT_DENIED_MESSAGE } from "@credtrail/db";
import type { PreparedBadgeRuleAuthoringFailureReason } from "./badge-rule-authoring-service";
import {
  apiSubmitBadgeRuleVersionStatusCode,
  submitBadgeRuleVersionForApprovalFailureMessage,
} from "./badge-rule-approval-outcomes";

/** HTTP error details for one rejected badge-rule authoring command. */
export type BadgeRuleAuthoringHttpFailure = {
  readonly error: string;
  readonly statusCode: 404 | 409 | 500 | 503;
};

/** Maps a domain authoring failure into the public HTTP contract. */
export const badgeRuleAuthoringHttpFailure = (
  reason: PreparedBadgeRuleAuthoringFailureReason,
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
    case "template_changed":
      return {
        error:
          "The badge template changed while this rule was being saved. Review it and try again.",
        statusCode: 409,
      };
    case "template_artwork_not_immutable":
      return {
        error:
          "Upload this badge's artwork in CredTrail before using it in an awarding rule. Managed artwork keeps approved versions and issued credentials unchanged.",
        statusCode: 409,
      };
    case "template_artwork_unavailable":
      return {
        error:
          "CredTrail could not check this badge's artwork right now. Wait a moment and try again.",
        statusCode: 503,
      };
    case "template_reuse_confirmation_required":
      return {
        error:
          "This badge is already used by another awarding rule. Confirm that this is another valid way to earn the same badge, then try again.",
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

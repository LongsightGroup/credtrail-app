import type { BadgeIssuanceRuleRecord, BadgeIssuanceRuleVersionRecord } from "@credtrail/db";
import type { BadgeIssuanceRuleDefinition } from "@credtrail/validation";
import { resolveAutomatedBadgeRuleIssuanceTiming } from "@credtrail/validation";
import { badgeRuleVersionStatusLabel } from "../badges/badge-rule-presentation";

/** The bounded action represented by the rule-detail next-step panel. */
export type BadgeRuleNextStepAction =
  | { readonly _tag: "view_latest" }
  | { readonly _tag: "submit_for_approval" }
  | { readonly _tag: "edit_rule" }
  | { readonly _tag: "review_approval" }
  | { readonly _tag: "await_approval"; readonly canWithdraw: boolean }
  | { readonly _tag: "activate" }
  | { readonly _tag: "configure_availability" }
  | { readonly _tag: "review_evaluation" }
  | { readonly _tag: "schedule_end_of_term" }
  | { readonly _tag: "review_availability" }
  | { readonly _tag: "resume" }
  | { readonly _tag: "copy_rule" };

/** User-facing ownership and outcome for the next legal rule-workflow step. */
export interface BadgeRuleNextStepModel {
  readonly title: string;
  readonly description: string;
  readonly owner: string;
  readonly outcome: string;
  readonly action: BadgeRuleNextStepAction;
}

/** Projects governed rule state into one clear next owner, outcome, and action. */
export const buildBadgeRuleNextStepModel = (input: {
  readonly userId: string;
  readonly rule: BadgeIssuanceRuleRecord;
  readonly selectedVersion: BadgeIssuanceRuleVersionRecord;
  readonly latestVersion: BadgeIssuanceRuleVersionRecord;
  readonly definition: BadgeIssuanceRuleDefinition;
  readonly activePlacementCount: number;
  readonly canReviewPendingVersion: boolean;
}): BadgeRuleNextStepModel => {
  if (input.selectedVersion.id !== input.latestVersion.id) {
    return {
      title: `Continue with version ${String(input.latestVersion.versionNumber)}`,
      description: `You are viewing version ${String(input.selectedVersion.versionNumber)}. Workflow actions apply to the latest version, which is ${badgeRuleVersionStatusLabel(input.latestVersion.status).toLowerCase()}.`,
      owner: "Institution administrator",
      outcome: "Opening the latest version puts you back in the current workflow.",
      action: { _tag: "view_latest" },
    };
  }

  switch (input.latestVersion.status) {
    case "draft":
      return {
        title: "Submit this draft for approval",
        description:
          "The rule is saved, but it cannot issue badges yet. Submit it to begin the institution's approval workflow.",
        owner: "Rule author or administrator",
        outcome: "An independent reviewer decides whether the rule can be activated.",
        action: { _tag: "submit_for_approval" },
      };
    case "rejected":
      return {
        title: "Revise the rule before resubmitting",
        description:
          "This version was rejected and cannot issue badges. Editing it creates a new draft while preserving this decision in the history.",
        owner: "Rule author or administrator",
        outcome: "The revised draft can be tested and submitted as a new version.",
        action: { _tag: "edit_rule" },
      };
    case "pending_approval": {
      if (input.canReviewPendingVersion) {
        return {
          title: "Review the submitted rule",
          description:
            "This version is waiting for your decision. Review its requirements and impact before approving it or returning it for changes.",
          owner: "You",
          outcome:
            "Approval makes the version eligible for activation; it does not start issuing yet.",
          action: { _tag: "review_approval" },
        };
      }

      return {
        title: "Wait for an independent review",
        description:
          "This version is submitted and cannot move forward until an assigned reviewer records a decision.",
        owner: "Assigned reviewer",
        outcome: "If approved, an administrator can activate the version next.",
        action: {
          _tag: "await_approval",
          canWithdraw: input.latestVersion.submittedByUserId === input.userId,
        },
      };
    }
    case "approved":
      return {
        title: "Activate the approved rule",
        description:
          "Approval is complete, but this version is not issuing badges yet. Activate it when the rule is ready to govern new awards.",
        owner: "Institution administrator",
        outcome: "The version becomes the rule's current awarding policy.",
        action: { _tag: "activate" },
      };
    case "active": {
      if (input.rule.activeVersionId !== input.latestVersion.id) {
        return {
          title: "Create a current rule from this version",
          description:
            "This version is marked active in its history, but it is not the rule's current awarding version.",
          owner: "Institution administrator",
          outcome: "A copied rule starts a separate governed lifecycle.",
          action: { _tag: "copy_rule" },
        };
      }

      if (input.activePlacementCount === 0) {
        return {
          title: "Make the rule available in the LMS",
          description:
            "The rule is active, but no active course placement is recorded. Confirm where it may be offered, then add CredTrail from an allowed LMS course.",
          owner: "Institution or LMS administrator",
          outcome: "A verified LMS launch creates the course placement.",
          action: { _tag: "configure_availability" },
        };
      }

      const issuanceTiming = resolveAutomatedBadgeRuleIssuanceTiming(input.definition);

      if (issuanceTiming === "immediate") {
        return {
          title: "CredTrail is checking eligibility automatically",
          description:
            "The rule is active in the LMS. CredTrail checks current learner facts and safely queues awards when requirements are met.",
          owner: "CredTrail",
          outcome: "Eligible learners receive the badge without an instructor issuing it manually.",
          action: { _tag: "review_evaluation" },
        };
      }

      if (issuanceTiming === "end_of_term") {
        if (input.latestVersion.expiresAt === null) {
          return {
            title: "Set the term end date",
            description:
              "This rule uses end-of-term awarding, but no end date is scheduled. CredTrail needs that date before it can run the batch.",
            owner: "Institution administrator",
            outcome: "CredTrail evaluates eligible learners when the rule reaches its end date.",
            action: { _tag: "schedule_end_of_term" },
          };
        }

        return {
          title: "CredTrail will run the end-of-term batch",
          description:
            "The rule is active and scheduled. No instructor action is required before the configured end date.",
          owner: "CredTrail",
          outcome: "Eligible learners are evaluated and queued for awards at the end of the term.",
          action: { _tag: "review_evaluation" },
        };
      }

      return {
        title: "Instructors confirm eligible learners",
        description:
          "The rule is active in the LMS. Course instructors make the final awarding decision from the CredTrail roster.",
        owner: "Course instructor",
        outcome:
          "Selected eligible learners receive the badge through the normal issuance safeguards.",
        action: { _tag: "review_availability" },
      };
    }
    case "suspended":
      return {
        title: "Resume issuance when the issue is resolved",
        description:
          "New awards are paused for this version. Existing awards remain valid while an administrator reviews the suspension.",
        owner: "Institution administrator",
        outcome: "Resuming restores this version as the active awarding policy.",
        action: { _tag: "resume" },
      };
    case "expired":
      return {
        title: "Create the next rule",
        description:
          "This version reached its end date and no longer issues badges. Its existing awards and history remain unchanged.",
        owner: "Institution administrator",
        outcome:
          "Copying starts a separate rule that can be reviewed and activated for the next term.",
        action: { _tag: "copy_rule" },
      };
    case "deprecated":
      return {
        title: "Create a new rule if this policy is needed again",
        description:
          "This previous version is read-only and cannot resume issuing badges. Its existing awards remain tied to it.",
        owner: "Institution administrator",
        outcome: "Copying preserves the useful settings in a new governed workflow.",
        action: { _tag: "copy_rule" },
      };
  }
};

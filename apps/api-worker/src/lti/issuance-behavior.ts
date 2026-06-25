import type { BadgeIssuanceRuleDefinition } from "@credtrail/validation";

export type LtiRosterIssuanceBehaviorKey =
  | "manual"
  | "immediate"
  | "end_of_term"
  | "rule_pending"
  | "unavailable";

export interface LtiRosterIssuanceBehavior {
  key: LtiRosterIssuanceBehaviorKey;
  label: string;
  detail: string;
  manualIssuanceAllowed: boolean;
}

export const ltiRosterIssuanceBehaviorFromRuleDefinition = (
  definition: BadgeIssuanceRuleDefinition,
): LtiRosterIssuanceBehavior => {
  const issuanceTiming = definition.options?.issuanceTiming ?? "immediate";

  switch (issuanceTiming) {
    case "manual":
      return {
        key: "manual",
        label: "Instructor confirmation",
        detail: "Eligible learners can be selected and issued from this course roster.",
        manualIssuanceAllowed: true,
      };
    case "end_of_term":
      return {
        key: "end_of_term",
        label: "End-of-term batch",
        detail:
          "This badge is handled through end-of-term batch issuance. Roster issuing is not available for this placement.",
        manualIssuanceAllowed: false,
      };
    case "immediate":
      return {
        key: "immediate",
        label: "Automatic",
        detail:
          "This badge is awarded automatically when learners meet the active rule. Roster issuing is not available for this placement.",
        manualIssuanceAllowed: false,
      };
  }
};

export const ltiRosterRulePendingIssuanceBehavior = (
  detail: string,
): LtiRosterIssuanceBehavior => ({
  key: "rule_pending",
  label: "Rule pending",
  detail,
  manualIssuanceAllowed: false,
});

export const ltiRosterUnavailableIssuanceBehavior = (
  detail: string,
): LtiRosterIssuanceBehavior => ({
  key: "unavailable",
  label: "Unavailable",
  detail,
  manualIssuanceAllowed: false,
});

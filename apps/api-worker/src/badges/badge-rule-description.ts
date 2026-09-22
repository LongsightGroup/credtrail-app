import type {
  BadgeIssuanceRuleCondition,
  BadgeIssuanceRuleDefinition,
} from "@credtrail/validation";

/** Short, factual description of the requirements, without badge names or internal IDs. */
export const describeBadgeRuleCondition = (
  condition: BadgeIssuanceRuleCondition,
  labels?: BadgeIssuanceRuleDefinition["referenceLabels"],
): string => {
  if ("all" in condition || "any" in condition) {
    const children = "all" in condition ? condition.all : condition.any;
    const first = children[0];
    if (first === undefined) return "Add awarding requirements";
    if (children.length === 1) return describeBadgeRuleCondition(first, labels);
    if ("any" in condition) return `Meet any of ${String(children.length)} requirements`;
    if (!("type" in first)) return `Meet all ${String(children.length)} requirements`;
    const second = children[1];
    if (children.length === 2 && second !== undefined && "type" in first && "type" in second) {
      const combined = `${describeBadgeRuleCondition(first, labels)}; ${describeBadgeRuleCondition(second, labels)}`;
      if (combined.length <= 110) return combined;
    }
    return `${describeBadgeRuleCondition(first, labels)} + ${String(children.length - 1)} more ${children.length === 2 ? "requirement" : "requirements"}`;
  }
  if ("not" in condition)
    return "type" in condition.not
      ? `Exclude: ${describeBadgeRuleCondition(condition.not, labels)}`
      : "Exclude learners who match the grouped requirements";
  switch (condition.type) {
    case "course_completion":
      return condition.minCompletionPercent === 100
        ? "Complete all gradebook items"
        : `Complete at least ${String(condition.minCompletionPercent)}% of gradebook items`;
    case "grade_threshold": {
      const score =
        condition.scoreField === "current_score" ? "Current course score" : "Final course score";
      if (condition.minScore !== undefined && condition.maxScore !== undefined) {
        return `${score} between ${String(condition.minScore)}% and ${String(condition.maxScore)}%`;
      }
      return condition.minScore !== undefined
        ? `${score} at least ${String(condition.minScore)}%`
        : `${score} at most ${String(condition.maxScore)}%`;
    }
    case "assignment_submission": {
      const itemTitle =
        labels?.assignments.find(
          (assignment) =>
            assignment.courseId === condition.courseId &&
            assignment.assignmentId === condition.assignmentId,
        )?.title ?? "the gradebook item";
      const item = itemTitle.length > 72 ? `${itemTitle.slice(0, 69)}…` : itemTitle;
      const score =
        condition.minScore === undefined
          ? ""
          : ` with a score of at least ${String(condition.minScore)}`;
      const states =
        condition.workflowStates === undefined
          ? ""
          : condition.workflowStates.join(" or ").length > 50
            ? " with the required workflow state"
            : ` (${condition.workflowStates.join(" or ").replaceAll("_", " ")})`;
      return `${condition.requireSubmitted === false ? "Match" : "Submit"} ${item}${score}${states}`;
    }
    case "program_completion":
      return condition.minimumCompleted === undefined
        ? "Complete every course in the pathway"
        : `Complete at least ${String(condition.minimumCompleted)} courses in the pathway`;
    case "survey_completion":
      return condition.requireCompleted === false
        ? "Match the survey requirement"
        : "Complete the survey";
    case "time_window":
      return "Qualify within the specified dates";
    case "prerequisite_badge":
      return "Earn the prerequisite badge";
    case "custom_field":
      return "Match the learner field requirement";
  }
};

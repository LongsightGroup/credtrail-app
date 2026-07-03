import {
  parseBadgeIssuanceRuleDefinition,
  type BadgeIssuanceRuleCondition,
} from "@credtrail/validation";
import type { HonoElement } from "./public-badge-ui";

export interface RuleDefinitionSummaryDisplayContext {
  readonly courseNamesById?: ReadonlyMap<string, string> | undefined;
  readonly badgeTemplateNamesById?: ReadonlyMap<string, string> | undefined;
}

export const createRuleDefinitionSummaryMarkup = (
  formatIsoTimestamp: (timestampIso: string) => string,
  displayContext: RuleDefinitionSummaryDisplayContext = {},
): ((ruleJson: string | null) => HonoElement) => {
  const labelWithRawId = (label: string, rawId: string): HonoElement => (
    <>
      {label} <span class="criteria-registry__muted">ID: {rawId}</span>
    </>
  );

  const courseLabel = (courseId: string): HonoElement => {
    const courseName = displayContext.courseNamesById?.get(courseId);

    return courseName === undefined ? <>course {courseId}</> : labelWithRawId(courseName, courseId);
  };

  const courseReferenceLabel = (condition: {
    readonly courseId?: string | undefined;
    readonly courseListId?: string | undefined;
  }): HonoElement => {
    if (condition.courseId !== undefined) {
      return courseLabel(condition.courseId);
    }

    if (condition.courseListId !== undefined) {
      return labelWithRawId("course list", condition.courseListId);
    }

    return <>the selected course</>;
  };

  const badgeTemplateLabel = (badgeTemplateId: string): HonoElement => {
    const templateName = displayContext.badgeTemplateNamesById?.get(badgeTemplateId);

    return templateName === undefined ? (
      <>badge template {badgeTemplateId}</>
    ) : (
      labelWithRawId(templateName, badgeTemplateId)
    );
  };

  const ruleConditionMarkup = (condition: BadgeIssuanceRuleCondition): HonoElement => {
    if ("all" in condition) {
      return (
        <li>
          <strong>All of these must be true:</strong>
          <ul>{condition.all.map((entry) => ruleConditionMarkup(entry))}</ul>
        </li>
      );
    }

    if ("any" in condition) {
      return (
        <li>
          <strong>At least one of these must be true:</strong>
          <ul>{condition.any.map((entry) => ruleConditionMarkup(entry))}</ul>
        </li>
      );
    }

    if ("not" in condition) {
      return (
        <li>
          <strong>None of these can be true:</strong>
          <ul>{ruleConditionMarkup(condition.not)}</ul>
        </li>
      );
    }

    switch (condition.type) {
      case "grade_threshold": {
        const scoreField = condition.scoreField ?? "final_score";
        const range =
          condition.minScore !== undefined && condition.maxScore !== undefined
            ? `between ${String(condition.minScore)} and ${String(condition.maxScore)}`
            : condition.minScore !== undefined
              ? `at least ${String(condition.minScore)}`
              : `at most ${String(condition.maxScore)}`;
        return (
          <li>
            For {courseReferenceLabel(condition)}, {scoreField.replaceAll("_", " ")} must be {range}
            .
          </li>
        );
      }
      case "course_completion": {
        return (
          <li>
            For {courseReferenceLabel(condition)}, at least {String(condition.minCompletionPercent)}
            % of gradebook items must be completed.
          </li>
        );
      }
      case "program_completion": {
        const programLabel =
          condition.courseIds === undefined
            ? `complete the courses in list ${condition.courseListId ?? "selected"}`
            : condition.minimumCompleted === undefined
              ? `complete all ${String(condition.courseIds.length)} listed courses`
              : `complete ${String(condition.minimumCompleted)} of ${String(condition.courseIds.length)} listed courses`;
        const courseList =
          condition.courseIds === undefined
            ? (condition.courseListId ?? "configured list")
            : condition.courseIds.join(", ");
        const minimumCompleted = programLabel;
        return (
          <li>
            Program requirement: {minimumCompleted} ({courseList}).
          </li>
        );
      }
      case "assignment_submission": {
        const scoreClause =
          condition.minScore === undefined
            ? ""
            : ` and earn at least ${String(condition.minScore)}`;
        const submissionClause =
          condition.requireSubmitted === false
            ? "submission is optional"
            : "submission is required";
        const workflowClause =
          condition.workflowStates === undefined
            ? ""
            : `, with workflow state in ${condition.workflowStates.join(", ")}`;
        return (
          <li>
            For assignment {labelWithRawId("selected assignment", condition.assignmentId)} in{" "}
            {courseLabel(condition.courseId)}, {submissionClause}
            {scoreClause}
            {workflowClause}.
          </li>
        );
      }
      case "survey_completion": {
        const sourceClause = condition.source === undefined ? "" : ` from ${condition.source}`;
        return (
          <li>
            Survey {condition.surveyId}
            {sourceClause} must be completed.
          </li>
        );
      }
      case "custom_field": {
        const operator = (condition.operator ?? "equals").replaceAll("_", " ");
        return (
          <li>
            Custom field {condition.fieldName} must {operator} {String(condition.expectedValue)}.
          </li>
        );
      }
      case "time_window": {
        const notBefore =
          condition.notBefore === undefined
            ? ""
            : ` on or after ${formatIsoTimestamp(condition.notBefore)} UTC`;
        const notAfter =
          condition.notAfter === undefined
            ? ""
            : ` on or before ${formatIsoTimestamp(condition.notAfter)} UTC`;
        return (
          <li>
            Qualifying activity must happen{notBefore}
            {notAfter}.
          </li>
        );
      }
      case "prerequisite_badge":
        return (
          <li>
            Requires earning this badge first:{" "}
            {condition.badgeTemplateId === undefined
              ? `badge template list ${condition.badgeTemplateListId ?? "selected"}`
              : badgeTemplateLabel(condition.badgeTemplateId)}
            .
          </li>
        );
    }
  };

  const ruleDefinitionSummaryMarkup = (ruleJson: string | null): HonoElement => {
    if (ruleJson === null) {
      return <p class="criteria-registry__muted">Rule definition unavailable.</p>;
    }

    try {
      const parsed = parseBadgeIssuanceRuleDefinition(JSON.parse(ruleJson));
      return (
        <ul class="criteria-registry__conditions">{ruleConditionMarkup(parsed.conditions)}</ul>
      );
    } catch {
      return <p class="criteria-registry__muted">Rule definition could not be parsed.</p>;
    }
  };

  return ruleDefinitionSummaryMarkup;
};

import {
  parseBadgeIssuanceRuleDefinition,
  type BadgeIssuanceRuleCondition,
  type BadgeIssuanceRuleDefinition,
} from "@credtrail/validation";
import type { HonoElement } from "../ui/jsx-utils";

/** An LMS reference rendered inside a human-readable rule summary. */
export type BadgeRuleSummaryLmsReference =
  | { readonly kind: "course"; readonly courseId: string }
  | {
      readonly kind: "assignment";
      readonly courseId: string;
      readonly assignmentId: string;
    };

/** Input for a surface-owned LMS reference renderer. */
export interface BadgeRuleSummaryLmsReferenceMarkupInput {
  readonly reference: BadgeRuleSummaryLmsReference;
  readonly label: string;
  readonly rawId: string;
}

/** Optional names and rendering behavior supplied by a rule-summary surface. */
export interface RuleDefinitionSummaryDisplayContext {
  readonly courseNamesById?: ReadonlyMap<string, string> | undefined;
  readonly badgeTemplateNamesById?: ReadonlyMap<string, string> | undefined;
  readonly renderLmsReference?:
    | ((input: BadgeRuleSummaryLmsReferenceMarkupInput) => HonoElement)
    | undefined;
}

/** Creates a renderer for one parsed, human-readable badge-rule definition summary. */
export const createRuleDefinitionSummaryMarkup = (
  formatIsoTimestamp: (timestampIso: string) => string,
  displayContext: RuleDefinitionSummaryDisplayContext = {},
): ((definition: BadgeIssuanceRuleDefinition | string | null) => HonoElement) => {
  const labelWithRawId = (
    label: string,
    rawId: string,
    reference?: BadgeRuleSummaryLmsReference,
  ): HonoElement => {
    if (reference !== undefined && displayContext.renderLmsReference !== undefined) {
      return displayContext.renderLmsReference({ reference, label, rawId });
    }

    return (
      <>
        {label} <span class="ct-rule-summary__muted">ID: {rawId}</span>
      </>
    );
  };

  const courseLabel = (courseId: string): HonoElement => {
    const courseName = displayContext.courseNamesById?.get(courseId);

    if (displayContext.renderLmsReference === undefined) {
      return courseName === undefined ? (
        <>course {courseId}</>
      ) : (
        labelWithRawId(courseName, courseId)
      );
    }

    return labelWithRawId(courseName ?? "Course", courseId, {
      kind: "course",
      courseId,
    });
  };

  const assignmentLabel = (courseId: string, assignmentId: string): HonoElement => {
    if (displayContext.renderLmsReference === undefined) {
      return labelWithRawId("selected assignment", assignmentId);
    }

    return labelWithRawId("Assignment", assignmentId, {
      kind: "assignment",
      courseId,
      assignmentId,
    });
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
        if (condition.courseIds === undefined) {
          return (
            <li>
              Program requirement: complete the courses in{" "}
              {labelWithRawId("course list", condition.courseListId ?? "selected")}.
            </li>
          );
        }

        const requirement =
          condition.minimumCompleted === undefined
            ? `complete all ${String(condition.courseIds.length)} listed courses`
            : `complete ${String(condition.minimumCompleted)} of ${String(condition.courseIds.length)} listed courses`;
        return (
          <li>
            Program requirement: {requirement}:{" "}
            {condition.courseIds.map((courseId, index) => (
              <>
                {index === 0 ? null : ", "}
                {courseLabel(courseId)}
              </>
            ))}
            .
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
            For {assignmentLabel(condition.courseId, condition.assignmentId)} in{" "}
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

  const ruleDefinitionSummaryMarkup = (
    definition: BadgeIssuanceRuleDefinition | string | null,
  ): HonoElement => {
    if (definition === null) {
      return <p class="ct-rule-summary__muted">Rule definition unavailable.</p>;
    }

    try {
      const parsed =
        typeof definition === "string"
          ? parseBadgeIssuanceRuleDefinition(JSON.parse(definition))
          : definition;
      return <ul class="ct-rule-summary__conditions">{ruleConditionMarkup(parsed.conditions)}</ul>;
    } catch {
      return <p class="ct-rule-summary__muted">Rule definition could not be parsed.</p>;
    }
  };

  return ruleDefinitionSummaryMarkup;
};

import type {
  BadgeIssuanceRuleCondition,
  BadgeIssuanceRuleDefinition,
} from "@credtrail/validation";

export interface BadgeIssuanceRuleGradeFact {
  courseId: string;
  learnerId: string;
  currentScore: number | null;
  finalScore: number | null;
}

export interface BadgeIssuanceRuleCompletionFact {
  courseId: string;
  learnerId: string;
  completed: boolean;
  completionPercent: number | null;
}

export interface BadgeIssuanceRuleSubmissionFact {
  courseId: string;
  assignmentId: string;
  learnerId: string;
  score: number | null;
  workflowState: string | null;
  submittedAt: string | null;
}

export interface BadgeIssuanceRuleSurveyCompletionFact {
  surveyId: string;
  learnerId: string;
  source: string | null;
  completed: boolean;
  completedAt: string | null;
}

export type BadgeIssuanceRuleCustomFieldValue = string | number | boolean;

export interface BadgeIssuanceRuleCustomFieldFact {
  learnerId: string;
  fieldName: string;
  value: BadgeIssuanceRuleCustomFieldValue | null;
}

export interface BadgeIssuanceRuleEvaluationFacts {
  learnerId: string;
  nowIso: string;
  grades: readonly BadgeIssuanceRuleGradeFact[];
  completions: readonly BadgeIssuanceRuleCompletionFact[];
  submissions: readonly BadgeIssuanceRuleSubmissionFact[];
  surveyCompletions: readonly BadgeIssuanceRuleSurveyCompletionFact[];
  customFields: readonly BadgeIssuanceRuleCustomFieldFact[];
  earnedBadgeTemplateIds: readonly string[];
}

export interface BadgeIssuanceRuleRequirements {
  courseIds: string[];
  assignmentRefs: {
    courseId: string;
    assignmentId: string;
  }[];
  surveyIds: string[];
  customFieldNames: string[];
  prerequisiteBadgeTemplateIds: string[];
}

export interface BadgeIssuanceRuleEvaluationNode {
  type: string;
  matched: boolean;
  detail: string;
  resultKind?: "matched" | "failed_condition" | "missing_data";
  children?: BadgeIssuanceRuleEvaluationNode[];
}

export interface BadgeIssuanceRuleEvaluationResult {
  matched: boolean;
  tree: BadgeIssuanceRuleEvaluationNode;
}

export interface BadgeIssuanceRuleEvaluationSummary {
  matchedLeafCount: number;
  failedConditionCount: number;
  missingDataCount: number;
}

const assignmentKey = (input: { courseId: string; assignmentId: string }): string => {
  return `${input.courseId}::${input.assignmentId}`;
};

export const extractBadgeIssuanceRuleRequirements = (
  definition: BadgeIssuanceRuleDefinition,
): BadgeIssuanceRuleRequirements => {
  const courseIds = new Set<string>();
  const assignmentRefs = new Map<string, { courseId: string; assignmentId: string }>();
  const surveyIds = new Set<string>();
  const customFieldNames = new Set<string>();
  const prerequisiteBadgeTemplateIds = new Set<string>();

  const collect = (condition: BadgeIssuanceRuleCondition): void => {
    if ("all" in condition) {
      for (const child of condition.all) {
        collect(child);
      }
      return;
    }

    if ("any" in condition) {
      for (const child of condition.any) {
        collect(child);
      }
      return;
    }

    if ("not" in condition) {
      collect(condition.not);
      return;
    }

    switch (condition.type) {
      case "grade_threshold":
      case "course_completion":
        if (condition.courseId !== undefined) {
          courseIds.add(condition.courseId);
        }
        return;
      case "program_completion":
        for (const courseId of condition.courseIds ?? []) {
          courseIds.add(courseId);
        }
        return;
      case "assignment_submission": {
        courseIds.add(condition.courseId);
        assignmentRefs.set(
          assignmentKey({
            courseId: condition.courseId,
            assignmentId: condition.assignmentId,
          }),
          {
            courseId: condition.courseId,
            assignmentId: condition.assignmentId,
          },
        );
        return;
      }
      case "survey_completion":
        surveyIds.add(condition.surveyId);
        return;
      case "custom_field":
        customFieldNames.add(condition.fieldName);
        return;
      case "prerequisite_badge":
        if (condition.badgeTemplateId !== undefined) {
          prerequisiteBadgeTemplateIds.add(condition.badgeTemplateId);
        }
        return;
      case "time_window":
        return;
    }
  };

  collect(definition.conditions);

  return {
    courseIds: Array.from(courseIds).sort(),
    assignmentRefs: Array.from(assignmentRefs.values()),
    surveyIds: Array.from(surveyIds).sort(),
    customFieldNames: Array.from(customFieldNames).sort(),
    prerequisiteBadgeTemplateIds: Array.from(prerequisiteBadgeTemplateIds).sort(),
  };
};

const customFieldValueLabel = (value: BadgeIssuanceRuleCustomFieldValue): string => {
  return typeof value === "string" ? value : String(value);
};

const customFieldValueAsNumber = (value: BadgeIssuanceRuleCustomFieldValue): number | null => {
  if (typeof value === "number") {
    return Number.isFinite(value) ? value : null;
  }

  if (typeof value === "string" && value.trim().length > 0) {
    const parsed = Number(value);
    return Number.isFinite(parsed) ? parsed : null;
  }

  return null;
};

const customFieldMatches = (input: {
  actual: BadgeIssuanceRuleCustomFieldValue;
  expected: BadgeIssuanceRuleCustomFieldValue;
  operator: "equals" | "not_equals" | "contains" | "greater_than_or_equal" | "less_than_or_equal";
}): boolean => {
  const { actual, expected, operator } = input;

  switch (operator) {
    case "equals":
      return actual === expected;
    case "not_equals":
      return actual !== expected;
    case "contains":
      return String(actual).toLowerCase().includes(String(expected).toLowerCase());
    case "greater_than_or_equal": {
      const actualNumber = customFieldValueAsNumber(actual);
      const expectedNumber = customFieldValueAsNumber(expected);
      return actualNumber !== null && expectedNumber !== null && actualNumber >= expectedNumber;
    }
    case "less_than_or_equal": {
      const actualNumber = customFieldValueAsNumber(actual);
      const expectedNumber = customFieldValueAsNumber(expected);
      return actualNumber !== null && expectedNumber !== null && actualNumber <= expectedNumber;
    }
  }
};

const evaluatePredicate = (
  condition: Exclude<
    BadgeIssuanceRuleCondition,
    | { all: BadgeIssuanceRuleCondition[] }
    | { any: BadgeIssuanceRuleCondition[] }
    | { not: BadgeIssuanceRuleCondition }
  >,
  facts: BadgeIssuanceRuleEvaluationFacts,
): BadgeIssuanceRuleEvaluationNode => {
  switch (condition.type) {
    case "grade_threshold": {
      const courseId = condition.courseId ?? "unknown course";
      const grade = facts.grades.find(
        (candidate) => candidate.courseId === courseId && candidate.learnerId === facts.learnerId,
      );

      if (grade === undefined) {
        return {
          type: "grade_threshold",
          matched: false,
          detail: `No grade fact found for course ${courseId}`,
          resultKind: "missing_data",
        };
      }

      const scoreField = condition.scoreField ?? "final_score";
      const score =
        scoreField === "current_score"
          ? grade.currentScore
          : (grade.finalScore ?? grade.currentScore);

      if (score === null) {
        return {
          type: "grade_threshold",
          matched: false,
          detail: `Score is unavailable for course ${courseId}`,
          resultKind: "missing_data",
        };
      }

      if (condition.minScore !== undefined && score < condition.minScore) {
        return {
          type: "grade_threshold",
          matched: false,
          detail: `Score ${score.toFixed(2)} is below minimum ${condition.minScore.toFixed(2)}`,
          resultKind: "failed_condition",
        };
      }

      if (condition.maxScore !== undefined && score > condition.maxScore) {
        return {
          type: "grade_threshold",
          matched: false,
          detail: `Score ${score.toFixed(2)} exceeds maximum ${condition.maxScore.toFixed(2)}`,
          resultKind: "failed_condition",
        };
      }

      return {
        type: "grade_threshold",
        matched: true,
        detail: `Score ${score.toFixed(2)} satisfies threshold for course ${courseId}`,
        resultKind: "matched",
      };
    }
    case "course_completion": {
      const courseId = condition.courseId ?? "unknown course";
      const completion = facts.completions.find(
        (candidate) => candidate.courseId === courseId && candidate.learnerId === facts.learnerId,
      );

      if (completion === undefined) {
        return {
          type: "course_completion",
          matched: false,
          detail: `No completion fact found for course ${courseId}`,
          resultKind: "missing_data",
        };
      }

      const requireCompleted = condition.requireCompleted ?? true;

      if (requireCompleted && !completion.completed) {
        return {
          type: "course_completion",
          matched: false,
          detail: `Course ${courseId} is not marked completed`,
          resultKind: "failed_condition",
        };
      }

      if (
        condition.minCompletionPercent !== undefined &&
        (completion.completionPercent === null ||
          completion.completionPercent < condition.minCompletionPercent)
      ) {
        return {
          type: "course_completion",
          matched: false,
          detail: `Completion percent for course ${courseId} is below ${String(condition.minCompletionPercent)}`,
          resultKind: "failed_condition",
        };
      }

      return {
        type: "course_completion",
        matched: true,
        detail: `Completion criteria satisfied for course ${courseId}`,
        resultKind: "matched",
      };
    }
    case "program_completion": {
      const courseIds = condition.courseIds ?? [];
      const minimumCompleted = condition.minimumCompleted ?? courseIds.length;
      let completedCount = 0;

      for (const courseId of courseIds) {
        const completion = facts.completions.find(
          (candidate) => candidate.courseId === courseId && candidate.learnerId === facts.learnerId,
        );

        if (completion?.completed === true) {
          completedCount += 1;
        }
      }

      if (completedCount < minimumCompleted) {
        return {
          type: "program_completion",
          matched: false,
          detail: `Completed ${String(completedCount)}/${String(courseIds.length)} courses; requires ${String(minimumCompleted)}`,
          resultKind: completedCount === 0 ? "missing_data" : "failed_condition",
        };
      }

      return {
        type: "program_completion",
        matched: true,
        detail: `Completed ${String(completedCount)}/${String(courseIds.length)} required courses`,
        resultKind: "matched",
      };
    }
    case "assignment_submission": {
      const assignmentId = condition.assignmentId;
      const submission = facts.submissions.find(
        (candidate) =>
          candidate.courseId === condition.courseId &&
          candidate.assignmentId === assignmentId &&
          candidate.learnerId === facts.learnerId,
      );

      if (submission === undefined) {
        return {
          type: "assignment_submission",
          matched: false,
          detail: `No submission found for assignment ${assignmentId}`,
          resultKind: "missing_data",
        };
      }

      const requireSubmitted = condition.requireSubmitted ?? true;
      const submitted =
        submission.submittedAt !== null ||
        (submission.workflowState !== null && submission.workflowState !== "unsubmitted");

      if (requireSubmitted && !submitted) {
        return {
          type: "assignment_submission",
          matched: false,
          detail: `Assignment ${assignmentId} has not been submitted`,
          resultKind: "failed_condition",
        };
      }

      if (
        condition.minScore !== undefined &&
        (submission.score === null || submission.score < condition.minScore)
      ) {
        return {
          type: "assignment_submission",
          matched: false,
          detail: `Assignment score is below required threshold ${String(condition.minScore)}`,
          resultKind: submission.score === null ? "missing_data" : "failed_condition",
        };
      }

      if (
        condition.workflowStates !== undefined &&
        (submission.workflowState === null ||
          !condition.workflowStates.includes(submission.workflowState))
      ) {
        return {
          type: "assignment_submission",
          matched: false,
          detail: `Submission workflow state ${submission.workflowState ?? "null"} is not allowed`,
          resultKind: submission.workflowState === null ? "missing_data" : "failed_condition",
        };
      }

      return {
        type: "assignment_submission",
        matched: true,
        detail: `Submission criteria satisfied for assignment ${assignmentId}`,
        resultKind: "matched",
      };
    }
    case "survey_completion": {
      const survey = facts.surveyCompletions.find(
        (candidate) =>
          candidate.surveyId === condition.surveyId &&
          candidate.learnerId === facts.learnerId &&
          (condition.source === undefined || candidate.source === condition.source),
      );

      if (survey === undefined) {
        return {
          type: "survey_completion",
          matched: false,
          detail: `No survey completion found for ${condition.surveyId}`,
          resultKind: "missing_data",
        };
      }

      const requireCompleted = condition.requireCompleted ?? true;

      if (requireCompleted && !survey.completed) {
        return {
          type: "survey_completion",
          matched: false,
          detail: `Survey ${condition.surveyId} is not marked completed`,
          resultKind: "failed_condition",
        };
      }

      return {
        type: "survey_completion",
        matched: true,
        detail: `Survey ${condition.surveyId} completion criteria satisfied`,
        resultKind: "matched",
      };
    }
    case "custom_field": {
      const field = facts.customFields.find(
        (candidate) =>
          candidate.fieldName === condition.fieldName && candidate.learnerId === facts.learnerId,
      );

      if (field === undefined || field.value === null) {
        return {
          type: "custom_field",
          matched: false,
          detail: `No custom field value found for ${condition.fieldName}`,
          resultKind: "missing_data",
        };
      }

      const operator = condition.operator ?? "equals";
      const matched = customFieldMatches({
        actual: field.value,
        expected: condition.expectedValue,
        operator,
      });

      return {
        type: "custom_field",
        matched,
        detail: matched
          ? `Custom field ${condition.fieldName} matched ${operator} ${customFieldValueLabel(condition.expectedValue)}`
          : `Custom field ${condition.fieldName} did not match ${operator} ${customFieldValueLabel(condition.expectedValue)}`,
        resultKind: matched ? "matched" : "failed_condition",
      };
    }
    case "prerequisite_badge": {
      const badgeTemplateId = condition.badgeTemplateId ?? "";
      const matched = facts.earnedBadgeTemplateIds.includes(badgeTemplateId);

      return {
        type: "prerequisite_badge",
        matched,
        detail: matched
          ? `Prerequisite badge ${badgeTemplateId} is present`
          : `Prerequisite badge ${badgeTemplateId} is missing`,
        resultKind: matched ? "matched" : "failed_condition",
      };
    }
    case "time_window": {
      const nowMs = Date.parse(facts.nowIso);

      if (!Number.isFinite(nowMs)) {
        return {
          type: "time_window",
          matched: false,
          detail: "Evaluation timestamp is invalid",
          resultKind: "missing_data",
        };
      }

      const notBeforeMs =
        condition.notBefore === undefined ? undefined : Date.parse(condition.notBefore);
      const notAfterMs =
        condition.notAfter === undefined ? undefined : Date.parse(condition.notAfter);

      if (notBeforeMs !== undefined && Number.isFinite(notBeforeMs) && nowMs < notBeforeMs) {
        return {
          type: "time_window",
          matched: false,
          detail: `Current time is before ${String(condition.notBefore)}`,
          resultKind: "failed_condition",
        };
      }

      if (notAfterMs !== undefined && Number.isFinite(notAfterMs) && nowMs > notAfterMs) {
        return {
          type: "time_window",
          matched: false,
          detail: `Current time is after ${String(condition.notAfter)}`,
          resultKind: "failed_condition",
        };
      }

      return {
        type: "time_window",
        matched: true,
        detail: "Evaluation timestamp is within allowed window",
        resultKind: "matched",
      };
    }
  }
};

const evaluateCondition = (
  condition: BadgeIssuanceRuleCondition,
  facts: BadgeIssuanceRuleEvaluationFacts,
): BadgeIssuanceRuleEvaluationNode => {
  if ("all" in condition) {
    const children = condition.all.map((child) => evaluateCondition(child, facts));
    const matched = children.every((child) => child.matched);

    return {
      type: "all",
      matched,
      detail: matched ? "All conditions matched" : "At least one condition failed",
      children,
    };
  }

  if ("any" in condition) {
    const children = condition.any.map((child) => evaluateCondition(child, facts));
    const matched = children.some((child) => child.matched);

    return {
      type: "any",
      matched,
      detail: matched ? "At least one condition matched" : "No conditions matched",
      children,
    };
  }

  if ("not" in condition) {
    const child = evaluateCondition(condition.not, facts);

    return {
      type: "not",
      matched: !child.matched,
      detail: !child.matched ? "Negated condition matched" : "Negated condition failed",
      children: [child],
    };
  }

  return evaluatePredicate(condition, facts);
};

export const evaluateBadgeIssuanceRuleDefinition = (
  definition: BadgeIssuanceRuleDefinition,
  facts: BadgeIssuanceRuleEvaluationFacts,
): BadgeIssuanceRuleEvaluationResult => {
  const tree = evaluateCondition(definition.conditions, facts);

  return {
    matched: tree.matched,
    tree,
  };
};

export const summarizeBadgeIssuanceRuleEvaluation = (
  evaluation: BadgeIssuanceRuleEvaluationResult,
): BadgeIssuanceRuleEvaluationSummary => {
  const summary: BadgeIssuanceRuleEvaluationSummary = {
    matchedLeafCount: 0,
    failedConditionCount: 0,
    missingDataCount: 0,
  };

  const visit = (node: BadgeIssuanceRuleEvaluationNode): void => {
    if (Array.isArray(node.children) && node.children.length > 0) {
      for (const child of node.children) {
        visit(child);
      }

      return;
    }

    if (node.resultKind === "matched") {
      summary.matchedLeafCount += 1;
      return;
    }

    if (node.resultKind === "missing_data") {
      summary.missingDataCount += 1;
      return;
    }

    summary.failedConditionCount += 1;
  };

  visit(evaluation.tree);
  return summary;
};

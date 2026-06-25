import { describe, expect, it } from "vitest";
import {
  evaluateBadgeIssuanceRuleDefinition,
  extractBadgeIssuanceRuleRequirements,
  primaryEvaluationDetail,
  summarizeBadgeIssuanceRuleEvaluation,
} from "./engine";
import { parseCreateBadgeIssuanceRuleRequest } from "@credtrail/validation";

const baseDefinition = parseCreateBadgeIssuanceRuleRequest({
  name: "CS Program Completion",
  badgeTemplateId: "badge_template_program",
  lmsConnectionId: "lms_123",
  lmsProviderKind: "canvas",
  definition: {
    conditions: {
      all: [
        {
          type: "course_completion",
          courseId: "course_101",
        },
        {
          type: "grade_threshold",
          courseId: "course_101",
          minScore: 85,
        },
        {
          type: "assignment_submission",
          courseId: "course_101",
          assignmentId: "assignment_midterm",
          minScore: 80,
        },
        {
          type: "survey_completion",
          source: "qualtrics",
          surveyId: "exit_survey",
        },
        {
          type: "custom_field",
          fieldName: "programStanding",
          operator: "equals",
          expectedValue: "eligible",
        },
        {
          type: "prerequisite_badge",
          badgeTemplateId: "badge_template_foundations",
        },
      ],
    },
  },
}).definition;

describe("badge issuance rule engine", () => {
  it("extracts referenced courses, assignments, and prerequisites", () => {
    const requirements = extractBadgeIssuanceRuleRequirements(baseDefinition);

    expect(requirements.courseIds).toEqual(["course_101"]);
    expect(requirements.assignmentRefs).toEqual([
      {
        courseId: "course_101",
        assignmentId: "assignment_midterm",
      },
    ]);
    expect(requirements.surveyIds).toEqual(["exit_survey"]);
    expect(requirements.customFieldNames).toEqual(["programStanding"]);
    expect(requirements.prerequisiteBadgeTemplateIds).toEqual(["badge_template_foundations"]);
  });

  it("returns a matched evaluation when all constraints pass", () => {
    const result = evaluateBadgeIssuanceRuleDefinition(baseDefinition, {
      learnerId: "learner_123",
      nowIso: "2026-02-17T00:00:00.000Z",
      grades: [
        {
          courseId: "course_101",
          learnerId: "learner_123",
          currentScore: 90,
          finalScore: 91,
        },
      ],
      completions: [
        {
          courseId: "course_101",
          learnerId: "learner_123",
          completed: true,
          completionPercent: 100,
        },
      ],
      submissions: [
        {
          courseId: "course_101",
          assignmentId: "assignment_midterm",
          learnerId: "learner_123",
          score: 90,
          workflowState: "graded",
          submittedAt: "2026-01-15T12:00:00.000Z",
        },
      ],
      surveyCompletions: [
        {
          surveyId: "exit_survey",
          learnerId: "learner_123",
          source: "qualtrics",
          completed: true,
          completedAt: "2026-01-16T12:00:00.000Z",
        },
      ],
      customFields: [
        {
          learnerId: "learner_123",
          fieldName: "programStanding",
          value: "eligible",
        },
      ],
      earnedBadgeTemplateIds: ["badge_template_foundations"],
    });

    expect(result.matched).toBe(true);
    expect(result.tree.type).toBe("all");
  });

  it("returns an unmatched evaluation when a prerequisite is missing", () => {
    const result = evaluateBadgeIssuanceRuleDefinition(baseDefinition, {
      learnerId: "learner_123",
      nowIso: "2026-02-17T00:00:00.000Z",
      grades: [
        {
          courseId: "course_101",
          learnerId: "learner_123",
          currentScore: 90,
          finalScore: 91,
        },
      ],
      completions: [
        {
          courseId: "course_101",
          learnerId: "learner_123",
          completed: true,
          completionPercent: 100,
        },
      ],
      submissions: [
        {
          courseId: "course_101",
          assignmentId: "assignment_midterm",
          learnerId: "learner_123",
          score: 90,
          workflowState: "graded",
          submittedAt: "2026-01-15T12:00:00.000Z",
        },
      ],
      surveyCompletions: [
        {
          surveyId: "exit_survey",
          learnerId: "learner_123",
          source: "qualtrics",
          completed: true,
          completedAt: "2026-01-16T12:00:00.000Z",
        },
      ],
      customFields: [
        {
          learnerId: "learner_123",
          fieldName: "programStanding",
          value: "eligible",
        },
      ],
      earnedBadgeTemplateIds: [],
    });

    expect(result.matched).toBe(false);
    expect(JSON.stringify(result.tree)).toContain(
      "Prerequisite badge badge_template_foundations is missing",
    );
  });

  it("summarizes missing-data evaluations for review workflows", () => {
    const result = evaluateBadgeIssuanceRuleDefinition(baseDefinition, {
      learnerId: "learner_123",
      nowIso: "2026-02-17T00:00:00.000Z",
      grades: [],
      completions: [
        {
          courseId: "course_101",
          learnerId: "learner_123",
          completed: true,
          completionPercent: 100,
        },
      ],
      submissions: [],
      surveyCompletions: [],
      customFields: [
        {
          learnerId: "learner_123",
          fieldName: "programStanding",
          value: "eligible",
        },
      ],
      earnedBadgeTemplateIds: ["badge_template_foundations"],
    });
    const summary = summarizeBadgeIssuanceRuleEvaluation(result);

    expect(result.matched).toBe(false);
    expect(summary.missingDataCount).toBeGreaterThan(0);
    expect(summary.failedConditionCount).toBe(0);
  });

  it("evaluates survey completion and custom field conditions", () => {
    const definition = parseCreateBadgeIssuanceRuleRequest({
      name: "Survey and cohort rule",
      badgeTemplateId: "badge_template_survey",
      lmsConnectionId: "lms_123",
      lmsProviderKind: "canvas",
      definition: {
        conditions: {
          all: [
            {
              type: "survey_completion",
              source: "qualtrics",
              surveyId: "exit_survey",
            },
            {
              type: "custom_field",
              fieldName: "cohortYear",
              operator: "greater_than_or_equal",
              expectedValue: 2026,
            },
          ],
        },
      },
    }).definition;

    const result = evaluateBadgeIssuanceRuleDefinition(definition, {
      learnerId: "learner_123",
      nowIso: "2026-02-17T00:00:00.000Z",
      grades: [],
      completions: [],
      submissions: [],
      surveyCompletions: [
        {
          surveyId: "exit_survey",
          learnerId: "learner_123",
          source: "qualtrics",
          completed: true,
          completedAt: "2026-02-16T00:00:00.000Z",
        },
      ],
      customFields: [
        {
          learnerId: "learner_123",
          fieldName: "cohortYear",
          value: 2026,
        },
      ],
      earnedBadgeTemplateIds: [],
    });

    expect(result.matched).toBe(true);
    expect(JSON.stringify(result.tree)).toContain("exit_survey");
    expect(JSON.stringify(result.tree)).toContain("cohortYear");
  });

  it("prefers missing-data detail when summarizing evaluation trees", () => {
    const detail = primaryEvaluationDetail({
      type: "all",
      matched: false,
      detail: "All conditions must match.",
      children: [
        {
          type: "grade_threshold",
          matched: false,
          detail: "Final score is below minimum.",
          resultKind: "failed_condition",
        },
        {
          type: "grade_threshold",
          matched: false,
          detail: "No final score is available.",
          resultKind: "missing_data",
        },
      ],
    });

    expect(detail).toBe("No final score is available.");
  });
});

import { describe, expect, it } from "vitest";
import { ltiCourseBadgeSetupRuleDefinition } from "./course-badge-setup";

describe("ltiCourseBadgeSetupRuleDefinition", () => {
  it("maps manual instructor approval to a shared manual course rule", () => {
    expect(
      ltiCourseBadgeSetupRuleDefinition("course-123", {
        preset: "manual_instructor_approval",
      }),
    ).toMatchObject({
      conditions: {
        type: "course_completion",
        courseId: "course-123",
        minCompletionPercent: 0,
      },
      options: {
        issuanceTiming: "manual",
        reviewOnMissingFacts: true,
      },
    });
  });

  it("maps final course score threshold to the shared grade threshold rule", () => {
    expect(
      ltiCourseBadgeSetupRuleDefinition("course-123", {
        preset: "final_course_score_threshold",
        scoreThreshold: 85,
      }),
    ).toMatchObject({
      conditions: {
        type: "grade_threshold",
        courseId: "course-123",
        scoreField: "final_score",
        minScore: 85,
      },
      options: {
        reviewOnMissingFacts: true,
      },
    });
  });

  it("maps gradebook item score threshold to the shared assignment rule", () => {
    expect(
      ltiCourseBadgeSetupRuleDefinition("course-123", {
        preset: "gradebook_item_score_threshold",
        gradebookItemId: "gradebook-item-7",
        scoreThreshold: 90,
      }),
    ).toMatchObject({
      conditions: {
        type: "assignment_submission",
        courseId: "course-123",
        assignmentId: "gradebook-item-7",
        requireSubmitted: true,
        minScore: 90,
      },
    });
  });

  it("maps assignment submitted or graded to the shared assignment workflow rule", () => {
    expect(
      ltiCourseBadgeSetupRuleDefinition("course-123", {
        preset: "assignment_submitted_or_graded",
        gradebookItemId: "assignment-2",
        workflowStates: ["submitted", "graded"],
      }),
    ).toMatchObject({
      conditions: {
        type: "assignment_submission",
        courseId: "course-123",
        assignmentId: "assignment-2",
        requireSubmitted: true,
        workflowStates: ["submitted", "graded"],
      },
    });
  });

  it("defaults assignment submitted or graded to Sakai graded workflow evidence", () => {
    expect(
      ltiCourseBadgeSetupRuleDefinition("course-123", {
        preset: "assignment_submitted_or_graded",
        gradebookItemId: "assignment-2",
      }),
    ).toMatchObject({
      conditions: {
        type: "assignment_submission",
        courseId: "course-123",
        assignmentId: "assignment-2",
        requireSubmitted: true,
        workflowStates: ["graded"],
      },
    });
  });

  it("maps completion percentage to the shared course completion rule", () => {
    expect(
      ltiCourseBadgeSetupRuleDefinition("course-123", {
        preset: "completion_percentage",
        completionPercent: 75,
      }),
    ).toMatchObject({
      conditions: {
        type: "course_completion",
        courseId: "course-123",
        minCompletionPercent: 75,
      },
    });
  });

  it("rejects presets missing the data required by the shared rule schema", () => {
    expect(
      ltiCourseBadgeSetupRuleDefinition("course-123", {
        preset: "gradebook_item_score_threshold",
        scoreThreshold: 80,
      }),
    ).toBeNull();
  });
});

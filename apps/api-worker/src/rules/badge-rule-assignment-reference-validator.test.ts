import { parseCreateBadgeIssuanceRuleRequest } from "@credtrail/validation";
import { describe, expect, it } from "vitest";
import type { GradebookAssignmentReader, GradebookAssignmentRecord } from "../lms/gradebook-types";
import { validateBadgeRuleAssignmentReferences } from "./badge-rule-assignment-reference-validator";

const definitionWithAssignments = (assignmentIds: readonly string[]) => {
  return parseCreateBadgeIssuanceRuleRequest({
    name: "Assignment rule",
    badgeTemplateId: "badge-template",
    badgeTemplateReuseAcknowledged: false,
    lmsConnectionId: "lms-connection",
    lmsProviderKind: "sakai",
    action: "save_draft",
    definition: {
      conditions: {
        all: assignmentIds.map((assignmentId) => ({
          type: "assignment_submission" as const,
          courseId: "course-101",
          assignmentId,
        })),
      },
    },
  }).definition;
};

const threeCoursePathwayDefinition = () => {
  return parseCreateBadgeIssuanceRuleRequest({
    name: "Sample Course Pathway Badge",
    badgeTemplateId: "badge-template",
    badgeTemplateReuseAcknowledged: false,
    lmsConnectionId: "lms-connection",
    lmsProviderKind: "sakai",
    action: "save_draft",
    definition: {
      conditions: {
        type: "program_completion",
        courseIds: ["course-101", "course-102", "course-103"],
        minimumCompleted: 3,
      },
    },
  }).definition;
};

const assignment = (assignmentId: string): GradebookAssignmentRecord => ({
  assignmentId,
  courseId: "course-101",
  title: assignmentId,
  workflowState: "published",
  pointsPossible: 100,
  dueAt: null,
});

const createProvider = (
  listAssignments: GradebookAssignmentReader["listAssignments"],
): GradebookAssignmentReader => ({
  listAssignments,
});

describe("validateBadgeRuleAssignmentReferences", () => {
  it("does not read gradebooks for a course-only pathway", async () => {
    const provider = createProvider(() =>
      Promise.reject(new Error("course-only rules must not load assignments")),
    );

    await expect(
      validateBadgeRuleAssignmentReferences({
        provider,
        definition: threeCoursePathwayDefinition(),
      }),
    ).resolves.toEqual({ status: "valid" });
  });

  it("loads each course gradebook once and reuses its assignments", async () => {
    const requestedCourseIds: string[] = [];
    const provider = createProvider((input) => {
      requestedCourseIds.push(input.courseId);
      return Promise.resolve([assignment("draft"), assignment("final")]);
    });

    await expect(
      validateBadgeRuleAssignmentReferences({
        provider,
        definition: definitionWithAssignments(["draft", "final"]),
      }),
    ).resolves.toEqual({ status: "valid" });
    expect(requestedCourseIds).toEqual(["course-101"]);
  });

  it("identifies an assignment absent from an accessible gradebook", async () => {
    const provider = createProvider(() => Promise.resolve([assignment("draft")]));

    await expect(
      validateBadgeRuleAssignmentReferences({
        provider,
        definition: definitionWithAssignments(["draft", "final"]),
      }),
    ).resolves.toEqual({
      status: "assignment_missing",
      courseId: "course-101",
      assignmentId: "final",
    });
  });

  it("returns the provider failure for an inaccessible course", async () => {
    const cause = new Error("forbidden");
    const provider = createProvider(() => Promise.reject(cause));

    await expect(
      validateBadgeRuleAssignmentReferences({
        provider,
        definition: definitionWithAssignments(["final"]),
      }),
    ).resolves.toEqual({
      status: "gradebook_unavailable",
      courseId: "course-101",
      cause,
    });
  });
});

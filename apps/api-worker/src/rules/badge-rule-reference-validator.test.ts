import { parseCreateBadgeIssuanceRuleRequest } from "@credtrail/validation";
import { describe, expect, it } from "vitest";
import type { GradebookAssignmentRecord, GradebookProvider } from "../lms/gradebook-types";
import { validateBadgeRuleReferences } from "./badge-rule-reference-validator";

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

const assignment = (assignmentId: string): GradebookAssignmentRecord => ({
  assignmentId,
  courseId: "course-101",
  title: assignmentId,
  workflowState: "published",
  pointsPossible: 100,
  dueAt: null,
});

const createProvider = (
  listAssignments: GradebookProvider["listAssignments"],
): GradebookProvider => ({
  kind: "sakai",
  listAssignments,
  listEnrollments: () => Promise.resolve([]),
  listLearners: () => Promise.resolve([]),
  listSubmissions: () => Promise.resolve([]),
  listGrades: () => Promise.resolve([]),
  listCompletions: () => Promise.resolve([]),
});

describe("validateBadgeRuleReferences", () => {
  it("loads each course gradebook once and reuses its assignments", async () => {
    const requestedCourseIds: string[] = [];
    const provider = createProvider((input) => {
      requestedCourseIds.push(input.courseId);
      return Promise.resolve([assignment("draft"), assignment("final")]);
    });

    await expect(
      validateBadgeRuleReferences({
        provider,
        definition: definitionWithAssignments(["draft", "final"]),
      }),
    ).resolves.toEqual({ status: "valid" });
    expect(requestedCourseIds).toEqual(["course-101"]);
  });

  it("identifies an assignment absent from an accessible gradebook", async () => {
    const provider = createProvider(() => Promise.resolve([assignment("draft")]));

    await expect(
      validateBadgeRuleReferences({
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
      validateBadgeRuleReferences({
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

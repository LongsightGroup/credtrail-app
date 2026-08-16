import { parseBadgeIssuanceRuleDefinition } from "@credtrail/validation";
import { describe, expect, it } from "vitest";
import type { GradebookAssignmentReader, GradebookCourseRecord } from "./gradebook-types";
import { resolveBadgeRuleReferenceLabels } from "./badge-rule-reference-labels";

const createProvider = (
  overrides: Partial<GradebookAssignmentReader> = {},
): GradebookAssignmentReader => ({
  listAssignments: () => Promise.resolve([]),
  ...overrides,
});

const courseRecord = (courseId: string, title = `Course ${courseId}`): GradebookCourseRecord => ({
  courseId,
  title,
  courseCode: null,
  workflowState: null,
  startsAt: null,
  endsAt: null,
});

describe("resolveBadgeRuleReferenceLabels", () => {
  it("returns exact course and assignment labels through the provider seam", async () => {
    const provider = createProvider({
      listAssignments: ({ courseId }) => {
        expect(courseId).toBe("course-101");
        return Promise.resolve([
          {
            courseId,
            assignmentId: "assignment-7",
            title: "Final project",
            workflowState: "published",
            pointsPossible: 100,
            dueAt: null,
          },
          {
            courseId,
            assignmentId: "assignment-unused",
            title: "Unreferenced work",
            workflowState: "published",
            pointsPossible: 10,
            dueAt: null,
          },
        ]);
      },
    });

    const result = await resolveBadgeRuleReferenceLabels({
      provider,
      courses: [courseRecord("course-101", "Advanced TypeScript")],
      definition: parseBadgeIssuanceRuleDefinition({
        conditions: {
          type: "assignment_submission",
          courseId: "course-101",
          assignmentId: "assignment-7",
        },
      }),
    });

    expect(result).toEqual({
      courses: [{ courseId: "course-101", title: "Advanced TypeScript" }],
      assignments: [
        {
          courseId: "course-101",
          assignmentId: "assignment-7",
          title: "Final project",
        },
      ],
    });
  });

  it("keeps assignment labels when the authorized course projection is unavailable", async () => {
    const provider = createProvider({
      listAssignments: ({ courseId }) =>
        Promise.resolve([
          {
            courseId,
            assignmentId: "assignment-7",
            title: "Final project",
            workflowState: "published",
            pointsPossible: 100,
            dueAt: null,
          },
        ]),
    });

    const result = await resolveBadgeRuleReferenceLabels({
      provider,
      courses: [],
      definition: parseBadgeIssuanceRuleDefinition({
        conditions: {
          type: "assignment_submission",
          courseId: "course-101",
          assignmentId: "assignment-7",
        },
      }),
    });

    expect(result).toEqual({
      courses: [],
      assignments: [
        {
          courseId: "course-101",
          assignmentId: "assignment-7",
          title: "Final project",
        },
      ],
    });
  });

  it("rejects when the LMS cannot read a referenced assignment", async () => {
    const provider = createProvider({
      listAssignments: () => Promise.reject(new Error("LMS gradebook unavailable")),
    });

    await expect(
      resolveBadgeRuleReferenceLabels({
        provider,
        courses: [courseRecord("course-101")],
        definition: parseBadgeIssuanceRuleDefinition({
          conditions: {
            type: "assignment_submission",
            courseId: "course-101",
            assignmentId: "assignment-7",
          },
        }),
      }),
    ).rejects.toThrow("LMS gradebook unavailable");
  });

  it("limits assignment reads for large rules", async () => {
    let activeReads = 0;
    let maximumActiveReads = 0;
    const provider = createProvider({
      listAssignments: async ({ courseId }) => {
        activeReads += 1;
        maximumActiveReads = Math.max(maximumActiveReads, activeReads);
        await new Promise<void>((resolve) => setImmediate(resolve));
        activeReads -= 1;
        return [
          {
            courseId,
            assignmentId: `assignment-${courseId}`,
            title: `Assignment ${courseId}`,
            workflowState: null,
            pointsPossible: null,
            dueAt: null,
          },
        ];
      },
    });
    const courseIds = ["course-1", "course-2", "course-3", "course-4", "course-5", "course-6"];

    const result = await resolveBadgeRuleReferenceLabels({
      provider,
      courses: courseIds.map((courseId) => courseRecord(courseId)),
      definition: parseBadgeIssuanceRuleDefinition({
        conditions: {
          all: courseIds.map((courseId) => ({
            type: "assignment_submission" as const,
            courseId,
            assignmentId: `assignment-${courseId}`,
          })),
        },
      }),
    });

    expect(result.courses).toHaveLength(courseIds.length);
    expect(maximumActiveReads).toBe(4);
  });
});

import type { BadgeIssuanceRuleDefinition } from "@credtrail/validation";
import type { GradebookAssignmentReader, GradebookRequestOptions } from "../lms/gradebook-types";
import type { BadgeRuleAssignmentReferenceLabel } from "../lms/badge-rule-reference-labels";
import { mapConcurrentBounded } from "../utils/map-concurrent-bounded";
import { extractBadgeIssuanceRuleRequirements } from "./engine";

const ASSIGNMENT_REFERENCE_VALIDATION_CONCURRENCY = 4;

export type BadgeRuleAssignmentReferenceValidationResult =
  | { readonly status: "valid"; readonly assignments: readonly BadgeRuleAssignmentReferenceLabel[] }
  | {
      readonly status: "gradebook_unavailable";
      readonly courseId: string;
      readonly cause: unknown;
    }
  | {
      readonly status: "assignment_missing";
      readonly courseId: string;
      readonly assignmentId: string;
    };

type CourseAssignmentValidation =
  | {
      readonly status: "available";
      readonly courseId: string;
      readonly assignmentIds: ReadonlySet<string>;
      readonly assignments: readonly BadgeRuleAssignmentReferenceLabel[];
    }
  | {
      readonly status: "unavailable";
      readonly courseId: string;
      readonly cause: unknown;
    };

/** Validates assignment references through gradebook access and reuses results per course. */
export const validateBadgeRuleAssignmentReferences = async (
  input: {
    readonly provider: GradebookAssignmentReader;
    readonly definition: BadgeIssuanceRuleDefinition;
  },
  options: GradebookRequestOptions = {},
): Promise<BadgeRuleAssignmentReferenceValidationResult> => {
  const requirements = extractBadgeIssuanceRuleRequirements(input.definition);
  const courseIds = [
    ...new Set(requirements.assignmentRefs.map((assignmentRef) => assignmentRef.courseId)),
  ];

  if (courseIds.length === 0) {
    return { status: "valid", assignments: [] };
  }

  const courseValidations = await mapConcurrentBounded(
    courseIds,
    { concurrency: ASSIGNMENT_REFERENCE_VALIDATION_CONCURRENCY },
    async (courseId): Promise<CourseAssignmentValidation> => {
      try {
        const assignments = await input.provider.listAssignments({ courseId }, options);
        return {
          status: "available",
          courseId,
          assignmentIds: new Set(assignments.map((assignment) => assignment.assignmentId)),
          assignments: assignments
            .filter((assignment) =>
              requirements.assignmentRefs.some(
                (reference) =>
                  reference.courseId === courseId &&
                  reference.assignmentId === assignment.assignmentId,
              ),
            )
            .map((assignment) => ({
              courseId,
              assignmentId: assignment.assignmentId,
              title: assignment.title,
            })),
        };
      } catch (cause: unknown) {
        return {
          status: "unavailable",
          courseId,
          cause,
        };
      }
    },
  );
  const unavailableCourse = courseValidations.find(
    (validation) => validation.status === "unavailable",
  );

  if (unavailableCourse !== undefined) {
    return {
      status: "gradebook_unavailable",
      courseId: unavailableCourse.courseId,
      cause: unavailableCourse.cause,
    };
  }

  const assignmentIdsByCourseId = new Map(
    courseValidations
      .filter((validation) => validation.status === "available")
      .map((validation) => [validation.courseId, validation.assignmentIds]),
  );

  for (const assignmentRef of requirements.assignmentRefs) {
    if (!assignmentIdsByCourseId.get(assignmentRef.courseId)?.has(assignmentRef.assignmentId)) {
      return {
        status: "assignment_missing",
        courseId: assignmentRef.courseId,
        assignmentId: assignmentRef.assignmentId,
      };
    }
  }

  return {
    status: "valid",
    assignments: courseValidations.flatMap((validation) =>
      validation.status === "available" ? validation.assignments : [],
    ),
  };
};

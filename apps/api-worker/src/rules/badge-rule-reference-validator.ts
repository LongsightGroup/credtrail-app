import type { BadgeIssuanceRuleDefinition } from "@credtrail/validation";
import type { GradebookProvider } from "../lms/gradebook-types";
import { mapConcurrentBounded } from "../utils/map-concurrent-bounded";
import { extractBadgeIssuanceRuleRequirements } from "./engine";

const RULE_REFERENCE_VALIDATION_CONCURRENCY = 4;

export type BadgeRuleReferenceValidationResult =
  | { readonly status: "valid" }
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
    }
  | {
      readonly status: "unavailable";
      readonly courseId: string;
      readonly cause: unknown;
    };

/** Validates every unique rule course through gradebook access and reuses assignment results. */
export const validateBadgeRuleReferences = async (input: {
  readonly provider: GradebookProvider;
  readonly definition: BadgeIssuanceRuleDefinition;
}): Promise<BadgeRuleReferenceValidationResult> => {
  const requirements = extractBadgeIssuanceRuleRequirements(input.definition);
  const courseIds = [
    ...new Set([
      ...requirements.courseIds,
      ...requirements.assignmentRefs.map((assignmentRef) => assignmentRef.courseId),
    ]),
  ];

  if (courseIds.length === 0) {
    return { status: "valid" };
  }

  const courseValidations = await mapConcurrentBounded(
    courseIds,
    { concurrency: RULE_REFERENCE_VALIDATION_CONCURRENCY },
    async (courseId): Promise<CourseAssignmentValidation> => {
      try {
        const assignments = await input.provider.listAssignments({ courseId });
        return {
          status: "available",
          courseId,
          assignmentIds: new Set(
            assignments.map((assignment) => assignment.assignmentId),
          ),
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

  return { status: "valid" };
};

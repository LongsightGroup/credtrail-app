import type { BadgeIssuanceRuleDefinition } from "@credtrail/validation";
import { extractBadgeIssuanceRuleRequirements } from "../rules/engine";
import { mapConcurrentBounded } from "../utils/map-concurrent-bounded";
import type { GradebookAssignmentReader, GradebookCourseRecord } from "./gradebook-types";

const RULE_REFERENCE_LABEL_CONCURRENCY = 4;

/** Display label for a course referenced by one saved badge-rule version. */
export interface BadgeRuleCourseReferenceLabel {
  readonly courseId: string;
  readonly title: string;
}

/** Display label for an assignment referenced by one saved badge-rule version. */
export interface BadgeRuleAssignmentReferenceLabel {
  readonly courseId: string;
  readonly assignmentId: string;
  readonly title: string;
}

/** Partial LMS label projection returned after bounded provider reads. */
export interface BadgeRuleReferenceLabelResolution {
  readonly courses: readonly BadgeRuleCourseReferenceLabel[];
  readonly assignments: readonly BadgeRuleAssignmentReferenceLabel[];
}

interface CourseReferenceLabels {
  readonly course: BadgeRuleCourseReferenceLabel | null;
  readonly assignments: readonly BadgeRuleAssignmentReferenceLabel[];
}

const resolveAssignmentReferenceLabels = async (input: {
  readonly provider: GradebookAssignmentReader;
  readonly courseId: string;
  readonly assignmentIds: ReadonlySet<string>;
}): Promise<readonly BadgeRuleAssignmentReferenceLabel[]> => {
  if (input.assignmentIds.size === 0) {
    return [];
  }

  const assignments = await input.provider.listAssignments({ courseId: input.courseId });
  return assignments
    .filter((assignment) => input.assignmentIds.has(assignment.assignmentId))
    .map((assignment) => ({
      courseId: input.courseId,
      assignmentId: assignment.assignmentId,
      title: assignment.title,
    }));
};

/** Resolves the labels referenced by one parsed rule with bounded LMS work. */
export const resolveBadgeRuleReferenceLabels = async (input: {
  readonly provider: GradebookAssignmentReader;
  readonly courses: readonly GradebookCourseRecord[];
  readonly definition: BadgeIssuanceRuleDefinition;
}): Promise<BadgeRuleReferenceLabelResolution> => {
  const requirements = extractBadgeIssuanceRuleRequirements(input.definition);
  const courseIds = [...new Set(requirements.courseIds)];

  if (courseIds.length === 0) {
    return { courses: [], assignments: [] };
  }

  const assignmentIdsByCourseId = new Map<string, ReadonlySet<string>>();
  const courseById = new Map(input.courses.map((course) => [course.courseId, course]));

  for (const reference of requirements.assignmentRefs) {
    const assignmentIds = new Set(assignmentIdsByCourseId.get(reference.courseId) ?? []);
    assignmentIds.add(reference.assignmentId);
    assignmentIdsByCourseId.set(reference.courseId, assignmentIds);
  }

  const labelsByCourse = await mapConcurrentBounded(
    courseIds,
    { concurrency: RULE_REFERENCE_LABEL_CONCURRENCY },
    async (courseId): Promise<CourseReferenceLabels> => {
      const assignmentIds = assignmentIdsByCourseId.get(courseId) ?? new Set<string>();
      const course = courseById.get(courseId) ?? null;
      const assignments = await resolveAssignmentReferenceLabels({
        provider: input.provider,
        courseId,
        assignmentIds,
      });

      return {
        course: course === null ? null : { courseId, title: course.title },
        assignments,
      };
    },
  );

  return {
    courses: labelsByCourse.flatMap((labels) => (labels.course === null ? [] : [labels.course])),
    assignments: labelsByCourse.flatMap((labels) => labels.assignments),
  };
};

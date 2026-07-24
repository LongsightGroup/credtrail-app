import { asJsonObject, asNonEmptyString, asString } from "../utils/value-parsers";
import {
  CANVAS_GRADEBOOK_FULL_MAX_PAGES,
  CANVAS_PICKER_MAX_PAGES,
  fetchCanvasJsonArrayPages,
} from "./canvas-link-pagination";
import type { GradebookProviderOperation } from "./gradebook-provider-error";
import type {
  CanvasGradebookProviderConfig,
  GradebookAssignmentRecord,
  GradebookCompletionRecord,
  GradebookCourseRecord,
  GradebookCourseSearchResult,
  GradebookEnrollmentRecord,
  GradebookGradeRecord,
  GradebookLearnerRecord,
  GradebookProvider,
  GradebookSubmissionRecord,
} from "./gradebook-types";

interface CreateCanvasGradebookProviderInput {
  config: CanvasGradebookProviderConfig;
  fetchImpl?: typeof fetch;
}

const asIdentifier = (value: unknown): string | null => {
  if (typeof value === "string") {
    const trimmed = value.trim();
    return trimmed.length === 0 ? null : trimmed;
  }

  if (typeof value === "number" && Number.isFinite(value)) {
    return value.toString();
  }

  return null;
};

const asNumber = (value: unknown): number | null => {
  if (typeof value === "number" && Number.isFinite(value)) {
    return value;
  }

  if (typeof value === "string") {
    const parsed = Number.parseFloat(value);
    return Number.isFinite(parsed) ? parsed : null;
  }

  return null;
};

const asBoolean = (value: unknown): boolean | null => {
  return typeof value === "boolean" ? value : null;
};

const asIsoTimestamp = (value: unknown): string | null => {
  const timestamp = asNonEmptyString(value);

  if (timestamp === null) {
    return null;
  }

  return Number.isFinite(Date.parse(timestamp)) ? timestamp : null;
};

const ensureHttpBaseUrl = (candidate: string): URL => {
  let parsed: URL;

  try {
    parsed = new URL(candidate);
  } catch {
    throw new Error("Gradebook provider apiBaseUrl must be a valid absolute URL");
  }

  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    throw new Error("Gradebook provider apiBaseUrl must use http or https");
  }

  if (!parsed.pathname.endsWith("/")) {
    parsed.pathname = `${parsed.pathname}/`;
  }

  return parsed;
};

const parseCourseRecord = (candidate: unknown): GradebookCourseRecord | null => {
  const course = asJsonObject(candidate);

  if (course === null) {
    return null;
  }

  const courseId = asIdentifier(course.id);
  const title = asNonEmptyString(course.name);

  if (courseId === null || title === null) {
    return null;
  }

  return {
    courseId,
    title,
    courseCode: asString(course.course_code),
    workflowState: asString(course.workflow_state),
    startsAt: asIsoTimestamp(course.start_at),
    endsAt: asIsoTimestamp(course.end_at),
  };
};

const parseAssignmentRecord = (
  courseId: string,
  candidate: unknown,
): GradebookAssignmentRecord | null => {
  const assignment = asJsonObject(candidate);

  if (assignment === null) {
    return null;
  }

  const assignmentId = asIdentifier(assignment.id);
  const title = asNonEmptyString(assignment.name);

  if (assignmentId === null || title === null) {
    return null;
  }

  return {
    assignmentId,
    courseId,
    title,
    workflowState: asString(assignment.workflow_state),
    pointsPossible: asNumber(assignment.points_possible),
    dueAt: asIsoTimestamp(assignment.due_at),
  };
};

const parseEnrollmentRecord = (
  courseId: string,
  candidate: unknown,
): GradebookEnrollmentRecord | null => {
  const enrollment = asJsonObject(candidate);

  if (enrollment === null) {
    return null;
  }

  const learnerId = asIdentifier(enrollment.user_id);
  const enrollmentState = asNonEmptyString(enrollment.enrollment_state);

  if (learnerId === null || enrollmentState === null) {
    return null;
  }

  return {
    courseId,
    learnerId,
    enrollmentState,
    role: asString(enrollment.type),
    startedAt: asIsoTimestamp(enrollment.created_at),
    lastActivityAt: asIsoTimestamp(enrollment.last_activity_at),
  };
};

const parseLearnerRecord = (
  courseId: string,
  candidate: unknown,
): GradebookLearnerRecord | null => {
  const user = asJsonObject(candidate);

  if (user === null) {
    return null;
  }

  const learnerId = asIdentifier(user.id);
  const displayName = asNonEmptyString(user.name);

  if (learnerId === null || displayName === null) {
    return null;
  }

  return {
    courseId,
    learnerId,
    displayName,
    email: asNonEmptyString(user.email),
  };
};

const parseSubmissionRecord = (
  courseId: string,
  candidate: unknown,
): GradebookSubmissionRecord | null => {
  const submission = asJsonObject(candidate);

  if (submission === null) {
    return null;
  }

  const learnerId = asIdentifier(submission.user_id);
  const assignmentId = asIdentifier(submission.assignment_id);

  if (learnerId === null || assignmentId === null) {
    return null;
  }

  return {
    courseId,
    learnerId,
    assignmentId,
    workflowState: asString(submission.workflow_state),
    score: asNumber(submission.score),
    submittedAt: asIsoTimestamp(submission.submitted_at),
    gradedAt: asIsoTimestamp(submission.graded_at),
    late: asBoolean(submission.late),
    missing: asBoolean(submission.missing),
  };
};

const parseGradeRecord = (courseId: string, candidate: unknown): GradebookGradeRecord | null => {
  const enrollment = asJsonObject(candidate);

  if (enrollment === null) {
    return null;
  }

  const learnerId = asIdentifier(enrollment.user_id);
  const grades = asJsonObject(enrollment.grades);

  if (learnerId === null || grades === null) {
    return null;
  }

  return {
    courseId,
    learnerId,
    currentScore: asNumber(grades.current_score),
    finalScore: asNumber(grades.final_score),
    currentGrade: asString(grades.current_grade),
    finalGrade: asString(grades.final_grade),
  };
};

const parseCompletionRecord = (
  courseId: string,
  enrollment: GradebookEnrollmentRecord,
  assignments: readonly GradebookAssignmentRecord[],
  submissions: readonly GradebookSubmissionRecord[],
): GradebookCompletionRecord | null => {
  if (assignments.length === 0) {
    return {
      courseId,
      learnerId: enrollment.learnerId,
      completed: false,
      completedAt: null,
      completionPercent: null,
      sourceState: null,
    };
  }

  const completedAssignmentIds = new Set(
    submissions
      .filter((submission) => submission.learnerId === enrollment.learnerId)
      .filter((submission) => {
        if (submission.missing === true) {
          return false;
        }

        return (
          submission.score !== null ||
          submission.submittedAt !== null ||
          submission.gradedAt !== null ||
          submission.workflowState === "submitted" ||
          submission.workflowState === "graded" ||
          submission.workflowState === "pending_review"
        );
      })
      .map((submission) => submission.assignmentId),
  );
  const assignmentIds = new Set(assignments.map((assignment) => assignment.assignmentId));
  const completedItems = [...completedAssignmentIds].filter((assignmentId) => {
    return assignmentIds.has(assignmentId);
  }).length;
  const completionPercent = (completedItems / assignments.length) * 100;

  return {
    courseId,
    learnerId: enrollment.learnerId,
    completed: completionPercent >= 100,
    completedAt: null,
    completionPercent,
    sourceState: "gradebook_items",
  };
};

export const createCanvasGradebookProvider = (
  input: CreateCanvasGradebookProviderInput,
): GradebookProvider => {
  const { config } = input;
  const fetchImpl = input.fetchImpl ?? fetch;
  const apiBaseUrl = ensureHttpBaseUrl(config.apiBaseUrl);
  const rawEnrollmentsCache = new Map<string, Promise<readonly unknown[]>>();
  const assignmentsCache = new Map<string, Promise<readonly GradebookAssignmentRecord[]>>();
  const submissionsCache = new Map<string, Promise<readonly GradebookSubmissionRecord[]>>();

  const readCachedArray = <T>(
    cache: Map<string, Promise<readonly T[]>>,
    key: string,
    load: () => Promise<readonly T[]>,
  ): Promise<readonly T[]> => {
    const cached = cache.get(key);

    if (cached !== undefined) {
      return cached;
    }

    const pending = load();
    cache.set(key, pending);
    return pending;
  };

  const enrollmentCacheKey = (input: { courseId: string; learnerId?: string }): string => {
    return JSON.stringify([input.courseId, input.learnerId ?? null]);
  };

  const submissionsCacheKey = (input: {
    courseId: string;
    assignmentId?: string;
    learnerId?: string;
  }): string => {
    return JSON.stringify([input.courseId, input.assignmentId ?? null, input.learnerId ?? null]);
  };

  const requestArray = async (
    path: string,
    query: URLSearchParams | undefined,
    maxPages: number,
    onMaxPages: "truncate" | "throw",
    operation: GradebookProviderOperation,
  ): Promise<readonly unknown[]> => {
    return fetchCanvasJsonArrayPages({
      apiBaseUrl,
      fetchImpl,
      accessToken: config.accessToken,
      path,
      ...(query !== undefined ? { query } : {}),
      maxPages,
      onMaxPages,
      operation,
    });
  };

  const listRawEnrollments = async (input: {
    courseId: string;
    learnerId?: string;
  }): Promise<readonly unknown[]> => {
    return readCachedArray(rawEnrollmentsCache, enrollmentCacheKey(input), async () => {
      const query = new URLSearchParams();
      query.set("per_page", "100");
      query.append("type[]", "StudentEnrollment");

      if (input.learnerId !== undefined) {
        query.append("student_ids[]", input.learnerId);
      }

      return requestArray(
        `/api/v1/courses/${encodeURIComponent(input.courseId)}/enrollments`,
        query,
        CANVAS_GRADEBOOK_FULL_MAX_PAGES,
        "throw",
        "gradebook_read",
      );
    });
  };

  const listAssignmentsForCourse = async (
    courseId: string,
  ): Promise<readonly GradebookAssignmentRecord[]> => {
    return readCachedArray(assignmentsCache, courseId, async () => {
      const query = new URLSearchParams();
      query.set("per_page", "100");
      const assignments = await requestArray(
        `/api/v1/courses/${encodeURIComponent(courseId)}/assignments`,
        query,
        CANVAS_GRADEBOOK_FULL_MAX_PAGES,
        "throw",
        "gradebook_read",
      );
      const normalizedAssignments = assignments
        .map((assignment) => parseAssignmentRecord(courseId, assignment))
        .filter((assignment): assignment is GradebookAssignmentRecord => assignment !== null);
      return normalizedAssignments;
    });
  };

  const fetchSubmissions = async (input: {
    courseId: string;
    assignmentId?: string;
    learnerId?: string;
  }): Promise<readonly GradebookSubmissionRecord[]> => {
    const query = new URLSearchParams();
    query.set("per_page", "100");

    if (input.assignmentId !== undefined) {
      query.append("assignment_ids[]", input.assignmentId);
    }

    if (input.learnerId !== undefined) {
      query.append("student_ids[]", input.learnerId);
    }

    const submissions = await requestArray(
      `/api/v1/courses/${encodeURIComponent(input.courseId)}/students/submissions`,
      query,
      CANVAS_GRADEBOOK_FULL_MAX_PAGES,
      "throw",
      "gradebook_read",
    );
    const normalizedSubmissions = submissions
      .map((submission) => parseSubmissionRecord(input.courseId, submission))
      .filter((submission): submission is GradebookSubmissionRecord => submission !== null);
    return normalizedSubmissions;
  };

  const listSubmissionsForCourse = async (input: {
    courseId: string;
    assignmentId?: string;
    learnerId?: string;
  }): Promise<readonly GradebookSubmissionRecord[]> => {
    if (input.assignmentId !== undefined) {
      const allSubmissionsKey = submissionsCacheKey({
        courseId: input.courseId,
        ...(input.learnerId !== undefined ? { learnerId: input.learnerId } : {}),
      });
      const allSubmissions = submissionsCache.get(allSubmissionsKey);

      if (allSubmissions !== undefined) {
        const submissions = await allSubmissions;
        return submissions.filter((submission) => submission.assignmentId === input.assignmentId);
      }
    }

    return readCachedArray(submissionsCache, submissionsCacheKey(input), async () => {
      return fetchSubmissions(input);
    });
  };

  return {
    kind: "canvas",
    listCourses: async (input): Promise<GradebookCourseSearchResult> => {
      const query = new URLSearchParams();
      query.set("per_page", "100");
      query.set("enrollment_state", "active");
      const courses = await requestArray(
        "/api/v1/courses",
        query,
        CANVAS_GRADEBOOK_FULL_MAX_PAGES,
        "throw",
        "course_search",
      );
      const normalizedCourses = courses
        .map((course) => parseCourseRecord(course))
        .filter((course): course is GradebookCourseRecord => course !== null);
      const searchTerm = input.searchTerm?.trim().toLocaleLowerCase() ?? "";

      const matchingCourses = normalizedCourses
        .filter((course) => {
          if (searchTerm.length === 0) {
            return true;
          }

          return [course.title, course.courseCode ?? "", course.courseId].some((value) =>
            value.toLocaleLowerCase().includes(searchTerm),
          );
        })
        .sort(
          (left, right) =>
            left.title.localeCompare(right.title) || left.courseId.localeCompare(right.courseId),
        );

      return {
        courses: matchingCourses.slice(0, input.limit),
        hasMore: matchingCourses.length > input.limit,
      };
    },
    listAssignments: async (input): Promise<readonly GradebookAssignmentRecord[]> => {
      return listAssignmentsForCourse(input.courseId);
    },
    listEnrollments: async (input): Promise<readonly GradebookEnrollmentRecord[]> => {
      const enrollments = await listRawEnrollments(input);
      const normalizedEnrollments = enrollments
        .map((enrollment) => parseEnrollmentRecord(input.courseId, enrollment))
        .filter((enrollment): enrollment is GradebookEnrollmentRecord => enrollment !== null);
      return normalizedEnrollments;
    },
    listLearners: async (input): Promise<readonly GradebookLearnerRecord[]> => {
      const query = new URLSearchParams();
      query.set("per_page", "100");
      query.append("enrollment_type[]", "student");
      query.append("enrollment_state[]", "active");
      const users = await requestArray(
        `/api/v1/courses/${encodeURIComponent(input.courseId)}/users`,
        query,
        CANVAS_PICKER_MAX_PAGES,
        "truncate",
        "learner_search",
      );
      const searchTerm = input.searchTerm?.trim().toLocaleLowerCase() ?? "";

      return users
        .map((user) => parseLearnerRecord(input.courseId, user))
        .filter((learner): learner is GradebookLearnerRecord => learner !== null)
        .filter((learner) => {
          if (searchTerm.length === 0) {
            return true;
          }

          return [learner.displayName, learner.email ?? "", learner.learnerId].some((value) =>
            value.toLocaleLowerCase().includes(searchTerm),
          );
        });
    },
    listSubmissions: async (input): Promise<readonly GradebookSubmissionRecord[]> => {
      return listSubmissionsForCourse(input);
    },
    listGrades: async (input): Promise<readonly GradebookGradeRecord[]> => {
      const enrollments = await listRawEnrollments(input);
      const normalizedGrades = enrollments
        .map((enrollment) => parseGradeRecord(input.courseId, enrollment))
        .filter((grade): grade is GradebookGradeRecord => grade !== null);
      return normalizedGrades;
    },
    listCompletions: async (input): Promise<readonly GradebookCompletionRecord[]> => {
      const [rawEnrollments, assignments, submissions] = await Promise.all([
        listRawEnrollments(input),
        listAssignmentsForCourse(input.courseId),
        listSubmissionsForCourse({
          courseId: input.courseId,
          ...(input.learnerId !== undefined ? { learnerId: input.learnerId } : {}),
        }),
      ]);
      const normalizedEnrollments = rawEnrollments
        .map((enrollment) => parseEnrollmentRecord(input.courseId, enrollment))
        .filter((enrollment): enrollment is GradebookEnrollmentRecord => enrollment !== null);
      const normalizedCompletions = normalizedEnrollments
        .map((enrollment) =>
          parseCompletionRecord(input.courseId, enrollment, assignments, submissions),
        )
        .filter((completion): completion is GradebookCompletionRecord => completion !== null);
      return normalizedCompletions;
    },
  };
};

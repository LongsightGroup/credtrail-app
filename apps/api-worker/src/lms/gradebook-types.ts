export const GRADEBOOK_PROVIDER_KINDS = [
  "canvas",
  "moodle",
  "blackboard_ultra",
  "d2l_brightspace",
  "sakai",
] as const;

export type GradebookProviderKind = (typeof GRADEBOOK_PROVIDER_KINDS)[number];

export interface GradebookCourseRecord {
  courseId: string;
  title: string;
  courseCode: string | null;
  workflowState: string | null;
  startsAt: string | null;
  endsAt: string | null;
}

export interface GradebookCourseSearchInput {
  readonly searchTerm?: string;
  readonly limit: number;
}

export interface GradebookCourseSearchResult {
  readonly courses: readonly GradebookCourseRecord[];
  readonly hasMore: boolean;
}

export interface GradebookCourseAccessResult {
  readonly authorizedCourses: readonly GradebookCourseRecord[];
  readonly unauthorizedCourseIds: readonly string[];
}

/** Caller-owned cancellation options for gradebook and LMS network work. */
export interface GradebookRequestOptions {
  readonly signal?: AbortSignal;
}

/** Course discovery and verification bound to one provider authorization boundary. */
export interface GradebookCourseCatalog {
  listCourses(
    input: GradebookCourseSearchInput,
    options?: GradebookRequestOptions,
  ): Promise<GradebookCourseSearchResult>;
  verifyCourseAccess(
    input: {
      readonly courseIds: readonly string[];
    },
    options?: GradebookRequestOptions,
  ): Promise<GradebookCourseAccessResult>;
}

export interface GradebookAssignmentRecord {
  assignmentId: string;
  courseId: string;
  title: string;
  workflowState: string | null;
  pointsPossible: number | null;
  dueAt: string | null;
}

export interface GradebookEnrollmentRecord {
  courseId: string;
  learnerId: string;
  enrollmentState: string;
  role: string | null;
  startedAt: string | null;
  lastActivityAt: string | null;
}

export interface GradebookLearnerRecord {
  courseId: string;
  learnerId: string;
  displayName: string;
  email: string | null;
}

export interface GradebookSubmissionRecord {
  courseId: string;
  assignmentId: string;
  learnerId: string;
  workflowState: string | null;
  score: number | null;
  submittedAt: string | null;
  gradedAt: string | null;
  late: boolean | null;
  missing: boolean | null;
}

export interface GradebookGradeRecord {
  courseId: string;
  learnerId: string;
  currentScore: number | null;
  finalScore: number | null;
  currentGrade: string | null;
  finalGrade: string | null;
}

export interface GradebookCompletionRecord {
  courseId: string;
  learnerId: string;
  completed: boolean;
  completedAt: string | null;
  completionPercent: number | null;
  sourceState: string | null;
}

/** Reads assignment metadata for course setup and reference validation. */
export interface GradebookAssignmentReader {
  listAssignments(
    input: {
      readonly courseId: string;
    },
    options?: GradebookRequestOptions,
  ): Promise<readonly GradebookAssignmentRecord[]>;
}

/** Reads enrollment records for one LMS course. */
export interface GradebookEnrollmentReader {
  listEnrollments(
    input: {
      readonly courseId: string;
      readonly learnerId?: string;
    },
    options?: GradebookRequestOptions,
  ): Promise<readonly GradebookEnrollmentRecord[]>;
}

/** Reads learner rosters for discovery and automated evaluation. */
export interface GradebookLearnerReader {
  listLearners(
    input: {
      readonly courseId: string;
      readonly searchTerm?: string;
    },
    options?: GradebookRequestOptions,
  ): Promise<readonly GradebookLearnerRecord[]>;
}

/** Reads assignment submissions for rule setup and evaluation. */
export interface GradebookSubmissionReader {
  listSubmissions(
    input: {
      readonly courseId: string;
      readonly assignmentId?: string;
      readonly learnerId?: string;
    },
    options?: GradebookRequestOptions,
  ): Promise<readonly GradebookSubmissionRecord[]>;
}

/** Reads the grade, completion, and submission facts required by badge rules. */
export interface GradebookRuleFactReader extends GradebookSubmissionReader {
  listGrades(
    input: {
      readonly courseId: string;
      readonly learnerId?: string;
    },
    options?: GradebookRequestOptions,
  ): Promise<readonly GradebookGradeRecord[]>;
  listCompletions(
    input: {
      readonly courseId: string;
      readonly learnerId?: string;
    },
    options?: GradebookRequestOptions,
  ): Promise<readonly GradebookCompletionRecord[]>;
}

/** Reads the roster and rule facts needed for automated badge evaluation. */
export type GradebookAutomatedEvaluationReader = GradebookLearnerReader & GradebookRuleFactReader;

/** Reads the assignment metadata and submissions needed by gradebook-item setup. */
export type GradebookItemSetupReader = GradebookAssignmentReader & GradebookSubmissionReader;

/** Full adapter contract implemented by supported LMS gradebook providers. */
export interface GradebookProvider
  extends GradebookAssignmentReader, GradebookEnrollmentReader, GradebookAutomatedEvaluationReader {
  readonly kind: GradebookProviderKind;
}

/** Canvas provider whose course catalog is bound to a linked Canvas user. */
export interface CanvasGradebookProvider extends GradebookProvider {
  readonly kind: "canvas";
  courseCatalogForUser(providerUserId: string): GradebookCourseCatalog;
}

/** Sakai provider whose course catalog is bound to the saved institutional connection. */
export interface SakaiGradebookProvider extends GradebookProvider {
  readonly kind: "sakai";
  courseCatalogForConnection(): GradebookCourseCatalog;
}

/** Implemented LMS providers that expose a course-authoring catalog. */
export type CourseAuthoringGradebookProvider = CanvasGradebookProvider | SakaiGradebookProvider;

interface GradebookProviderConfigBase {
  kind: GradebookProviderKind;
  apiBaseUrl: string;
  accessToken: string;
}

export interface CanvasGradebookProviderConfig extends GradebookProviderConfigBase {
  kind: "canvas";
}

export interface MoodleGradebookProviderConfig extends GradebookProviderConfigBase {
  kind: "moodle";
}

export interface BlackboardUltraGradebookProviderConfig extends GradebookProviderConfigBase {
  kind: "blackboard_ultra";
}

export interface D2LBrightspaceGradebookProviderConfig extends GradebookProviderConfigBase {
  kind: "d2l_brightspace";
}

export interface SakaiGradebookProviderConfig extends GradebookProviderConfigBase {
  kind: "sakai";
}

export type GradebookProviderConfig =
  | CanvasGradebookProviderConfig
  | MoodleGradebookProviderConfig
  | BlackboardUltraGradebookProviderConfig
  | D2LBrightspaceGradebookProviderConfig
  | SakaiGradebookProviderConfig;

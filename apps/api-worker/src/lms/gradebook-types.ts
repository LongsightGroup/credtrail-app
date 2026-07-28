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
  readonly providerUserId: string;
  readonly searchTerm?: string;
  readonly limit: number;
}

export interface GradebookCourseSearchResult {
  readonly courses: readonly GradebookCourseRecord[];
  readonly hasMore: boolean;
}

export interface GradebookCourseAccessResult {
  readonly unauthorizedCourseIds: readonly string[];
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

export interface GradebookProvider {
  readonly kind: GradebookProviderKind;
  listCourses(input: GradebookCourseSearchInput): Promise<GradebookCourseSearchResult>;
  verifyCourseAccess(input: {
    readonly providerUserId: string;
    readonly courseIds: readonly string[];
  }): Promise<GradebookCourseAccessResult>;
  listAssignments(input: { courseId: string }): Promise<readonly GradebookAssignmentRecord[]>;
  listEnrollments(input: {
    courseId: string;
    learnerId?: string;
  }): Promise<readonly GradebookEnrollmentRecord[]>;
  listLearners(input: {
    courseId: string;
    searchTerm?: string;
  }): Promise<readonly GradebookLearnerRecord[]>;
  listSubmissions(input: {
    courseId: string;
    assignmentId?: string;
    learnerId?: string;
  }): Promise<readonly GradebookSubmissionRecord[]>;
  listGrades(input: {
    courseId: string;
    learnerId?: string;
  }): Promise<readonly GradebookGradeRecord[]>;
  listCompletions(input: {
    courseId: string;
    learnerId?: string;
  }): Promise<readonly GradebookCompletionRecord[]>;
}

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

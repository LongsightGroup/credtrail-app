import type { TenantLmsConnectionRecord } from "@credtrail/db";
import type {
  GradebookAssignmentRecord,
  GradebookAssignmentReader,
  GradebookRequestOptions,
  GradebookSubmissionReader,
  GradebookSubmissionRecord,
} from "./gradebook-types";
import { GradebookProviderError } from "./gradebook-provider-error";

export interface WorkflowStateOption {
  value: string;
  label: string;
  source: "default" | "observed";
  preselected: boolean;
}

export interface GradebookPickerConnection {
  id: string;
  providerKind: "canvas" | "sakai";
}

/** Admin and LTI LMS pickers load results into HTML selects; keep HTTP payloads bounded. */
export const LMS_PICKER_MAX_GRADEBOOK_ITEMS = 200;

const searchMatches = (query: string | undefined, values: readonly (string | null)[]): boolean => {
  if (query === undefined || query.trim().length === 0) {
    return true;
  }

  const normalizedQuery = query.trim().toLowerCase();
  return values.some((value) => value !== null && value.toLowerCase().includes(normalizedQuery));
};

export const assignmentMatches = (
  query: string | undefined,
  assignment: GradebookAssignmentRecord,
): boolean => {
  return searchMatches(query, [
    assignment.assignmentId,
    assignment.courseId,
    assignment.title,
    assignment.workflowState,
  ]);
};

const workflowStateLabel = (value: string): string => {
  return value
    .split("_")
    .map((part) => (part.length === 0 ? part : part[0]?.toUpperCase() + part.slice(1)))
    .join(" ");
};

export const defaultWorkflowStates = (
  providerKind: "canvas" | "sakai",
): readonly WorkflowStateOption[] => {
  if (providerKind === "canvas") {
    return [
      { value: "submitted", label: "Submitted", source: "default", preselected: true },
      { value: "unsubmitted", label: "Unsubmitted", source: "default", preselected: false },
      { value: "graded", label: "Graded", source: "default", preselected: true },
      { value: "pending_review", label: "Pending review", source: "default", preselected: false },
    ];
  }

  return [{ value: "graded", label: "Graded", source: "default", preselected: true }];
};

export const mergeWorkflowStates = (input: {
  defaults: readonly WorkflowStateOption[];
  observedStates: Iterable<string>;
}): WorkflowStateOption[] => {
  const byValue = new Map<string, WorkflowStateOption>();

  for (const option of input.defaults) {
    byValue.set(option.value, option);
  }

  for (const observedState of input.observedStates) {
    const value = observedState.trim();

    if (value.length === 0 || byValue.has(value)) {
      continue;
    }

    byValue.set(value, {
      value,
      label: workflowStateLabel(value),
      source: "observed",
      preselected: false,
    });
  }

  return Array.from(byValue.values()).sort((left, right) => {
    if (left.source !== right.source) {
      return left.source === "default" ? -1 : 1;
    }

    return left.label.localeCompare(right.label);
  });
};

export const observedWorkflowStates = (
  submissions: readonly GradebookSubmissionRecord[],
): Set<string> => {
  const states = new Set<string>();

  for (const submission of submissions) {
    if (submission.workflowState !== null && submission.workflowState.length > 0) {
      states.add(submission.workflowState);
    }
  }

  return states;
};

export const lmsLookupErrorMessage = (
  connection: Pick<TenantLmsConnectionRecord, "providerKind">,
  error: unknown,
  fallback: string,
): string => {
  if (
    error instanceof GradebookProviderError &&
    error.providerKind === "sakai" &&
    connection.providerKind === "sakai" &&
    error.statusCode === 403 &&
    error.operation === "course_search"
  ) {
    return "Sakai blocked CredTrail from searching courses (403). Save a Sakai administrator username and password, then try again. If it still fails, ask a Sakai administrator to allow EntityBroker Sites and Gradebook access.";
  }

  if (
    error instanceof GradebookProviderError &&
    error.providerKind === "sakai" &&
    connection.providerKind === "sakai" &&
    error.statusCode === 403 &&
    error.operation === "gradebook_read"
  ) {
    return "Sakai blocked CredTrail from reading this course gradebook (403). Confirm that the saved Sakai account can view the course and gradebook, then try again.";
  }

  return fallback;
};

export const listGradebookItemsForCourse = async (
  input: {
    provider: GradebookAssignmentReader;
    courseId: string;
    query: string | undefined;
  },
  options: GradebookRequestOptions = {},
): Promise<readonly GradebookAssignmentRecord[]> => {
  return (await input.provider.listAssignments({ courseId: input.courseId }, options))
    .filter((assignment) => assignmentMatches(input.query, assignment))
    .slice(0, LMS_PICKER_MAX_GRADEBOOK_ITEMS);
};

export const listWorkflowStatesForAssignment = async (
  input: {
    provider: GradebookSubmissionReader;
    connection: GradebookPickerConnection;
    courseId: string;
    assignmentId: string;
  },
  options: GradebookRequestOptions = {},
): Promise<WorkflowStateOption[]> => {
  const submissions = await input.provider.listSubmissions(
    {
      courseId: input.courseId,
      assignmentId: input.assignmentId,
    },
    options,
  );

  return mergeWorkflowStates({
    defaults: defaultWorkflowStates(input.connection.providerKind),
    observedStates: observedWorkflowStates(submissions),
  });
};

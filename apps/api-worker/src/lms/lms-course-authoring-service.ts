import type { SqlDatabase } from "@credtrail/db";
import type { BadgeIssuanceRuleDefinition } from "@credtrail/validation";
import { extractBadgeIssuanceRuleRequirements } from "../rules/engine";
import {
  listGradebookItemsForCourse,
  listWorkflowStatesForAssignment,
  lmsLookupErrorMessage,
  type WorkflowStateOption,
} from "./gradebook-picker";
import { isGradebookProviderRequestCancelled } from "./gradebook-provider-error";
import { gradebookRequestOptionsWithDeadline } from "./gradebook-request-options";
import {
  GradebookProviderResolutionError,
  resolveGradebookProviderWithConnection,
  type ResolvedGradebookProvider,
} from "./gradebook-provider-resolution";
import type {
  GradebookAssignmentRecord,
  GradebookCourseCatalog,
  GradebookCourseRecord,
  GradebookLearnerRecord,
  GradebookRequestOptions,
} from "./gradebook-types";
import {
  resolveBadgeRuleReferenceLabels,
  type BadgeRuleReferenceLabelResolution,
} from "./badge-rule-reference-labels";
import { lmsCourseAuthorizationFromAccess, resolveLmsCourseCatalog } from "./user-course-access";

/** Expected failure returned by the LMS course-authoring use case. */
export type LmsCourseAuthoringFailure =
  | { readonly status: "connection_not_found"; readonly error: string }
  | { readonly status: "connection_unusable"; readonly error: string }
  | { readonly status: "dependency_unavailable"; readonly error: string }
  | { readonly status: "identity_unlinked"; readonly error: string }
  | { readonly status: "course_unauthorized"; readonly error: string }
  | { readonly status: "request_cancelled"; readonly error: string }
  | { readonly status: "provider_unavailable"; readonly error: string };

type LmsCourseAuthoringResult<T extends object> =
  | ({ readonly status: "resolved" } & T)
  | LmsCourseAuthoringFailure;

interface LmsCourseAuthoringRequest {
  readonly db: SqlDatabase;
  readonly tenantId: string;
  readonly connectionId: string;
  readonly userId: string;
}

/** Search input for LMS courses visible to one authoring user. */
export interface SearchLmsCoursesInput extends LmsCourseAuthoringRequest {
  readonly searchTerm?: string;
  readonly limit: number;
}

/** Input for resolving exact LMS courses visible to one authoring user. */
export interface ResolveLmsCoursesInput extends LmsCourseAuthoringRequest {
  readonly courseIds: readonly string[];
}

/** Search input for learners in one authorized LMS course. */
export interface SearchLmsLearnersInput extends LmsCourseAuthoringRequest {
  readonly courseId: string;
  readonly searchTerm?: string;
  readonly limit: number;
}

/** Input for listing gradebook items in one authorized LMS course. */
export interface ListLmsGradebookItemsInput extends LmsCourseAuthoringRequest {
  readonly courseId: string;
  readonly searchTerm?: string;
}

/** Input for listing workflow states from one authorized LMS assignment. */
export interface ListLmsWorkflowStatesInput extends LmsCourseAuthoringRequest {
  readonly courseId: string;
  readonly assignmentId: string;
}

/** Input for resolving display labels from authorized LMS rule references. */
export interface ResolveLmsReferenceLabelsInput extends LmsCourseAuthoringRequest {
  readonly definition: BadgeIssuanceRuleDefinition;
}

/** Caller-owned cancellation options for one LMS course-authoring operation. */
export type LmsCourseAuthoringOptions = GradebookRequestOptions;

/** Cohesive LMS course-authoring operations shared by HTTP and rule-label workflows. */
export interface LmsCourseAuthoringService {
  /** Searches courses within the current user's provider authorization boundary. */
  searchCourses(
    input: SearchLmsCoursesInput,
    options?: LmsCourseAuthoringOptions,
  ): Promise<
    LmsCourseAuthoringResult<{
      readonly courses: readonly GradebookCourseRecord[];
      readonly hasMore: boolean;
    }>
  >;

  /** Resolves exact courses within the current user's provider authorization boundary. */
  resolveCourses(
    input: ResolveLmsCoursesInput,
    options?: LmsCourseAuthoringOptions,
  ): Promise<LmsCourseAuthoringResult<{ readonly courses: readonly GradebookCourseRecord[] }>>;

  /** Searches learners after verifying that the current user can author against the course. */
  searchLearners(
    input: SearchLmsLearnersInput,
    options?: LmsCourseAuthoringOptions,
  ): Promise<
    LmsCourseAuthoringResult<{
      readonly learners: readonly GradebookLearnerRecord[];
      readonly hasMore: boolean;
    }>
  >;

  /** Lists gradebook items after verifying course authoring access. */
  listGradebookItems(
    input: ListLmsGradebookItemsInput,
    options?: LmsCourseAuthoringOptions,
  ): Promise<LmsCourseAuthoringResult<{ readonly items: readonly GradebookAssignmentRecord[] }>>;

  /** Lists assignment workflow states after verifying course authoring access. */
  listWorkflowStates(
    input: ListLmsWorkflowStatesInput,
    options?: LmsCourseAuthoringOptions,
  ): Promise<LmsCourseAuthoringResult<{ readonly states: readonly WorkflowStateOption[] }>>;

  /** Resolves course and assignment labels after authorizing every referenced course. */
  resolveReferenceLabels(
    input: ResolveLmsReferenceLabelsInput,
    options?: LmsCourseAuthoringOptions,
  ): Promise<LmsCourseAuthoringResult<{ readonly labels: BadgeRuleReferenceLabelResolution }>>;
}

interface CreateLmsCourseAuthoringServiceInput {
  readonly currentTimestamp: () => string;
  readonly fetchImpl?: typeof fetch;
  readonly requestTimeoutMs: number;
}

type ResolvedProviderResult = LmsCourseAuthoringResult<{
  readonly resolvedProvider: ResolvedGradebookProvider;
}>;

type ResolvedCatalogResult = LmsCourseAuthoringResult<{
  readonly catalog: GradebookCourseCatalog;
}>;

const providerFailure = (
  resolvedProvider: ResolvedGradebookProvider,
  cause: unknown,
  fallback: string,
  options: GradebookRequestOptions,
): LmsCourseAuthoringFailure => {
  if (isGradebookProviderRequestCancelled(cause, options)) {
    return { status: "request_cancelled", error: "LMS request was cancelled" };
  }

  return {
    status: "provider_unavailable",
    error: lmsLookupErrorMessage(resolvedProvider.connection, cause, fallback),
  };
};

/** Creates the LMS course-authoring use case with explicit time and remote transport dependencies. */
export const createLmsCourseAuthoringService = (
  dependencies: CreateLmsCourseAuthoringServiceInput,
): LmsCourseAuthoringService => {
  const requestOptions = (options: LmsCourseAuthoringOptions): GradebookRequestOptions =>
    gradebookRequestOptionsWithDeadline(options, dependencies.requestTimeoutMs);

  const resolveProvider = async (
    input: LmsCourseAuthoringRequest,
    options: GradebookRequestOptions,
  ): Promise<ResolvedProviderResult> => {
    try {
      const resolvedProvider = await resolveGradebookProviderWithConnection(
        {
          db: input.db,
          tenantId: input.tenantId,
          lmsConnectionId: input.connectionId,
          nowIso: dependencies.currentTimestamp(),
          ...(dependencies.fetchImpl === undefined ? {} : { fetchImpl: dependencies.fetchImpl }),
        },
        options,
      );
      return { status: "resolved", resolvedProvider };
    } catch (cause: unknown) {
      if (cause instanceof GradebookProviderResolutionError) {
        if (cause.reason === "cancelled") {
          return { status: "request_cancelled", error: cause.message };
        }

        if (cause.reason === "not_found") {
          return { status: "connection_not_found", error: cause.message };
        }

        return { status: "connection_unusable", error: cause.message };
      }

      return options.signal?.aborted === true
        ? { status: "request_cancelled", error: "LMS request was cancelled" }
        : {
            status: "dependency_unavailable",
            error: "Unable to load the LMS connection",
          };
    }
  };

  const resolveCatalog = async (
    input: LmsCourseAuthoringRequest,
    resolvedProvider: ResolvedGradebookProvider,
    options: GradebookRequestOptions,
  ): Promise<ResolvedCatalogResult> => {
    try {
      options.signal?.throwIfAborted();
      const catalog = await resolveLmsCourseCatalog({
        db: input.db,
        resolvedProvider,
        userId: input.userId,
      });
      options.signal?.throwIfAborted();
      return catalog;
    } catch {
      return options.signal?.aborted === true
        ? { status: "request_cancelled", error: "LMS request was cancelled" }
        : {
            status: "dependency_unavailable",
            error: "Unable to load LMS user access",
          };
    }
  };

  const authorizeCourses = async (
    input: LmsCourseAuthoringRequest & { readonly courseIds: readonly string[] },
    options: GradebookRequestOptions,
  ): Promise<
    LmsCourseAuthoringResult<{
      readonly resolvedProvider: ResolvedGradebookProvider;
      readonly courses: readonly GradebookCourseRecord[];
    }>
  > => {
    const providerResult = await resolveProvider(input, options);

    if (providerResult.status !== "resolved") {
      return providerResult;
    }

    const { resolvedProvider } = providerResult;
    const catalogResult = await resolveCatalog(input, resolvedProvider, options);

    if (catalogResult.status !== "resolved") {
      return catalogResult;
    }

    try {
      const access = await catalogResult.catalog.verifyCourseAccess(
        { courseIds: input.courseIds },
        options,
      );
      const authorization = lmsCourseAuthorizationFromAccess({
        resolvedProvider,
        access,
      });

      if (authorization.status === "identity_unlinked") {
        return authorization;
      }

      if (authorization.status === "course_unauthorized") {
        return { status: "course_unauthorized", error: authorization.error };
      }

      return {
        status: "resolved",
        resolvedProvider,
        courses: authorization.courses,
      };
    } catch (cause: unknown) {
      return providerFailure(
        resolvedProvider,
        cause,
        "Unable to verify LMS course access",
        options,
      );
    }
  };

  return {
    resolveCourses: async (input, options = {}) => {
      const authorization = await authorizeCourses(input, requestOptions(options));

      if (authorization.status !== "resolved") {
        return authorization;
      }

      return {
        status: "resolved",
        courses: authorization.courses,
      };
    },
    searchCourses: async (input, options = {}) => {
      const operationOptions = requestOptions(options);
      const providerResult = await resolveProvider(input, operationOptions);

      if (providerResult.status !== "resolved") {
        return providerResult;
      }

      const { resolvedProvider } = providerResult;
      const catalogResult = await resolveCatalog(input, resolvedProvider, operationOptions);

      if (catalogResult.status !== "resolved") {
        return catalogResult;
      }

      try {
        const result = await catalogResult.catalog.listCourses(
          {
            limit: input.limit,
            ...(input.searchTerm === undefined ? {} : { searchTerm: input.searchTerm }),
          },
          operationOptions,
        );
        return { status: "resolved", ...result };
      } catch (cause: unknown) {
        return providerFailure(
          resolvedProvider,
          cause,
          "Unable to search LMS courses",
          operationOptions,
        );
      }
    },
    searchLearners: async (input, options = {}) => {
      const operationOptions = requestOptions(options);
      const authorization = await authorizeCourses(
        { ...input, courseIds: [input.courseId] },
        operationOptions,
      );

      if (authorization.status !== "resolved") {
        return authorization;
      }

      try {
        const matchingLearners = await authorization.resolvedProvider.provider.listLearners(
          {
            courseId: input.courseId,
            ...(input.searchTerm === undefined ? {} : { searchTerm: input.searchTerm }),
          },
          operationOptions,
        );
        return {
          status: "resolved",
          learners: matchingLearners.slice(0, input.limit),
          hasMore: matchingLearners.length > input.limit,
        };
      } catch (cause: unknown) {
        return providerFailure(
          authorization.resolvedProvider,
          cause,
          "Unable to search LMS learners",
          operationOptions,
        );
      }
    },
    listGradebookItems: async (input, options = {}) => {
      const operationOptions = requestOptions(options);
      const authorization = await authorizeCourses(
        { ...input, courseIds: [input.courseId] },
        operationOptions,
      );

      if (authorization.status !== "resolved") {
        return authorization;
      }

      try {
        const items = await listGradebookItemsForCourse(
          {
            provider: authorization.resolvedProvider.provider,
            courseId: input.courseId,
            query: input.searchTerm,
          },
          operationOptions,
        );
        return { status: "resolved", items };
      } catch (cause: unknown) {
        return providerFailure(
          authorization.resolvedProvider,
          cause,
          "Unable to list gradebook items",
          operationOptions,
        );
      }
    },
    listWorkflowStates: async (input, options = {}) => {
      const operationOptions = requestOptions(options);
      const authorization = await authorizeCourses(
        { ...input, courseIds: [input.courseId] },
        operationOptions,
      );

      if (authorization.status !== "resolved") {
        return authorization;
      }

      try {
        const states = await listWorkflowStatesForAssignment(
          {
            provider: authorization.resolvedProvider.provider,
            connection: authorization.resolvedProvider.connection,
            courseId: input.courseId,
            assignmentId: input.assignmentId,
          },
          operationOptions,
        );
        return { status: "resolved", states };
      } catch (cause: unknown) {
        return providerFailure(
          authorization.resolvedProvider,
          cause,
          "Unable to list workflow state options",
          operationOptions,
        );
      }
    },
    resolveReferenceLabels: async (input, options = {}) => {
      const operationOptions = requestOptions(options);
      const courseIds = extractBadgeIssuanceRuleRequirements(input.definition).courseIds;

      if (courseIds.length === 0) {
        return {
          status: "resolved",
          labels: { courses: [], assignments: [] },
        };
      }

      const authorization = await authorizeCourses({ ...input, courseIds }, operationOptions);

      if (authorization.status !== "resolved") {
        return authorization;
      }

      try {
        const labels = await resolveBadgeRuleReferenceLabels(
          {
            provider: authorization.resolvedProvider.provider,
            courses: authorization.courses,
            definition: input.definition,
          },
          operationOptions,
        );
        return { status: "resolved", labels };
      } catch (cause: unknown) {
        return providerFailure(
          authorization.resolvedProvider,
          cause,
          "Unable to load course and assignment names from the LMS",
          operationOptions,
        );
      }
    },
  };
};

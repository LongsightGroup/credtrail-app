import type { SqlDatabase } from "@credtrail/db";
import type { BadgeIssuanceRuleDefinition } from "@credtrail/validation";
import { extractBadgeIssuanceRuleRequirements } from "../rules/engine";
import {
  listGradebookItemsForCourse,
  listWorkflowStatesForAssignment,
  lmsLookupErrorMessage,
  type WorkflowStateOption,
} from "./gradebook-picker";
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

/** Cohesive LMS course-authoring operations shared by HTTP and rule-label workflows. */
export interface LmsCourseAuthoringService {
  /** Searches courses within the current user's provider authorization boundary. */
  searchCourses(input: SearchLmsCoursesInput): Promise<
    LmsCourseAuthoringResult<{
      readonly courses: readonly GradebookCourseRecord[];
      readonly hasMore: boolean;
    }>
  >;

  /** Searches learners after verifying that the current user can author against the course. */
  searchLearners(input: SearchLmsLearnersInput): Promise<
    LmsCourseAuthoringResult<{
      readonly learners: readonly GradebookLearnerRecord[];
      readonly hasMore: boolean;
    }>
  >;

  /** Lists gradebook items after verifying course authoring access. */
  listGradebookItems(
    input: ListLmsGradebookItemsInput,
  ): Promise<LmsCourseAuthoringResult<{ readonly items: readonly GradebookAssignmentRecord[] }>>;

  /** Lists assignment workflow states after verifying course authoring access. */
  listWorkflowStates(
    input: ListLmsWorkflowStatesInput,
  ): Promise<LmsCourseAuthoringResult<{ readonly states: readonly WorkflowStateOption[] }>>;

  /** Resolves course and assignment labels after authorizing every referenced course. */
  resolveReferenceLabels(
    input: ResolveLmsReferenceLabelsInput,
  ): Promise<LmsCourseAuthoringResult<{ readonly labels: BadgeRuleReferenceLabelResolution }>>;
}

interface CreateLmsCourseAuthoringServiceInput {
  readonly currentTimestamp: () => string;
  readonly fetchImpl?: typeof fetch;
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
): LmsCourseAuthoringFailure => ({
  status: "provider_unavailable",
  error: lmsLookupErrorMessage(resolvedProvider.connection, cause, fallback),
});

/** Creates the LMS course-authoring use case with explicit time and remote transport dependencies. */
export const createLmsCourseAuthoringService = (
  dependencies: CreateLmsCourseAuthoringServiceInput,
): LmsCourseAuthoringService => {
  const resolveProvider = async (
    input: LmsCourseAuthoringRequest,
  ): Promise<ResolvedProviderResult> => {
    try {
      const resolvedProvider = await resolveGradebookProviderWithConnection({
        db: input.db,
        tenantId: input.tenantId,
        lmsConnectionId: input.connectionId,
        nowIso: dependencies.currentTimestamp(),
        ...(dependencies.fetchImpl === undefined ? {} : { fetchImpl: dependencies.fetchImpl }),
      });
      return { status: "resolved", resolvedProvider };
    } catch (cause: unknown) {
      if (cause instanceof GradebookProviderResolutionError) {
        if (cause.reason === "not_found") {
          return { status: "connection_not_found", error: cause.message };
        }

        return { status: "connection_unusable", error: cause.message };
      }

      return {
        status: "dependency_unavailable",
        error: "Unable to load the LMS connection",
      };
    }
  };

  const resolveCatalog = async (
    input: LmsCourseAuthoringRequest,
    resolvedProvider: ResolvedGradebookProvider,
  ): Promise<ResolvedCatalogResult> => {
    try {
      return await resolveLmsCourseCatalog({
        db: input.db,
        resolvedProvider,
        userId: input.userId,
      });
    } catch {
      return {
        status: "dependency_unavailable",
        error: "Unable to load LMS user access",
      };
    }
  };

  const authorizeCourses = async (
    input: LmsCourseAuthoringRequest & { readonly courseIds: readonly string[] },
  ): Promise<
    LmsCourseAuthoringResult<{
      readonly resolvedProvider: ResolvedGradebookProvider;
      readonly courses: readonly GradebookCourseRecord[];
    }>
  > => {
    const providerResult = await resolveProvider(input);

    if (providerResult.status !== "resolved") {
      return providerResult;
    }

    const { resolvedProvider } = providerResult;
    const catalogResult = await resolveCatalog(input, resolvedProvider);

    if (catalogResult.status !== "resolved") {
      return catalogResult;
    }

    try {
      const access = await catalogResult.catalog.verifyCourseAccess({
        courseIds: input.courseIds,
      });
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
      return providerFailure(resolvedProvider, cause, "Unable to verify LMS course access");
    }
  };

  return {
    searchCourses: async (input) => {
      const providerResult = await resolveProvider(input);

      if (providerResult.status !== "resolved") {
        return providerResult;
      }

      const { resolvedProvider } = providerResult;
      const catalogResult = await resolveCatalog(input, resolvedProvider);

      if (catalogResult.status !== "resolved") {
        return catalogResult;
      }

      try {
        const result = await catalogResult.catalog.listCourses({
          limit: input.limit,
          ...(input.searchTerm === undefined ? {} : { searchTerm: input.searchTerm }),
        });
        return { status: "resolved", ...result };
      } catch (cause: unknown) {
        return providerFailure(resolvedProvider, cause, "Unable to search LMS courses");
      }
    },
    searchLearners: async (input) => {
      const authorization = await authorizeCourses({ ...input, courseIds: [input.courseId] });

      if (authorization.status !== "resolved") {
        return authorization;
      }

      try {
        const matchingLearners = await authorization.resolvedProvider.provider.listLearners({
          courseId: input.courseId,
          ...(input.searchTerm === undefined ? {} : { searchTerm: input.searchTerm }),
        });
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
        );
      }
    },
    listGradebookItems: async (input) => {
      const authorization = await authorizeCourses({ ...input, courseIds: [input.courseId] });

      if (authorization.status !== "resolved") {
        return authorization;
      }

      try {
        const items = await listGradebookItemsForCourse({
          provider: authorization.resolvedProvider.provider,
          courseId: input.courseId,
          query: input.searchTerm,
        });
        return { status: "resolved", items };
      } catch (cause: unknown) {
        return providerFailure(
          authorization.resolvedProvider,
          cause,
          "Unable to list gradebook items",
        );
      }
    },
    listWorkflowStates: async (input) => {
      const authorization = await authorizeCourses({ ...input, courseIds: [input.courseId] });

      if (authorization.status !== "resolved") {
        return authorization;
      }

      try {
        const states = await listWorkflowStatesForAssignment({
          provider: authorization.resolvedProvider.provider,
          connection: authorization.resolvedProvider.connection,
          courseId: input.courseId,
          assignmentId: input.assignmentId,
        });
        return { status: "resolved", states };
      } catch (cause: unknown) {
        return providerFailure(
          authorization.resolvedProvider,
          cause,
          "Unable to list workflow state options",
        );
      }
    },
    resolveReferenceLabels: async (input) => {
      const courseIds = extractBadgeIssuanceRuleRequirements(input.definition).courseIds;

      if (courseIds.length === 0) {
        return {
          status: "resolved",
          labels: { courses: [], assignments: [] },
        };
      }

      const authorization = await authorizeCourses({ ...input, courseIds });

      if (authorization.status !== "resolved") {
        return authorization;
      }

      try {
        const labels = await resolveBadgeRuleReferenceLabels({
          provider: authorization.resolvedProvider.provider,
          courses: authorization.courses,
          definition: input.definition,
        });
        return { status: "resolved", labels };
      } catch (cause: unknown) {
        return providerFailure(
          authorization.resolvedProvider,
          cause,
          "Unable to load course and assignment names from the LMS",
        );
      }
    },
  };
};

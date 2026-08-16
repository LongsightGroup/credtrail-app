import { findTenantLmsUserIdentity, type SqlDatabase } from "@credtrail/db";
import type { GradebookCourseCatalog, GradebookCourseRecord } from "./gradebook-types";
import type { ResolvedGradebookProvider } from "./gradebook-provider-resolution";

/** Result of binding course discovery to the current authoring user's LMS access. */
export type LmsCourseCatalogResult =
  | {
      readonly status: "resolved";
      readonly catalog: GradebookCourseCatalog;
    }
  | {
      readonly status: "identity_unlinked";
      readonly error: string;
    };

export type LmsCourseAuthorizationResult =
  | { readonly status: "authorized" }
  | {
      readonly status: "identity_unlinked";
      readonly error: string;
    }
  | {
      readonly status: "course_unauthorized";
      readonly courseId: string;
      readonly error: string;
    };

/** Course-authorization result that retains exact authorized LMS course records on success. */
export type LmsCourseAuthorizationWithRecordsResult =
  | {
      readonly status: "authorized";
      readonly courses: readonly GradebookCourseRecord[];
    }
  | Exclude<LmsCourseAuthorizationResult, { readonly status: "authorized" }>;

const canvasIdentityRequiredMessage =
  "Open CredTrail from Canvas once to link your account before choosing courses.";

/** Resolves a course catalog already bound to the authoring user's LMS access. */
export const resolveLmsCourseCatalog = async (input: {
  readonly db: SqlDatabase;
  readonly resolvedProvider: ResolvedGradebookProvider;
  readonly userId: string;
}): Promise<LmsCourseCatalogResult> => {
  if (input.resolvedProvider.providerKind === "sakai") {
    return {
      status: "resolved",
      catalog: input.resolvedProvider.provider.courseCatalogForConnection(),
    };
  }

  const identity = await findTenantLmsUserIdentity(input.db, {
    tenantId: input.resolvedProvider.connection.tenantId,
    connectionId: input.resolvedProvider.connection.id,
    userId: input.userId,
  });

  if (identity === null) {
    return {
      status: "identity_unlinked",
      error: canvasIdentityRequiredMessage,
    };
  }

  return {
    status: "resolved",
    catalog: input.resolvedProvider.provider.courseCatalogForUser(identity.providerUserId),
  };
};

/** Verifies every referenced course through the provider's resolved authorization boundary. */
export const authorizeLmsUserCoursesWithRecords = async (input: {
  readonly db: SqlDatabase;
  readonly resolvedProvider: ResolvedGradebookProvider;
  readonly userId: string;
  readonly courseIds: readonly string[];
}): Promise<LmsCourseAuthorizationWithRecordsResult> => {
  const catalogResult = await resolveLmsCourseCatalog(input);

  if (catalogResult.status === "identity_unlinked") {
    return catalogResult;
  }

  const access = await catalogResult.catalog.verifyCourseAccess({
    courseIds: input.courseIds,
  });
  const unauthorizedCourseId = access.unauthorizedCourseIds[0];

  if (unauthorizedCourseId === undefined) {
    return {
      status: "authorized",
      courses: access.authorizedCourses,
    };
  }

  return {
    status: "course_unauthorized",
    courseId: unauthorizedCourseId,
    error:
      input.resolvedProvider.providerKind === "sakai"
        ? `Course ${unauthorizedCourseId} is not available to ${input.resolvedProvider.connection.displayName}.`
        : `You do not have instructor access to course ${unauthorizedCourseId} in ${input.resolvedProvider.connection.displayName}.`,
  };
};

/** Verifies course access without returning the matching provider course records. */
export const authorizeLmsUserCourses = async (input: {
  readonly db: SqlDatabase;
  readonly resolvedProvider: ResolvedGradebookProvider;
  readonly userId: string;
  readonly courseIds: readonly string[];
}): Promise<LmsCourseAuthorizationResult> => {
  const authorization = await authorizeLmsUserCoursesWithRecords(input);
  return authorization.status === "authorized" ? { status: "authorized" } : authorization;
};

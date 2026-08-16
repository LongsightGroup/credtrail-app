import {
  findTenantLmsUserIdentity,
  type SqlDatabase,
  type TenantLmsConnectionRecord,
} from "@credtrail/db";
import type {
  GradebookCourseAccessScope,
  GradebookCourseRecord,
  GradebookProvider,
} from "./gradebook-types";

export type LmsCourseAccessScopeResult =
  | {
      readonly status: "resolved";
      readonly accessScope: GradebookCourseAccessScope;
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
export type LmsScopedCourseAuthorizationResult =
  | {
      readonly status: "authorized";
      readonly courses: readonly GradebookCourseRecord[];
    }
  | Exclude<LmsCourseAuthorizationResult, { readonly status: "authorized" }>;

const canvasIdentityRequiredMessage =
  "Open CredTrail from Canvas once to link your account before choosing courses.";

/** Resolves the provider-specific authorization boundary used for LMS course authoring. */
export const resolveLmsCourseAccessScope = async (input: {
  readonly db: SqlDatabase;
  readonly connection: TenantLmsConnectionRecord;
  readonly userId: string;
}): Promise<LmsCourseAccessScopeResult> => {
  if (input.connection.providerKind === "sakai") {
    return {
      status: "resolved",
      accessScope: { kind: "connection" },
    };
  }

  const identity = await findTenantLmsUserIdentity(input.db, {
    tenantId: input.connection.tenantId,
    connectionId: input.connection.id,
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
    accessScope: {
      kind: "provider_user",
      providerUserId: identity.providerUserId,
    },
  };
};

/** Verifies every referenced course through the provider's resolved authorization boundary. */
export const authorizeLmsUserCoursesWithScope = async (input: {
  readonly db: SqlDatabase;
  readonly connection: TenantLmsConnectionRecord;
  readonly provider: GradebookProvider;
  readonly userId: string;
  readonly courseIds: readonly string[];
}): Promise<LmsScopedCourseAuthorizationResult> => {
  const scope = await resolveLmsCourseAccessScope(input);

  if (scope.status === "identity_unlinked") {
    return scope;
  }

  const access = await input.provider.verifyCourseAccess({
    accessScope: scope.accessScope,
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
      scope.accessScope.kind === "connection"
        ? `Course ${unauthorizedCourseId} is not available to ${input.connection.displayName}.`
        : `You do not have instructor access to course ${unauthorizedCourseId} in ${input.connection.displayName}.`,
  };
};

/** Verifies course access without exposing the resolved provider identity to callers. */
export const authorizeLmsUserCourses = async (input: {
  readonly db: SqlDatabase;
  readonly connection: TenantLmsConnectionRecord;
  readonly provider: GradebookProvider;
  readonly userId: string;
  readonly courseIds: readonly string[];
}): Promise<LmsCourseAuthorizationResult> => {
  const authorization = await authorizeLmsUserCoursesWithScope(input);
  return authorization.status === "authorized" ? { status: "authorized" } : authorization;
};

import {
  findTenantLmsUserIdentity,
  type SqlDatabase,
  type TenantLmsConnectionRecord,
} from "@credtrail/db";
import type { GradebookProvider } from "./gradebook-types";

export type LmsUserCourseScopeResult =
  | {
      readonly status: "linked";
      readonly providerUserId: string;
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

const identityRequiredMessage = (providerKind: "canvas" | "sakai"): string => {
  const providerName = providerKind === "sakai" ? "Sakai" : "Canvas";
  return `Open CredTrail from ${providerName} once to link your account before choosing courses.`;
};

/** Resolves the LMS subject established for a CredTrail user by a verified LTI launch. */
export const resolveLmsUserCourseScope = async (input: {
  readonly db: SqlDatabase;
  readonly connection: TenantLmsConnectionRecord;
  readonly userId: string;
}): Promise<LmsUserCourseScopeResult> => {
  const identity = await findTenantLmsUserIdentity(input.db, {
    tenantId: input.connection.tenantId,
    connectionId: input.connection.id,
    userId: input.userId,
  });

  if (identity === null) {
    return {
      status: "identity_unlinked",
      error: identityRequiredMessage(input.connection.providerKind),
    };
  }

  return {
    status: "linked",
    providerUserId: identity.providerUserId,
  };
};

/** Verifies that the interactive user can manage every referenced LMS course. */
export const authorizeLmsUserCourses = async (input: {
  readonly db: SqlDatabase;
  readonly connection: TenantLmsConnectionRecord;
  readonly provider: GradebookProvider;
  readonly userId: string;
  readonly courseIds: readonly string[];
}): Promise<LmsCourseAuthorizationResult> => {
  const scope = await resolveLmsUserCourseScope(input);

  if (scope.status === "identity_unlinked") {
    return scope;
  }

  const access = await input.provider.verifyCourseAccess({
    providerUserId: scope.providerUserId,
    courseIds: input.courseIds,
  });
  const unauthorizedCourseId = access.unauthorizedCourseIds[0];

  if (unauthorizedCourseId === undefined) {
    return { status: "authorized" };
  }

  return {
    status: "course_unauthorized",
    courseId: unauthorizedCourseId,
    error: `You do not have instructor access to course ${unauthorizedCourseId} in ${input.connection.displayName}.`,
  };
};

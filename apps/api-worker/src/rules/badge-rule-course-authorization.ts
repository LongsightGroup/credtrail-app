import type { SqlDatabase } from "@credtrail/db";
import type { BadgeIssuanceRuleDefinition } from "@credtrail/validation";
import type { ResolvedGradebookProvider } from "../lms/gradebook-provider-resolution";
import type { GradebookRequestOptions } from "../lms/gradebook-types";
import {
  authorizeLmsUserCourses,
  type LmsCourseAuthorizationResult,
} from "../lms/user-course-access";
import { extractBadgeIssuanceRuleRequirements } from "./engine";

/** Applies the authoring user's LMS course scope to every course referenced by a rule. */
export const authorizeBadgeRuleCourses = async (
  input: {
    readonly db: SqlDatabase;
    readonly resolvedProvider: ResolvedGradebookProvider;
    readonly userId: string;
    readonly definition: BadgeIssuanceRuleDefinition;
  },
  options: GradebookRequestOptions = {},
): Promise<LmsCourseAuthorizationResult> => {
  const requirements = extractBadgeIssuanceRuleRequirements(input.definition);

  if (requirements.courseIds.length === 0) {
    return { status: "authorized" };
  }

  return authorizeLmsUserCourses(
    {
      db: input.db,
      resolvedProvider: input.resolvedProvider,
      userId: input.userId,
      courseIds: requirements.courseIds,
    },
    options,
  );
};

import {
  findBadgeIssuanceRuleVersionById,
  listBadgeIssuanceRuleVersionApprovalSteps,
  type BadgeIssuanceRuleApprovalStepRecord,
  type BadgeIssuanceRuleVersionRecord,
  type SqlDatabase,
  type TenantMembershipRole,
} from "@credtrail/db";
import {
  parseBadgeIssuanceRuleDefinitionJson,
  type BadgeIssuanceRuleDefinition,
} from "@credtrail/validation";
import { actorCanViewBadgeRuleVersionApproval } from "../badges/badge-rule-approval-access";
import { resolveBadgeIssuanceRuleDefinitionValueLists } from "../rules/badge-rule-definition-resolver";
import { extractBadgeIssuanceRuleRequirements } from "../rules/engine";
import { lmsLookupErrorMessage } from "./gradebook-picker";
import {
  GradebookProviderResolutionError,
  resolveGradebookProviderWithConnection,
  type ResolvedGradebookProvider,
} from "./gradebook-provider-resolution";
import {
  resolveBadgeRuleReferenceLabels,
  type BadgeRuleReferenceLabelResolution,
} from "./badge-rule-reference-labels";
import {
  authorizeLmsUserCoursesWithRecords,
  type LmsCourseAuthorizationWithRecordsResult,
} from "./user-course-access";

export interface BadgeRuleVersionReferenceLabelServiceInput {
  readonly db: SqlDatabase;
  readonly tenantId: string;
  readonly ruleId: string;
  readonly versionId: string;
  readonly actorUserId: string;
  readonly actorRole: TenantMembershipRole;
}

export type BadgeRuleVersionReferenceLabelServiceResult =
  | {
      readonly status: "resolved";
      readonly labels: BadgeRuleReferenceLabelResolution;
    }
  | {
      readonly status: "not_found" | "forbidden" | "conflict" | "bad_gateway";
      readonly error: string;
    };

interface LmsReferenceLabelContextInput {
  readonly db: SqlDatabase;
  readonly tenantId: string;
  readonly actorUserId: string;
  readonly lmsConnectionId: string | null;
  readonly definition: BadgeIssuanceRuleDefinition;
}

type LmsReferenceLabelContextResult =
  | {
      readonly status: "resolved";
      readonly labels: BadgeRuleReferenceLabelResolution;
    }
  | {
      readonly status: "forbidden" | "conflict" | "bad_gateway";
      readonly error: string;
    };

interface LmsReferenceLabelContext {
  readonly resolve: (
    input: LmsReferenceLabelContextInput,
  ) => Promise<LmsReferenceLabelContextResult>;
}

export interface BadgeRuleVersionReferenceLabelServiceDependencies {
  readonly findVersion: (
    db: SqlDatabase,
    input: Pick<BadgeRuleVersionReferenceLabelServiceInput, "tenantId" | "ruleId" | "versionId">,
  ) => Promise<BadgeIssuanceRuleVersionRecord | null>;
  readonly listApprovalSteps: (
    db: SqlDatabase,
    input: Pick<BadgeRuleVersionReferenceLabelServiceInput, "tenantId" | "ruleId" | "versionId">,
  ) => Promise<readonly BadgeIssuanceRuleApprovalStepRecord[]>;
  readonly actorCanView: (
    db: SqlDatabase,
    input: {
      readonly tenantId: string;
      readonly actorUserId: string;
      readonly actorRole: TenantMembershipRole;
      readonly version: BadgeIssuanceRuleVersionRecord;
      readonly approvalSteps: readonly BadgeIssuanceRuleApprovalStepRecord[];
    },
  ) => Promise<boolean>;
  readonly resolveDefinitionValueLists: typeof resolveBadgeIssuanceRuleDefinitionValueLists;
  readonly lmsReferenceLabels: LmsReferenceLabelContext;
}

export type LoadBadgeRuleVersionReferenceLabels = (
  input: BadgeRuleVersionReferenceLabelServiceInput,
) => Promise<BadgeRuleVersionReferenceLabelServiceResult>;

const emptyLabels = (): BadgeRuleReferenceLabelResolution => ({ courses: [], assignments: [] });

const lmsReferenceLabelContext: LmsReferenceLabelContext = {
  resolve: async (input) => {
    const courseIds = extractBadgeIssuanceRuleRequirements(input.definition).courseIds;

    if (courseIds.length === 0 || input.lmsConnectionId === null) {
      return { status: "resolved", labels: emptyLabels() };
    }

    let resolvedProvider: ResolvedGradebookProvider;

    try {
      resolvedProvider = await resolveGradebookProviderWithConnection({
        db: input.db,
        tenantId: input.tenantId,
        lmsConnectionId: input.lmsConnectionId,
        nowIso: new Date().toISOString(),
      });
    } catch (cause: unknown) {
      return {
        status: "conflict",
        error:
          cause instanceof GradebookProviderResolutionError
            ? cause.message
            : "Unable to use the LMS connection",
      };
    }

    let authorization: LmsCourseAuthorizationWithRecordsResult;

    try {
      authorization = await authorizeLmsUserCoursesWithRecords({
        db: input.db,
        resolvedProvider,
        userId: input.actorUserId,
        courseIds,
      });
    } catch (cause: unknown) {
      return {
        status: "bad_gateway",
        error: lmsLookupErrorMessage(
          resolvedProvider.connection,
          cause,
          "Unable to verify LMS course access",
        ),
      };
    }

    if (authorization.status !== "authorized") {
      return { status: "forbidden", error: authorization.error };
    }

    try {
      const labels = await resolveBadgeRuleReferenceLabels({
        provider: resolvedProvider.provider,
        courses: authorization.courses,
        definition: input.definition,
      });
      return { status: "resolved", labels };
    } catch (cause: unknown) {
      return {
        status: "bad_gateway",
        error: lmsLookupErrorMessage(
          resolvedProvider.connection,
          cause,
          "Unable to load course and assignment names from the LMS",
        ),
      };
    }
  },
};

/** Creates the use case that authorizes and resolves labels for one immutable rule version. */
export const createBadgeRuleVersionReferenceLabelService = (
  dependencies: BadgeRuleVersionReferenceLabelServiceDependencies,
): LoadBadgeRuleVersionReferenceLabels => {
  return async (input) => {
    const path = {
      tenantId: input.tenantId,
      ruleId: input.ruleId,
      versionId: input.versionId,
    };
    const version = await dependencies.findVersion(input.db, path);

    if (version === null) {
      return { status: "not_found", error: "Badge rule version not found" };
    }

    const approvalSteps =
      input.actorRole === "owner" || input.actorRole === "admin"
        ? []
        : await dependencies.listApprovalSteps(input.db, path);
    const canView = await dependencies.actorCanView(input.db, {
      tenantId: input.tenantId,
      actorUserId: input.actorUserId,
      actorRole: input.actorRole,
      version,
      approvalSteps,
    });

    if (!canView) {
      return { status: "forbidden", error: "Approval step not assigned to this reviewer" };
    }

    let parsedDefinition: BadgeIssuanceRuleDefinition;

    try {
      parsedDefinition = parseBadgeIssuanceRuleDefinitionJson(version.ruleJson);
    } catch {
      return { status: "conflict", error: "Saved badge rule definition is invalid" };
    }

    let definition: BadgeIssuanceRuleDefinition;

    try {
      definition = await dependencies.resolveDefinitionValueLists(
        input.db,
        input.tenantId,
        parsedDefinition,
      );
    } catch {
      return { status: "conflict", error: "Saved badge rule references could not be resolved" };
    }

    return dependencies.lmsReferenceLabels.resolve({
      db: input.db,
      tenantId: input.tenantId,
      actorUserId: input.actorUserId,
      lmsConnectionId: version.snapshot.lmsConnectionId,
      definition,
    });
  };
};

/** Production service assembled from the database, approval, and LMS adapters. */
export const loadBadgeRuleVersionReferenceLabels = createBadgeRuleVersionReferenceLabelService({
  findVersion: findBadgeIssuanceRuleVersionById,
  listApprovalSteps: listBadgeIssuanceRuleVersionApprovalSteps,
  actorCanView: actorCanViewBadgeRuleVersionApproval,
  resolveDefinitionValueLists: resolveBadgeIssuanceRuleDefinitionValueLists,
  lmsReferenceLabels: lmsReferenceLabelContext,
});

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
import type { BadgeRuleReferenceLabelResolution } from "./badge-rule-reference-labels";
import type {
  LmsCourseAuthoringOptions,
  LmsCourseAuthoringService,
} from "./lms-course-authoring-service";

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
  readonly lmsCourseAuthoring: Pick<LmsCourseAuthoringService, "resolveReferenceLabels">;
}

export type LoadBadgeRuleVersionReferenceLabels = (
  input: BadgeRuleVersionReferenceLabelServiceInput,
  options?: LmsCourseAuthoringOptions,
) => Promise<BadgeRuleVersionReferenceLabelServiceResult>;

const emptyLabels = (): BadgeRuleReferenceLabelResolution => ({ courses: [], assignments: [] });

/** Creates the use case that authorizes and resolves labels for one immutable rule version. */
export const createBadgeRuleVersionReferenceLabelService = (
  dependencies: BadgeRuleVersionReferenceLabelServiceDependencies,
): LoadBadgeRuleVersionReferenceLabels => {
  return async (input, options = {}) => {
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

    const lmsConnectionId = version.snapshot.lmsConnectionId;

    if (lmsConnectionId === null) {
      return { status: "resolved", labels: emptyLabels() };
    }

    const labelsResult = await dependencies.lmsCourseAuthoring.resolveReferenceLabels(
      {
        db: input.db,
        tenantId: input.tenantId,
        connectionId: lmsConnectionId,
        userId: input.actorUserId,
        definition,
      },
      options,
    );

    switch (labelsResult.status) {
      case "resolved":
        return labelsResult;
      case "identity_unlinked":
      case "course_unauthorized":
        return { status: "forbidden", error: labelsResult.error };
      case "connection_not_found":
      case "connection_unusable":
        return { status: "conflict", error: labelsResult.error };
      case "dependency_unavailable":
      case "request_cancelled":
      case "provider_unavailable":
        return { status: "bad_gateway", error: labelsResult.error };
    }
  };
};

/** Creates the reference-label use case from production persistence and LMS adapters. */
export const createProductionBadgeRuleVersionReferenceLabelService = (
  lmsCourseAuthoring: LmsCourseAuthoringService,
): LoadBadgeRuleVersionReferenceLabels =>
  createBadgeRuleVersionReferenceLabelService({
    findVersion: findBadgeIssuanceRuleVersionById,
    listApprovalSteps: listBadgeIssuanceRuleVersionApprovalSteps,
    actorCanView: actorCanViewBadgeRuleVersionApproval,
    resolveDefinitionValueLists: resolveBadgeIssuanceRuleDefinitionValueLists,
    lmsCourseAuthoring,
  });

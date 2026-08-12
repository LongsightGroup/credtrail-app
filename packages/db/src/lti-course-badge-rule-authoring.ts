import { createAuditLog } from "./audit-logs.js";
import { createBadgeIssuanceRuleWithActionWithinTransaction } from "./badge-issuance-rule-authoring.js";
import { findBadgeIssuanceRuleById } from "./badge-issuance-rule-reads.js";
import {
  latestBadgeIssuanceRuleVersion,
  listBadgeIssuanceRuleVersions,
} from "./badge-issuance-rule-version-reads.js";
import type {
  ExpectedBadgeTemplateRevision,
  BadgeIssuanceRuleLmsProviderKind,
  BadgeIssuanceRuleRecord,
  BadgeIssuanceRuleVersionRecord,
} from "./badge-issuance-rule-types.js";
import { ensureExternalCourseOrgUnit } from "./external-course-org-units.js";
import { normalizeLtiIssuer } from "./lti.js";
import {
  findLtiResourceLinkPlacement,
  upsertLtiResourceLinkPlacement,
  type LtiResourceLinkPlacementRecord,
} from "./lti-resource-link-placements.js";
import { runSqlTransaction, type SqlDatabase } from "./tenant-scope.js";
import type { TenantMembershipRole } from "./tenant-memberships.js";

/** Input for atomically creating an LTI course scope, badge rule, and resource-link placement. */
export interface CreateLtiCourseBadgeRuleInput {
  readonly tenantId: string;
  readonly course: {
    readonly parentOrgUnitId: string;
    readonly externalSystemId: string;
    readonly externalCourseId: string;
    readonly title: string;
  };
  readonly rule: {
    readonly name: string;
    readonly description: string;
    readonly badgeTemplateId: string;
    readonly expectedBadgeTemplateRevision: ExpectedBadgeTemplateRevision;
    readonly lmsProviderKind: BadgeIssuanceRuleLmsProviderKind;
    readonly lmsConnectionId: string;
    readonly ruleJson: string;
    readonly changeSummary: string;
  };
  readonly placement: {
    readonly issuer: string;
    readonly clientId: string;
    readonly deploymentId: string;
    readonly contextId: string | null;
    readonly resourceLinkId: string;
    readonly delegatedGrantId: string | null;
  };
  readonly actorUserId: string;
  readonly actorRole: TenantMembershipRole;
}

/** Outcome of atomically authoring and placing an LTI course badge rule. */
export type CreateLtiCourseBadgeRuleResult =
  | {
      readonly status: "completed";
      readonly writeStatus: "created" | "replayed";
      readonly rule: BadgeIssuanceRuleRecord;
      readonly version: BadgeIssuanceRuleVersionRecord;
      readonly placement: LtiResourceLinkPlacementRecord;
    }
  | {
      readonly status: "course_org_unit_error";
      readonly reason: "invalid_parent" | "slug_conflict";
    }
  | {
      readonly status: "authoring_failed";
      readonly reason:
        | "self_certification_required"
        | "policy_missing_steps"
        | "template_changed"
        | "template_artwork_not_immutable"
        | "template_reuse_confirmation_required";
    }
  | {
      readonly status: "placement_conflict";
    };

const AUTHORING_SAVEPOINT = "lti_course_badge_rule_authoring";

const rollbackAuthoringSavepoint = async (db: SqlDatabase): Promise<void> => {
  await db.prepare(`ROLLBACK TO SAVEPOINT ${AUTHORING_SAVEPOINT}`).run();
  await db.prepare(`RELEASE SAVEPOINT ${AUTHORING_SAVEPOINT}`).run();
};

const placementIdentity = (input: CreateLtiCourseBadgeRuleInput): string => {
  return JSON.stringify([
    normalizeLtiIssuer(input.placement.issuer),
    input.placement.clientId,
    input.placement.deploymentId,
    input.placement.resourceLinkId,
  ]);
};

type PlacementReplayResolution =
  | Extract<CreateLtiCourseBadgeRuleResult, { readonly status: "completed" }>
  | Extract<CreateLtiCourseBadgeRuleResult, { readonly status: "placement_conflict" }>
  | null;

const resolveExistingPlacement = async (
  db: SqlDatabase,
  input: CreateLtiCourseBadgeRuleInput,
  placement: LtiResourceLinkPlacementRecord | null,
): Promise<PlacementReplayResolution> => {
  if (placement === null) {
    return null;
  }

  const placementMatches =
    placement.tenantId === input.tenantId &&
    placement.contextId === input.placement.contextId &&
    placement.badgeTemplateId === input.rule.badgeTemplateId;

  if (!placementMatches) {
    return { status: "placement_conflict" };
  }

  if (placement.ruleId === null) {
    return null;
  }

  const rule = await findBadgeIssuanceRuleById(db, input.tenantId, placement.ruleId);
  const versions =
    rule === null
      ? []
      : await listBadgeIssuanceRuleVersions(db, {
          tenantId: input.tenantId,
          ruleId: rule.id,
        });
  const version = latestBadgeIssuanceRuleVersion(versions);

  if (rule === null || version === null) {
    throw new Error(
      `LTI resource-link placement "${placement.id}" references an unavailable badge rule`,
    );
  }

  const ruleMatches =
    rule.badgeTemplateId === input.rule.badgeTemplateId &&
    rule.lmsProviderKind === input.rule.lmsProviderKind &&
    rule.lmsConnectionId === input.rule.lmsConnectionId &&
    version.ruleJson === input.rule.ruleJson;

  if (!ruleMatches) {
    return { status: "placement_conflict" };
  }

  return {
    status: "completed",
    writeStatus: "replayed",
    rule,
    version,
    placement,
  };
};

/** Creates the complete LTI course-badge persistence graph in one transaction. */
export const createLtiCourseBadgeRule = async (
  db: SqlDatabase,
  input: CreateLtiCourseBadgeRuleInput,
): Promise<CreateLtiCourseBadgeRuleResult> => {
  return runSqlTransaction(db, async (transactionDb) => {
    await transactionDb
      .prepare("SELECT pg_advisory_xact_lock(hashtextextended(?, 0))")
      .bind(placementIdentity(input))
      .run();

    const existingPlacement = await findLtiResourceLinkPlacement(transactionDb, input.placement);
    const replay = await resolveExistingPlacement(transactionDb, input, existingPlacement);

    if (replay !== null) {
      return replay;
    }

    await transactionDb.prepare(`SAVEPOINT ${AUTHORING_SAVEPOINT}`).run();
    const courseOrgUnitResult = await ensureExternalCourseOrgUnit(transactionDb, {
      tenantId: input.tenantId,
      parentOrgUnitId: input.course.parentOrgUnitId,
      externalSystemId: input.course.externalSystemId,
      externalCourseId: input.course.externalCourseId,
      courseTitle: input.course.title,
      createdByUserId: input.actorUserId,
    });

    if (courseOrgUnitResult.status !== "ok") {
      await rollbackAuthoringSavepoint(transactionDb);
      return {
        status: "course_org_unit_error",
        reason: courseOrgUnitResult.status,
      };
    }

    const courseOrgUnit = courseOrgUnitResult.orgUnit;
    const authored = await createBadgeIssuanceRuleWithActionWithinTransaction(transactionDb, {
      tenantId: input.tenantId,
      name: input.rule.name,
      description: input.rule.description,
      badgeTemplateId: input.rule.badgeTemplateId,
      expectedBadgeTemplateRevision: input.rule.expectedBadgeTemplateRevision,
      orgUnitId: courseOrgUnit.id,
      lmsProviderKind: input.rule.lmsProviderKind,
      lmsConnectionId: input.rule.lmsConnectionId,
      ruleJson: input.rule.ruleJson,
      changeSummary: input.rule.changeSummary,
      action: "submit_for_approval",
      actorUserId: input.actorUserId,
      actorRole: input.actorRole,
      badgeTemplateReuseAcknowledged: false,
    });

    if (authored.status === "failed") {
      if (
        authored.reason !== "self_certification_required" &&
        authored.reason !== "policy_missing_steps" &&
        authored.reason !== "template_changed" &&
        authored.reason !== "template_artwork_not_immutable" &&
        authored.reason !== "template_reuse_confirmation_required"
      ) {
        throw new Error(`Unexpected LTI badge-rule authoring failure: ${authored.reason}`);
      }

      await rollbackAuthoringSavepoint(transactionDb);
      return {
        status: "authoring_failed",
        reason: authored.reason,
      };
    }

    const placement = await upsertLtiResourceLinkPlacement(transactionDb, {
      tenantId: input.tenantId,
      issuer: input.placement.issuer,
      clientId: input.placement.clientId,
      deploymentId: input.placement.deploymentId,
      contextId: input.placement.contextId,
      resourceLinkId: input.placement.resourceLinkId,
      badgeTemplateId: input.rule.badgeTemplateId,
      ruleId: authored.rule.id,
      createdByUserId: input.actorUserId,
    });
    const auditMetadata = {
      badgeTemplateId: input.rule.badgeTemplateId,
      ruleVersionId: authored.version.id,
      ltiIssuer: normalizeLtiIssuer(input.placement.issuer),
      ltiClientId: input.placement.clientId,
      ltiDeploymentId: input.placement.deploymentId,
      ltiContextId: input.placement.contextId,
      ltiResourceLinkId: input.placement.resourceLinkId,
      delegatedGrantId: input.placement.delegatedGrantId,
      lmsConnectionId: input.rule.lmsConnectionId,
      courseOrgUnitId: courseOrgUnit.id,
      courseParentOrgUnitId: input.course.parentOrgUnitId,
    };

    await createAuditLog(transactionDb, {
      tenantId: input.tenantId,
      actorUserId: input.actorUserId,
      action: "lti.course_badge_setup_submitted",
      targetType: "badge_issuance_rule",
      targetId: authored.rule.id,
      metadata: auditMetadata,
    });
    await createAuditLog(transactionDb, {
      tenantId: input.tenantId,
      actorUserId: input.actorUserId,
      action: "lti.resource_link_placement_upserted",
      targetType: "lti_resource_link_placement",
      targetId: placement.id,
      metadata: auditMetadata,
    });

    await transactionDb.prepare(`RELEASE SAVEPOINT ${AUTHORING_SAVEPOINT}`).run();

    return {
      status: "completed",
      writeStatus: "created",
      rule: authored.rule,
      version: authored.version,
      placement,
    };
  });
};

import { findBadgeIssuanceRuleById } from "./badge-issuance-rule-reads.js";
import { findBadgeIssuanceRuleVersionById } from "./badge-issuance-rule-version-reads.js";
import type {
  BadgeIssuanceRuleRecord,
  BadgeIssuanceRuleVersionRecord,
} from "./badge-issuance-rule-types.js";
import {
  resolveBadgeRulePlacementAvailabilityForContext,
  type BadgeRulePlacementAuthorizationResult,
} from "./badge-rule-placement-availability.js";
import { findBadgeTemplateById, type BadgeTemplateRecord } from "./badge-templates.js";
import { normalizeLtiIssuer } from "./lti.js";
import {
  findLtiResourceLinkPlacementForUpdateWithinTransaction,
  upsertLtiResourceLinkPlacementWithinTransaction,
  type LtiResourceLinkPlacementRecord,
} from "./lti-resource-link-placements.js";
import { runSqlTransaction, type SqlDatabase } from "./tenant-scope.js";

export interface PlaceStableLtiBadgeRuleInput {
  readonly tenantId: string;
  readonly lmsConnectionId: string;
  readonly contextId: string;
  readonly issuer: string;
  readonly clientId: string;
  readonly deploymentId: string;
  readonly resourceLinkId: string;
  readonly incomingRuleId: string | null;
  readonly incomingBadgeTemplateId: string | null;
  readonly linkedUserId: string;
  readonly roleKind: "instructor" | "learner" | "unknown";
  readonly evaluatedAt?: string | undefined;
}

export interface PlacedStableLtiBadgeRule {
  readonly placement: LtiResourceLinkPlacementRecord;
  readonly rule: BadgeIssuanceRuleRecord;
  readonly version: BadgeIssuanceRuleVersionRecord;
  readonly badgeTemplate: BadgeTemplateRecord;
}

export type PlaceStableLtiBadgeRuleResult =
  | ({ readonly status: "placed" } & PlacedStableLtiBadgeRule)
  | ({ readonly status: "reactivated" } & PlacedStableLtiBadgeRule)
  | ({ readonly status: "existing" } & PlacedStableLtiBadgeRule)
  | { readonly status: "replace_link_required" }
  | { readonly status: "placement_conflict" }
  | { readonly status: "rule_not_found" }
  | { readonly status: "rule_not_active" }
  | { readonly status: "template_mismatch" }
  | { readonly status: "course_context_not_found" }
  | { readonly status: "course_unmapped" }
  | { readonly status: "outside_availability" }
  | { readonly status: "course_relative_rule_not_supported" };

interface LockedRuleRow {
  readonly id: string;
  readonly badgeTemplateId: string;
  readonly lmsConnectionId: string;
  readonly activeVersionId: string | null;
}

interface LockedVersionRow {
  readonly id: string;
  readonly status: string;
  readonly effectiveStartsAt: string | null;
  readonly expiresAt: string | null;
}

const COURSE_RELATIVE_AUTHORING_ACTION = ["lti.course", "badge", "setup", "submitted"].join("_");

const hasUsableWindow = (version: LockedVersionRow, evaluatedAt: string): boolean => {
  const evaluatedTimestamp = Date.parse(evaluatedAt);
  const startsTimestamp =
    version.effectiveStartsAt === null ? null : Date.parse(version.effectiveStartsAt);
  const expiresTimestamp = version.expiresAt === null ? null : Date.parse(version.expiresAt);

  return (
    version.status === "active" &&
    Number.isFinite(evaluatedTimestamp) &&
    (startsTimestamp === null ||
      (Number.isFinite(startsTimestamp) && startsTimestamp <= evaluatedTimestamp)) &&
    (expiresTimestamp === null ||
      (Number.isFinite(expiresTimestamp) && expiresTimestamp > evaluatedTimestamp))
  );
};

const denialFromAvailability = (
  result: Exclude<BadgeRulePlacementAuthorizationResult, { readonly status: "allowed" }>,
): Exclude<
  PlaceStableLtiBadgeRuleResult,
  { readonly status: "placed" | "reactivated" | "existing" }
> => {
  switch (result.status) {
    case "course_context_not_found":
      return { status: "course_context_not_found" };
    case "course_unmapped":
      return { status: "course_unmapped" };
    case "no_policy":
    case "org_unit_inactive":
    case "outside_availability":
      return { status: "outside_availability" };
  }
};

/** Identifies rules authored by the removed course-relative LTI setup workflow. */
export const isCourseRelativeLtiAuthoredBadgeRule = async (
  db: SqlDatabase,
  input: { readonly tenantId: string; readonly ruleId: string },
): Promise<boolean> => {
  const row = await db
    .prepare(
      `
      SELECT 1 AS present
      FROM audit_logs
      WHERE tenant_id = ?
        AND action = ?
        AND target_type = 'badge_issuance_rule'
        AND target_id = ?
      LIMIT 1
    `,
    )
    .bind(input.tenantId, COURSE_RELATIVE_AUTHORING_ACTION, input.ruleId)
    .first<{ readonly present: number | boolean }>();

  return row !== null;
};

/**
 * Authorizes and records one stable rule placement atomically from verified LTI launch data.
 */
export const placeStableLtiBadgeRule = async (
  db: SqlDatabase,
  input: PlaceStableLtiBadgeRuleInput,
): Promise<PlaceStableLtiBadgeRuleResult> => {
  const normalizedIssuer = normalizeLtiIssuer(input.issuer);

  return runSqlTransaction(db, async (transactionDb) => {
    await transactionDb
      .prepare(
        `
        SELECT pg_advisory_xact_lock(
          hashtextextended(? || CHR(31) || ? || CHR(31) || ? || CHR(31) || ?, 0)
        ) AS locked
      `,
      )
      .bind(normalizedIssuer, input.clientId, input.deploymentId, input.resourceLinkId)
      .first<{ readonly locked: unknown }>();

    const existingPlacement = await findLtiResourceLinkPlacementForUpdateWithinTransaction(
      transactionDb,
      {
        issuer: normalizedIssuer,
        clientId: input.clientId,
        deploymentId: input.deploymentId,
        resourceLinkId: input.resourceLinkId,
      },
    );

    if (
      existingPlacement !== null &&
      (existingPlacement.tenantId !== input.tenantId ||
        (existingPlacement.contextId !== null && existingPlacement.contextId !== input.contextId))
    ) {
      return { status: "placement_conflict" };
    }

    if (
      input.incomingRuleId !== null &&
      existingPlacement?.ruleId !== null &&
      existingPlacement?.ruleId !== undefined &&
      existingPlacement.ruleId !== input.incomingRuleId
    ) {
      return { status: "placement_conflict" };
    }

    const ruleId = input.incomingRuleId ?? existingPlacement?.ruleId ?? null;

    if (ruleId === null) {
      return { status: "replace_link_required" };
    }

    if (
      input.incomingRuleId !== null &&
      existingPlacement === null &&
      (await isCourseRelativeLtiAuthoredBadgeRule(transactionDb, {
        tenantId: input.tenantId,
        ruleId,
      }))
    ) {
      return { status: "course_relative_rule_not_supported" };
    }

    const lockedRule = await transactionDb
      .prepare(
        `
        SELECT
          id,
          badge_template_id AS badgeTemplateId,
          lms_connection_id AS lmsConnectionId,
          active_version_id AS activeVersionId
        FROM badge_issuance_rules
        WHERE tenant_id = ?
          AND id = ?
        LIMIT 1
        FOR UPDATE
      `,
      )
      .bind(input.tenantId, ruleId)
      .first<LockedRuleRow>();

    if (lockedRule === null) {
      return { status: "rule_not_found" };
    }

    if (lockedRule.lmsConnectionId !== input.lmsConnectionId) {
      return { status: "outside_availability" };
    }

    if (lockedRule.activeVersionId === null) {
      return { status: "rule_not_active" };
    }

    const lockedVersion = await transactionDb
      .prepare(
        `
        SELECT
          id,
          status,
          effective_starts_at AS effectiveStartsAt,
          expires_at AS expiresAt
        FROM badge_issuance_rule_versions
        WHERE tenant_id = ?
          AND rule_id = ?
          AND id = ?
        LIMIT 1
        FOR UPDATE
      `,
      )
      .bind(input.tenantId, ruleId, lockedRule.activeVersionId)
      .first<LockedVersionRow>();
    const evaluatedAt = input.evaluatedAt ?? new Date().toISOString();

    if (lockedVersion === null || !hasUsableWindow(lockedVersion, evaluatedAt)) {
      return { status: "rule_not_active" };
    }

    const connection = await transactionDb
      .prepare(
        `
        SELECT id
        FROM tenant_lms_connections
        WHERE tenant_id = ?
          AND id = ?
          AND lti_issuer = ?
          AND lti_client_id = ?
          AND lti_deployment_id = ?
        LIMIT 1
        FOR UPDATE
      `,
      )
      .bind(
        input.tenantId,
        input.lmsConnectionId,
        normalizedIssuer,
        input.clientId,
        input.deploymentId,
      )
      .first<{ readonly id: string }>();

    if (connection === null) {
      return { status: "course_context_not_found" };
    }

    await transactionDb
      .prepare(
        `
        SELECT id
        FROM badge_rule_placement_availabilities
        WHERE tenant_id = ?
          AND rule_id = ?
        LIMIT 1
        FOR UPDATE
      `,
      )
      .bind(input.tenantId, ruleId)
      .first<{ readonly id: string }>();
    const courseContext = await transactionDb
      .prepare(
        `
        SELECT id
        FROM tenant_lms_course_contexts
        WHERE tenant_id = ?
          AND lms_connection_id = ?
          AND context_id = ?
        LIMIT 1
        FOR UPDATE
      `,
      )
      .bind(input.tenantId, input.lmsConnectionId, input.contextId)
      .first<{ readonly id: string }>();

    if (courseContext === null) {
      return { status: "course_context_not_found" };
    }

    const availability = await resolveBadgeRulePlacementAvailabilityForContext(transactionDb, {
      tenantId: input.tenantId,
      ruleId,
      lmsConnectionId: input.lmsConnectionId,
      contextId: input.contextId,
    });

    if (availability.status !== "allowed") {
      return denialFromAvailability(availability);
    }

    if (
      (input.incomingBadgeTemplateId !== null &&
        input.incomingBadgeTemplateId !== lockedRule.badgeTemplateId) ||
      (existingPlacement !== null &&
        existingPlacement.badgeTemplateId !== lockedRule.badgeTemplateId)
    ) {
      return { status: "template_mismatch" };
    }

    const lockedTemplate = await transactionDb
      .prepare(
        `
        SELECT id
        FROM badge_templates
        WHERE tenant_id = ?
          AND id = ?
        LIMIT 1
        FOR UPDATE
      `,
      )
      .bind(input.tenantId, lockedRule.badgeTemplateId)
      .first<{ readonly id: string }>();

    if (lockedTemplate === null) {
      return { status: "template_mismatch" };
    }

    const badgeTemplate = await findBadgeTemplateById(
      transactionDb,
      input.tenantId,
      lockedRule.badgeTemplateId,
    );

    if (badgeTemplate === null || badgeTemplate.isArchived) {
      return { status: "template_mismatch" };
    }

    const rule = await findBadgeIssuanceRuleById(transactionDb, input.tenantId, ruleId);
    const version = await findBadgeIssuanceRuleVersionById(transactionDb, {
      tenantId: input.tenantId,
      ruleId,
      versionId: lockedVersion.id,
    });

    if (rule === null) {
      return { status: "rule_not_found" };
    }

    if (version === null || version.snapshot.badgeTemplateId !== badgeTemplate.id) {
      return { status: "template_mismatch" };
    }

    const placement = await upsertLtiResourceLinkPlacementWithinTransaction(transactionDb, {
      tenantId: input.tenantId,
      issuer: normalizedIssuer,
      clientId: input.clientId,
      deploymentId: input.deploymentId,
      contextId: input.contextId,
      resourceLinkId: input.resourceLinkId,
      badgeTemplateId: badgeTemplate.id,
      ruleId,
      createdByUserId: input.linkedUserId,
    });

    return {
      status:
        existingPlacement === null
          ? "placed"
          : existingPlacement.status === "retired"
            ? "reactivated"
            : "existing",
      placement,
      rule,
      version,
      badgeTemplate,
    };
  });
};

import type { SqlDatabase, SqlQueryResult } from "./tenant-scope";
import { actorCanDecideApprovalStep } from "./badge-rule-approval-authorization.js";
import type { TenantMembershipRole } from "./tenant-memberships";
import type {
  BadgeIssuanceRuleApprovalEventAction,
  BadgeIssuanceRuleApprovalEventRecord,
  BadgeIssuanceRuleApprovalStepRecord,
  BadgeIssuanceRuleApprovalStepStatus,
  BadgeIssuanceRuleApprovalStepTarget,
  ListBadgeIssuanceRuleVersionApprovalEventsInput,
  ListBadgeIssuanceRuleVersionApprovalHistoryForVersionsInput,
  ListBadgeIssuanceRuleVersionApprovalStepsInput,
  ListPendingBadgeIssuanceRuleApprovalsForActorInput,
  PendingBadgeIssuanceRuleApprovalRecord,
} from "./badge-issuance-rule-types.js";

interface BadgeIssuanceRuleApprovalStepRow {
  id: string;
  tenantId: string;
  versionId: string;
  stepNumber: number;
  targetType: BadgeIssuanceRuleApprovalStepRecord["targetType"];
  requiredRole: TenantMembershipRole | null;
  targetUserId: string | null;
  targetApproverGroupId: string | null;
  orgUnitId: string | null;
  label: string | null;
  status: BadgeIssuanceRuleApprovalStepStatus;
  decidedByUserId: string | null;
  decidedAt: string | null;
  decisionComment: string | null;
  createdAt: string;
  updatedAt: string;
}

const mapBadgeIssuanceRuleApprovalStepTarget = (
  row: BadgeIssuanceRuleApprovalStepRow,
): BadgeIssuanceRuleApprovalStepTarget => {
  if (row.targetType === "user" && row.targetUserId !== null) {
    return {
      targetType: "user",
      requiredRole: row.requiredRole,
      targetUserId: row.targetUserId,
      targetApproverGroupId: null,
    };
  }

  if (row.targetType === "approver_group" && row.targetApproverGroupId !== null) {
    return {
      targetType: "approver_group",
      requiredRole: row.requiredRole,
      targetUserId: null,
      targetApproverGroupId: row.targetApproverGroupId,
    };
  }

  if (row.targetType === "role_threshold" && row.requiredRole !== null) {
    return {
      targetType: "role_threshold",
      requiredRole: row.requiredRole,
      targetUserId: null,
      targetApproverGroupId: null,
    };
  }

  throw new Error(`Invalid stored badge rule approval step target for step "${row.id}"`);
};

interface BadgeIssuanceRuleApprovalEventRow {
  id: string;
  tenantId: string;
  versionId: string;
  stepNumber: number | null;
  action: BadgeIssuanceRuleApprovalEventAction;
  actorUserId: string | null;
  actorRole: TenantMembershipRole | null;
  comment: string | null;
  occurredAt: string;
  createdAt: string;
}

interface PendingBadgeIssuanceRuleApprovalRow extends BadgeIssuanceRuleApprovalStepRow {
  ruleId: string;
  versionName: string;
  badgeTemplateId: string;
  badgeTemplateTitle: string;
  orgUnitIdForRule: string;
  orgUnitDisplayName: string | null;
  versionNumber: number;
  versionCreatedByUserId: string | null;
  submittedByUserId: string | null;
  submittedByEmail: string | null;
  submittedAt: string | null;
}
const BADGE_ISSUANCE_RULE_APPROVAL_STEP_STATUSES = new Set<BadgeIssuanceRuleApprovalStepStatus>([
  "queued",
  "pending",
  "approved",
  "rejected",
  "changes_requested",
]);

const BADGE_ISSUANCE_RULE_APPROVAL_EVENT_ACTIONS = new Set<BadgeIssuanceRuleApprovalEventAction>([
  "submitted",
  "approved",
  "rejected",
  "changes_requested",
  "withdrawn",
  "reopened",
]);
const uniqueNonEmptyIds = (ids: readonly string[]): readonly string[] => {
  return [...new Set(ids.filter((id) => id.length > 0))];
};
const BADGE_ISSUANCE_RULE_APPROVAL_STEP_SELECT_COLUMNS = `
  steps.id,
  steps.tenant_id AS tenantId,
  steps.version_id AS versionId,
  steps.step_number AS stepNumber,
  steps.target_type AS targetType,
  steps.required_role AS requiredRole,
  steps.target_user_id AS targetUserId,
  steps.target_approver_group_id AS targetApproverGroupId,
  steps.org_unit_id AS orgUnitId,
  steps.label,
  steps.status,
  steps.decided_by_user_id AS decidedByUserId,
  steps.decided_at AS decidedAt,
  steps.decision_comment AS decisionComment,
  steps.created_at AS createdAt,
  steps.updated_at AS updatedAt
`;

const BADGE_ISSUANCE_RULE_APPROVAL_EVENT_SELECT_COLUMNS = `
  events.id,
  events.tenant_id AS tenantId,
  events.version_id AS versionId,
  events.step_number AS stepNumber,
  events.action,
  events.actor_user_id AS actorUserId,
  events.actor_role AS actorRole,
  events.comment,
  events.occurred_at AS occurredAt,
  events.created_at AS createdAt
`;
const mapBadgeIssuanceRuleApprovalStepRow = (
  row: BadgeIssuanceRuleApprovalStepRow,
): BadgeIssuanceRuleApprovalStepRecord => {
  return {
    id: row.id,
    tenantId: row.tenantId,
    versionId: row.versionId,
    stepNumber: row.stepNumber,
    ...mapBadgeIssuanceRuleApprovalStepTarget(row),
    orgUnitId: row.orgUnitId ?? null,
    label: row.label,
    status: row.status,
    decidedByUserId: row.decidedByUserId,
    decidedAt: row.decidedAt,
    decisionComment: row.decisionComment,
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
  };
};

const mapBadgeIssuanceRuleApprovalEventRow = (
  row: BadgeIssuanceRuleApprovalEventRow,
): BadgeIssuanceRuleApprovalEventRecord => {
  return {
    id: row.id,
    tenantId: row.tenantId,
    versionId: row.versionId,
    stepNumber: row.stepNumber,
    action: row.action,
    actorUserId: row.actorUserId,
    actorRole: row.actorRole,
    comment: row.comment,
    occurredAt: row.occurredAt,
    createdAt: row.createdAt,
  };
};
export const listBadgeIssuanceRuleVersionApprovalSteps = async (
  db: SqlDatabase,
  input: ListBadgeIssuanceRuleVersionApprovalStepsInput,
): Promise<BadgeIssuanceRuleApprovalStepRecord[]> => {
  const listStatement = (): Promise<SqlQueryResult<BadgeIssuanceRuleApprovalStepRow>> =>
    db
      .prepare(
        `
        SELECT
          ${BADGE_ISSUANCE_RULE_APPROVAL_STEP_SELECT_COLUMNS}
        FROM badge_issuance_rule_approval_steps AS steps
        INNER JOIN badge_issuance_rule_versions AS versions
          ON versions.id = steps.version_id
          AND versions.tenant_id = steps.tenant_id
        WHERE steps.tenant_id = ?
          AND versions.rule_id = ?
          AND steps.version_id = ?
        ORDER BY steps.step_number ASC
      `,
      )
      .bind(input.tenantId, input.ruleId, input.versionId)
      .all<BadgeIssuanceRuleApprovalStepRow>();

  const result = await listStatement();

  return result.results
    .map((row) => mapBadgeIssuanceRuleApprovalStepRow(row))
    .filter((step) => BADGE_ISSUANCE_RULE_APPROVAL_STEP_STATUSES.has(step.status));
};

/** Loads approval steps for the requested tenant-scoped rule-version IDs in one query. */
export const listBadgeIssuanceRuleVersionApprovalStepsForVersions = async (
  db: SqlDatabase,
  input: ListBadgeIssuanceRuleVersionApprovalHistoryForVersionsInput,
): Promise<BadgeIssuanceRuleApprovalStepRecord[]> => {
  const versionIds = uniqueNonEmptyIds(input.versionIds);

  if (versionIds.length === 0) {
    return [];
  }

  const versionIdPlaceholders = versionIds.map(() => "?").join(", ");
  const result = await db
    .prepare(
      `
        SELECT
          ${BADGE_ISSUANCE_RULE_APPROVAL_STEP_SELECT_COLUMNS}
        FROM badge_issuance_rule_approval_steps AS steps
        INNER JOIN badge_issuance_rule_versions AS versions
          ON versions.id = steps.version_id
          AND versions.tenant_id = steps.tenant_id
        WHERE steps.tenant_id = ?
          AND steps.version_id IN (${versionIdPlaceholders})
        ORDER BY steps.version_id ASC, steps.step_number ASC
      `,
    )
    .bind(input.tenantId, ...versionIds)
    .all<BadgeIssuanceRuleApprovalStepRow>();

  return result.results
    .map((row) => mapBadgeIssuanceRuleApprovalStepRow(row))
    .filter((step) => BADGE_ISSUANCE_RULE_APPROVAL_STEP_STATUSES.has(step.status));
};

const mapPendingBadgeIssuanceRuleApprovalRow = (
  row: PendingBadgeIssuanceRuleApprovalRow,
): PendingBadgeIssuanceRuleApprovalRecord => {
  const currentStep: BadgeIssuanceRuleApprovalStepRecord = {
    ...mapBadgeIssuanceRuleApprovalStepTarget(row),
    id: row.id,
    tenantId: row.tenantId,
    versionId: row.versionId,
    stepNumber: row.stepNumber,
    orgUnitId: row.orgUnitId,
    label: row.label,
    status: row.status,
    decidedByUserId: row.decidedByUserId,
    decidedAt: row.decidedAt,
    decisionComment: row.decisionComment,
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
  };

  return {
    tenantId: row.tenantId,
    ruleId: row.ruleId,
    versionName: row.versionName,
    badgeTemplateId: row.badgeTemplateId,
    badgeTemplateTitle: row.badgeTemplateTitle,
    orgUnitId: row.orgUnitIdForRule,
    orgUnitDisplayName: row.orgUnitDisplayName,
    versionId: row.versionId,
    versionNumber: row.versionNumber,
    versionCreatedByUserId: row.versionCreatedByUserId,
    submittedByUserId: row.submittedByUserId,
    submittedByEmail: row.submittedByEmail,
    submittedAt: row.submittedAt,
    currentStep,
  };
};

export const listPendingBadgeIssuanceRuleApprovalsForActor = async (
  db: SqlDatabase,
  input: ListPendingBadgeIssuanceRuleApprovalsForActorInput,
): Promise<PendingBadgeIssuanceRuleApprovalRecord[]> => {
  const limit = input.limit ?? 50;
  const result = await db
    .prepare(
      `
        SELECT
          steps.id,
          steps.tenant_id AS tenantId,
          steps.version_id AS versionId,
          steps.step_number AS stepNumber,
          steps.target_type AS targetType,
          steps.required_role AS requiredRole,
          steps.target_user_id AS targetUserId,
          steps.target_approver_group_id AS targetApproverGroupId,
          steps.org_unit_id AS orgUnitId,
          steps.label,
          steps.status,
          steps.decided_by_user_id AS decidedByUserId,
          steps.decided_at AS decidedAt,
          steps.decision_comment AS decisionComment,
          steps.created_at AS createdAt,
          steps.updated_at AS updatedAt,
          versions.rule_id AS ruleId,
          versions.snapshot_name AS versionName,
          versions.snapshot_badge_template_id AS badgeTemplateId,
          versions.snapshot_badge_template_title AS badgeTemplateTitle,
          versions.snapshot_org_unit_id AS orgUnitIdForRule,
          org_units.display_name AS orgUnitDisplayName,
          versions.version_number AS versionNumber,
          versions.created_by_user_id AS versionCreatedByUserId,
          versions.submitted_by_user_id AS submittedByUserId,
          submitters.email AS submittedByEmail,
          versions.submitted_at AS submittedAt
        FROM badge_issuance_rule_approval_steps AS steps
        INNER JOIN badge_issuance_rule_versions AS versions
          ON versions.id = steps.version_id
          AND versions.tenant_id = steps.tenant_id
        LEFT JOIN tenant_org_units AS org_units
          ON org_units.id = versions.snapshot_org_unit_id
          AND org_units.tenant_id = versions.tenant_id
        LEFT JOIN users AS submitters
          ON submitters.id = versions.submitted_by_user_id
        WHERE steps.tenant_id = ?
          AND steps.status = 'pending'
          AND versions.status = 'pending_approval'
          AND (versions.created_by_user_id IS NULL OR versions.created_by_user_id <> ?)
          AND (versions.submitted_by_user_id IS NULL OR versions.submitted_by_user_id <> ?)
        ORDER BY versions.submitted_at ASC, versions.created_at ASC, steps.step_number ASC
      `,
    )
    .bind(input.tenantId, input.actorUserId, input.actorUserId)
    .all<PendingBadgeIssuanceRuleApprovalRow>();

  const entries: PendingBadgeIssuanceRuleApprovalRecord[] = [];

  for (const row of result.results) {
    const entry = mapPendingBadgeIssuanceRuleApprovalRow(row);
    const canDecide = await actorCanDecideApprovalStep(db, {
      tenantId: input.tenantId,
      actorUserId: input.actorUserId,
      actorRole: input.actorRole,
      step: entry.currentStep,
    });

    if (canDecide) {
      entries.push(entry);
    }

    if (entries.length >= limit) {
      break;
    }
  }

  return entries;
};

export const listBadgeIssuanceRuleVersionApprovalEvents = async (
  db: SqlDatabase,
  input: ListBadgeIssuanceRuleVersionApprovalEventsInput,
): Promise<BadgeIssuanceRuleApprovalEventRecord[]> => {
  const listStatement = (): Promise<SqlQueryResult<BadgeIssuanceRuleApprovalEventRow>> =>
    db
      .prepare(
        `
        SELECT
          ${BADGE_ISSUANCE_RULE_APPROVAL_EVENT_SELECT_COLUMNS}
        FROM badge_issuance_rule_approval_events AS events
        INNER JOIN badge_issuance_rule_versions AS versions
          ON versions.id = events.version_id
          AND versions.tenant_id = events.tenant_id
        WHERE events.tenant_id = ?
          AND versions.rule_id = ?
          AND events.version_id = ?
        ORDER BY events.occurred_at ASC, events.created_at ASC
      `,
      )
      .bind(input.tenantId, input.ruleId, input.versionId)
      .all<BadgeIssuanceRuleApprovalEventRow>();

  const result = await listStatement();

  return result.results
    .map((row) => mapBadgeIssuanceRuleApprovalEventRow(row))
    .filter((event) => BADGE_ISSUANCE_RULE_APPROVAL_EVENT_ACTIONS.has(event.action));
};

/** Loads approval events for the requested tenant-scoped rule-version IDs in one query. */
export const listBadgeIssuanceRuleVersionApprovalEventsForVersions = async (
  db: SqlDatabase,
  input: ListBadgeIssuanceRuleVersionApprovalHistoryForVersionsInput,
): Promise<BadgeIssuanceRuleApprovalEventRecord[]> => {
  const versionIds = uniqueNonEmptyIds(input.versionIds);

  if (versionIds.length === 0) {
    return [];
  }

  const versionIdPlaceholders = versionIds.map(() => "?").join(", ");
  const result = await db
    .prepare(
      `
        SELECT
          ${BADGE_ISSUANCE_RULE_APPROVAL_EVENT_SELECT_COLUMNS}
        FROM badge_issuance_rule_approval_events AS events
        INNER JOIN badge_issuance_rule_versions AS versions
          ON versions.id = events.version_id
          AND versions.tenant_id = events.tenant_id
        WHERE events.tenant_id = ?
          AND events.version_id IN (${versionIdPlaceholders})
        ORDER BY events.version_id ASC, events.occurred_at ASC, events.created_at ASC
      `,
    )
    .bind(input.tenantId, ...versionIds)
    .all<BadgeIssuanceRuleApprovalEventRow>();

  return result.results
    .map((row) => mapBadgeIssuanceRuleApprovalEventRow(row))
    .filter((event) => BADGE_ISSUANCE_RULE_APPROVAL_EVENT_ACTIONS.has(event.action));
};

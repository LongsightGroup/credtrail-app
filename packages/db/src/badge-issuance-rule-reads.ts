import type { SqlDatabase, SqlQueryResult } from "./tenant-scope";
import { listTenantMembershipOrgUnitScopes, type TenantMembershipRole } from "./tenant-memberships";
import type {
  BadgeIssuanceRuleApprovalEventAction,
  BadgeIssuanceRuleApprovalEventRecord,
  BadgeIssuanceRuleApprovalStepRecord,
  BadgeIssuanceRuleApprovalStepStatus,
  BadgeIssuanceRuleApprovalStepTarget,
  BadgeIssuanceRuleLmsProviderKind,
  BadgeIssuanceRuleRecord,
  BadgeIssuanceRuleVersionRecord,
  BadgeIssuanceRuleVersionStatus,
  ListBadgeIssuanceRuleVersionApprovalEventsInput,
  ListBadgeIssuanceRuleVersionApprovalStepsInput,
  ListBadgeIssuanceRuleVersionsInput,
  ListBadgeIssuanceRulesInput,
} from "./badge-issuance-rule-types.js";

interface BadgeIssuanceRuleRow {
  id: string;
  tenantId: string;
  name: string;
  description: string | null;
  badgeTemplateId: string;
  orgUnitId: string;
  ownerOrgUnitId: string;
  lmsProviderKind: BadgeIssuanceRuleLmsProviderKind;
  lmsConnectionId: string | null;
  activeVersionId: string | null;
  createdByUserId: string | null;
  createdAt: string;
  updatedAt: string;
}

interface BadgeIssuanceRuleVersionRow {
  id: string;
  tenantId: string;
  ruleId: string;
  versionNumber: number;
  status: BadgeIssuanceRuleVersionStatus;
  ruleJson: string;
  changeSummary: string | null;
  createdByUserId: string | null;
  submittedByUserId: string | null;
  submittedAt: string | null;
  approvedByUserId: string | null;
  approvedAt: string | null;
  activatedByUserId: string | null;
  activatedAt: string | null;
  createdAt: string;
  updatedAt: string;
}

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

export interface BadgeIssuanceRuleVersionNumberRow {
  maxVersionNumber: number | string | null;
}

const BADGE_ISSUANCE_RULE_VERSION_STATUSES = new Set<BadgeIssuanceRuleVersionStatus>([
  "draft",
  "pending_approval",
  "approved",
  "active",
  "rejected",
  "deprecated",
]);

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
]);

const BADGE_ISSUANCE_RULE_SELECT_COLUMNS = `
  id,
  tenant_id AS tenantId,
  name,
  description,
  badge_template_id AS badgeTemplateId,
  org_unit_id AS orgUnitId,
  owner_org_unit_id AS ownerOrgUnitId,
  lms_provider_kind AS lmsProviderKind,
  lms_connection_id AS lmsConnectionId,
  active_version_id AS activeVersionId,
  created_by_user_id AS createdByUserId,
  created_at AS createdAt,
  updated_at AS updatedAt
`;

const mapBadgeIssuanceRuleRow = (row: BadgeIssuanceRuleRow): BadgeIssuanceRuleRecord => {
  return {
    id: row.id,
    tenantId: row.tenantId,
    name: row.name,
    description: row.description,
    badgeTemplateId: row.badgeTemplateId,
    orgUnitId: row.orgUnitId,
    ownerOrgUnitId: row.ownerOrgUnitId,
    lmsProviderKind: row.lmsProviderKind,
    lmsConnectionId: row.lmsConnectionId,
    activeVersionId: row.activeVersionId,
    createdByUserId: row.createdByUserId,
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
  };
};

const mapBadgeIssuanceRuleVersionRow = (
  row: BadgeIssuanceRuleVersionRow,
): BadgeIssuanceRuleVersionRecord => {
  return {
    id: row.id,
    tenantId: row.tenantId,
    ruleId: row.ruleId,
    versionNumber: row.versionNumber,
    status: row.status,
    ruleJson: row.ruleJson,
    changeSummary: row.changeSummary,
    createdByUserId: row.createdByUserId,
    submittedByUserId: row.submittedByUserId ?? null,
    submittedAt: row.submittedAt ?? null,
    approvedByUserId: row.approvedByUserId,
    approvedAt: row.approvedAt,
    activatedByUserId: row.activatedByUserId,
    activatedAt: row.activatedAt,
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
  };
};

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

const listBadgeIssuanceRulesByOrgUnitIds = async (
  db: SqlDatabase,
  input: {
    readonly tenantId: string;
    readonly orgUnitIds: readonly string[];
  },
): Promise<BadgeIssuanceRuleRecord[]> => {
  if (input.orgUnitIds.length === 0) {
    return [];
  }

  const placeholders = input.orgUnitIds.map(() => "?").join(", ");
  const result = await db
    .prepare(
      `
      SELECT
        ${BADGE_ISSUANCE_RULE_SELECT_COLUMNS}
      FROM badge_issuance_rules
      WHERE tenant_id = ?
        AND org_unit_id IN (${placeholders})
      ORDER BY created_at DESC, id DESC
    `,
    )
    .bind(input.tenantId, ...input.orgUnitIds)
    .all<BadgeIssuanceRuleRow>();

  return result.results.map((row) => mapBadgeIssuanceRuleRow(row));
};

const listBadgeIssuanceRulesByDescendantRoots = async (
  db: SqlDatabase,
  input: {
    readonly tenantId: string;
    readonly rootOrgUnitIds: readonly string[];
  },
): Promise<BadgeIssuanceRuleRecord[]> => {
  if (input.rootOrgUnitIds.length === 0) {
    return [];
  }

  const rootValues = input.rootOrgUnitIds.map(() => "(?)").join(", ");
  const result = await db
    .prepare(
      `
      WITH RECURSIVE scoped_roots(id) AS (
        VALUES ${rootValues}
      ),
      scoped_descendants AS (
        SELECT org_units.id AS orgUnitId
        FROM tenant_org_units AS org_units
        INNER JOIN scoped_roots
          ON scoped_roots.id = org_units.id
        WHERE org_units.tenant_id = ?

        UNION

        SELECT child.id AS orgUnitId
        FROM tenant_org_units AS child
        INNER JOIN scoped_descendants
          ON child.parent_org_unit_id = scoped_descendants.orgUnitId
        WHERE child.tenant_id = ?
      )
      SELECT
        ${BADGE_ISSUANCE_RULE_SELECT_COLUMNS}
      FROM badge_issuance_rules
      WHERE tenant_id = ?
        AND org_unit_id IN (
          SELECT orgUnitId
          FROM scoped_descendants
        )
      ORDER BY created_at DESC, id DESC
    `,
    )
    .bind(...input.rootOrgUnitIds, input.tenantId, input.tenantId, input.tenantId)
    .all<BadgeIssuanceRuleRow>();

  return result.results.map((row) => mapBadgeIssuanceRuleRow(row));
};

export const resolveListBadgeIssuanceRulesInput = async (
  db: SqlDatabase,
  input: {
    readonly tenantId: string;
    readonly userId: string;
    readonly membershipRole: TenantMembershipRole;
  },
): Promise<ListBadgeIssuanceRulesInput> => {
  if (input.membershipRole === "owner" || input.membershipRole === "admin") {
    return { tenantId: input.tenantId };
  }

  const scopes = await listTenantMembershipOrgUnitScopes(db, {
    tenantId: input.tenantId,
    userId: input.userId,
  });
  const rootOrgUnitIds = Array.from(new Set(scopes.map((scope) => scope.orgUnitId))).sort((a, b) =>
    a.localeCompare(b),
  );

  if (rootOrgUnitIds.length === 0) {
    return { tenantId: input.tenantId };
  }

  return {
    tenantId: input.tenantId,
    scope: {
      type: "descendants",
      rootOrgUnitIds,
    },
  };
};

export const findBadgeIssuanceRuleById = async (
  db: SqlDatabase,
  tenantId: string,
  ruleId: string,
): Promise<BadgeIssuanceRuleRecord | null> => {
  const lookupStatement = (): Promise<BadgeIssuanceRuleRow | null> =>
    db
      .prepare(
        `
        SELECT
          ${BADGE_ISSUANCE_RULE_SELECT_COLUMNS}
        FROM badge_issuance_rules
        WHERE tenant_id = ?
          AND id = ?
        LIMIT 1
      `,
      )
      .bind(tenantId, ruleId)
      .first<BadgeIssuanceRuleRow>();

  const row = await lookupStatement();

  return row === null ? null : mapBadgeIssuanceRuleRow(row);
};

export const listBadgeIssuanceRules = async (
  db: SqlDatabase,
  input: ListBadgeIssuanceRulesInput,
): Promise<BadgeIssuanceRuleRecord[]> => {
  if (input.scope?.type === "org_unit") {
    return listBadgeIssuanceRulesByOrgUnitIds(db, {
      tenantId: input.tenantId,
      orgUnitIds: [input.scope.orgUnitId],
    });
  }

  if (input.scope?.type === "descendants") {
    return listBadgeIssuanceRulesByDescendantRoots(db, {
      tenantId: input.tenantId,
      rootOrgUnitIds: input.scope.rootOrgUnitIds,
    });
  }

  const listStatement = (): Promise<SqlQueryResult<BadgeIssuanceRuleRow>> =>
    db
      .prepare(
        `
        SELECT
          ${BADGE_ISSUANCE_RULE_SELECT_COLUMNS}
        FROM badge_issuance_rules
        WHERE tenant_id = ?
        ORDER BY created_at DESC, id DESC
      `,
      )
      .bind(input.tenantId)
      .all<BadgeIssuanceRuleRow>();

  const result = await listStatement();

  return result.results.map((row) => mapBadgeIssuanceRuleRow(row));
};

export const listBadgeIssuanceRuleVersions = async (
  db: SqlDatabase,
  input: ListBadgeIssuanceRuleVersionsInput,
): Promise<BadgeIssuanceRuleVersionRecord[]> => {
  const listStatement = (): Promise<SqlQueryResult<BadgeIssuanceRuleVersionRow>> =>
    db
      .prepare(
        `
        SELECT
          id,
          tenant_id AS tenantId,
          rule_id AS ruleId,
          version_number AS versionNumber,
          status,
          rule_json AS ruleJson,
          change_summary AS changeSummary,
          created_by_user_id AS createdByUserId,
          submitted_by_user_id AS submittedByUserId,
          submitted_at AS submittedAt,
          approved_by_user_id AS approvedByUserId,
          approved_at AS approvedAt,
          activated_by_user_id AS activatedByUserId,
          activated_at AS activatedAt,
          created_at AS createdAt,
          updated_at AS updatedAt
        FROM badge_issuance_rule_versions
        WHERE tenant_id = ?
          AND rule_id = ?
        ORDER BY version_number DESC
      `,
      )
      .bind(input.tenantId, input.ruleId)
      .all<BadgeIssuanceRuleVersionRow>();

  const result = await listStatement();

  return result.results
    .map((row) => mapBadgeIssuanceRuleVersionRow(row))
    .filter((version) => BADGE_ISSUANCE_RULE_VERSION_STATUSES.has(version.status));
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

export const listBadgeIssuanceRuleVersionApprovalEvents = async (
  db: SqlDatabase,
  input: ListBadgeIssuanceRuleVersionApprovalEventsInput,
): Promise<BadgeIssuanceRuleApprovalEventRecord[]> => {
  const listStatement = (): Promise<SqlQueryResult<BadgeIssuanceRuleApprovalEventRow>> =>
    db
      .prepare(
        `
        SELECT
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

export const findBadgeIssuanceRuleVersionById = async (
  db: SqlDatabase,
  input: {
    tenantId: string;
    ruleId: string;
    versionId: string;
  },
): Promise<BadgeIssuanceRuleVersionRecord | null> => {
  const lookupStatement = (): Promise<BadgeIssuanceRuleVersionRow | null> =>
    db
      .prepare(
        `
        SELECT
          id,
          tenant_id AS tenantId,
          rule_id AS ruleId,
          version_number AS versionNumber,
          status,
          rule_json AS ruleJson,
          change_summary AS changeSummary,
          created_by_user_id AS createdByUserId,
          submitted_by_user_id AS submittedByUserId,
          submitted_at AS submittedAt,
          approved_by_user_id AS approvedByUserId,
          approved_at AS approvedAt,
          activated_by_user_id AS activatedByUserId,
          activated_at AS activatedAt,
          created_at AS createdAt,
          updated_at AS updatedAt
        FROM badge_issuance_rule_versions
        WHERE tenant_id = ?
          AND rule_id = ?
          AND id = ?
        LIMIT 1
      `,
      )
      .bind(input.tenantId, input.ruleId, input.versionId)
      .first<BadgeIssuanceRuleVersionRow>();

  const row = await lookupStatement();

  if (row === null) {
    return null;
  }

  const version = mapBadgeIssuanceRuleVersionRow(row);
  return BADGE_ISSUANCE_RULE_VERSION_STATUSES.has(version.status) ? version : null;
};

export const findActiveBadgeIssuanceRuleVersion = async (
  db: SqlDatabase,
  input: {
    tenantId: string;
    ruleId: string;
  },
): Promise<BadgeIssuanceRuleVersionRecord | null> => {
  const lookupStatement = (): Promise<BadgeIssuanceRuleVersionRow | null> =>
    db
      .prepare(
        `
        SELECT
          versions.id,
          versions.tenant_id AS tenantId,
          versions.rule_id AS ruleId,
          versions.version_number AS versionNumber,
          versions.status,
          versions.rule_json AS ruleJson,
          versions.change_summary AS changeSummary,
          versions.created_by_user_id AS createdByUserId,
          versions.submitted_by_user_id AS submittedByUserId,
          versions.submitted_at AS submittedAt,
          versions.approved_by_user_id AS approvedByUserId,
          versions.approved_at AS approvedAt,
          versions.activated_by_user_id AS activatedByUserId,
          versions.activated_at AS activatedAt,
          versions.created_at AS createdAt,
          versions.updated_at AS updatedAt
        FROM badge_issuance_rules AS rules
        INNER JOIN badge_issuance_rule_versions AS versions
          ON versions.id = rules.active_version_id
          AND versions.rule_id = rules.id
          AND versions.tenant_id = rules.tenant_id
        WHERE rules.tenant_id = ?
          AND rules.id = ?
        LIMIT 1
      `,
      )
      .bind(input.tenantId, input.ruleId)
      .first<BadgeIssuanceRuleVersionRow>();

  const row = await lookupStatement();

  if (row === null) {
    return null;
  }

  const version = mapBadgeIssuanceRuleVersionRow(row);
  return BADGE_ISSUANCE_RULE_VERSION_STATUSES.has(version.status) ? version : null;
};

const DRAFT_EDITABLE_BADGE_ISSUANCE_RULE_VERSION_STATUSES: ReadonlySet<BadgeIssuanceRuleVersionStatus> =
  new Set(["draft", "rejected"]);

export const latestBadgeIssuanceRuleVersion = (
  versions: readonly BadgeIssuanceRuleVersionRecord[],
): BadgeIssuanceRuleVersionRecord | null => {
  return (
    versions.slice().sort((left, right) => right.versionNumber - left.versionNumber)[0] ?? null
  );
};

export const canEditBadgeIssuanceRuleDraft = (
  rule: BadgeIssuanceRuleRecord,
  versions: readonly BadgeIssuanceRuleVersionRecord[],
): boolean => {
  const latestVersion = latestBadgeIssuanceRuleVersion(versions);

  return (
    rule.activeVersionId === null &&
    latestVersion !== null &&
    DRAFT_EDITABLE_BADGE_ISSUANCE_RULE_VERSION_STATUSES.has(latestVersion.status)
  );
};

export const canDeleteBadgeIssuanceRuleDraft = (
  rule: BadgeIssuanceRuleRecord,
  versions: readonly BadgeIssuanceRuleVersionRecord[],
): boolean => {
  return (
    rule.activeVersionId === null &&
    versions.length > 0 &&
    versions.every((version) =>
      DRAFT_EDITABLE_BADGE_ISSUANCE_RULE_VERSION_STATUSES.has(version.status),
    )
  );
};

import { createPrefixedId } from "./shared-helpers";
import {
  runSqlTransaction,
  type SqlDatabase,
  type SqlQueryResult,
  type SqlRunResult,
} from "./tenant-scope";
import {
  isTenantMembershipRole,
  tenantMembershipRoleSatisfiesMinimumRole,
  type TenantMembershipRole,
} from "./tenant-memberships";

export type BadgeIssuanceRuleLmsProviderKind =
  | "canvas"
  | "moodle"
  | "blackboard_ultra"
  | "d2l_brightspace"
  | "sakai";

export type BadgeIssuanceRuleVersionStatus =
  | "draft"
  | "pending_approval"
  | "approved"
  | "active"
  | "rejected"
  | "deprecated";

export type BadgeIssuanceRuleApprovalStepStatus = "queued" | "pending" | "approved" | "rejected";

export type BadgeIssuanceRuleApprovalEventAction = "submitted" | "approved" | "rejected";

export interface BadgeIssuanceRuleRecord {
  id: string;
  tenantId: string;
  name: string;
  description: string | null;
  badgeTemplateId: string;
  lmsProviderKind: BadgeIssuanceRuleLmsProviderKind;
  lmsConnectionId: string | null;
  activeVersionId: string | null;
  createdByUserId: string | null;
  createdAt: string;
  updatedAt: string;
}

export interface BadgeIssuanceRuleVersionRecord {
  id: string;
  tenantId: string;
  ruleId: string;
  versionNumber: number;
  status: BadgeIssuanceRuleVersionStatus;
  ruleJson: string;
  changeSummary: string | null;
  createdByUserId: string | null;
  approvedByUserId: string | null;
  approvedAt: string | null;
  activatedByUserId: string | null;
  activatedAt: string | null;
  createdAt: string;
  updatedAt: string;
}

export interface BadgeIssuanceRuleApprovalChainStepInput {
  requiredRole: TenantMembershipRole;
  label?: string | undefined;
}

export interface BadgeIssuanceRuleApprovalStepRecord {
  id: string;
  tenantId: string;
  versionId: string;
  stepNumber: number;
  requiredRole: TenantMembershipRole;
  label: string | null;
  status: BadgeIssuanceRuleApprovalStepStatus;
  decidedByUserId: string | null;
  decidedAt: string | null;
  decisionComment: string | null;
  createdAt: string;
  updatedAt: string;
}

export interface BadgeIssuanceRuleApprovalEventRecord {
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

export interface CreateBadgeIssuanceRuleInput {
  tenantId: string;
  name: string;
  description?: string | undefined;
  badgeTemplateId: string;
  lmsProviderKind: BadgeIssuanceRuleLmsProviderKind;
  lmsConnectionId: string;
  ruleJson: string;
  approvalChain?: BadgeIssuanceRuleApprovalChainStepInput[] | undefined;
  changeSummary?: string | undefined;
  createdByUserId?: string | undefined;
}

export interface CreateBadgeIssuanceRuleVersionInput {
  tenantId: string;
  ruleId: string;
  ruleJson: string;
  approvalChain?: BadgeIssuanceRuleApprovalChainStepInput[] | undefined;
  changeSummary?: string | undefined;
  createdByUserId?: string | undefined;
}

export interface UpdateBadgeIssuanceRuleDraftInput {
  tenantId: string;
  ruleId: string;
  name: string;
  description?: string | undefined;
  badgeTemplateId: string;
  lmsProviderKind: BadgeIssuanceRuleLmsProviderKind;
  lmsConnectionId: string;
  ruleJson: string;
  approvalChain?: BadgeIssuanceRuleApprovalChainStepInput[] | undefined;
  changeSummary?: string | undefined;
  createdByUserId?: string | undefined;
}

export interface ListBadgeIssuanceRulesInput {
  tenantId: string;
}

export interface ListBadgeIssuanceRuleVersionsInput {
  tenantId: string;
  ruleId: string;
}

export interface SubmitBadgeIssuanceRuleVersionForApprovalInput {
  tenantId: string;
  ruleId: string;
  versionId: string;
  actorUserId?: string | undefined;
  actorRole?: TenantMembershipRole | undefined;
  comment?: string | undefined;
  occurredAt?: string | undefined;
}

export interface DecideBadgeIssuanceRuleVersionInput {
  tenantId: string;
  ruleId: string;
  versionId: string;
  decision: "approved" | "rejected";
  actorUserId: string;
  actorRole: TenantMembershipRole;
  comment?: string | undefined;
  occurredAt?: string | undefined;
}

export interface ListBadgeIssuanceRuleVersionApprovalStepsInput {
  tenantId: string;
  ruleId: string;
  versionId: string;
}

export interface ListBadgeIssuanceRuleVersionApprovalEventsInput {
  tenantId: string;
  ruleId: string;
  versionId: string;
}

export interface ActivateBadgeIssuanceRuleVersionInput {
  tenantId: string;
  ruleId: string;
  versionId: string;
  actorUserId: string;
  activatedAt?: string | undefined;
}

interface BadgeIssuanceRuleRow {
  id: string;
  tenantId: string;
  name: string;
  description: string | null;
  badgeTemplateId: string;
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
  requiredRole: TenantMembershipRole;
  label: string | null;
  status: BadgeIssuanceRuleApprovalStepStatus;
  decidedByUserId: string | null;
  decidedAt: string | null;
  decisionComment: string | null;
  createdAt: string;
  updatedAt: string;
}

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

interface BadgeIssuanceRuleVersionNumberRow {
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
]);

const BADGE_ISSUANCE_RULE_APPROVAL_EVENT_ACTIONS = new Set<BadgeIssuanceRuleApprovalEventAction>([
  "submitted",
  "approved",
  "rejected",
]);

const mapBadgeIssuanceRuleRow = (row: BadgeIssuanceRuleRow): BadgeIssuanceRuleRecord => {
  return {
    id: row.id,
    tenantId: row.tenantId,
    name: row.name,
    description: row.description,
    badgeTemplateId: row.badgeTemplateId,
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
    requiredRole: row.requiredRole,
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

export interface CreateBadgeIssuanceRuleResult {
  rule: BadgeIssuanceRuleRecord;
  version: BadgeIssuanceRuleVersionRecord;
}

export type UpdateBadgeIssuanceRuleDraftResult =
  | {
      status: "updated";
      rule: BadgeIssuanceRuleRecord;
      version: BadgeIssuanceRuleVersionRecord;
    }
  | {
      status: "not_found";
    }
  | {
      status: "not_editable";
      rule: BadgeIssuanceRuleRecord;
      versions: BadgeIssuanceRuleVersionRecord[];
    };

export type DeleteDraftBadgeIssuanceRuleResult =
  | {
      status: "deleted";
      rule: BadgeIssuanceRuleRecord;
      versions: BadgeIssuanceRuleVersionRecord[];
    }
  | {
      status: "not_found";
    }
  | {
      status: "not_deletable";
      rule: BadgeIssuanceRuleRecord;
      versions: BadgeIssuanceRuleVersionRecord[];
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
          id,
          tenant_id AS tenantId,
          name,
          description,
          badge_template_id AS badgeTemplateId,
          lms_provider_kind AS lmsProviderKind,
          lms_connection_id AS lmsConnectionId,
          active_version_id AS activeVersionId,
          created_by_user_id AS createdByUserId,
          created_at AS createdAt,
          updated_at AS updatedAt
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
  const listStatement = (): Promise<SqlQueryResult<BadgeIssuanceRuleRow>> =>
    db
      .prepare(
        `
        SELECT
          id,
          tenant_id AS tenantId,
          name,
          description,
          badge_template_id AS badgeTemplateId,
          lms_provider_kind AS lmsProviderKind,
          lms_connection_id AS lmsConnectionId,
          active_version_id AS activeVersionId,
          created_by_user_id AS createdByUserId,
          created_at AS createdAt,
          updated_at AS updatedAt
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
          steps.required_role AS requiredRole,
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

const DEFAULT_BADGE_ISSUANCE_RULE_APPROVAL_CHAIN: readonly BadgeIssuanceRuleApprovalChainStepInput[] =
  [
    {
      requiredRole: "admin",
      label: "Administrative approval",
    },
  ] as const;

const normalizeBadgeIssuanceRuleApprovalChain = (
  chain: readonly BadgeIssuanceRuleApprovalChainStepInput[] | undefined,
): BadgeIssuanceRuleApprovalChainStepInput[] => {
  const normalizedChain =
    chain === undefined ? [...DEFAULT_BADGE_ISSUANCE_RULE_APPROVAL_CHAIN] : [...chain];

  if (normalizedChain.length === 0) {
    throw new Error("Badge issuance rule approval chain must include at least one step");
  }

  for (const step of normalizedChain) {
    const requiredRole: unknown = step.requiredRole;

    if (!isTenantMembershipRole(requiredRole)) {
      throw new Error(`Unsupported tenant role in approval chain: ${String(requiredRole)}`);
    }
  }

  return normalizedChain;
};

const insertBadgeIssuanceRuleApprovalSteps = async (
  db: SqlDatabase,
  input: {
    tenantId: string;
    versionId: string;
    approvalChain: readonly BadgeIssuanceRuleApprovalChainStepInput[];
    createdAt: string;
  },
): Promise<void> => {
  const insertSteps = async (): Promise<void> => {
    for (const [index, step] of input.approvalChain.entries()) {
      await db
        .prepare(
          `
          INSERT INTO badge_issuance_rule_approval_steps (
            id,
            tenant_id,
            version_id,
            step_number,
            required_role,
            label,
            status,
            decided_by_user_id,
            decided_at,
            decision_comment,
            created_at,
            updated_at
          )
          VALUES (?, ?, ?, ?, ?, ?, 'queued', NULL, NULL, NULL, ?, ?)
        `,
        )
        .bind(
          createPrefixedId("bras"),
          input.tenantId,
          input.versionId,
          index + 1,
          step.requiredRole,
          step.label ?? null,
          input.createdAt,
          input.createdAt,
        )
        .run();
    }
  };

  await insertSteps();
};

const insertBadgeIssuanceRuleApprovalEvent = async (
  db: SqlDatabase,
  input: {
    tenantId: string;
    versionId: string;
    stepNumber: number | null;
    action: BadgeIssuanceRuleApprovalEventAction;
    actorUserId: string | null;
    actorRole: TenantMembershipRole | null;
    comment: string | null;
    occurredAt: string;
  },
): Promise<void> => {
  const insertEventStatement = (): Promise<SqlRunResult> =>
    db
      .prepare(
        `
        INSERT INTO badge_issuance_rule_approval_events (
          id,
          tenant_id,
          version_id,
          step_number,
          action,
          actor_user_id,
          actor_role,
          comment,
          occurred_at,
          created_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `,
      )
      .bind(
        createPrefixedId("brae"),
        input.tenantId,
        input.versionId,
        input.stepNumber,
        input.action,
        input.actorUserId,
        input.actorRole,
        input.comment,
        input.occurredAt,
        input.occurredAt,
      )
      .run();

  await insertEventStatement();
};

const ensureBadgeIssuanceRuleApprovalStepsInitialized = async (
  db: SqlDatabase,
  input: {
    tenantId: string;
    ruleId: string;
    versionId: string;
  },
): Promise<BadgeIssuanceRuleApprovalStepRecord[]> => {
  const existingSteps = await listBadgeIssuanceRuleVersionApprovalSteps(db, input);

  if (existingSteps.length > 0) {
    return existingSteps;
  }

  const nowIso = new Date().toISOString();
  await insertBadgeIssuanceRuleApprovalSteps(db, {
    tenantId: input.tenantId,
    versionId: input.versionId,
    approvalChain: DEFAULT_BADGE_ISSUANCE_RULE_APPROVAL_CHAIN,
    createdAt: nowIso,
  });

  return listBadgeIssuanceRuleVersionApprovalSteps(db, input);
};

const createBadgeIssuanceRuleInDatabase = async (
  db: SqlDatabase,
  input: CreateBadgeIssuanceRuleInput,
): Promise<CreateBadgeIssuanceRuleResult> => {
  const nowIso = new Date().toISOString();
  const ruleId = createPrefixedId("brl");
  const versionId = createPrefixedId("brv");
  const approvalChain = normalizeBadgeIssuanceRuleApprovalChain(input.approvalChain);
  const insertRuleStatement = (): Promise<SqlRunResult> =>
    db
      .prepare(
        `
        INSERT INTO badge_issuance_rules (
          id,
          tenant_id,
          name,
          description,
          badge_template_id,
          lms_provider_kind,
          lms_connection_id,
          active_version_id,
          created_by_user_id,
          created_at,
          updated_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, NULL, ?, ?, ?)
      `,
      )
      .bind(
        ruleId,
        input.tenantId,
        input.name,
        input.description ?? null,
        input.badgeTemplateId,
        input.lmsProviderKind,
        input.lmsConnectionId,
        input.createdByUserId ?? null,
        nowIso,
        nowIso,
      )
      .run();
  const insertVersionStatement = (): Promise<SqlRunResult> =>
    db
      .prepare(
        `
        INSERT INTO badge_issuance_rule_versions (
          id,
          tenant_id,
          rule_id,
          version_number,
          status,
          rule_json,
          change_summary,
          created_by_user_id,
          approved_by_user_id,
          approved_at,
          activated_by_user_id,
          activated_at,
          created_at,
          updated_at
        )
        VALUES (?, ?, ?, 1, 'draft', ?, ?, ?, NULL, NULL, NULL, NULL, ?, ?)
      `,
      )
      .bind(
        versionId,
        input.tenantId,
        ruleId,
        input.ruleJson,
        input.changeSummary ?? null,
        input.createdByUserId ?? null,
        nowIso,
        nowIso,
      )
      .run();

  await insertRuleStatement();
  await insertVersionStatement();

  await insertBadgeIssuanceRuleApprovalSteps(db, {
    tenantId: input.tenantId,
    versionId,
    approvalChain,
    createdAt: nowIso,
  });

  const rule = await findBadgeIssuanceRuleById(db, input.tenantId, ruleId);
  const version = await findBadgeIssuanceRuleVersionById(db, {
    tenantId: input.tenantId,
    ruleId,
    versionId,
  });

  if (rule === null || version === null) {
    throw new Error(`Unable to create badge issuance rule "${ruleId}"`);
  }

  return {
    rule,
    version,
  };
};

export const createBadgeIssuanceRule = async (
  db: SqlDatabase,
  input: CreateBadgeIssuanceRuleInput,
): Promise<CreateBadgeIssuanceRuleResult> => {
  return runSqlTransaction(db, async (transactionDb) =>
    createBadgeIssuanceRuleInDatabase(transactionDb, input),
  );
};

const createBadgeIssuanceRuleVersionInDatabase = async (
  db: SqlDatabase,
  input: CreateBadgeIssuanceRuleVersionInput,
): Promise<BadgeIssuanceRuleVersionRecord> => {
  const nowIso = new Date().toISOString();
  const versionId = createPrefixedId("brv");
  const approvalChain = normalizeBadgeIssuanceRuleApprovalChain(input.approvalChain);
  const nextVersionStatement = (): Promise<BadgeIssuanceRuleVersionNumberRow | null> =>
    db
      .prepare(
        `
        SELECT MAX(version_number) AS maxVersionNumber
        FROM badge_issuance_rule_versions
        WHERE tenant_id = ?
          AND rule_id = ?
      `,
      )
      .bind(input.tenantId, input.ruleId)
      .first<BadgeIssuanceRuleVersionNumberRow>();
  const insertStatement = (versionNumber: number): Promise<SqlRunResult> =>
    db
      .prepare(
        `
        INSERT INTO badge_issuance_rule_versions (
          id,
          tenant_id,
          rule_id,
          version_number,
          status,
          rule_json,
          change_summary,
          created_by_user_id,
          approved_by_user_id,
          approved_at,
          activated_by_user_id,
          activated_at,
          created_at,
          updated_at
        )
        VALUES (?, ?, ?, ?, 'draft', ?, ?, ?, NULL, NULL, NULL, NULL, ?, ?)
      `,
      )
      .bind(
        versionId,
        input.tenantId,
        input.ruleId,
        versionNumber,
        input.ruleJson,
        input.changeSummary ?? null,
        input.createdByUserId ?? null,
        nowIso,
        nowIso,
      )
      .run();

  const maxRow = await nextVersionStatement();

  const currentMax =
    maxRow?.maxVersionNumber === null || maxRow?.maxVersionNumber === undefined
      ? 0
      : Number(maxRow.maxVersionNumber);
  const nextVersionNumber = Number.isFinite(currentMax) ? Math.floor(currentMax) + 1 : 1;
  await insertStatement(nextVersionNumber);
  await insertBadgeIssuanceRuleApprovalSteps(db, {
    tenantId: input.tenantId,
    versionId,
    approvalChain,
    createdAt: nowIso,
  });

  const version = await findBadgeIssuanceRuleVersionById(db, {
    tenantId: input.tenantId,
    ruleId: input.ruleId,
    versionId,
  });

  if (version === null) {
    throw new Error(
      `Unable to create badge issuance rule version for rule "${input.ruleId}" in tenant "${input.tenantId}"`,
    );
  }

  return version;
};

export const createBadgeIssuanceRuleVersion = async (
  db: SqlDatabase,
  input: CreateBadgeIssuanceRuleVersionInput,
): Promise<BadgeIssuanceRuleVersionRecord> => {
  return runSqlTransaction(db, async (transactionDb) =>
    createBadgeIssuanceRuleVersionInDatabase(transactionDb, input),
  );
};

export const updateBadgeIssuanceRuleDraft = async (
  db: SqlDatabase,
  input: UpdateBadgeIssuanceRuleDraftInput,
): Promise<UpdateBadgeIssuanceRuleDraftResult> => {
  const existingRule = await findBadgeIssuanceRuleById(db, input.tenantId, input.ruleId);

  if (existingRule === null) {
    return { status: "not_found" };
  }

  const versions = await listBadgeIssuanceRuleVersions(db, {
    tenantId: input.tenantId,
    ruleId: input.ruleId,
  });

  if (!canEditBadgeIssuanceRuleDraft(existingRule, versions)) {
    return {
      status: "not_editable",
      rule: existingRule,
      versions,
    };
  }

  const nowIso = new Date().toISOString();

  // Product decision: editing from the builder preserves history by appending a new draft version.
  return runSqlTransaction(db, async (transactionDb) => {
    const updateRuleStatement = (): Promise<SqlRunResult> =>
      transactionDb
        .prepare(
          `
          UPDATE badge_issuance_rules
          SET
            name = ?,
            description = ?,
            badge_template_id = ?,
            lms_provider_kind = ?,
            lms_connection_id = ?,
            updated_at = ?
          WHERE tenant_id = ?
            AND id = ?
        `,
        )
        .bind(
          input.name,
          input.description ?? null,
          input.badgeTemplateId,
          input.lmsProviderKind,
          input.lmsConnectionId,
          nowIso,
          input.tenantId,
          input.ruleId,
        )
        .run();

    await updateRuleStatement();

    const version = await createBadgeIssuanceRuleVersionInDatabase(transactionDb, {
      tenantId: input.tenantId,
      ruleId: input.ruleId,
      ruleJson: input.ruleJson,
      approvalChain: input.approvalChain,
      changeSummary: input.changeSummary,
      createdByUserId: input.createdByUserId,
    });
    const rule = await findBadgeIssuanceRuleById(transactionDb, input.tenantId, input.ruleId);

    if (rule === null) {
      throw new Error(`Unable to update badge issuance rule "${input.ruleId}"`);
    }

    return {
      status: "updated",
      rule,
      version,
    };
  });
};

export const deleteDraftBadgeIssuanceRule = async (
  db: SqlDatabase,
  input: {
    tenantId: string;
    ruleId: string;
  },
): Promise<DeleteDraftBadgeIssuanceRuleResult> => {
  const existingRule = await findBadgeIssuanceRuleById(db, input.tenantId, input.ruleId);

  if (existingRule === null) {
    return { status: "not_found" };
  }

  const versions = await listBadgeIssuanceRuleVersions(db, {
    tenantId: input.tenantId,
    ruleId: input.ruleId,
  });

  if (!canDeleteBadgeIssuanceRuleDraft(existingRule, versions)) {
    return {
      status: "not_deletable",
      rule: existingRule,
      versions,
    };
  }

  await db
    .prepare(
      `
      DELETE FROM badge_issuance_rules
      WHERE tenant_id = ?
        AND id = ?
    `,
    )
    .bind(input.tenantId, input.ruleId)
    .run();

  return {
    status: "deleted",
    rule: existingRule,
    versions,
  };
};

export const submitBadgeIssuanceRuleVersionForApproval = async (
  db: SqlDatabase,
  input: SubmitBadgeIssuanceRuleVersionForApprovalInput,
): Promise<BadgeIssuanceRuleVersionRecord | null> => {
  const occurredAt = input.occurredAt ?? new Date().toISOString();
  const version = await findBadgeIssuanceRuleVersionById(db, {
    tenantId: input.tenantId,
    ruleId: input.ruleId,
    versionId: input.versionId,
  });

  if (version === null) {
    return null;
  }

  if (version.status !== "draft" && version.status !== "rejected") {
    return null;
  }

  const approvalSteps = await ensureBadgeIssuanceRuleApprovalStepsInitialized(db, {
    tenantId: input.tenantId,
    ruleId: input.ruleId,
    versionId: input.versionId,
  });
  const firstStep = approvalSteps[0];

  if (firstStep === undefined) {
    return null;
  }

  const resetApprovalStepsStatement = (): Promise<SqlRunResult> =>
    db
      .prepare(
        `
        UPDATE badge_issuance_rule_approval_steps
        SET
          status = 'queued',
          decided_by_user_id = NULL,
          decided_at = NULL,
          decision_comment = NULL,
          updated_at = ?
        WHERE tenant_id = ?
          AND version_id = ?
      `,
      )
      .bind(occurredAt, input.tenantId, input.versionId)
      .run();
  const activateFirstApprovalStepStatement = (): Promise<SqlRunResult> =>
    db
      .prepare(
        `
        UPDATE badge_issuance_rule_approval_steps
        SET
          status = 'pending',
          updated_at = ?
        WHERE tenant_id = ?
          AND version_id = ?
          AND step_number = ?
      `,
      )
      .bind(occurredAt, input.tenantId, input.versionId, firstStep.stepNumber)
      .run();
  const submitVersionStatement = (): Promise<SqlRunResult> =>
    db
      .prepare(
        `
        UPDATE badge_issuance_rule_versions
        SET
          status = 'pending_approval',
          approved_by_user_id = NULL,
          approved_at = NULL,
          updated_at = ?
        WHERE tenant_id = ?
          AND rule_id = ?
          AND id = ?
      `,
      )
      .bind(occurredAt, input.tenantId, input.ruleId, input.versionId)
      .run();

  await resetApprovalStepsStatement();
  await activateFirstApprovalStepStatement();
  await submitVersionStatement();

  await insertBadgeIssuanceRuleApprovalEvent(db, {
    tenantId: input.tenantId,
    versionId: input.versionId,
    stepNumber: firstStep.stepNumber,
    action: "submitted",
    actorUserId: input.actorUserId ?? null,
    actorRole: input.actorRole ?? null,
    comment: input.comment ?? null,
    occurredAt,
  });

  return findBadgeIssuanceRuleVersionById(db, {
    tenantId: input.tenantId,
    ruleId: input.ruleId,
    versionId: input.versionId,
  });
};

export const decideBadgeIssuanceRuleVersion = async (
  db: SqlDatabase,
  input: DecideBadgeIssuanceRuleVersionInput,
): Promise<BadgeIssuanceRuleVersionRecord | null> => {
  const occurredAt = input.occurredAt ?? new Date().toISOString();
  const currentVersion = await findBadgeIssuanceRuleVersionById(db, {
    tenantId: input.tenantId,
    ruleId: input.ruleId,
    versionId: input.versionId,
  });

  if (currentVersion?.status !== "pending_approval") {
    return null;
  }

  const steps = await ensureBadgeIssuanceRuleApprovalStepsInitialized(db, {
    tenantId: input.tenantId,
    ruleId: input.ruleId,
    versionId: input.versionId,
  });
  const currentStep = steps.find((step) => step.status === "pending");

  if (currentStep === undefined) {
    return null;
  }

  if (!tenantMembershipRoleSatisfiesMinimumRole(input.actorRole, currentStep.requiredRole)) {
    throw new Error(
      `Role ${input.actorRole} does not satisfy required approval role ${currentStep.requiredRole}`,
    );
  }

  const nextStep = steps.find((step) => step.stepNumber > currentStep.stepNumber);
  const markCurrentStepStatement = (status: "approved" | "rejected"): Promise<SqlRunResult> =>
    db
      .prepare(
        `
        UPDATE badge_issuance_rule_approval_steps
        SET
          status = ?,
          decided_by_user_id = ?,
          decided_at = ?,
          decision_comment = ?,
          updated_at = ?
        WHERE tenant_id = ?
          AND version_id = ?
          AND step_number = ?
      `,
      )
      .bind(
        status,
        input.actorUserId,
        occurredAt,
        input.comment ?? null,
        occurredAt,
        input.tenantId,
        input.versionId,
        currentStep.stepNumber,
      )
      .run();
  const markNextStepPendingStatement = (): Promise<SqlRunResult> =>
    db
      .prepare(
        `
        UPDATE badge_issuance_rule_approval_steps
        SET
          status = 'pending',
          updated_at = ?
        WHERE tenant_id = ?
          AND version_id = ?
          AND step_number = ?
      `,
      )
      .bind(occurredAt, input.tenantId, input.versionId, nextStep?.stepNumber ?? null)
      .run();
  const updateVersionPendingStatement = (): Promise<SqlRunResult> =>
    db
      .prepare(
        `
        UPDATE badge_issuance_rule_versions
        SET
          status = 'pending_approval',
          updated_at = ?
        WHERE tenant_id = ?
          AND rule_id = ?
          AND id = ?
      `,
      )
      .bind(occurredAt, input.tenantId, input.ruleId, input.versionId)
      .run();
  const updateVersionApprovedStatement = (): Promise<SqlRunResult> =>
    db
      .prepare(
        `
        UPDATE badge_issuance_rule_versions
        SET
          status = 'approved',
          approved_by_user_id = ?,
          approved_at = ?,
          updated_at = ?
        WHERE tenant_id = ?
          AND rule_id = ?
          AND id = ?
      `,
      )
      .bind(
        input.actorUserId,
        occurredAt,
        occurredAt,
        input.tenantId,
        input.ruleId,
        input.versionId,
      )
      .run();
  const updateVersionRejectedStatement = (): Promise<SqlRunResult> =>
    db
      .prepare(
        `
        UPDATE badge_issuance_rule_versions
        SET
          status = 'rejected',
          approved_by_user_id = NULL,
          approved_at = NULL,
          updated_at = ?
        WHERE tenant_id = ?
          AND rule_id = ?
          AND id = ?
      `,
      )
      .bind(occurredAt, input.tenantId, input.ruleId, input.versionId)
      .run();

  if (input.decision === "rejected") {
    await markCurrentStepStatement("rejected");
    await updateVersionRejectedStatement();
  } else {
    await markCurrentStepStatement("approved");

    if (nextStep === undefined) {
      await updateVersionApprovedStatement();
    } else {
      await markNextStepPendingStatement();
      await updateVersionPendingStatement();
    }
  }

  await insertBadgeIssuanceRuleApprovalEvent(db, {
    tenantId: input.tenantId,
    versionId: input.versionId,
    stepNumber: currentStep.stepNumber,
    action: input.decision,
    actorUserId: input.actorUserId,
    actorRole: input.actorRole,
    comment: input.comment ?? null,
    occurredAt,
  });

  return findBadgeIssuanceRuleVersionById(db, {
    tenantId: input.tenantId,
    ruleId: input.ruleId,
    versionId: input.versionId,
  });
};

export const activateBadgeIssuanceRuleVersion = async (
  db: SqlDatabase,
  input: ActivateBadgeIssuanceRuleVersionInput,
): Promise<BadgeIssuanceRuleVersionRecord | null> => {
  const activatedAt = input.activatedAt ?? new Date().toISOString();
  const deprecateExistingStatement = (): Promise<SqlRunResult> =>
    db
      .prepare(
        `
        UPDATE badge_issuance_rule_versions
        SET
          status = 'deprecated',
          updated_at = ?
        WHERE tenant_id = ?
          AND rule_id = ?
          AND status = 'active'
          AND id <> ?
      `,
      )
      .bind(activatedAt, input.tenantId, input.ruleId, input.versionId)
      .run();
  const activateStatement = (): Promise<SqlRunResult> =>
    db
      .prepare(
        `
        UPDATE badge_issuance_rule_versions
        SET
          status = 'active',
          activated_by_user_id = ?,
          activated_at = ?,
          updated_at = ?
        WHERE tenant_id = ?
          AND rule_id = ?
          AND id = ?
      `,
      )
      .bind(
        input.actorUserId,
        activatedAt,
        activatedAt,
        input.tenantId,
        input.ruleId,
        input.versionId,
      )
      .run();
  const updateRuleActiveVersionStatement = (): Promise<SqlRunResult> =>
    db
      .prepare(
        `
        UPDATE badge_issuance_rules
        SET
          active_version_id = ?,
          updated_at = ?
        WHERE tenant_id = ?
          AND id = ?
      `,
      )
      .bind(input.versionId, activatedAt, input.tenantId, input.ruleId)
      .run();

  let activated: SqlRunResult;

  await deprecateExistingStatement();
  activated = await activateStatement();
  await updateRuleActiveVersionStatement();

  if ((activated.meta.rowsWritten ?? 0) === 0) {
    return null;
  }

  return findBadgeIssuanceRuleVersionById(db, {
    tenantId: input.tenantId,
    ruleId: input.ruleId,
    versionId: input.versionId,
  });
};

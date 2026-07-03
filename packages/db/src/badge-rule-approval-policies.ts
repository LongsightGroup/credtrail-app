import { createPrefixedId } from "./shared-helpers";
import type { SqlDatabase, SqlRunResult } from "./tenant-scope";
import { isTenantMembershipRole, type TenantMembershipRole } from "./tenant-memberships";

export type BadgeRuleApprovalRequirement = "always" | "never";

export interface BadgeRuleApprovalPolicyStepInput {
  readonly requiredRole: TenantMembershipRole;
  readonly label?: string | undefined;
}

export interface BadgeRuleApprovalPolicyStepRecord {
  readonly requiredRole: TenantMembershipRole;
  readonly label: string | null;
}

export interface BadgeRuleApprovalPolicyRecord {
  readonly id: string | null;
  readonly tenantId: string;
  readonly orgUnitId: string | null;
  readonly approvalRequirement: BadgeRuleApprovalRequirement;
  readonly approvalSteps: readonly BadgeRuleApprovalPolicyStepRecord[];
  readonly createdByUserId: string | null;
  readonly createdAt: string;
  readonly updatedAt: string;
}

export interface UpsertBadgeRuleApprovalPolicyInput {
  readonly tenantId: string;
  readonly orgUnitId?: string | null | undefined;
  readonly approvalRequirement: BadgeRuleApprovalRequirement;
  readonly approvalSteps: readonly BadgeRuleApprovalPolicyStepInput[];
  readonly createdByUserId?: string | undefined;
}

interface BadgeRuleApprovalPolicyRow {
  id: string;
  tenantId: string;
  orgUnitId: string | null;
  approvalRequirement: BadgeRuleApprovalRequirement;
  approvalStepsJson: string;
  createdByUserId: string | null;
  createdAt: string;
  updatedAt: string;
}

const DEFAULT_BADGE_RULE_APPROVAL_POLICY_STEPS: readonly BadgeRuleApprovalPolicyStepRecord[] = [
  {
    requiredRole: "admin",
    label: "Administrative approval",
  },
] as const;

const normalizeBadgeRuleApprovalPolicySteps = (
  approvalRequirement: BadgeRuleApprovalRequirement,
  steps: readonly BadgeRuleApprovalPolicyStepInput[],
): BadgeRuleApprovalPolicyStepRecord[] => {
  if (approvalRequirement === "always" && steps.length === 0) {
    throw new Error("Badge rule approval policy must include at least one approval step");
  }

  return steps.map((step) => {
    if (!isTenantMembershipRole(step.requiredRole)) {
      throw new Error(
        `Unsupported tenant role in badge rule approval policy: ${String(step.requiredRole)}`,
      );
    }

    return {
      requiredRole: step.requiredRole,
      label: step.label ?? null,
    };
  });
};

const parseBadgeRuleApprovalPolicyStepsJson = (
  approvalRequirement: BadgeRuleApprovalRequirement,
  stepsJson: string,
): BadgeRuleApprovalPolicyStepRecord[] => {
  const parsed: unknown = JSON.parse(stepsJson);

  if (!Array.isArray(parsed)) {
    throw new Error("Stored badge rule approval policy steps must be an array");
  }

  const steps = parsed.map((entry): BadgeRuleApprovalPolicyStepInput => {
    if (entry === null || typeof entry !== "object") {
      throw new Error("Stored badge rule approval policy step must be an object");
    }

    const record = entry as Record<string, unknown>;
    const requiredRole = record.requiredRole;
    const label = record.label;

    if (!isTenantMembershipRole(requiredRole)) {
      throw new Error("Stored badge rule approval policy step has an unsupported role");
    }

    if (label !== undefined && label !== null && typeof label !== "string") {
      throw new Error("Stored badge rule approval policy step label must be a string");
    }

    return {
      requiredRole,
      ...(typeof label === "string" ? { label } : {}),
    };
  });

  return normalizeBadgeRuleApprovalPolicySteps(approvalRequirement, steps);
};

const buildDefaultBadgeRuleApprovalPolicy = (
  tenantId: string,
  orgUnitId: string | null,
  nowIso: string = new Date().toISOString(),
): BadgeRuleApprovalPolicyRecord => {
  return {
    id: null,
    tenantId,
    orgUnitId,
    approvalRequirement: "always",
    approvalSteps: DEFAULT_BADGE_RULE_APPROVAL_POLICY_STEPS,
    createdByUserId: null,
    createdAt: nowIso,
    updatedAt: nowIso,
  };
};

const mapBadgeRuleApprovalPolicyRow = (
  row: BadgeRuleApprovalPolicyRow,
): BadgeRuleApprovalPolicyRecord => {
  return {
    id: row.id,
    tenantId: row.tenantId,
    orgUnitId: row.orgUnitId,
    approvalRequirement: row.approvalRequirement,
    approvalSteps: parseBadgeRuleApprovalPolicyStepsJson(
      row.approvalRequirement,
      row.approvalStepsJson,
    ),
    createdByUserId: row.createdByUserId,
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
  };
};

const findBadgeRuleApprovalPolicy = async (
  db: SqlDatabase,
  input: {
    readonly tenantId: string;
    readonly orgUnitId: string | null;
  },
): Promise<BadgeRuleApprovalPolicyRecord | null> => {
  const row =
    input.orgUnitId === null
      ? await db
          .prepare(
            `
            SELECT
              id,
              tenant_id AS tenantId,
              org_unit_id AS orgUnitId,
              approval_requirement AS approvalRequirement,
              approval_steps_json AS approvalStepsJson,
              created_by_user_id AS createdByUserId,
              created_at AS createdAt,
              updated_at AS updatedAt
            FROM badge_rule_approval_policies
            WHERE tenant_id = ?
              AND org_unit_id IS NULL
            LIMIT 1
          `,
          )
          .bind(input.tenantId)
          .first<BadgeRuleApprovalPolicyRow>()
      : await db
          .prepare(
            `
            SELECT
              id,
              tenant_id AS tenantId,
              org_unit_id AS orgUnitId,
              approval_requirement AS approvalRequirement,
              approval_steps_json AS approvalStepsJson,
              created_by_user_id AS createdByUserId,
              created_at AS createdAt,
              updated_at AS updatedAt
            FROM badge_rule_approval_policies
            WHERE tenant_id = ?
              AND org_unit_id = ?
            LIMIT 1
          `,
          )
          .bind(input.tenantId, input.orgUnitId)
          .first<BadgeRuleApprovalPolicyRow>();

  return row === null ? null : mapBadgeRuleApprovalPolicyRow(row);
};

export const resolveBadgeRuleApprovalPolicy = async (
  db: SqlDatabase,
  input: {
    readonly tenantId: string;
    readonly orgUnitId: string;
  },
): Promise<BadgeRuleApprovalPolicyRecord> => {
  const orgUnitPolicy = await findBadgeRuleApprovalPolicy(db, {
    tenantId: input.tenantId,
    orgUnitId: input.orgUnitId,
  });

  if (orgUnitPolicy !== null) {
    return orgUnitPolicy;
  }

  const tenantPolicy = await findBadgeRuleApprovalPolicy(db, {
    tenantId: input.tenantId,
    orgUnitId: null,
  });

  return tenantPolicy ?? buildDefaultBadgeRuleApprovalPolicy(input.tenantId, null);
};

export const upsertBadgeRuleApprovalPolicy = async (
  db: SqlDatabase,
  input: UpsertBadgeRuleApprovalPolicyInput,
): Promise<BadgeRuleApprovalPolicyRecord> => {
  const orgUnitId = input.orgUnitId ?? null;
  const approvalSteps = normalizeBadgeRuleApprovalPolicySteps(
    input.approvalRequirement,
    input.approvalSteps,
  );
  const existing = await findBadgeRuleApprovalPolicy(db, {
    tenantId: input.tenantId,
    orgUnitId,
  });
  const nowIso = new Date().toISOString();
  const approvalStepsJson = JSON.stringify(approvalSteps);

  if (existing === null) {
    const id = createPrefixedId("brap");
    const insertStatement = (): Promise<SqlRunResult> =>
      db
        .prepare(
          `
          INSERT INTO badge_rule_approval_policies (
            id,
            tenant_id,
            org_unit_id,
            approval_requirement,
            approval_steps_json,
            created_by_user_id,
            created_at,
            updated_at
          )
          VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        `,
        )
        .bind(
          id,
          input.tenantId,
          orgUnitId,
          input.approvalRequirement,
          approvalStepsJson,
          input.createdByUserId ?? null,
          nowIso,
          nowIso,
        )
        .run();

    await insertStatement();
  } else {
    const updateStatement = (): Promise<SqlRunResult> =>
      db
        .prepare(
          `
          UPDATE badge_rule_approval_policies
          SET
            approval_requirement = ?,
            approval_steps_json = ?,
            updated_at = ?
          WHERE tenant_id = ?
            AND id = ?
        `,
        )
        .bind(input.approvalRequirement, approvalStepsJson, nowIso, input.tenantId, existing.id)
        .run();

    await updateStatement();
  }

  const policy = await findBadgeRuleApprovalPolicy(db, {
    tenantId: input.tenantId,
    orgUnitId,
  });

  if (policy === null) {
    throw new Error(`Unable to upsert badge rule approval policy for tenant "${input.tenantId}"`);
  }

  return policy;
};

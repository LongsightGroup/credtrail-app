import { z } from "zod";
import { createPrefixedId } from "./shared-helpers";
import type { SqlDatabase, SqlRunResult } from "./tenant-scope";
import type { TenantMembershipRole } from "./tenant-memberships";

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

export const tenantDefaultBadgeRuleApprovalPolicyId = (tenantId: string): string => {
  return `${tenantId}:badge-rule-approval-policy:default`;
};

const tenantMembershipRoleSchema = z.enum(["owner", "admin", "issuer", "viewer"]);
const badgeRuleApprovalPolicyStepJsonSchema = z.object({
  requiredRole: tenantMembershipRoleSchema,
  label: z.string().nullable().optional(),
});
const badgeRuleApprovalPolicyStepsJsonSchema = z.array(badgeRuleApprovalPolicyStepJsonSchema);

const normalizeBadgeRuleApprovalPolicySteps = (
  approvalRequirement: BadgeRuleApprovalRequirement,
  steps: readonly BadgeRuleApprovalPolicyStepInput[],
): BadgeRuleApprovalPolicyStepRecord[] => {
  if (approvalRequirement === "never") {
    return [];
  }

  if (approvalRequirement === "always" && steps.length === 0) {
    throw new Error("Badge rule approval policy must include at least one approval step");
  }

  return steps.map((step) => {
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
  const steps = badgeRuleApprovalPolicyStepsJsonSchema.parse(JSON.parse(stepsJson)).map((step) => {
    return {
      requiredRole: step.requiredRole,
      ...(step.label === undefined || step.label === null ? {} : { label: step.label }),
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
  const row = await db
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
        AND (
          (? IS NULL AND org_unit_id IS NULL)
          OR org_unit_id = ?
        )
      LIMIT 1
    `,
    )
    .bind(input.tenantId, input.orgUnitId, input.orgUnitId)
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

export const ensureTenantDefaultBadgeRuleApprovalPolicy = async (
  db: SqlDatabase,
  tenantId: string,
): Promise<BadgeRuleApprovalPolicyRecord> => {
  const nowIso = new Date().toISOString();
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
        VALUES (?, ?, NULL, 'always', ?, NULL, ?, ?)
        ON CONFLICT DO NOTHING
      `,
      )
      .bind(
        tenantDefaultBadgeRuleApprovalPolicyId(tenantId),
        tenantId,
        JSON.stringify(DEFAULT_BADGE_RULE_APPROVAL_POLICY_STEPS),
        nowIso,
        nowIso,
      )
      .run();

  await insertStatement();

  const policy = await findBadgeRuleApprovalPolicy(db, {
    tenantId,
    orgUnitId: null,
  });

  if (policy === null) {
    throw new Error(`Unable to ensure default badge rule approval policy for tenant "${tenantId}"`);
  }

  return policy;
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

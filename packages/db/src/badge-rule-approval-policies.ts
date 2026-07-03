import { z } from "zod";
import { createPrefixedId } from "./shared-helpers";
import { ORG_ANCESTORS_WITH_DEPTH_CTE } from "./tenant-org-unit-hierarchy-sql.js";
import type { SqlDatabase, SqlRunResult } from "./tenant-scope";
import type { TenantMembershipRole } from "./tenant-memberships";
import type { BadgeIssuanceRuleApprovalStepTarget } from "./badge-issuance-rule-types.js";

export type BadgeRuleApprovalRequirement = "always" | "never";

export type BadgeRuleApprovalPolicyStepInput =
  | {
      readonly targetType?: "role_threshold" | undefined;
      readonly requiredRole: TenantMembershipRole;
      readonly orgUnitId?: string | null | undefined;
      readonly label?: string | undefined;
    }
  | {
      readonly targetType: "user";
      readonly targetUserId: string;
      readonly requiredRole?: TenantMembershipRole | null | undefined;
      readonly orgUnitId?: string | null | undefined;
      readonly label?: string | undefined;
    }
  | {
      readonly targetType: "approver_group";
      readonly targetApproverGroupId: string;
      readonly requiredRole?: TenantMembershipRole | null | undefined;
      readonly orgUnitId?: string | null | undefined;
      readonly label?: string | undefined;
    };

export type BadgeRuleApprovalPolicyStepRecord = BadgeIssuanceRuleApprovalStepTarget & {
  readonly orgUnitId: string | null;
  readonly label: string | null;
};

export interface BadgeRuleApprovalPolicyRecord {
  readonly id: string | null;
  readonly tenantId: string;
  readonly orgUnitId: string | null;
  readonly approvalRequirement: BadgeRuleApprovalRequirement;
  readonly allowSelfCertification: boolean;
  readonly approvalSteps: readonly BadgeRuleApprovalPolicyStepRecord[];
  readonly createdByUserId: string | null;
  readonly createdAt: string;
  readonly updatedAt: string;
}

export interface UpsertBadgeRuleApprovalPolicyInput {
  readonly tenantId: string;
  readonly orgUnitId?: string | null | undefined;
  readonly approvalRequirement: BadgeRuleApprovalRequirement;
  readonly allowSelfCertification?: boolean | undefined;
  readonly approvalSteps: readonly BadgeRuleApprovalPolicyStepInput[];
  readonly createdByUserId?: string | undefined;
}

interface BadgeRuleApprovalPolicyRow {
  id: string;
  tenantId: string;
  orgUnitId: string | null;
  approvalRequirement: BadgeRuleApprovalRequirement;
  allowSelfCertification: boolean | number;
  approvalStepsJson: string;
  createdByUserId: string | null;
  createdAt: string;
  updatedAt: string;
}

const DEFAULT_BADGE_RULE_APPROVAL_POLICY_STEPS: readonly BadgeRuleApprovalPolicyStepRecord[] = [
  {
    targetType: "role_threshold",
    requiredRole: "admin",
    targetUserId: null,
    targetApproverGroupId: null,
    orgUnitId: null,
    label: "Administrative approval",
  },
] as const;

export const tenantDefaultBadgeRuleApprovalPolicyId = (tenantId: string): string => {
  return `${tenantId}:badge-rule-approval-policy:default`;
};

const tenantMembershipRoleSchema = z.enum(["owner", "admin", "issuer", "viewer"]);
const badgeRuleApprovalPolicyStepJsonSchema = z
  .discriminatedUnion("targetType", [
    z.object({
      targetType: z.literal("role_threshold"),
      requiredRole: tenantMembershipRoleSchema,
      targetUserId: z.null().optional(),
      targetApproverGroupId: z.null().optional(),
      orgUnitId: z.string().nullable().optional(),
      label: z.string().nullable().optional(),
    }),
    z.object({
      targetType: z.literal("user"),
      requiredRole: tenantMembershipRoleSchema.nullable().optional(),
      targetUserId: z.string().min(1),
      targetApproverGroupId: z.null().optional(),
      orgUnitId: z.string().nullable().optional(),
      label: z.string().nullable().optional(),
    }),
    z.object({
      targetType: z.literal("approver_group"),
      requiredRole: tenantMembershipRoleSchema.nullable().optional(),
      targetUserId: z.null().optional(),
      targetApproverGroupId: z.string().min(1),
      orgUnitId: z.string().nullable().optional(),
      label: z.string().nullable().optional(),
    }),
  ])
  .or(
    z.object({
      requiredRole: tenantMembershipRoleSchema,
      label: z.string().nullable().optional(),
    }),
  );
const badgeRuleApprovalPolicyStepsJsonSchema = z.array(badgeRuleApprovalPolicyStepJsonSchema);

const mapPolicyStepInputToRecord = (
  step: BadgeRuleApprovalPolicyStepInput,
): BadgeRuleApprovalPolicyStepRecord => {
  if (step.targetType === "user") {
    return {
      targetType: "user",
      requiredRole: step.requiredRole ?? null,
      targetUserId: step.targetUserId,
      targetApproverGroupId: null,
      orgUnitId: step.orgUnitId ?? null,
      label: step.label ?? null,
    };
  }

  if (step.targetType === "approver_group") {
    return {
      targetType: "approver_group",
      requiredRole: step.requiredRole ?? null,
      targetUserId: null,
      targetApproverGroupId: step.targetApproverGroupId,
      orgUnitId: step.orgUnitId ?? null,
      label: step.label ?? null,
    };
  }

  return {
    targetType: "role_threshold",
    requiredRole: step.requiredRole,
    targetUserId: null,
    targetApproverGroupId: null,
    orgUnitId: step.orgUnitId ?? null,
    label: step.label ?? null,
  };
};

const parseBadgeRuleApprovalPolicyStepJson = (step: unknown): BadgeRuleApprovalPolicyStepRecord => {
  const parsed = badgeRuleApprovalPolicyStepJsonSchema.parse(step);

  if ("targetType" in parsed && parsed.targetType === "user") {
    return {
      targetType: "user",
      requiredRole: parsed.requiredRole ?? null,
      targetUserId: parsed.targetUserId,
      targetApproverGroupId: null,
      orgUnitId: parsed.orgUnitId ?? null,
      label: parsed.label ?? null,
    };
  }

  if ("targetType" in parsed && parsed.targetType === "approver_group") {
    return {
      targetType: "approver_group",
      requiredRole: parsed.requiredRole ?? null,
      targetUserId: null,
      targetApproverGroupId: parsed.targetApproverGroupId,
      orgUnitId: parsed.orgUnitId ?? null,
      label: parsed.label ?? null,
    };
  }

  return {
    targetType: "role_threshold",
    requiredRole: parsed.requiredRole,
    targetUserId: null,
    targetApproverGroupId: null,
    orgUnitId: "targetType" in parsed ? (parsed.orgUnitId ?? null) : null,
    label: parsed.label ?? null,
  };
};

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

  return steps.map(mapPolicyStepInputToRecord);
};

const parseBadgeRuleApprovalPolicyStepsJson = (
  approvalRequirement: BadgeRuleApprovalRequirement,
  stepsJson: string,
): BadgeRuleApprovalPolicyStepRecord[] => {
  const steps = badgeRuleApprovalPolicyStepsJsonSchema
    .parse(JSON.parse(stepsJson))
    .map(parseBadgeRuleApprovalPolicyStepJson);

  if (approvalRequirement === "never") {
    return [];
  }

  if (approvalRequirement === "always" && steps.length === 0) {
    throw new Error("Badge rule approval policy must include at least one approval step");
  }

  return steps;
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
    allowSelfCertification: false,
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
    allowSelfCertification: row.allowSelfCertification === true || row.allowSelfCertification === 1,
    approvalSteps: parseBadgeRuleApprovalPolicyStepsJson(
      row.approvalRequirement,
      row.approvalStepsJson,
    ),
    createdByUserId: row.createdByUserId,
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
  };
};

const BADGE_RULE_APPROVAL_POLICY_SELECT_COLUMNS = `
  id,
  tenant_id AS tenantId,
  org_unit_id AS orgUnitId,
  approval_requirement AS approvalRequirement,
  allow_self_certification AS allowSelfCertification,
  approval_steps_json AS approvalStepsJson,
  created_by_user_id AS createdByUserId,
  created_at AS createdAt,
  updated_at AS updatedAt
`;

const findBadgeRuleApprovalPolicy = async (
  db: SqlDatabase,
  input: {
    readonly tenantId: string;
    readonly orgUnitId: string | null;
  },
): Promise<BadgeRuleApprovalPolicyRecord | null> => {
  if (input.orgUnitId === null) {
    const row = await db
      .prepare(
        `
        SELECT
          ${BADGE_RULE_APPROVAL_POLICY_SELECT_COLUMNS}
        FROM badge_rule_approval_policies
        WHERE tenant_id = ?
          AND org_unit_id IS NULL
        LIMIT 1
      `,
      )
      .bind(input.tenantId)
      .first<BadgeRuleApprovalPolicyRow>();

    return row === null ? null : mapBadgeRuleApprovalPolicyRow(row);
  }

  const row = await db
    .prepare(
      `
      SELECT
        ${BADGE_RULE_APPROVAL_POLICY_SELECT_COLUMNS}
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
  const row = await db
    .prepare(
      `
      ${ORG_ANCESTORS_WITH_DEPTH_CTE}
      SELECT
        ${BADGE_RULE_APPROVAL_POLICY_SELECT_COLUMNS}
      FROM org_ancestors
      INNER JOIN badge_rule_approval_policies AS policies
        ON policies.tenant_id = ?
        AND policies.org_unit_id = org_ancestors.orgUnitId
      ORDER BY org_ancestors.depth ASC
      LIMIT 1
    `,
    )
    .bind(input.tenantId, input.orgUnitId, input.tenantId, input.tenantId)
    .first<BadgeRuleApprovalPolicyRow>();

  if (row !== null) {
    return mapBadgeRuleApprovalPolicyRow(row);
  }

  const tenantPolicy = await findBadgeRuleApprovalPolicy(db, {
    tenantId: input.tenantId,
    orgUnitId: null,
  });

  return tenantPolicy ?? buildDefaultBadgeRuleApprovalPolicy(input.tenantId, null);
};

export const resolveTenantDefaultBadgeRuleApprovalPolicy = async (
  db: SqlDatabase,
  tenantId: string,
): Promise<BadgeRuleApprovalPolicyRecord> => {
  const tenantPolicy = await findBadgeRuleApprovalPolicy(db, {
    tenantId,
    orgUnitId: null,
  });

  return tenantPolicy ?? buildDefaultBadgeRuleApprovalPolicy(tenantId, null);
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
          allow_self_certification,
          approval_steps_json,
          created_by_user_id,
          created_at,
          updated_at
        )
        VALUES (?, ?, NULL, 'always', FALSE, ?, NULL, ?, ?)
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
  const allowSelfCertification =
    input.approvalRequirement === "never" ? input.allowSelfCertification === true : false;

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
            allow_self_certification,
            approval_steps_json,
            created_by_user_id,
            created_at,
            updated_at
          )
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        `,
        )
        .bind(
          id,
          input.tenantId,
          orgUnitId,
          input.approvalRequirement,
          allowSelfCertification,
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
            allow_self_certification = ?,
            approval_steps_json = ?,
            updated_at = ?
          WHERE tenant_id = ?
            AND id = ?
        `,
        )
        .bind(
          input.approvalRequirement,
          allowSelfCertification,
          approvalStepsJson,
          nowIso,
          input.tenantId,
          existing.id,
        )
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

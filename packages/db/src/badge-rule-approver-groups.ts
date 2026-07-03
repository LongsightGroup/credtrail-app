import { createPrefixedId } from "./shared-helpers";
import type { SqlDatabase } from "./tenant-scope";

export interface BadgeRuleApproverGroupRecord {
  readonly id: string;
  readonly tenantId: string;
  readonly orgUnitId: string | null;
  readonly name: string;
  readonly createdByUserId: string | null;
  readonly createdAt: string;
  readonly updatedAt: string;
}

export interface CreateBadgeRuleApproverGroupInput {
  readonly tenantId: string;
  readonly orgUnitId?: string | null | undefined;
  readonly name: string;
  readonly createdByUserId?: string | undefined;
}

export interface AddBadgeRuleApproverGroupMemberInput {
  readonly tenantId: string;
  readonly groupId: string;
  readonly userId: string;
  readonly createdByUserId?: string | undefined;
}

export const createBadgeRuleApproverGroup = async (
  db: SqlDatabase,
  input: CreateBadgeRuleApproverGroupInput,
): Promise<BadgeRuleApproverGroupRecord> => {
  const id = createPrefixedId("brag");
  const nowIso = new Date().toISOString();
  const orgUnitId = input.orgUnitId ?? null;

  await db
    .prepare(
      `
      INSERT INTO badge_rule_approver_groups (
        id,
        tenant_id,
        org_unit_id,
        name,
        created_by_user_id,
        created_at,
        updated_at
      )
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `,
    )
    .bind(id, input.tenantId, orgUnitId, input.name, input.createdByUserId ?? null, nowIso, nowIso)
    .run();

  return {
    id,
    tenantId: input.tenantId,
    orgUnitId,
    name: input.name,
    createdByUserId: input.createdByUserId ?? null,
    createdAt: nowIso,
    updatedAt: nowIso,
  };
};

export const addBadgeRuleApproverGroupMember = async (
  db: SqlDatabase,
  input: AddBadgeRuleApproverGroupMemberInput,
): Promise<void> => {
  const nowIso = new Date().toISOString();

  await db
    .prepare(
      `
      INSERT INTO badge_rule_approver_group_members (
        tenant_id,
        group_id,
        user_id,
        created_by_user_id,
        created_at
      )
      VALUES (?, ?, ?, ?, ?)
    `,
    )
    .bind(input.tenantId, input.groupId, input.userId, input.createdByUserId ?? null, nowIso)
    .run();
};

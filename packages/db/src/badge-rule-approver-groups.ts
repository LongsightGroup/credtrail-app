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

export interface BadgeRuleApproverGroupMemberRecord {
  readonly tenantId: string;
  readonly groupId: string;
  readonly userId: string;
  readonly email: string | null;
  readonly role: string | null;
  readonly createdByUserId: string | null;
  readonly createdAt: string;
}

export interface BadgeRuleApproverGroupWithMembersRecord extends BadgeRuleApproverGroupRecord {
  readonly members: readonly BadgeRuleApproverGroupMemberRecord[];
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

export type AddBadgeRuleApproverGroupMemberResult =
  | {
      readonly status: "added";
    }
  | {
      readonly status: "group_not_found";
    }
  | {
      readonly status: "membership_not_found";
    }
  | {
      readonly status: "already_member";
    };

export type RemoveBadgeRuleApproverGroupMemberResult =
  | {
      readonly status: "removed";
    }
  | {
      readonly status: "group_not_found";
    }
  | {
      readonly status: "member_not_found";
    };

interface BadgeRuleApproverGroupRow {
  id: string;
  tenantId: string;
  orgUnitId: string | null;
  name: string;
  createdByUserId: string | null;
  createdAt: string;
  updatedAt: string;
}

interface BadgeRuleApproverGroupMemberRow {
  tenantId: string;
  groupId: string;
  userId: string;
  email: string | null;
  role: string | null;
  createdByUserId: string | null;
  createdAt: string;
}

interface ApproverGroupExistsRow {
  id: string;
}

const mapBadgeRuleApproverGroupRow = (
  row: BadgeRuleApproverGroupRow,
): BadgeRuleApproverGroupRecord => ({
  id: row.id,
  tenantId: row.tenantId,
  orgUnitId: row.orgUnitId,
  name: row.name,
  createdByUserId: row.createdByUserId,
  createdAt: row.createdAt,
  updatedAt: row.updatedAt,
});

const mapBadgeRuleApproverGroupMemberRow = (
  row: BadgeRuleApproverGroupMemberRow,
): BadgeRuleApproverGroupMemberRecord => ({
  tenantId: row.tenantId,
  groupId: row.groupId,
  userId: row.userId,
  email: row.email,
  role: row.role,
  createdByUserId: row.createdByUserId,
  createdAt: row.createdAt,
});

const badgeRuleApproverGroupExists = async (
  db: SqlDatabase,
  input: {
    readonly tenantId: string;
    readonly groupId: string;
  },
): Promise<boolean> => {
  const row = await db
    .prepare(
      `
      SELECT id
      FROM badge_rule_approver_groups
      WHERE tenant_id = ?
        AND id = ?
      LIMIT 1
    `,
    )
    .bind(input.tenantId, input.groupId)
    .first<ApproverGroupExistsRow>();

  return row !== null;
};

const tenantMembershipExists = async (
  db: SqlDatabase,
  input: {
    readonly tenantId: string;
    readonly userId: string;
  },
): Promise<boolean> => {
  const row = await db
    .prepare(
      `
      SELECT user_id AS userId
      FROM memberships
      WHERE tenant_id = ?
        AND user_id = ?
      LIMIT 1
    `,
    )
    .bind(input.tenantId, input.userId)
    .first<{ userId: string }>();

  return row !== null;
};

const badgeRuleApproverGroupMemberExists = async (
  db: SqlDatabase,
  input: {
    readonly tenantId: string;
    readonly groupId: string;
    readonly userId: string;
  },
): Promise<boolean> => {
  const row = await db
    .prepare(
      `
      SELECT user_id AS userId
      FROM badge_rule_approver_group_members
      WHERE tenant_id = ?
        AND group_id = ?
        AND user_id = ?
      LIMIT 1
    `,
    )
    .bind(input.tenantId, input.groupId, input.userId)
    .first<{ userId: string }>();

  return row !== null;
};

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
): Promise<AddBadgeRuleApproverGroupMemberResult> => {
  const nowIso = new Date().toISOString();
  const groupExists = await badgeRuleApproverGroupExists(db, {
    tenantId: input.tenantId,
    groupId: input.groupId,
  });

  if (!groupExists) {
    return { status: "group_not_found" };
  }

  const membershipExists = await tenantMembershipExists(db, {
    tenantId: input.tenantId,
    userId: input.userId,
  });

  if (!membershipExists) {
    return { status: "membership_not_found" };
  }

  const memberExists = await badgeRuleApproverGroupMemberExists(db, {
    tenantId: input.tenantId,
    groupId: input.groupId,
    userId: input.userId,
  });

  if (memberExists) {
    return { status: "already_member" };
  }

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

  return { status: "added" };
};

export const listBadgeRuleApproverGroupsWithMembers = async (
  db: SqlDatabase,
  tenantId: string,
): Promise<BadgeRuleApproverGroupWithMembersRecord[]> => {
  const [groupResult, memberResult] = await Promise.all([
    db
      .prepare(
        `
        SELECT
          id,
          tenant_id AS tenantId,
          org_unit_id AS orgUnitId,
          name,
          created_by_user_id AS createdByUserId,
          created_at AS createdAt,
          updated_at AS updatedAt
        FROM badge_rule_approver_groups
        WHERE tenant_id = ?
        ORDER BY name ASC, id ASC
      `,
      )
      .bind(tenantId)
      .all<BadgeRuleApproverGroupRow>(),
    db
      .prepare(
        `
        SELECT
          members.tenant_id AS tenantId,
          members.group_id AS groupId,
          members.user_id AS userId,
          users.email,
          memberships.role,
          members.created_by_user_id AS createdByUserId,
          members.created_at AS createdAt
        FROM badge_rule_approver_group_members AS members
        LEFT JOIN users
          ON users.id = members.user_id
        LEFT JOIN memberships
          ON memberships.tenant_id = members.tenant_id
          AND memberships.user_id = members.user_id
        WHERE members.tenant_id = ?
        ORDER BY users.email ASC, members.user_id ASC
      `,
      )
      .bind(tenantId)
      .all<BadgeRuleApproverGroupMemberRow>(),
  ]);
  const membersByGroupId = new Map<string, BadgeRuleApproverGroupMemberRecord[]>();

  for (const row of memberResult.results) {
    const member = mapBadgeRuleApproverGroupMemberRow(row);
    const members = membersByGroupId.get(member.groupId) ?? [];
    members.push(member);
    membersByGroupId.set(member.groupId, members);
  }

  return groupResult.results.map((row) => {
    const group = mapBadgeRuleApproverGroupRow(row);

    return {
      ...group,
      members: membersByGroupId.get(group.id) ?? [],
    };
  });
};

export const removeBadgeRuleApproverGroupMember = async (
  db: SqlDatabase,
  input: {
    readonly tenantId: string;
    readonly groupId: string;
    readonly userId: string;
  },
): Promise<RemoveBadgeRuleApproverGroupMemberResult> => {
  const groupExists = await badgeRuleApproverGroupExists(db, {
    tenantId: input.tenantId,
    groupId: input.groupId,
  });

  if (!groupExists) {
    return { status: "group_not_found" };
  }

  const result = await db
    .prepare(
      `
      DELETE FROM badge_rule_approver_group_members
      WHERE tenant_id = ?
        AND group_id = ?
        AND user_id = ?
    `,
    )
    .bind(input.tenantId, input.groupId, input.userId)
    .run();

  return (result.meta.rowsWritten ?? 0) > 0
    ? { status: "removed" }
    : { status: "member_not_found" };
};

export const removeBadgeRuleApproverGroup = async (
  db: SqlDatabase,
  input: {
    readonly tenantId: string;
    readonly groupId: string;
  },
): Promise<boolean> => {
  const result = await db
    .prepare(
      `
      DELETE FROM badge_rule_approver_groups
      WHERE tenant_id = ?
        AND id = ?
    `,
    )
    .bind(input.tenantId, input.groupId)
    .run();

  return (result.meta.rowsWritten ?? 0) > 0;
};

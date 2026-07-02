import {
  countTenantMembershipsByRole,
  createAuditLog,
  findTenantMembership,
  findUserById,
  listTenantMembers,
  removeTenantMembership,
  revokeTenantBreakGlassAccount,
  upsertTenantMembershipRole,
  upsertUserByEmail,
  type SqlDatabase,
  type TenantMembershipRole,
} from "@credtrail/db";
import {
  parseCreateTenantMemberRequest,
  parseTenantMemberPathParams,
  parseTenantPathParams,
  parseUpdateTenantMemberRoleRequest,
} from "@credtrail/validation";
import type { Hono } from "hono";
import type { AppContext, AppEnv } from "../app";
import type { RequireTenantRole, ResolveDatabase } from "../app/route-deps";

type TenantMemberInviteResult = {
  deliveryStatus: "sent" | "skipped" | "failed";
  inviteKind: "magic_link" | "sso_notice";
};

type MembershipAuditAction =
  | "membership.role_assigned"
  | "membership.role_changed"
  | "membership.role_reasserted";

interface RegisterTenantMemberManagementRoutesInput {
  app: Hono<AppEnv>;
  assertRoleChangeAllowed: (
    c: AppContext,
    input: {
      db: SqlDatabase;
      tenantId: string;
      actorUserId: string;
      actorRole: TenantMembershipRole;
      targetUserId: string;
      previousRole: TenantMembershipRole | null;
      nextRole: TenantMembershipRole;
    },
  ) => Promise<Response | null>;
  canManageTenantRole: (
    actorRole: TenantMembershipRole,
    targetRole: TenantMembershipRole,
  ) => boolean;
  membershipAuditAction: (
    previousRole: TenantMembershipRole | null,
    nextRole: TenantMembershipRole,
  ) => MembershipAuditAction;
  requestInviteForTenantMember: (
    c: AppContext,
    input: {
      tenantId: string;
      email: string;
      role: TenantMembershipRole;
      sendInvite: boolean;
    },
  ) => Promise<TenantMemberInviteResult>;
  resolveDatabase: ResolveDatabase;
  requireTenantRole: RequireTenantRole;
  ADMIN_ROLES: readonly TenantMembershipRole[];
}

export const registerTenantMemberManagementRoutes = (
  input: RegisterTenantMemberManagementRoutesInput,
): void => {
  const {
    app,
    assertRoleChangeAllowed,
    canManageTenantRole,
    membershipAuditAction,
    requestInviteForTenantMember,
    resolveDatabase,
    requireTenantRole,
    ADMIN_ROLES,
  } = input;

  app.get("/v1/tenants/:tenantId/members", async (c) => {
    const pathParams = parseTenantPathParams(c.req.param());
    const roleCheck = await requireTenantRole(c, pathParams.tenantId, ADMIN_ROLES);

    if (roleCheck instanceof Response) {
      return roleCheck;
    }

    const members = await listTenantMembers(resolveDatabase(c.env), pathParams.tenantId);

    return c.json({
      tenantId: pathParams.tenantId,
      members,
    });
  });

  app.post("/v1/tenants/:tenantId/members", async (c) => {
    const pathParams = parseTenantPathParams(c.req.param());
    let request: ReturnType<typeof parseCreateTenantMemberRequest>;

    try {
      request = parseCreateTenantMemberRequest(await c.req.json<unknown>());
    } catch {
      return c.json(
        {
          error: "Invalid tenant member payload",
        },
        400,
      );
    }

    const roleCheck = await requireTenantRole(c, pathParams.tenantId, ADMIN_ROLES);

    if (roleCheck instanceof Response) {
      return roleCheck;
    }

    const { session, membershipRole } = roleCheck;
    const db = resolveDatabase(c.env);
    const user = await upsertUserByEmail(db, request.email);
    const existingMembership = await findTenantMembership(db, pathParams.tenantId, user.id);
    const rolePolicyResponse = await assertRoleChangeAllowed(c, {
      db,
      tenantId: pathParams.tenantId,
      actorUserId: session.userId,
      actorRole: membershipRole,
      targetUserId: user.id,
      previousRole: existingMembership?.role ?? null,
      nextRole: request.role,
    });

    if (rolePolicyResponse !== null) {
      return rolePolicyResponse;
    }

    const roleResult = await upsertTenantMembershipRole(db, {
      tenantId: pathParams.tenantId,
      userId: user.id,
      role: request.role,
    });
    const invite = await requestInviteForTenantMember(c, {
      tenantId: pathParams.tenantId,
      email: user.email,
      role: roleResult.membership.role,
      sendInvite: request.sendInvite !== false,
    });
    const action = membershipAuditAction(roleResult.previousRole, roleResult.membership.role);

    await createAuditLog(db, {
      tenantId: pathParams.tenantId,
      actorUserId: session.userId,
      action,
      targetType: "membership",
      targetId: `${pathParams.tenantId}:${user.id}`,
      metadata: {
        actorRole: membershipRole,
        userId: user.id,
        email: user.email,
        previousRole: roleResult.previousRole,
        newRole: roleResult.membership.role,
        role: roleResult.membership.role,
        changed: roleResult.changed,
        inviteDeliveryStatus: invite.deliveryStatus,
        inviteKind: invite.inviteKind,
      },
    });

    if (invite.deliveryStatus !== "skipped") {
      await createAuditLog(db, {
        tenantId: pathParams.tenantId,
        actorUserId: session.userId,
        action: "membership.invite_sent",
        targetType: "membership",
        targetId: `${pathParams.tenantId}:${user.id}`,
        metadata: {
          actorRole: membershipRole,
          userId: user.id,
          email: user.email,
          newRole: roleResult.membership.role,
          role: roleResult.membership.role,
          inviteDeliveryStatus: invite.deliveryStatus,
          inviteKind: invite.inviteKind,
        },
      });
    }

    return c.json(
      {
        tenantId: pathParams.tenantId,
        member: {
          ...roleResult.membership,
          email: user.email,
        },
        previousRole: roleResult.previousRole,
        changed: roleResult.changed,
        invite,
      },
      roleResult.previousRole === null ? 201 : 200,
    );
  });

  app.patch("/v1/tenants/:tenantId/members/:userId/role", async (c) => {
    const pathParams = parseTenantMemberPathParams(c.req.param());
    let request: ReturnType<typeof parseUpdateTenantMemberRoleRequest>;

    try {
      request = parseUpdateTenantMemberRoleRequest(await c.req.json<unknown>());
    } catch {
      return c.json(
        {
          error: "Invalid tenant member role payload",
        },
        400,
      );
    }

    const roleCheck = await requireTenantRole(c, pathParams.tenantId, ADMIN_ROLES);

    if (roleCheck instanceof Response) {
      return roleCheck;
    }

    const { session, membershipRole } = roleCheck;
    const db = resolveDatabase(c.env);
    const existingMembership = await findTenantMembership(
      db,
      pathParams.tenantId,
      pathParams.userId,
    );

    if (existingMembership === null) {
      return c.json(
        {
          error: "Tenant member not found",
        },
        404,
      );
    }

    const rolePolicyResponse = await assertRoleChangeAllowed(c, {
      db,
      tenantId: pathParams.tenantId,
      actorUserId: session.userId,
      actorRole: membershipRole,
      targetUserId: pathParams.userId,
      previousRole: existingMembership.role,
      nextRole: request.role,
    });

    if (rolePolicyResponse !== null) {
      return rolePolicyResponse;
    }

    const [roleResult, user] = await Promise.all([
      upsertTenantMembershipRole(db, {
        tenantId: pathParams.tenantId,
        userId: pathParams.userId,
        role: request.role,
      }),
      findUserById(db, pathParams.userId),
    ]);
    const action = membershipAuditAction(roleResult.previousRole, roleResult.membership.role);

    await createAuditLog(db, {
      tenantId: pathParams.tenantId,
      actorUserId: session.userId,
      action,
      targetType: "membership",
      targetId: `${pathParams.tenantId}:${pathParams.userId}`,
      metadata: {
        actorRole: membershipRole,
        userId: pathParams.userId,
        email: user?.email ?? null,
        previousRole: roleResult.previousRole,
        newRole: roleResult.membership.role,
        role: roleResult.membership.role,
        changed: roleResult.changed,
      },
    });

    return c.json({
      tenantId: pathParams.tenantId,
      member: {
        ...roleResult.membership,
        email: user?.email ?? "",
      },
      previousRole: roleResult.previousRole,
      changed: roleResult.changed,
    });
  });

  app.post("/v1/tenants/:tenantId/members/:userId/invite", async (c) => {
    const pathParams = parseTenantMemberPathParams(c.req.param());
    const roleCheck = await requireTenantRole(c, pathParams.tenantId, ADMIN_ROLES);

    if (roleCheck instanceof Response) {
      return roleCheck;
    }

    const { session, membershipRole } = roleCheck;
    const db = resolveDatabase(c.env);
    const [membership, user] = await Promise.all([
      findTenantMembership(db, pathParams.tenantId, pathParams.userId),
      findUserById(db, pathParams.userId),
    ]);

    if (membership === null || user === null) {
      return c.json(
        {
          error: "Tenant member not found",
        },
        404,
      );
    }

    if (!canManageTenantRole(membershipRole, membership.role)) {
      return c.json(
        {
          error: "Only tenant owners can invite owner members.",
        },
        403,
      );
    }

    const invite = await requestInviteForTenantMember(c, {
      tenantId: pathParams.tenantId,
      email: user.email,
      role: membership.role,
      sendInvite: true,
    });

    await createAuditLog(db, {
      tenantId: pathParams.tenantId,
      actorUserId: session.userId,
      action: "membership.invite_sent",
      targetType: "membership",
      targetId: `${pathParams.tenantId}:${pathParams.userId}`,
      metadata: {
        actorRole: membershipRole,
        userId: pathParams.userId,
        email: user.email,
        newRole: membership.role,
        role: membership.role,
        inviteDeliveryStatus: invite.deliveryStatus,
        inviteKind: invite.inviteKind,
      },
    });

    return c.json({
      tenantId: pathParams.tenantId,
      userId: pathParams.userId,
      invite,
    });
  });

  app.delete("/v1/tenants/:tenantId/members/:userId", async (c) => {
    const pathParams = parseTenantMemberPathParams(c.req.param());
    const roleCheck = await requireTenantRole(c, pathParams.tenantId, ADMIN_ROLES);

    if (roleCheck instanceof Response) {
      return roleCheck;
    }

    const { session, membershipRole } = roleCheck;
    const db = resolveDatabase(c.env);
    const [membership, user] = await Promise.all([
      findTenantMembership(db, pathParams.tenantId, pathParams.userId),
      findUserById(db, pathParams.userId),
    ]);

    if (membership === null) {
      return c.json(
        {
          error: "Tenant member not found",
        },
        404,
      );
    }

    if (pathParams.userId === session.userId) {
      return c.json(
        {
          error: "You cannot remove your own tenant membership.",
        },
        409,
      );
    }

    if (membership.role === "owner" && membershipRole !== "owner") {
      return c.json(
        {
          error: "Only tenant owners can remove an owner membership.",
        },
        403,
      );
    }

    if (membership.role === "owner") {
      const counts = await countTenantMembershipsByRole(db, pathParams.tenantId);

      if (counts.owner <= 1) {
        return c.json(
          {
            error: "At least one tenant owner must remain.",
          },
          409,
        );
      }
    }

    const removed = await removeTenantMembership(db, pathParams.tenantId, pathParams.userId);
    const revokedBreakGlass = await revokeTenantBreakGlassAccount(db, {
      tenantId: pathParams.tenantId,
      userId: pathParams.userId,
      revokedAt: new Date().toISOString(),
    });

    if (removed) {
      await createAuditLog(db, {
        tenantId: pathParams.tenantId,
        actorUserId: session.userId,
        action: "membership.removed",
        targetType: "membership",
        targetId: `${pathParams.tenantId}:${pathParams.userId}`,
        metadata: {
          actorRole: membershipRole,
          userId: pathParams.userId,
          email: user?.email ?? null,
          previousRole: membership.role,
          revokedBreakGlass,
        },
      });
    }

    return c.json({
      tenantId: pathParams.tenantId,
      userId: pathParams.userId,
      removed,
      revokedBreakGlass,
    });
  });
};

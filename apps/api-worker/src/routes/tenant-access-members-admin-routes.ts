import {
  countTenantMembershipsByRole,
  createAuditLog,
  findTenantMembership,
  findUserById,
  removeTenantMembership,
  revokeTenantBreakGlassAccount,
  upsertTenantMembershipRole,
  upsertUserByEmail,
  type SessionRecord,
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
import { readOptionalFormField } from "../admin/admin-form-helpers";
import { setAdminListMessageFlash } from "../admin/admin-list-message-flash";
import {
  buildAccessMembersAdminPath,
  tenantAccessMemberCreatePath,
} from "../admin/access-admin-helpers";
import type { AppBindings, AppContext, AppEnv } from "../app";

type TenantMemberInviteResult = {
  deliveryStatus: "sent" | "skipped" | "failed";
  inviteKind: "magic_link" | "sso_notice";
};

type MembershipAuditAction =
  | "membership.role_assigned"
  | "membership.role_changed"
  | "membership.role_reasserted";

interface RegisterTenantAccessMembersAdminRoutesInput {
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
  resolveDatabase: (bindings: AppBindings) => SqlDatabase;
  resolveInstitutionAdminAdminRole: (
    c: AppContext,
    tenantId: string,
    nextPath: string,
  ) => Promise<
    | Response
    | {
        session: SessionRecord;
        membershipRole: TenantMembershipRole;
      }
  >;
}

const redirectToMembers = async (
  c: AppContext,
  input: {
    tenantId: string;
    userId: string;
    tone: "success" | "error";
    message: string;
  },
): Promise<Response> => {
  await setAdminListMessageFlash(c, {
    tenantId: input.tenantId,
    userId: input.userId,
    workspace: "access_members",
    tone: input.tone,
    message: input.message,
  });

  return c.redirect(buildAccessMembersAdminPath(input.tenantId), 303);
};

export const registerTenantAccessMembersAdminRoutes = (
  input: RegisterTenantAccessMembersAdminRoutesInput,
): void => {
  const {
    app,
    assertRoleChangeAllowed,
    canManageTenantRole,
    membershipAuditAction,
    requestInviteForTenantMember,
    resolveDatabase,
    resolveInstitutionAdminAdminRole,
  } = input;

  app.post("/tenants/:tenantId/admin/access/members/create", async (c) => {
    const pathParams = parseTenantPathParams(c.req.param());
    const nextPath = tenantAccessMemberCreatePath(pathParams.tenantId);
    const roleCheck = await resolveInstitutionAdminAdminRole(c, pathParams.tenantId, nextPath);

    if (roleCheck instanceof Response) {
      return roleCheck;
    }

    const { session, membershipRole } = roleCheck;
    const formData = await c.req.formData();
    const email = readOptionalFormField(formData, "email") ?? "";
    const role = readOptionalFormField(formData, "role");

    let request: ReturnType<typeof parseCreateTenantMemberRequest>;

    try {
      request = parseCreateTenantMemberRequest({
        email,
        role,
        sendInvite: formData.get("sendInvite") !== null,
      });
    } catch {
      return redirectToMembers(c, {
        tenantId: pathParams.tenantId,
        userId: session.userId,
        tone: "error",
        message: "Enter an institution email and tenant role, then try again.",
      });
    }

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
      return redirectToMembers(c, {
        tenantId: pathParams.tenantId,
        userId: session.userId,
        tone: "error",
        message: "You do not have permission to assign that tenant role.",
      });
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

    const inviteNote =
      invite.deliveryStatus === "failed"
        ? " Invite email could not be sent."
        : invite.deliveryStatus === "sent"
          ? " Invite email sent."
          : "";

    return redirectToMembers(c, {
      tenantId: pathParams.tenantId,
      userId: session.userId,
      tone: "success",
      message: `Saved ${user.email} as ${roleResult.membership.role}.${inviteNote}`,
    });
  });

  app.post("/tenants/:tenantId/admin/access/members/:userId/role", async (c) => {
    const pathParams = parseTenantMemberPathParams(c.req.param());
    const nextPath = buildAccessMembersAdminPath(pathParams.tenantId);
    const roleCheck = await resolveInstitutionAdminAdminRole(c, pathParams.tenantId, nextPath);

    if (roleCheck instanceof Response) {
      return roleCheck;
    }

    const { session, membershipRole } = roleCheck;
    const formData = await c.req.formData();
    const role = readOptionalFormField(formData, "role");

    let request: ReturnType<typeof parseUpdateTenantMemberRoleRequest>;

    try {
      request = parseUpdateTenantMemberRoleRequest({ role });
    } catch {
      return redirectToMembers(c, {
        tenantId: pathParams.tenantId,
        userId: session.userId,
        tone: "error",
        message: "Choose a valid tenant role before saving.",
      });
    }

    const db = resolveDatabase(c.env);
    const existingMembership = await findTenantMembership(
      db,
      pathParams.tenantId,
      pathParams.userId,
    );

    if (existingMembership === null) {
      return redirectToMembers(c, {
        tenantId: pathParams.tenantId,
        userId: session.userId,
        tone: "error",
        message: "That tenant member was not found.",
      });
    }

    if (existingMembership.role === request.role) {
      return redirectToMembers(c, {
        tenantId: pathParams.tenantId,
        userId: session.userId,
        tone: "success",
        message: "Member role is already set to that value.",
      });
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
      return redirectToMembers(c, {
        tenantId: pathParams.tenantId,
        userId: session.userId,
        tone: "error",
        message: "You do not have permission to change this member to that role.",
      });
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

    return redirectToMembers(c, {
      tenantId: pathParams.tenantId,
      userId: session.userId,
      tone: "success",
      message: `Updated ${user?.email ?? "member"} to ${roleResult.membership.role}.`,
    });
  });

  app.post("/tenants/:tenantId/admin/access/members/:userId/invite", async (c) => {
    const pathParams = parseTenantMemberPathParams(c.req.param());
    const nextPath = buildAccessMembersAdminPath(pathParams.tenantId);
    const roleCheck = await resolveInstitutionAdminAdminRole(c, pathParams.tenantId, nextPath);

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
      return redirectToMembers(c, {
        tenantId: pathParams.tenantId,
        userId: session.userId,
        tone: "error",
        message: "That tenant member was not found.",
      });
    }

    if (!canManageTenantRole(membershipRole, membership.role)) {
      return redirectToMembers(c, {
        tenantId: pathParams.tenantId,
        userId: session.userId,
        tone: "error",
        message: "Only tenant owners can invite owner members.",
      });
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

    const tone = invite.deliveryStatus === "failed" ? "error" : "success";
    const message =
      invite.deliveryStatus === "failed"
        ? `Invite for ${user.email} could not be sent.`
        : `Invite processed for ${user.email} (${invite.deliveryStatus}).`;

    return redirectToMembers(c, {
      tenantId: pathParams.tenantId,
      userId: session.userId,
      tone,
      message,
    });
  });

  app.post("/tenants/:tenantId/admin/access/members/:userId/remove", async (c) => {
    const pathParams = parseTenantMemberPathParams(c.req.param());
    const nextPath = buildAccessMembersAdminPath(pathParams.tenantId);
    const roleCheck = await resolveInstitutionAdminAdminRole(c, pathParams.tenantId, nextPath);

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
      return redirectToMembers(c, {
        tenantId: pathParams.tenantId,
        userId: session.userId,
        tone: "error",
        message: "That tenant member was not found.",
      });
    }

    if (pathParams.userId === session.userId) {
      return redirectToMembers(c, {
        tenantId: pathParams.tenantId,
        userId: session.userId,
        tone: "error",
        message: "You cannot remove your own tenant membership.",
      });
    }

    if (membership.role === "owner" && membershipRole !== "owner") {
      return redirectToMembers(c, {
        tenantId: pathParams.tenantId,
        userId: session.userId,
        tone: "error",
        message: "Only tenant owners can remove an owner membership.",
      });
    }

    if (membership.role === "owner") {
      const counts = await countTenantMembershipsByRole(db, pathParams.tenantId);

      if (counts.owner <= 1) {
        return redirectToMembers(c, {
          tenantId: pathParams.tenantId,
          userId: session.userId,
          tone: "error",
          message: "At least one tenant owner must remain.",
        });
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

    if (!removed) {
      return redirectToMembers(c, {
        tenantId: pathParams.tenantId,
        userId: session.userId,
        tone: "error",
        message: "No matching tenant membership was found.",
      });
    }

    return redirectToMembers(c, {
      tenantId: pathParams.tenantId,
      userId: session.userId,
      tone: "success",
      message: `Removed tenant access for ${user?.email ?? "member"}.`,
    });
  });
};

import {
  createAuditLog,
  ensureTenantMembership,
  findActiveTenantBreakGlassAccountByUserId,
  listTenantBreakGlassAccounts,
  revokeTenantBreakGlassAccount,
  upsertTenantBreakGlassAccount,
  upsertUserByEmail,
  type SqlDatabase,
  type TenantMembershipRole,
} from "@credtrail/db";
import {
  parseCreateTenantBreakGlassAccountRequest,
  parseTenantPathParams,
  parseTenantUserPathParams,
} from "@credtrail/validation";
import type { Hono } from "hono";
import type { AppContext, AppEnv } from "../app";
import { breakGlassPasswordResetEnrollmentStatus } from "../auth/break-glass-policy";
import type { RequireTenantRole, ResolveDatabase } from "../app/route-deps";

interface RegisterTenantBreakGlassRoutesInput {
  app: Hono<AppEnv>;
  requestBreakGlassPasswordReset:
    | ((
        c: AppContext,
        input: {
          tenantId: string;
          email: string;
        },
      ) => Promise<"sent" | "unavailable">)
    | undefined;
  requireEnterpriseTenant: (
    c: AppContext,
    tenantId: string,
    db: SqlDatabase,
  ) => Promise<Response | null>;
  resolveDatabase: ResolveDatabase;
  requireTenantRole: RequireTenantRole;
  ADMIN_ROLES: readonly TenantMembershipRole[];
}

export const registerTenantBreakGlassRoutes = (
  input: RegisterTenantBreakGlassRoutesInput,
): void => {
  const {
    app,
    requestBreakGlassPasswordReset,
    requireEnterpriseTenant,
    resolveDatabase,
    requireTenantRole,
    ADMIN_ROLES,
  } = input;

  app.get("/v1/tenants/:tenantId/break-glass-accounts", async (c) => {
    const pathParams = parseTenantPathParams(c.req.param());
    const roleCheck = await requireTenantRole(c, pathParams.tenantId, ADMIN_ROLES);

    if (roleCheck instanceof Response) {
      return roleCheck;
    }

    const db = resolveDatabase(c.env);
    const enterpriseCheck = await requireEnterpriseTenant(c, pathParams.tenantId, db);

    if (enterpriseCheck !== null) {
      return enterpriseCheck;
    }

    const accounts = await listTenantBreakGlassAccounts(db, pathParams.tenantId);
    return c.json(accounts);
  });

  app.post("/v1/tenants/:tenantId/break-glass-accounts", async (c) => {
    const pathParams = parseTenantPathParams(c.req.param());
    let request: ReturnType<typeof parseCreateTenantBreakGlassAccountRequest>;

    try {
      request = parseCreateTenantBreakGlassAccountRequest(await c.req.json<unknown>());
    } catch {
      return c.json(
        {
          error: "Invalid break-glass account payload",
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
    const enterpriseCheck = await requireEnterpriseTenant(c, pathParams.tenantId, db);

    if (enterpriseCheck !== null) {
      return enterpriseCheck;
    }

    const user = await upsertUserByEmail(db, request.email);
    const membershipResult = await ensureTenantMembership(db, pathParams.tenantId, user.id);
    const account = await upsertTenantBreakGlassAccount(db, {
      tenantId: pathParams.tenantId,
      userId: user.id,
      createdByUserId: session.userId,
    });
    const passwordResetStatus = await breakGlassPasswordResetEnrollmentStatus(
      requestBreakGlassPasswordReset,
      c,
      {
        tenantId: pathParams.tenantId,
        email: request.email,
        sendEnrollmentEmail: request.sendEnrollmentEmail !== false,
      },
    );

    if (membershipResult.created) {
      await createAuditLog(db, {
        tenantId: pathParams.tenantId,
        actorUserId: session.userId,
        action: "membership.role_assigned",
        targetType: "membership",
        targetId: `${pathParams.tenantId}:${user.id}`,
        metadata: {
          userId: user.id,
          role: membershipResult.membership.role,
        },
      });
    }

    await createAuditLog(db, {
      tenantId: pathParams.tenantId,
      actorUserId: session.userId,
      action: "tenant.break_glass_account_upserted",
      targetType: "tenant_break_glass_account",
      targetId: `${pathParams.tenantId}:${user.id}`,
      metadata: {
        role: membershipRole,
        email: request.email,
        sendEnrollmentEmail: request.sendEnrollmentEmail !== false,
        passwordResetStatus,
      },
    });

    return c.json(
      {
        account,
        passwordResetStatus,
      },
      201,
    );
  });

  app.delete("/v1/tenants/:tenantId/break-glass-accounts/:userId", async (c) => {
    const pathParams = parseTenantUserPathParams(c.req.param());
    const roleCheck = await requireTenantRole(c, pathParams.tenantId, ADMIN_ROLES);

    if (roleCheck instanceof Response) {
      return roleCheck;
    }

    const { session, membershipRole } = roleCheck;
    const db = resolveDatabase(c.env);
    const enterpriseCheck = await requireEnterpriseTenant(c, pathParams.tenantId, db);

    if (enterpriseCheck !== null) {
      return enterpriseCheck;
    }

    const existingAccount = await findActiveTenantBreakGlassAccountByUserId(
      db,
      pathParams.tenantId,
      pathParams.userId,
    );
    const removed = await revokeTenantBreakGlassAccount(db, {
      tenantId: pathParams.tenantId,
      userId: pathParams.userId,
      revokedAt: new Date().toISOString(),
    });

    if (removed) {
      await createAuditLog(db, {
        tenantId: pathParams.tenantId,
        actorUserId: session.userId,
        action: "tenant.break_glass_account_revoked",
        targetType: "tenant_break_glass_account",
        targetId: `${pathParams.tenantId}:${pathParams.userId}`,
        metadata: {
          role: membershipRole,
          email: existingAccount?.email ?? null,
        },
      });
    }

    return c.json({ removed });
  });
};

import {
  createAuditLog,
  listTenantMembershipOrgUnitScopes,
  removeTenantMembershipOrgUnitScope,
  upsertTenantMembershipOrgUnitScope,
  type TenantMembershipRole,
} from "@credtrail/db";
import {
  parseTenantUserOrgUnitPathParams,
  parseTenantUserPathParams,
  parseUpsertTenantMembershipOrgUnitScopeRequest,
} from "@credtrail/validation";
import type { Hono } from "hono";
import type { AppEnv } from "../app";
import type { RequireTenantRole, ResolveDatabase } from "../app/route-deps";

interface RegisterTenantMembershipScopeRoutesInput {
  app: Hono<AppEnv>;
  resolveDatabase: ResolveDatabase;
  requireTenantRole: RequireTenantRole;
  ADMIN_ROLES: readonly TenantMembershipRole[];
}

export const registerTenantMembershipScopeRoutes = (
  input: RegisterTenantMembershipScopeRoutesInput,
): void => {
  const { app, resolveDatabase, requireTenantRole, ADMIN_ROLES } = input;

  app.get("/v1/tenants/:tenantId/users/:userId/org-unit-scopes", async (c) => {
    const pathParams = parseTenantUserPathParams(c.req.param());
    const roleCheck = await requireTenantRole(c, pathParams.tenantId, ADMIN_ROLES);

    if (roleCheck instanceof Response) {
      return roleCheck;
    }

    const scopes = await listTenantMembershipOrgUnitScopes(resolveDatabase(c.env), {
      tenantId: pathParams.tenantId,
      userId: pathParams.userId,
    });

    return c.json({
      tenantId: pathParams.tenantId,
      userId: pathParams.userId,
      scopes,
    });
  });

  app.put("/v1/tenants/:tenantId/users/:userId/org-unit-scopes/:orgUnitId", async (c) => {
    const pathParams = parseTenantUserOrgUnitPathParams(c.req.param());
    let request: ReturnType<typeof parseUpsertTenantMembershipOrgUnitScopeRequest>;

    try {
      request = parseUpsertTenantMembershipOrgUnitScopeRequest(await c.req.json<unknown>());
    } catch {
      return c.json(
        {
          error: "Invalid org-unit scope payload",
        },
        400,
      );
    }

    const roleCheck = await requireTenantRole(c, pathParams.tenantId, ADMIN_ROLES);

    if (roleCheck instanceof Response) {
      return roleCheck;
    }

    const { principal, membershipRole } = roleCheck;

    try {
      const result = await upsertTenantMembershipOrgUnitScope(resolveDatabase(c.env), {
        tenantId: pathParams.tenantId,
        userId: pathParams.userId,
        orgUnitId: pathParams.orgUnitId,
        role: request.role,
        createdByUserId: principal.userId,
      });

      const action =
        result.previousRole === null
          ? "membership.org_scope_assigned"
          : result.previousRole === result.scope.role
            ? "membership.org_scope_reasserted"
            : "membership.org_scope_changed";

      await createAuditLog(resolveDatabase(c.env), {
        tenantId: pathParams.tenantId,
        actorUserId: principal.userId,
        action,
        targetType: "membership_org_scope",
        targetId: `${pathParams.tenantId}:${pathParams.userId}:${pathParams.orgUnitId}`,
        metadata: {
          role: membershipRole,
          userId: pathParams.userId,
          orgUnitId: pathParams.orgUnitId,
          previousRole: result.previousRole,
          scopeRole: result.scope.role,
          changed: result.changed,
        },
      });

      return c.json(
        {
          tenantId: pathParams.tenantId,
          userId: pathParams.userId,
          orgUnitId: pathParams.orgUnitId,
          scope: result.scope,
          previousRole: result.previousRole,
          changed: result.changed,
        },
        result.previousRole === null ? 201 : 200,
      );
    } catch (error: unknown) {
      if (error instanceof Error) {
        if (error.message.includes("Membership not found for tenant")) {
          return c.json(
            {
              error: error.message,
            },
            422,
          );
        }

        if (error.message.includes("Org unit") && error.message.includes("not found for tenant")) {
          return c.json(
            {
              error: error.message,
            },
            422,
          );
        }
      }

      throw error;
    }
  });

  app.delete("/v1/tenants/:tenantId/users/:userId/org-unit-scopes/:orgUnitId", async (c) => {
    const pathParams = parseTenantUserOrgUnitPathParams(c.req.param());
    const roleCheck = await requireTenantRole(c, pathParams.tenantId, ADMIN_ROLES);

    if (roleCheck instanceof Response) {
      return roleCheck;
    }

    const { principal, membershipRole } = roleCheck;
    const removed = await removeTenantMembershipOrgUnitScope(resolveDatabase(c.env), {
      tenantId: pathParams.tenantId,
      userId: pathParams.userId,
      orgUnitId: pathParams.orgUnitId,
    });

    if (removed) {
      await createAuditLog(resolveDatabase(c.env), {
        tenantId: pathParams.tenantId,
        actorUserId: principal.userId,
        action: "membership.org_scope_removed",
        targetType: "membership_org_scope",
        targetId: `${pathParams.tenantId}:${pathParams.userId}:${pathParams.orgUnitId}`,
        metadata: {
          role: membershipRole,
          userId: pathParams.userId,
          orgUnitId: pathParams.orgUnitId,
        },
      });
    }

    return c.json({
      tenantId: pathParams.tenantId,
      userId: pathParams.userId,
      orgUnitId: pathParams.orgUnitId,
      removed,
    });
  });
};

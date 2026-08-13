import {
  createAuditLog,
  removeTenantMembershipOrgUnitScope,
  upsertTenantMembershipOrgUnitScope,
} from "@credtrail/db";
import {
  parseTenantPathParams,
  parseUpsertTenantMembershipOrgUnitScopeRequest,
} from "@credtrail/validation";
import { buildAccessOrgUnitAccessAdminPath } from "../admin/access-admin-helpers";
import { readOptionalFormField } from "../admin/admin-form-helpers";
import { redirectWithAdminListFlash } from "../admin/admin-list-flash-redirect";
import type { AppContext } from "../app";
import type { TenantAccessAdminRouteDeps } from "./tenant-access-admin-route-deps";

const redirectToOrgUnitAccess = (
  c: AppContext,
  input: {
    tenantId: string;
    userId: string;
    tone: "success" | "error";
    message: string;
  },
): Promise<Response> => {
  return redirectWithAdminListFlash(c, {
    ...input,
    workspace: "access_org_unit_access",
    path: buildAccessOrgUnitAccessAdminPath(input.tenantId),
  });
};

const mapScopeErrorMessage = (error: unknown): string => {
  if (!(error instanceof Error)) {
    return "Unable to save the scoped role. Check the member, org unit, and role, then try again.";
  }

  if (error.message.includes("Membership not found for tenant")) {
    return "Choose a tenant member who already belongs to this organization.";
  }

  if (error.message.includes("Org unit") && error.message.includes("not found for tenant")) {
    return "Choose an org unit that belongs to this organization.";
  }

  return "Unable to save the scoped role. Check the member, org unit, and role, then try again.";
};

export const registerTenantAccessOrgUnitAccessAdminRoutes = (
  input: TenantAccessAdminRouteDeps,
): void => {
  const { app, resolveDatabase, resolveInstitutionAdminAdminRole } = input;

  app.post("/tenants/:tenantId/admin/access/org-unit-access/scopes", async (c) => {
    const pathParams = parseTenantPathParams(c.req.param());
    const nextPath = buildAccessOrgUnitAccessAdminPath(pathParams.tenantId);
    const roleCheck = await resolveInstitutionAdminAdminRole(c, pathParams.tenantId, nextPath);

    if (roleCheck instanceof Response) {
      return roleCheck;
    }

    const { principal, membershipRole } = roleCheck;
    const formData = await c.req.formData();
    const userId = readOptionalFormField(formData, "userId") ?? "";
    const orgUnitId = readOptionalFormField(formData, "orgUnitId") ?? "";
    const role = readOptionalFormField(formData, "role");

    let request: ReturnType<typeof parseUpsertTenantMembershipOrgUnitScopeRequest>;

    try {
      request = parseUpsertTenantMembershipOrgUnitScopeRequest({ role });
    } catch {
      return redirectToOrgUnitAccess(c, {
        tenantId: pathParams.tenantId,
        userId: principal.userId,
        tone: "error",
        message: "Choose a member, org unit, and scoped role before saving.",
      });
    }

    if (userId.length === 0 || orgUnitId.length === 0) {
      return redirectToOrgUnitAccess(c, {
        tenantId: pathParams.tenantId,
        userId: principal.userId,
        tone: "error",
        message: "Choose a member, org unit, and scoped role before saving.",
      });
    }

    const db = resolveDatabase(c.env);

    try {
      const result = await upsertTenantMembershipOrgUnitScope(db, {
        tenantId: pathParams.tenantId,
        userId,
        orgUnitId,
        role: request.role,
        createdByUserId: principal.userId,
      });
      const action =
        result.previousRole === null
          ? "membership.org_scope_assigned"
          : result.previousRole === result.scope.role
            ? "membership.org_scope_reasserted"
            : "membership.org_scope_changed";

      await createAuditLog(db, {
        tenantId: pathParams.tenantId,
        actorUserId: principal.userId,
        action,
        targetType: "membership_org_scope",
        targetId: `${pathParams.tenantId}:${userId}:${orgUnitId}`,
        metadata: {
          role: membershipRole,
          userId,
          orgUnitId,
          previousRole: result.previousRole,
          scopeRole: result.scope.role,
          changed: result.changed,
        },
      });

      return redirectToOrgUnitAccess(c, {
        tenantId: pathParams.tenantId,
        userId: principal.userId,
        tone: "success",
        message: `Saved scoped role ${result.scope.role} for ${userId}.`,
      });
    } catch (error: unknown) {
      return redirectToOrgUnitAccess(c, {
        tenantId: pathParams.tenantId,
        userId: principal.userId,
        tone: "error",
        message: mapScopeErrorMessage(error),
      });
    }
  });

  app.post("/tenants/:tenantId/admin/access/org-unit-access/scopes/remove", async (c) => {
    const pathParams = parseTenantPathParams(c.req.param());
    const nextPath = buildAccessOrgUnitAccessAdminPath(pathParams.tenantId);
    const roleCheck = await resolveInstitutionAdminAdminRole(c, pathParams.tenantId, nextPath);

    if (roleCheck instanceof Response) {
      return roleCheck;
    }

    const { principal, membershipRole } = roleCheck;
    const formData = await c.req.formData();
    const userId = readOptionalFormField(formData, "userId") ?? "";
    const orgUnitId = readOptionalFormField(formData, "orgUnitId") ?? "";

    if (userId.length === 0 || orgUnitId.length === 0) {
      return redirectToOrgUnitAccess(c, {
        tenantId: pathParams.tenantId,
        userId: principal.userId,
        tone: "error",
        message: "Scoped role identifiers are missing.",
      });
    }

    const db = resolveDatabase(c.env);
    const removed = await removeTenantMembershipOrgUnitScope(db, {
      tenantId: pathParams.tenantId,
      userId,
      orgUnitId,
    });

    if (!removed) {
      return redirectToOrgUnitAccess(c, {
        tenantId: pathParams.tenantId,
        userId: principal.userId,
        tone: "error",
        message: "No matching scoped role was found.",
      });
    }

    await createAuditLog(db, {
      tenantId: pathParams.tenantId,
      actorUserId: principal.userId,
      action: "membership.org_scope_removed",
      targetType: "membership_org_scope",
      targetId: `${pathParams.tenantId}:${userId}:${orgUnitId}`,
      metadata: {
        role: membershipRole,
        userId,
        orgUnitId,
      },
    });

    return redirectToOrgUnitAccess(c, {
      tenantId: pathParams.tenantId,
      userId: principal.userId,
      tone: "success",
      message: "Scoped role removed.",
    });
  });
};

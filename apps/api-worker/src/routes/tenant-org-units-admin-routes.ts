import {
  createAuditLog,
  createTenantOrgUnit,
  type SessionRecord,
  type SqlDatabase,
  type TenantMembershipRole,
} from "@credtrail/db";
import { parseCreateTenantOrgUnitRequest, parseTenantPathParams } from "@credtrail/validation";
import type { Hono } from "hono";
import { deriveSlugFromDisplayName, readOptionalFormField } from "../admin/admin-form-helpers";
import { setAdminListMessageFlash } from "../admin/admin-list-message-flash";
import { buildAccessOrgUnitsAdminPath } from "../admin/access-admin-helpers";
import type { AppBindings, AppContext, AppEnv } from "../app";

interface RegisterTenantOrgUnitsAdminRoutesInput {
  app: Hono<AppEnv>;
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

const buildCreateOrgUnitPayload = (formData: FormData): unknown => {
  const displayName = readOptionalFormField(formData, "displayName") ?? "";
  const unitType = readOptionalFormField(formData, "unitType");
  const parentOrgUnitId = readOptionalFormField(formData, "parentOrgUnitId");

  return {
    displayName,
    unitType,
    slug: deriveSlugFromDisplayName(displayName),
    ...(parentOrgUnitId !== undefined ? { parentOrgUnitId } : {}),
  };
};

const isTenantOrgUnitSlugConflict = (error: unknown): boolean => {
  return (
    error !== null &&
    typeof error === "object" &&
    !Array.isArray(error) &&
    "code" in error &&
    "constraint" in error &&
    error.code === "23505" &&
    error.constraint === "tenant_org_units_tenant_id_slug_key"
  );
};

export const registerTenantOrgUnitsAdminRoutes = (
  input: RegisterTenantOrgUnitsAdminRoutesInput,
): void => {
  const { app, resolveDatabase, resolveInstitutionAdminAdminRole } = input;

  app.post("/tenants/:tenantId/admin/access/org-units/create", async (c) => {
    const pathParams = parseTenantPathParams(c.req.param());
    const nextPath = buildAccessOrgUnitsAdminPath(pathParams.tenantId);
    const roleCheck = await resolveInstitutionAdminAdminRole(c, pathParams.tenantId, nextPath);

    if (roleCheck instanceof Response) {
      return roleCheck;
    }

    const { session, membershipRole } = roleCheck;
    const formData = await c.req.formData();

    let request: ReturnType<typeof parseCreateTenantOrgUnitRequest>;

    try {
      request = parseCreateTenantOrgUnitRequest(buildCreateOrgUnitPayload(formData));
    } catch {
      await setAdminListMessageFlash(c, {
        tenantId: pathParams.tenantId,
        userId: session.userId,
        workspace: "access_org_units",
        tone: "error",
        message: "Enter a display name and unit type, then try again.",
      });

      return c.redirect(buildAccessOrgUnitsAdminPath(pathParams.tenantId), 303);
    }

    const db = resolveDatabase(c.env);

    try {
      const orgUnit = await createTenantOrgUnit(db, {
        tenantId: pathParams.tenantId,
        unitType: request.unitType,
        slug: request.slug,
        displayName: request.displayName,
        parentOrgUnitId: request.parentOrgUnitId,
        createdByUserId: session.userId,
      });

      await createAuditLog(db, {
        tenantId: pathParams.tenantId,
        actorUserId: session.userId,
        action: "tenant.org_unit_created",
        targetType: "org_unit",
        targetId: orgUnit.id,
        metadata: {
          role: membershipRole,
          unitType: orgUnit.unitType,
          slug: orgUnit.slug,
          parentOrgUnitId: orgUnit.parentOrgUnitId,
        },
      });

      await setAdminListMessageFlash(c, {
        tenantId: pathParams.tenantId,
        userId: session.userId,
        workspace: "access_org_units",
        tone: "success",
        message: `Created org unit “${orgUnit.displayName}”.`,
      });
    } catch (error: unknown) {
      const message = isTenantOrgUnitSlugConflict(error)
        ? "An org unit with that name already exists. Try a more specific display name."
        : error instanceof Error && error.message.includes("parent org unit")
          ? "Selected unit type requires a parent org unit."
          : "Unable to create the org unit. Check the display name, unit type, and parent.";

      await setAdminListMessageFlash(c, {
        tenantId: pathParams.tenantId,
        userId: session.userId,
        workspace: "access_org_units",
        tone: "error",
        message,
      });
    }

    return c.redirect(buildAccessOrgUnitsAdminPath(pathParams.tenantId), 303);
  });
};

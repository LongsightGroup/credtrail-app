import {
  createAuditLog,
  createTenantOrgUnit,
  listTenantOrgUnits,
  type SessionRecord,
  type SqlDatabase,
  type TenantMembershipRole,
} from "@credtrail/db";
import {
  parseCreateTenantOrgUnitRequest,
  parseTenantOrgUnitListQuery,
  parseTenantPathParams,
} from "@credtrail/validation";
import type { Hono } from "hono";
import type { AppBindings, AppContext, AppEnv } from "../app";

interface RegisterTenantOrgUnitRoutesInput {
  app: Hono<AppEnv>;
  resolveDatabase: (bindings: AppBindings) => SqlDatabase;
  requireTenantRole: (
    c: AppContext,
    tenantId: string,
    allowedRoles: readonly TenantMembershipRole[],
  ) => Promise<
    | {
        session: SessionRecord;
        membershipRole: TenantMembershipRole;
      }
    | Response
  >;
  ADMIN_ROLES: readonly TenantMembershipRole[];
  ISSUER_ROLES: readonly TenantMembershipRole[];
}

const deriveUrlKey = (value: string): string => {
  return value
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .replace(/-{2,}/g, "-");
};

const withDerivedOrgUnitSlug = (input: unknown): unknown => {
  if (input === null || typeof input !== "object" || Array.isArray(input)) {
    return input;
  }

  const payload = input as Record<string, unknown>;
  const rawSlug = payload.slug;

  if (typeof rawSlug === "string" && rawSlug.trim().length > 0) {
    return input;
  }

  const rawDisplayName = payload.displayName;

  if (typeof rawDisplayName !== "string") {
    return input;
  }

  return {
    ...payload,
    slug: deriveUrlKey(rawDisplayName),
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

export const registerTenantOrgUnitRoutes = (input: RegisterTenantOrgUnitRoutesInput): void => {
  const { app, resolveDatabase, requireTenantRole, ADMIN_ROLES, ISSUER_ROLES } = input;

  app.get("/v1/tenants/:tenantId/org-units", async (c) => {
    const pathParams = parseTenantPathParams(c.req.param());
    const query = parseTenantOrgUnitListQuery({
      includeInactive: c.req.query("includeInactive"),
    });
    const roleCheck = await requireTenantRole(c, pathParams.tenantId, ISSUER_ROLES);

    if (roleCheck instanceof Response) {
      return roleCheck;
    }

    const orgUnits = await listTenantOrgUnits(resolveDatabase(c.env), {
      tenantId: pathParams.tenantId,
      includeInactive: query.includeInactive,
    });

    return c.json({
      tenantId: pathParams.tenantId,
      orgUnits,
    });
  });

  app.post("/v1/tenants/:tenantId/org-units", async (c) => {
    const pathParams = parseTenantPathParams(c.req.param());
    let request: ReturnType<typeof parseCreateTenantOrgUnitRequest>;

    try {
      request = parseCreateTenantOrgUnitRequest(
        withDerivedOrgUnitSlug(await c.req.json<unknown>()),
      );
    } catch {
      return c.json(
        {
          error: "Invalid org unit request payload",
        },
        400,
      );
    }

    const roleCheck = await requireTenantRole(c, pathParams.tenantId, ADMIN_ROLES);

    if (roleCheck instanceof Response) {
      return roleCheck;
    }

    const { session, membershipRole } = roleCheck;

    try {
      const orgUnit = await createTenantOrgUnit(resolveDatabase(c.env), {
        tenantId: pathParams.tenantId,
        unitType: request.unitType,
        slug: request.slug,
        displayName: request.displayName,
        parentOrgUnitId: request.parentOrgUnitId,
        createdByUserId: session.userId,
      });

      await createAuditLog(resolveDatabase(c.env), {
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

      return c.json(
        {
          tenantId: pathParams.tenantId,
          orgUnit,
        },
        201,
      );
    } catch (error: unknown) {
      if (error instanceof Error) {
        if (isTenantOrgUnitSlugConflict(error)) {
          return c.json(
            {
              error: "An org unit with that URL key already exists.",
            },
            409,
          );
        }

        if (
          (error.message.includes("Parent org unit") &&
            error.message.includes("not found for tenant")) ||
          error.message.includes("cannot have a parent org unit") ||
          error.message.includes("requires parent org unit type") ||
          error.message.includes("is inactive for tenant")
        ) {
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
};

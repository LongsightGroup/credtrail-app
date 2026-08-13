import {
  createAuditLog,
  createDelegatedIssuingAuthorityGrant,
  findDelegatedIssuingAuthorityGrantById,
  listDelegatedIssuingAuthorityGrantEvents,
  listDelegatedIssuingAuthorityGrants,
  revokeDelegatedIssuingAuthorityGrant,
  type TenantMembershipRole,
} from "@credtrail/db";
import {
  parseCreateDelegatedIssuingAuthorityGrantRequest,
  parseDelegatedIssuingAuthorityGrantListQuery,
  parseRevokeDelegatedIssuingAuthorityGrantRequest,
  parseTenantUserDelegatedGrantPathParams,
  parseTenantUserPathParams,
} from "@credtrail/validation";
import type { Hono } from "hono";
import type { AppEnv } from "../app";
import type { RequireTenantRole, ResolveDatabase } from "../app/route-deps";

interface RegisterTenantDelegatedAuthorityRoutesInput {
  app: Hono<AppEnv>;
  resolveDatabase: ResolveDatabase;
  requireTenantRole: RequireTenantRole;
  ADMIN_ROLES: readonly TenantMembershipRole[];
}

export const registerTenantDelegatedAuthorityRoutes = (
  input: RegisterTenantDelegatedAuthorityRoutesInput,
): void => {
  const { app, resolveDatabase, requireTenantRole, ADMIN_ROLES } = input;

  app.get("/v1/tenants/:tenantId/users/:userId/issuing-authority-grants", async (c) => {
    const pathParams = parseTenantUserPathParams(c.req.param());
    const query = parseDelegatedIssuingAuthorityGrantListQuery({
      includeRevoked: c.req.query("includeRevoked"),
      includeExpired: c.req.query("includeExpired"),
    });
    const roleCheck = await requireTenantRole(c, pathParams.tenantId, ADMIN_ROLES);

    if (roleCheck instanceof Response) {
      return roleCheck;
    }

    const grants = await listDelegatedIssuingAuthorityGrants(resolveDatabase(c.env), {
      tenantId: pathParams.tenantId,
      delegateUserId: pathParams.userId,
      includeRevoked: query.includeRevoked,
      includeExpired: query.includeExpired,
    });

    return c.json({
      tenantId: pathParams.tenantId,
      userId: pathParams.userId,
      grants,
    });
  });

  app.post("/v1/tenants/:tenantId/users/:userId/issuing-authority-grants", async (c) => {
    const pathParams = parseTenantUserPathParams(c.req.param());
    let request: ReturnType<typeof parseCreateDelegatedIssuingAuthorityGrantRequest>;

    try {
      request = parseCreateDelegatedIssuingAuthorityGrantRequest(await c.req.json<unknown>());
    } catch {
      return c.json(
        {
          error: "Invalid delegated authority grant payload",
        },
        400,
      );
    }

    const roleCheck = await requireTenantRole(c, pathParams.tenantId, ADMIN_ROLES);

    if (roleCheck instanceof Response) {
      return roleCheck;
    }

    const { principal, membershipRole } = roleCheck;
    const startsAt = request.startsAt ?? new Date().toISOString();

    try {
      const grant = await createDelegatedIssuingAuthorityGrant(resolveDatabase(c.env), {
        tenantId: pathParams.tenantId,
        delegateUserId: pathParams.userId,
        delegatedByUserId: principal.userId,
        orgUnitId: request.orgUnitId,
        allowedActions: request.allowedActions,
        badgeTemplateIds: request.badgeTemplateIds,
        startsAt,
        endsAt: request.endsAt,
        reason: request.reason,
      });

      await createAuditLog(resolveDatabase(c.env), {
        tenantId: pathParams.tenantId,
        actorUserId: principal.userId,
        action: "delegated_issuing_authority.granted",
        targetType: "delegated_issuing_authority_grant",
        targetId: grant.id,
        metadata: {
          role: membershipRole,
          delegateUserId: pathParams.userId,
          orgUnitId: request.orgUnitId,
          allowedActions: request.allowedActions,
          badgeTemplateIds: request.badgeTemplateIds ?? [],
          startsAt,
          endsAt: request.endsAt,
        },
      });

      return c.json(
        {
          tenantId: pathParams.tenantId,
          userId: pathParams.userId,
          grant,
        },
        201,
      );
    } catch (error: unknown) {
      if (error instanceof Error) {
        if (error.message.includes("conflicts with existing grant")) {
          return c.json(
            {
              error: error.message,
            },
            409,
          );
        }

        if (
          error.message.includes("Membership not found for tenant") ||
          (error.message.includes("Org unit") && error.message.includes("not found for tenant")) ||
          (error.message.includes("Badge template") &&
            error.message.includes("not found for tenant")) ||
          error.message.includes("outside delegated org-unit scope") ||
          error.message.includes("is inactive for tenant") ||
          error.message.includes("must be after") ||
          error.message.includes("must be a valid ISO timestamp")
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

  app.post(
    "/v1/tenants/:tenantId/users/:userId/issuing-authority-grants/:grantId/revoke",
    async (c) => {
      const pathParams = parseTenantUserDelegatedGrantPathParams(c.req.param());
      let request: ReturnType<typeof parseRevokeDelegatedIssuingAuthorityGrantRequest>;

      try {
        let payload: unknown = {};

        try {
          payload = await c.req.json<unknown>();
        } catch {
          payload = {};
        }

        request = parseRevokeDelegatedIssuingAuthorityGrantRequest(payload);
      } catch {
        return c.json(
          {
            error: "Invalid delegated authority revoke payload",
          },
          400,
        );
      }

      const roleCheck = await requireTenantRole(c, pathParams.tenantId, ADMIN_ROLES);

      if (roleCheck instanceof Response) {
        return roleCheck;
      }

      const { principal, membershipRole } = roleCheck;
      const db = resolveDatabase(c.env);
      const existingGrant = await findDelegatedIssuingAuthorityGrantById(
        db,
        pathParams.tenantId,
        pathParams.grantId,
      );

      if (existingGrant?.delegateUserId !== pathParams.userId) {
        return c.json(
          {
            error: "Delegated issuing authority grant not found",
          },
          404,
        );
      }

      const revokedAt = request.revokedAt ?? new Date().toISOString();

      try {
        const result = await revokeDelegatedIssuingAuthorityGrant(db, {
          tenantId: pathParams.tenantId,
          grantId: pathParams.grantId,
          revokedByUserId: principal.userId,
          revokedReason: request.reason,
          revokedAt,
        });

        if (result.status === "revoked") {
          await createAuditLog(db, {
            tenantId: pathParams.tenantId,
            actorUserId: principal.userId,
            action: "delegated_issuing_authority.revoked",
            targetType: "delegated_issuing_authority_grant",
            targetId: pathParams.grantId,
            metadata: {
              role: membershipRole,
              delegateUserId: pathParams.userId,
              revokedAt,
              reason: request.reason,
            },
          });
        }

        return c.json({
          tenantId: pathParams.tenantId,
          userId: pathParams.userId,
          status: result.status,
          grant: result.grant,
        });
      } catch (error: unknown) {
        if (error instanceof Error) {
          if (
            error.message.includes("not found for tenant") ||
            error.message.includes("must be a valid ISO timestamp")
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
    },
  );

  app.get(
    "/v1/tenants/:tenantId/users/:userId/issuing-authority-grants/:grantId/events",
    async (c) => {
      const pathParams = parseTenantUserDelegatedGrantPathParams(c.req.param());
      const roleCheck = await requireTenantRole(c, pathParams.tenantId, ADMIN_ROLES);

      if (roleCheck instanceof Response) {
        return roleCheck;
      }

      const limitRaw = c.req.query("limit");
      let limit: number | undefined;

      if (limitRaw !== undefined) {
        const parsed = Number.parseInt(limitRaw, 10);

        if (!Number.isFinite(parsed) || parsed < 1) {
          return c.json(
            {
              error: "limit must be a positive integer",
            },
            400,
          );
        }

        limit = parsed;
      }

      const db = resolveDatabase(c.env);
      const grant = await findDelegatedIssuingAuthorityGrantById(
        db,
        pathParams.tenantId,
        pathParams.grantId,
      );

      if (grant?.delegateUserId !== pathParams.userId) {
        return c.json(
          {
            error: "Delegated issuing authority grant not found",
          },
          404,
        );
      }

      const events = await listDelegatedIssuingAuthorityGrantEvents(db, {
        tenantId: pathParams.tenantId,
        grantId: pathParams.grantId,
        ...(limit === undefined ? {} : { limit }),
      });

      return c.json({
        tenantId: pathParams.tenantId,
        userId: pathParams.userId,
        grant,
        events,
      });
    },
  );
};

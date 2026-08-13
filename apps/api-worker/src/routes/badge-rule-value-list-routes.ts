import {
  createAuditLog,
  createBadgeIssuanceRuleValueList,
  type TenantMembershipRole,
} from "@credtrail/db";
import {
  parseBadgeIssuanceRuleValueListQuery,
  parseCreateBadgeIssuanceRuleValueListRequest,
  parseTenantPathParams,
} from "@credtrail/validation";
import type { Hono } from "hono";
import { loadTenantBadgeRuleValueLists } from "../admin/rule-value-lists-presentation";
import type { AppEnv } from "../app";
import type { RequireTenantRole, ResolveDatabase } from "../app/route-deps";

interface RegisterBadgeRuleValueListRoutesInput {
  app: Hono<AppEnv>;
  resolveDatabase: ResolveDatabase;
  requireTenantRole: RequireTenantRole;
  ISSUER_ROLES: readonly TenantMembershipRole[];
}

export const registerBadgeRuleValueListRoutes = (
  input: RegisterBadgeRuleValueListRoutesInput,
): void => {
  const { app, resolveDatabase, requireTenantRole, ISSUER_ROLES } = input;

  app.get("/v1/tenants/:tenantId/badge-rule-value-lists", async (c) => {
    const pathParams = parseTenantPathParams(c.req.param());
    let query;

    try {
      query = parseBadgeIssuanceRuleValueListQuery(c.req.query());
    } catch {
      return c.json(
        {
          error: "Invalid badge rule value-list query",
        },
        400,
      );
    }

    const roleCheck = await requireTenantRole(c, pathParams.tenantId, ISSUER_ROLES);

    if (roleCheck instanceof Response) {
      return roleCheck;
    }

    const valueLists =
      query.kind === undefined
        ? await loadTenantBadgeRuleValueLists(resolveDatabase(c.env), pathParams.tenantId, {
            limit: "none",
          })
        : await loadTenantBadgeRuleValueLists(resolveDatabase(c.env), pathParams.tenantId, {
            kind: query.kind,
            limit: "none",
          });

    return c.json({
      tenantId: pathParams.tenantId,
      valueLists,
    });
  });

  app.post("/v1/tenants/:tenantId/badge-rule-value-lists", async (c) => {
    const pathParams = parseTenantPathParams(c.req.param());
    let request;

    try {
      request = parseCreateBadgeIssuanceRuleValueListRequest(await c.req.json<unknown>());
    } catch {
      return c.json(
        {
          error: "Invalid badge rule value-list payload",
        },
        400,
      );
    }

    const roleCheck = await requireTenantRole(c, pathParams.tenantId, ISSUER_ROLES);

    if (roleCheck instanceof Response) {
      return roleCheck;
    }

    const { principal, membershipRole } = roleCheck;
    const valueList = await createBadgeIssuanceRuleValueList(resolveDatabase(c.env), {
      tenantId: pathParams.tenantId,
      label: request.label,
      kind: request.kind,
      values: request.values,
      createdByUserId: principal.userId,
    });

    await createAuditLog(resolveDatabase(c.env), {
      tenantId: pathParams.tenantId,
      actorUserId: principal.userId,
      action: "badge_rule.value_list_created",
      targetType: "badge_rule_value_list",
      targetId: valueList.id,
      metadata: {
        role: membershipRole,
        kind: valueList.kind,
        valueCount: valueList.values.length,
      },
    });

    return c.json(
      {
        tenantId: pathParams.tenantId,
        valueList,
      },
      201,
    );
  });
};

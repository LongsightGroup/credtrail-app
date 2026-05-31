import type { Hono } from "hono";
import {
  parseBadgeIssuanceRuleEvaluationPathParams,
  parseBadgeIssuanceRuleReviewQueueQuery,
  parseResolveBadgeIssuanceRuleReviewRequest,
  parseTenantPathParams,
} from "@credtrail/validation";
import type { AppBindings, AppContext, AppEnv } from "../app";
import { resolveBadgeRuleReviewQueueEntry } from "../badge-rule-review-queue-resolve";
import { loadBadgeRuleReviewQueueForApi } from "../badge-rule-review-queue-workspace";
import type { DirectIssueBadgeResult, IssueBadgeForTenant } from "./badge-rule-evaluation-types";
import type { SessionRecord, SqlDatabase, TenantMembershipRole } from "@credtrail/db";

interface RegisterBadgeRuleReviewQueueRoutesInput {
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
  issueBadgeForTenant: IssueBadgeForTenant;
  ISSUER_ROLES: readonly TenantMembershipRole[];
}

export const registerBadgeRuleReviewQueueRoutes = (
  input: RegisterBadgeRuleReviewQueueRoutesInput,
): void => {
  const { app, resolveDatabase, requireTenantRole, issueBadgeForTenant, ISSUER_ROLES } = input;

  app.get("/v1/tenants/:tenantId/badge-rules/review-queue", async (c) => {
    const pathParams = parseTenantPathParams(c.req.param());
    let query;

    try {
      query = parseBadgeIssuanceRuleReviewQueueQuery(c.req.query());
    } catch {
      return c.json(
        {
          error: "Invalid review queue query",
        },
        400,
      );
    }

    const roleCheck = await requireTenantRole(c, pathParams.tenantId, ISSUER_ROLES);

    if (roleCheck instanceof Response) {
      return roleCheck;
    }

    const reviewStatus = query.status ?? "pending";
    const db = resolveDatabase(c.env);
    const queue = await loadBadgeRuleReviewQueueForApi(db, pathParams.tenantId, {
      reviewStatus,
      ...(query.limit === undefined ? {} : { limit: query.limit }),
    });

    return c.json({
      tenantId: pathParams.tenantId,
      reviewStatus,
      queue,
    });
  });

  app.post("/v1/tenants/:tenantId/badge-rules/review-queue/:evaluationId/resolve", async (c) => {
    const pathParams = parseBadgeIssuanceRuleEvaluationPathParams(c.req.param());
    let request;

    try {
      request = parseResolveBadgeIssuanceRuleReviewRequest(await c.req.json<unknown>());
    } catch {
      return c.json(
        {
          error: "Invalid review queue resolution payload",
        },
        400,
      );
    }

    const roleCheck = await requireTenantRole(c, pathParams.tenantId, ISSUER_ROLES);

    if (roleCheck instanceof Response) {
      return roleCheck;
    }

    const { session, membershipRole } = roleCheck;
    const db = resolveDatabase(c.env);
    const result = await resolveBadgeRuleReviewQueueEntry({
      c,
      db,
      tenantId: pathParams.tenantId,
      evaluationId: pathParams.evaluationId,
      request,
      session,
      membershipRole,
      issueBadgeForTenant,
    });

    if (!result.ok) {
      if (result.payload !== undefined) {
        return c.json(result.payload, result.status);
      }

      return c.json(
        {
          error: result.error,
        },
        result.status,
      );
    }

    const issuance: DirectIssueBadgeResult | null =
      result.issuance === null
        ? null
        : {
            status: result.issuance.status,
            assertionId: result.issuance.assertionId,
          };

    return c.json({
      tenantId: pathParams.tenantId,
      review: result.review,
      issuance,
    });
  });
};

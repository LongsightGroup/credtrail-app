import type { TenantMembershipRole } from "@credtrail/db";
import {
  parseBadgeIssuanceRuleEvaluationPathParams,
  parseBadgeIssuanceRuleReviewQueueQuery,
  parseResolveBadgeIssuanceRuleReviewRequest,
  parseTenantPathParams,
} from "@credtrail/validation";
import type { Hono } from "hono";
import type { AppEnv } from "../app";
import type { IssueBadgeForTenant, RequireTenantRole, ResolveDatabase } from "../app/route-deps";
import type { DirectIssueBadgeResult } from "../badges/direct-issue";
import { resolveBadgeRuleReviewQueueEntry } from "../badge-rule-review-queue-resolve";
import { loadBadgeRuleReviewQueueForApi } from "../badge-rule-review-queue-workspace";

interface RegisterBadgeRuleReviewQueueRoutesInput {
  app: Hono<AppEnv>;
  resolveDatabase: ResolveDatabase;
  requireTenantRole: RequireTenantRole;
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

    const { principal, membershipRole } = roleCheck;
    const db = resolveDatabase(c.env);
    const result = await resolveBadgeRuleReviewQueueEntry({
      c,
      db,
      tenantId: pathParams.tenantId,
      evaluationId: pathParams.evaluationId,
      request,
      principal,
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

    const issuance: Pick<DirectIssueBadgeResult, "status" | "assertionId"> | null =
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

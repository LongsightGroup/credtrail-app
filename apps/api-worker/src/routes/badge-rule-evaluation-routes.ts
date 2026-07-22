import type { TenantMembershipRole } from "@credtrail/db";
import type { Hono } from "hono";
import type { AppEnv } from "../app";
import type { RequireTenantRole, ResolveDatabase } from "../app/route-deps";
import type { IssueBadgeForTenant } from "./badge-rule-evaluation-types";
import { registerBadgeRulePreviewRoutes } from "./badge-rule-preview-routes";
import { registerBadgeRuleReviewQueueRoutes } from "./badge-rule-review-queue-routes";

interface RegisterBadgeRuleEvaluationRoutesInput {
  app: Hono<AppEnv>;
  resolveDatabase: ResolveDatabase;
  requireTenantRole: RequireTenantRole;
  issueBadgeForTenant: IssueBadgeForTenant;
  ISSUER_ROLES: readonly TenantMembershipRole[];
}

export const registerBadgeRuleEvaluationRoutes = (
  input: RegisterBadgeRuleEvaluationRoutesInput,
): void => {
  const { app, resolveDatabase, requireTenantRole, issueBadgeForTenant, ISSUER_ROLES } = input;

  registerBadgeRulePreviewRoutes({
    app,
    resolveDatabase,
    requireTenantRole,
    ISSUER_ROLES,
  });

  registerBadgeRuleReviewQueueRoutes({
    app,
    resolveDatabase,
    requireTenantRole,
    issueBadgeForTenant,
    ISSUER_ROLES,
  });
};

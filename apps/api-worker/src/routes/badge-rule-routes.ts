import type { TenantMembershipRole } from "@credtrail/db";
import type { Hono } from "hono";
import type { AppEnv } from "../app";
import type { RequireTenantRole, ResolveDatabase } from "../app/route-deps";
import { registerBadgeRuleCoreRoutes } from "./badge-rule-core-routes";
import { registerBadgeRuleEvaluationRoutes } from "./badge-rule-evaluation-routes";
import type { IssueBadgeForTenant } from "./badge-rule-evaluation-types";
import { registerBadgeRuleValueListRoutes } from "./badge-rule-value-list-routes";
import { registerBadgeRuleVersionRoutes } from "./badge-rule-version-routes";

interface RegisterBadgeRuleRoutesInput {
  app: Hono<AppEnv>;
  resolveDatabase: ResolveDatabase;
  requireTenantRole: RequireTenantRole;
  issueBadgeForTenant: IssueBadgeForTenant;
  ISSUER_ROLES: readonly TenantMembershipRole[];
  ADMIN_ROLES: readonly TenantMembershipRole[];
  TENANT_MEMBER_ROLES: readonly TenantMembershipRole[];
}

export const registerBadgeRuleRoutes = (input: RegisterBadgeRuleRoutesInput): void => {
  const {
    app,
    resolveDatabase,
    requireTenantRole,
    issueBadgeForTenant,
    ISSUER_ROLES,
    ADMIN_ROLES,
    TENANT_MEMBER_ROLES,
  } = input;

  registerBadgeRuleValueListRoutes({
    app,
    resolveDatabase,
    requireTenantRole,
    ISSUER_ROLES,
  });

  registerBadgeRuleEvaluationRoutes({
    app,
    resolveDatabase,
    requireTenantRole,
    issueBadgeForTenant,
    ISSUER_ROLES,
  });

  registerBadgeRuleVersionRoutes({
    app,
    resolveDatabase,
    requireTenantRole,
    ISSUER_ROLES,
    ADMIN_ROLES,
    TENANT_MEMBER_ROLES,
  });

  registerBadgeRuleCoreRoutes({
    app,
    resolveDatabase,
    requireTenantRole,
    ISSUER_ROLES,
  });
};

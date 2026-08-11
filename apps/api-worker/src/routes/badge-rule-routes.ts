import type { TenantMembershipRole } from "@credtrail/db";
import type { Hono } from "hono";
import type { AppEnv } from "../app";
import type { IssueBadgeForTenant, RequireTenantRole, ResolveDatabase } from "../app/route-deps";
import { registerBadgeRuleCoreRoutes } from "./badge-rule-core-routes";
import { registerBadgeRulePreviewRoutes } from "./badge-rule-preview-routes";
import { registerBadgeRuleReviewQueueRoutes } from "./badge-rule-review-queue-routes";
import { registerBadgeRuleValueListRoutes } from "./badge-rule-value-list-routes";
import { registerBadgeRuleVersionReferenceRoutes } from "./badge-rule-version-reference-routes";
import { registerBadgeRuleVersionRoutes } from "./badge-rule-version-routes";
import { loadBadgeRuleVersionReferenceLabels } from "../lms/badge-rule-version-reference-label-service";

interface RegisterBadgeRuleRoutesInput {
  app: Hono<AppEnv>;
  resolveDatabase: ResolveDatabase;
  requireTenantRole: RequireTenantRole;
  issueBadgeForTenant: IssueBadgeForTenant;
  ISSUER_ROLES: readonly TenantMembershipRole[];
  ADMIN_ROLES: readonly TenantMembershipRole[];
  APPROVAL_WORKSPACE_ROLES: readonly TenantMembershipRole[];
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
    APPROVAL_WORKSPACE_ROLES,
    TENANT_MEMBER_ROLES,
  } = input;

  registerBadgeRuleValueListRoutes({
    app,
    resolveDatabase,
    requireTenantRole,
    ISSUER_ROLES,
  });

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

  registerBadgeRuleVersionRoutes({
    app,
    resolveDatabase,
    requireTenantRole,
    ISSUER_ROLES,
    ADMIN_ROLES,
    TENANT_MEMBER_ROLES,
  });

  registerBadgeRuleVersionReferenceRoutes({
    app,
    resolveDatabase,
    requireTenantRole,
    APPROVAL_WORKSPACE_ROLES,
    loadReferenceLabels: loadBadgeRuleVersionReferenceLabels,
  });

  registerBadgeRuleCoreRoutes({
    app,
    resolveDatabase,
    requireTenantRole,
    ISSUER_ROLES,
  });
};

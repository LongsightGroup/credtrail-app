import type { TenantMembershipRole } from "@credtrail/db";
import type { Hono } from "hono";
import type { AppEnv } from "../app";
import type { IssueBadgeForTenant, RequireTenantRole, ResolveDatabase } from "../app/route-deps";
import type { LoadBadgeRuleVersionReferenceLabels } from "../lms/badge-rule-version-reference-label-service";
import { registerBadgeRuleCoreRoutes } from "./badge-rule-core-routes";
import { registerBadgeRulePreviewRoutes } from "./badge-rule-preview-routes";
import { registerBadgeRuleReviewQueueRoutes } from "./badge-rule-review-queue-routes";
import { registerBadgeRuleValueListRoutes } from "./badge-rule-value-list-routes";
import { registerBadgeRuleVersionReferenceRoutes } from "./badge-rule-version-reference-routes";
import { registerBadgeRuleVersionRoutes } from "./badge-rule-version-routes";

interface RegisterBadgeRuleRoutesInput {
  app: Hono<AppEnv>;
  resolveDatabase: ResolveDatabase;
  requireTenantRole: RequireTenantRole;
  issueBadgeForTenant: IssueBadgeForTenant;
  loadBadgeRuleVersionReferenceLabels: LoadBadgeRuleVersionReferenceLabels;
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
    loadBadgeRuleVersionReferenceLabels,
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

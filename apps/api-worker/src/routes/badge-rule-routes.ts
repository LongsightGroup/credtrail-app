import type { SessionRecord, SqlDatabase, TenantMembershipRole } from "@credtrail/db";
import type { Hono } from "hono";
import type { AppBindings, AppContext, AppEnv } from "../app";
import { registerBadgeRuleCoreRoutes } from "./badge-rule-core-routes";
import { registerBadgeRuleEvaluationRoutes } from "./badge-rule-evaluation-routes";
import { registerBadgeRuleValueListRoutes } from "./badge-rule-value-list-routes";
import { registerBadgeRuleVersionRoutes } from "./badge-rule-version-routes";

interface DirectIssueBadgeRequest {
  badgeTemplateId: string;
  recipientIdentity: string;
  recipientIdentityType: "email" | "email_sha256" | "did" | "url";
  idempotencyKey: string;
}

interface DirectIssueBadgeResult {
  status: "issued" | "already_issued";
  assertionId: string;
}

interface RegisterBadgeRuleRoutesInput {
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
  issueBadgeForTenant: (
    c: AppContext,
    tenantId: string,
    request: DirectIssueBadgeRequest,
    issuedByUserId?: string,
  ) => Promise<DirectIssueBadgeResult>;
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

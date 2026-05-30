import {
  findBadgeTemplateById,
  type BadgeTemplateRecord,
  type SqlDatabase,
  type TenantMembershipOrgUnitScopeRole,
  type TenantMembershipRole,
} from "@credtrail/db";
import type { AppBindings, AppContext } from "../app";

export interface BadgeTemplateIssuerAccessInput {
  c: AppContext;
  tenantId: string;
  badgeTemplateId: string;
  nextPath: string;
  resolveDatabase: (bindings: AppBindings) => SqlDatabase;
  resolveInstitutionAdminAdminRole: (
    c: AppContext,
    tenantId: string,
    nextPath: string,
  ) => Promise<
    | Response
    | {
        session: { userId: string };
        membershipRole: TenantMembershipRole;
      }
  >;
  requireScopedOrgUnitPermission: (
    c: AppContext,
    input: {
      db: SqlDatabase;
      tenantId: string;
      userId: string;
      membershipRole: TenantMembershipRole;
      orgUnitId: string;
      requiredRole: TenantMembershipOrgUnitScopeRole;
      allowWhenNoScopes?: boolean;
    },
  ) => Promise<Response | null>;
  notFound: () => Response;
}

export interface BadgeTemplateIssuerAccessContext {
  db: SqlDatabase;
  session: { userId: string };
  membershipRole: TenantMembershipRole;
  template: BadgeTemplateRecord;
}

export const withBadgeTemplateIssuerAccess = async (
  input: BadgeTemplateIssuerAccessInput,
  handler: (context: BadgeTemplateIssuerAccessContext) => Promise<Response>,
): Promise<Response> => {
  const roleCheck = await input.resolveInstitutionAdminAdminRole(
    input.c,
    input.tenantId,
    input.nextPath,
  );

  if (roleCheck instanceof Response) {
    return roleCheck;
  }

  const db = input.resolveDatabase(input.c.env);
  const template = await findBadgeTemplateById(db, input.tenantId, input.badgeTemplateId);

  if (template === null) {
    return input.notFound();
  }

  const { session, membershipRole } = roleCheck;
  const scopeCheck = await input.requireScopedOrgUnitPermission(input.c, {
    db,
    tenantId: input.tenantId,
    userId: session.userId,
    membershipRole,
    orgUnitId: template.ownerOrgUnitId,
    requiredRole: "issuer",
    allowWhenNoScopes: true,
  });

  if (scopeCheck !== null) {
    return scopeCheck;
  }

  return handler({
    db,
    session,
    membershipRole,
    template,
  });
};

import {
  findBadgeTemplateById,
  type BadgeTemplateRecord,
  type SqlDatabase,
  type TenantMembershipRole,
} from "@credtrail/db";
import type { AppContext } from "../app";
import type { RequireScopedOrgUnitPermission, ResolveDatabase } from "../app/route-deps";

export interface BadgeTemplateIssuerAccessInput {
  c: AppContext;
  tenantId: string;
  badgeTemplateId: string;
  nextPath: string;
  resolveDatabase: ResolveDatabase;
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
  requireScopedOrgUnitPermission: RequireScopedOrgUnitPermission;
  notFound: (context: { session: { userId: string } }) => Response | Promise<Response>;
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

  const { session, membershipRole } = roleCheck;

  if (template === null) {
    return input.notFound({ session });
  }
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

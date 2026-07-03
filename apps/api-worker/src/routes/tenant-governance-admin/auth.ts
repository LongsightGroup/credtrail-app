import {
  findTenantById,
  type SessionRecord,
  type SqlDatabase,
  type TenantMembershipRole,
} from "@credtrail/db";
import { renderAppPage } from "../../ui/render-page";
import type { AppContext } from "../../app";
import { buildLocalTwoFactorPath } from "../../auth/break-glass-policy";
import { adminRoleRequiredPage } from "../tenant-governance-shared-pages";
import type { RegisterTenantGovernanceRoutesInput } from "../tenant-governance-routes.types";

export type TenantGovernanceAdminAuth = ReturnType<typeof createTenantGovernanceAdminAuth>;

export const createTenantGovernanceAdminAuth = (
  input: Pick<
    RegisterTenantGovernanceRoutesInput,
    | "requireTenantRole"
    | "ADMIN_ROLES"
    | "APPROVAL_WORKSPACE_ROLES"
    | "ISSUER_ROLES"
    | "requestTenantMemberInvite"
  >,
) => {
  const {
    requireTenantRole,
    ADMIN_ROLES,
    APPROVAL_WORKSPACE_ROLES,
    ISSUER_ROLES,
    requestTenantMemberInvite,
  } = input;
  const EVIDENCE_WORKSPACE_ROLES = Array.from(
    new Set([...ISSUER_ROLES, ...APPROVAL_WORKSPACE_ROLES]),
  );

  const requireEnterpriseTenant = async (
    c: AppContext,
    tenantId: string,
    db: SqlDatabase,
  ): Promise<Response | null> => {
    const tenant = await findTenantById(db, tenantId);

    if (tenant === null) {
      return c.json(
        {
          error: "Tenant not found",
        },
        404,
      );
    }

    if (tenant.planTier !== "enterprise") {
      return c.json(
        {
          error: "Feature requires enterprise tenant plan",
        },
        403,
      );
    }

    return null;
  };

  const memberInviteSkipped = {
    deliveryStatus: "skipped" as const,
    inviteKind: "magic_link" as const,
  };

  const requestInviteForTenantMember = async (
    c: AppContext,
    input: {
      tenantId: string;
      email: string;
      role: TenantMembershipRole;
      sendInvite: boolean;
    },
  ): Promise<{
    deliveryStatus: "sent" | "skipped" | "failed";
    inviteKind: "magic_link" | "sso_notice";
  }> => {
    if (!input.sendInvite || requestTenantMemberInvite === undefined) {
      return memberInviteSkipped;
    }

    return requestTenantMemberInvite(c, {
      tenantId: input.tenantId,
      email: input.email,
      role: input.role,
    });
  };

  const redirectToTenantLogin = (c: AppContext, tenantId: string, nextPath: string): Response => {
    const loginUrl = new URL("/login", c.req.url);
    loginUrl.searchParams.set("tenantId", tenantId);
    loginUrl.searchParams.set("next", nextPath);
    loginUrl.searchParams.set("reason", "auth_required");
    return c.redirect(`${loginUrl.pathname}${loginUrl.search}`, 302);
  };

  const resolveTenantWorkspaceRole = async (
    c: AppContext,
    tenantId: string,
    nextPath: string,
    allowedRoles: readonly TenantMembershipRole[],
  ): Promise<
    | Response
    | {
        session: SessionRecord;
        membershipRole: TenantMembershipRole;
      }
  > => {
    const roleCheck = await requireTenantRole(c, tenantId, allowedRoles);

    if (roleCheck instanceof Response) {
      if (roleCheck.status === 401) {
        return redirectToTenantLogin(c, tenantId, nextPath);
      }

      if (roleCheck.status === 423) {
        return c.redirect(
          buildLocalTwoFactorPath({
            tenantId,
            nextPath,
            setup: true,
            reason: "break_glass_mfa_setup_pending",
          }),
          302,
        );
      }

      if (roleCheck.status === 403) {
        c.header("Cache-Control", "no-store");
        return renderAppPage(c, adminRoleRequiredPage(tenantId), 403);
      }

      return roleCheck;
    }

    return roleCheck;
  };

  const resolveInstitutionAdminAdminRole = (
    c: AppContext,
    tenantId: string,
    nextPath: string,
  ): ReturnType<typeof resolveTenantWorkspaceRole> =>
    resolveTenantWorkspaceRole(c, tenantId, nextPath, ADMIN_ROLES);

  const resolveBadgeRuleApprovalWorkspaceRole = (
    c: AppContext,
    tenantId: string,
    nextPath: string,
  ): ReturnType<typeof resolveTenantWorkspaceRole> =>
    resolveTenantWorkspaceRole(c, tenantId, nextPath, APPROVAL_WORKSPACE_ROLES);

  const resolveInstitutionAdminEvidenceRole = (
    c: AppContext,
    tenantId: string,
    nextPath: string,
  ): ReturnType<typeof resolveTenantWorkspaceRole> =>
    resolveTenantWorkspaceRole(c, tenantId, nextPath, EVIDENCE_WORKSPACE_ROLES);

  return {
    requireEnterpriseTenant,
    requestInviteForTenantMember,
    redirectToTenantLogin,
    resolveBadgeRuleApprovalWorkspaceRole,
    resolveInstitutionAdminEvidenceRole,
    resolveInstitutionAdminAdminRole,
  };
};

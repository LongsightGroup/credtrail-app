import {
  createAuditLog,
  createDelegatedIssuingAuthorityGrant,
  findDelegatedIssuingAuthorityGrantById,
  removeTenantMembershipOrgUnitScope,
  revokeDelegatedIssuingAuthorityGrant,
  upsertBadgeRuleApprovalPolicy,
  upsertTenantMembershipOrgUnitScope,
  type SessionRecord,
  type TenantMembershipRole,
} from "@credtrail/db";
import {
  parseCreateDelegatedIssuingAuthorityGrantRequest,
  parseRevokeDelegatedIssuingAuthorityGrantRequest,
  parseTenantPathParams,
  parseUpsertBadgeRuleApprovalPolicyRequest,
  parseUpsertTenantMembershipOrgUnitScopeRequest,
} from "@credtrail/validation";
import type { Hono } from "hono";
import {
  buildAccessGovernanceAdminPath,
  buildAccessGovernanceDelegationNewPath,
} from "../admin/access-admin-helpers";
import { readOptionalFormField } from "../admin/admin-form-helpers";
import { setAdminListMessageFlash } from "../admin/admin-list-message-flash";
import type { AppContext, AppEnv } from "../app";
import type { ResolveDatabase } from "../app/route-deps";

interface RegisterTenantAccessGovernanceAdminRoutesInput {
  app: Hono<AppEnv>;
  resolveDatabase: ResolveDatabase;
  resolveInstitutionAdminAdminRole: (
    c: AppContext,
    tenantId: string,
    nextPath: string,
  ) => Promise<
    | Response
    | {
        session: SessionRecord;
        membershipRole: TenantMembershipRole;
      }
  >;
}

const redirectToGovernance = async (
  c: AppContext,
  input: {
    tenantId: string;
    userId: string;
    tone: "success" | "error";
    message: string;
  },
): Promise<Response> => {
  await setAdminListMessageFlash(c, {
    tenantId: input.tenantId,
    userId: input.userId,
    workspace: "access_governance",
    tone: input.tone,
    message: input.message,
  });

  return c.redirect(buildAccessGovernanceAdminPath(input.tenantId), 303);
};

const redirectToDelegationNew = async (
  c: AppContext,
  input: {
    tenantId: string;
    userId: string;
    tone: "success" | "error";
    message: string;
  },
): Promise<Response> => {
  await setAdminListMessageFlash(c, {
    tenantId: input.tenantId,
    userId: input.userId,
    workspace: "access_governance_delegation",
    tone: input.tone,
    message: input.message,
  });

  return c.redirect(buildAccessGovernanceDelegationNewPath(input.tenantId), 303);
};

const readBadgeTemplateIdsFromForm = (formData: FormData): string[] => {
  const raw = formData.get("badgeTemplateIds");

  if (typeof raw !== "string") {
    return [];
  }

  const trimmed = raw.trim();

  return trimmed.length > 0 ? [trimmed] : [];
};

const mapScopeErrorMessage = (error: unknown): string => {
  if (!(error instanceof Error)) {
    return "Unable to save the scoped role. Check the member, org unit, and role, then try again.";
  }

  if (error.message.includes("Membership not found for tenant")) {
    return "Choose a tenant member who already belongs to this organization.";
  }

  if (error.message.includes("Org unit") && error.message.includes("not found for tenant")) {
    return "Choose an org unit that belongs to this organization.";
  }

  return "Unable to save the scoped role. Check the member, org unit, and role, then try again.";
};

const mapDelegationErrorMessage = (error: unknown): string => {
  if (!(error instanceof Error)) {
    return "Unable to save the delegation. Check the delegate, org unit, actions, and end time.";
  }

  if (error.message.includes("conflicts with existing grant")) {
    return "This delegation overlaps an existing grant for the same person and org unit.";
  }

  if (error.message.includes("Membership not found for tenant")) {
    return "Choose a tenant member who already belongs to this organization.";
  }

  if (error.message.includes("Org unit") && error.message.includes("not found for tenant")) {
    return "Choose an org unit that belongs to this organization.";
  }

  if (error.message.includes("Badge template") && error.message.includes("not found for tenant")) {
    return "Choose a badge template that belongs to this organization.";
  }

  if (error.message.includes("must be after") || error.message.includes("valid ISO timestamp")) {
    return "Choose a valid end date and time for this delegation.";
  }

  return "Unable to save the delegation. Check the delegate, org unit, actions, and end time.";
};

export const registerTenantAccessGovernanceAdminRoutes = (
  input: RegisterTenantAccessGovernanceAdminRoutesInput,
): void => {
  const { app, resolveDatabase, resolveInstitutionAdminAdminRole } = input;

  app.post("/tenants/:tenantId/admin/access/governance/rule-approval-policy", async (c) => {
    const pathParams = parseTenantPathParams(c.req.param());
    const nextPath = buildAccessGovernanceAdminPath(pathParams.tenantId);
    const roleCheck = await resolveInstitutionAdminAdminRole(c, pathParams.tenantId, nextPath);

    if (roleCheck instanceof Response) {
      return roleCheck;
    }

    const { session, membershipRole } = roleCheck;
    const formData = await c.req.formData();
    const approvalRequirement = readOptionalFormField(formData, "approvalRequirement");
    const requiredRole = readOptionalFormField(formData, "requiredRole");

    let request: ReturnType<typeof parseUpsertBadgeRuleApprovalPolicyRequest>;

    try {
      request = parseUpsertBadgeRuleApprovalPolicyRequest({
        approvalRequirement,
        ...(requiredRole === undefined ? {} : { requiredRole }),
      });
    } catch {
      return redirectToGovernance(c, {
        tenantId: pathParams.tenantId,
        userId: session.userId,
        tone: "error",
        message: "Choose an approval requirement and reviewer role before saving.",
      });
    }

    const approvalSteps =
      request.approvalRequirement === "always"
        ? [
            {
              requiredRole: request.requiredRole,
              label: "Badge rule approval",
            },
          ]
        : [];
    const db = resolveDatabase(c.env);

    try {
      const policy = await upsertBadgeRuleApprovalPolicy(db, {
        tenantId: pathParams.tenantId,
        orgUnitId: null,
        approvalRequirement: request.approvalRequirement,
        approvalSteps,
        createdByUserId: session.userId,
      });

      await createAuditLog(db, {
        tenantId: pathParams.tenantId,
        actorUserId: session.userId,
        action: "badge_rule.approval_policy_upserted",
        targetType: "badge_rule_approval_policy",
        targetId: policy.id ?? pathParams.tenantId,
        metadata: {
          role: membershipRole,
          orgUnitId: null,
          approvalRequirement: policy.approvalRequirement,
          approvalSteps: policy.approvalSteps,
        },
      });

      return redirectToGovernance(c, {
        tenantId: pathParams.tenantId,
        userId: session.userId,
        tone: "success",
        message: "Badge rule approval policy saved.",
      });
    } catch {
      return redirectToGovernance(c, {
        tenantId: pathParams.tenantId,
        userId: session.userId,
        tone: "error",
        message: "Unable to save the badge rule approval policy. Check the settings and try again.",
      });
    }
  });

  app.post("/tenants/:tenantId/admin/access/governance/scopes", async (c) => {
    const pathParams = parseTenantPathParams(c.req.param());
    const nextPath = buildAccessGovernanceAdminPath(pathParams.tenantId);
    const roleCheck = await resolveInstitutionAdminAdminRole(c, pathParams.tenantId, nextPath);

    if (roleCheck instanceof Response) {
      return roleCheck;
    }

    const { session, membershipRole } = roleCheck;
    const formData = await c.req.formData();
    const userId = readOptionalFormField(formData, "userId") ?? "";
    const orgUnitId = readOptionalFormField(formData, "orgUnitId") ?? "";
    const role = readOptionalFormField(formData, "role");

    let request: ReturnType<typeof parseUpsertTenantMembershipOrgUnitScopeRequest>;

    try {
      request = parseUpsertTenantMembershipOrgUnitScopeRequest({ role });
    } catch {
      return redirectToGovernance(c, {
        tenantId: pathParams.tenantId,
        userId: session.userId,
        tone: "error",
        message: "Choose a member, org unit, and scoped role before saving.",
      });
    }

    if (userId.length === 0 || orgUnitId.length === 0) {
      return redirectToGovernance(c, {
        tenantId: pathParams.tenantId,
        userId: session.userId,
        tone: "error",
        message: "Choose a member, org unit, and scoped role before saving.",
      });
    }

    const db = resolveDatabase(c.env);

    try {
      const result = await upsertTenantMembershipOrgUnitScope(db, {
        tenantId: pathParams.tenantId,
        userId,
        orgUnitId,
        role: request.role,
        createdByUserId: session.userId,
      });
      const action =
        result.previousRole === null
          ? "membership.org_scope_assigned"
          : result.previousRole === result.scope.role
            ? "membership.org_scope_reasserted"
            : "membership.org_scope_changed";

      await createAuditLog(db, {
        tenantId: pathParams.tenantId,
        actorUserId: session.userId,
        action,
        targetType: "membership_org_scope",
        targetId: `${pathParams.tenantId}:${userId}:${orgUnitId}`,
        metadata: {
          role: membershipRole,
          userId,
          orgUnitId,
          previousRole: result.previousRole,
          scopeRole: result.scope.role,
          changed: result.changed,
        },
      });

      return redirectToGovernance(c, {
        tenantId: pathParams.tenantId,
        userId: session.userId,
        tone: "success",
        message: `Saved scoped role ${result.scope.role} for ${userId}.`,
      });
    } catch (error: unknown) {
      return redirectToGovernance(c, {
        tenantId: pathParams.tenantId,
        userId: session.userId,
        tone: "error",
        message: mapScopeErrorMessage(error),
      });
    }
  });

  app.post("/tenants/:tenantId/admin/access/governance/scopes/remove", async (c) => {
    const pathParams = parseTenantPathParams(c.req.param());
    const nextPath = buildAccessGovernanceAdminPath(pathParams.tenantId);
    const roleCheck = await resolveInstitutionAdminAdminRole(c, pathParams.tenantId, nextPath);

    if (roleCheck instanceof Response) {
      return roleCheck;
    }

    const { session, membershipRole } = roleCheck;
    const formData = await c.req.formData();
    const userId = readOptionalFormField(formData, "userId") ?? "";
    const orgUnitId = readOptionalFormField(formData, "orgUnitId") ?? "";

    if (userId.length === 0 || orgUnitId.length === 0) {
      return redirectToGovernance(c, {
        tenantId: pathParams.tenantId,
        userId: session.userId,
        tone: "error",
        message: "Scoped role identifiers are missing.",
      });
    }

    const db = resolveDatabase(c.env);
    const removed = await removeTenantMembershipOrgUnitScope(db, {
      tenantId: pathParams.tenantId,
      userId,
      orgUnitId,
    });

    if (!removed) {
      return redirectToGovernance(c, {
        tenantId: pathParams.tenantId,
        userId: session.userId,
        tone: "error",
        message: "No matching scoped role was found.",
      });
    }

    await createAuditLog(db, {
      tenantId: pathParams.tenantId,
      actorUserId: session.userId,
      action: "membership.org_scope_removed",
      targetType: "membership_org_scope",
      targetId: `${pathParams.tenantId}:${userId}:${orgUnitId}`,
      metadata: {
        role: membershipRole,
        userId,
        orgUnitId,
      },
    });

    return redirectToGovernance(c, {
      tenantId: pathParams.tenantId,
      userId: session.userId,
      tone: "success",
      message: "Scoped role removed.",
    });
  });

  app.post("/tenants/:tenantId/admin/access/governance/delegations", async (c) => {
    const pathParams = parseTenantPathParams(c.req.param());
    const nextPath = buildAccessGovernanceDelegationNewPath(pathParams.tenantId);
    const roleCheck = await resolveInstitutionAdminAdminRole(c, pathParams.tenantId, nextPath);

    if (roleCheck instanceof Response) {
      return roleCheck;
    }

    const { session, membershipRole } = roleCheck;
    const formData = await c.req.formData();
    const delegateUserId = readOptionalFormField(formData, "delegateUserId") ?? "";
    const orgUnitId = readOptionalFormField(formData, "orgUnitId") ?? "";
    const endsAtLocal = readOptionalFormField(formData, "endsAt") ?? "";
    const reason = readOptionalFormField(formData, "reason");
    const allowedActions = formData
      .getAll("allowedAction")
      .map((value) => (typeof value === "string" ? value.trim() : ""))
      .filter((value) => value.length > 0);
    const badgeTemplateIds = readBadgeTemplateIdsFromForm(formData);

    if (delegateUserId.length === 0 || orgUnitId.length === 0) {
      return redirectToDelegationNew(c, {
        tenantId: pathParams.tenantId,
        userId: session.userId,
        tone: "error",
        message: "Choose a delegate and org unit before saving.",
      });
    }

    if (allowedActions.length === 0) {
      return redirectToDelegationNew(c, {
        tenantId: pathParams.tenantId,
        userId: session.userId,
        tone: "error",
        message: "Select at least one allowed badge action.",
      });
    }

    if (endsAtLocal.length === 0) {
      return redirectToDelegationNew(c, {
        tenantId: pathParams.tenantId,
        userId: session.userId,
        tone: "error",
        message: "Choose when this delegation should end.",
      });
    }

    const parsedEndsAtMs = Date.parse(endsAtLocal);

    if (!Number.isFinite(parsedEndsAtMs)) {
      return redirectToDelegationNew(c, {
        tenantId: pathParams.tenantId,
        userId: session.userId,
        tone: "error",
        message: "Choose a valid end date and time for this delegation.",
      });
    }

    const endsAtIso = new Date(parsedEndsAtMs).toISOString();

    let request: ReturnType<typeof parseCreateDelegatedIssuingAuthorityGrantRequest>;

    try {
      request = parseCreateDelegatedIssuingAuthorityGrantRequest({
        orgUnitId,
        allowedActions,
        ...(badgeTemplateIds.length > 0 ? { badgeTemplateIds } : {}),
        endsAt: endsAtIso,
        ...(reason !== undefined ? { reason } : {}),
      });
    } catch {
      return redirectToDelegationNew(c, {
        tenantId: pathParams.tenantId,
        userId: session.userId,
        tone: "error",
        message: "Check the delegate, org unit, allowed actions, and end time, then try again.",
      });
    }

    const db = resolveDatabase(c.env);

    try {
      const grant = await createDelegatedIssuingAuthorityGrant(db, {
        tenantId: pathParams.tenantId,
        delegateUserId,
        delegatedByUserId: session.userId,
        orgUnitId: request.orgUnitId,
        allowedActions: request.allowedActions,
        badgeTemplateIds: request.badgeTemplateIds,
        startsAt: request.startsAt ?? new Date().toISOString(),
        endsAt: request.endsAt,
        reason: request.reason,
      });

      await createAuditLog(db, {
        tenantId: pathParams.tenantId,
        actorUserId: session.userId,
        action: "delegated_issuing_authority.granted",
        targetType: "delegated_issuing_authority_grant",
        targetId: grant.id,
        metadata: {
          role: membershipRole,
          delegateUserId,
          orgUnitId: request.orgUnitId,
          allowedActions: request.allowedActions,
          badgeTemplateIds: request.badgeTemplateIds ?? [],
          startsAt: grant.startsAt,
          endsAt: request.endsAt,
        },
      });

      return redirectToGovernance(c, {
        tenantId: pathParams.tenantId,
        userId: session.userId,
        tone: "success",
        message: `Delegation saved for ${delegateUserId}.`,
      });
    } catch (error: unknown) {
      return redirectToDelegationNew(c, {
        tenantId: pathParams.tenantId,
        userId: session.userId,
        tone: "error",
        message: mapDelegationErrorMessage(error),
      });
    }
  });

  app.post("/tenants/:tenantId/admin/access/governance/delegations/revoke", async (c) => {
    const pathParams = parseTenantPathParams(c.req.param());
    const nextPath = buildAccessGovernanceAdminPath(pathParams.tenantId);
    const roleCheck = await resolveInstitutionAdminAdminRole(c, pathParams.tenantId, nextPath);

    if (roleCheck instanceof Response) {
      return roleCheck;
    }

    const { session, membershipRole } = roleCheck;
    const formData = await c.req.formData();
    const delegateUserId = readOptionalFormField(formData, "delegateUserId") ?? "";
    const grantId = readOptionalFormField(formData, "grantId") ?? "";
    const reason = readOptionalFormField(formData, "reason");

    if (delegateUserId.length === 0 || grantId.length === 0) {
      return redirectToGovernance(c, {
        tenantId: pathParams.tenantId,
        userId: session.userId,
        tone: "error",
        message: "Delegation identifiers are missing.",
      });
    }

    let request: ReturnType<typeof parseRevokeDelegatedIssuingAuthorityGrantRequest>;

    try {
      request = parseRevokeDelegatedIssuingAuthorityGrantRequest(
        reason !== undefined ? { reason } : {},
      );
    } catch {
      return redirectToGovernance(c, {
        tenantId: pathParams.tenantId,
        userId: session.userId,
        tone: "error",
        message: "Unable to remove this delegation.",
      });
    }

    const db = resolveDatabase(c.env);
    const existingGrant = await findDelegatedIssuingAuthorityGrantById(
      db,
      pathParams.tenantId,
      grantId,
    );

    if (existingGrant === null || existingGrant.delegateUserId !== delegateUserId) {
      return redirectToGovernance(c, {
        tenantId: pathParams.tenantId,
        userId: session.userId,
        tone: "error",
        message: "That delegation was not found.",
      });
    }

    const revokedAt = request.revokedAt ?? new Date().toISOString();

    let revokeResult: Awaited<ReturnType<typeof revokeDelegatedIssuingAuthorityGrant>>;

    try {
      revokeResult = await revokeDelegatedIssuingAuthorityGrant(db, {
        tenantId: pathParams.tenantId,
        grantId,
        revokedByUserId: session.userId,
        revokedReason: request.reason,
        revokedAt,
      });
    } catch {
      return redirectToGovernance(c, {
        tenantId: pathParams.tenantId,
        userId: session.userId,
        tone: "error",
        message: "That delegation is no longer active.",
      });
    }

    if (revokeResult.status !== "revoked") {
      return redirectToGovernance(c, {
        tenantId: pathParams.tenantId,
        userId: session.userId,
        tone: "error",
        message: "That delegation is no longer active.",
      });
    }

    await createAuditLog(db, {
      tenantId: pathParams.tenantId,
      actorUserId: session.userId,
      action: "delegated_issuing_authority.revoked",
      targetType: "delegated_issuing_authority_grant",
      targetId: grantId,
      metadata: {
        role: membershipRole,
        delegateUserId,
        reason: request.reason ?? null,
      },
    });

    return redirectToGovernance(c, {
      tenantId: pathParams.tenantId,
      userId: session.userId,
      tone: "success",
      message: "Delegation removed.",
    });
  });
};

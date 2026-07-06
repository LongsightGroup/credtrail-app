import {
  addBadgeRuleApproverGroupMember,
  createAuditLog,
  createBadgeRuleApproverGroup,
  createDelegatedIssuingAuthorityGrant,
  findDelegatedIssuingAuthorityGrantById,
  approvalPolicyStepsFromUpsertRequest,
  removeBadgeRuleApproverGroup,
  removeBadgeRuleApproverGroupMember,
  removeTenantMembershipOrgUnitScope,
  revokeDelegatedIssuingAuthorityGrant,
  upsertBadgeRuleApprovalPolicy,
  upsertTenantMembershipOrgUnitScope,
  type SessionRecord,
  type TenantMembershipRole,
} from "@credtrail/db";
import {
  parseAddBadgeRuleApproverGroupMemberRequest,
  parseCreateDelegatedIssuingAuthorityGrantRequest,
  parseCreateBadgeRuleApproverGroupRequest,
  parseRemoveBadgeRuleApproverGroupMemberRequest,
  parseRemoveBadgeRuleApproverGroupRequest,
  parseRevokeDelegatedIssuingAuthorityGrantRequest,
  parseTenantPathParams,
  parseUpsertBadgeRuleApprovalPolicyRequest,
  parseUpsertTenantMembershipOrgUnitScopeRequest,
} from "@credtrail/validation";
import type { Hono } from "hono";
import {
  buildAccessDelegationsAdminPath,
  buildAccessGovernanceAdminPath,
  buildAccessGovernanceDelegationNewPath,
  buildAccessOrgUnitAccessAdminPath,
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

const redirectToOrgUnitAccess = async (
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
    workspace: "access_org_unit_access",
    tone: input.tone,
    message: input.message,
  });

  return c.redirect(buildAccessOrgUnitAccessAdminPath(input.tenantId), 303);
};

const redirectToDelegations = async (
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
    workspace: "access_delegations",
    tone: input.tone,
    message: input.message,
  });

  return c.redirect(buildAccessDelegationsAdminPath(input.tenantId), 303);
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

const mapAddApproverGroupMemberResultMessage = (
  status: Awaited<ReturnType<typeof addBadgeRuleApproverGroupMember>>["status"],
): string => {
  switch (status) {
    case "group_not_found":
      return "Choose an approver group that belongs to this organization.";
    case "membership_not_found":
      return "Choose a tenant member who already belongs to this organization.";
    case "already_member":
      return "That member is already in the approver group.";
    case "added":
      return "Approver group member added.";
  }
};

const mapRemoveApproverGroupMemberResultMessage = (
  status: Awaited<ReturnType<typeof removeBadgeRuleApproverGroupMember>>["status"],
): string => {
  switch (status) {
    case "group_not_found":
      return "Choose an approver group that belongs to this organization.";
    case "member_not_found":
      return "No matching approver group member was found.";
    case "removed":
      return "Approver group member removed.";
  }
};

const mapRemoveApproverGroupResultMessage = (
  status: Awaited<ReturnType<typeof removeBadgeRuleApproverGroup>>["status"],
): string => {
  switch (status) {
    case "group_not_found":
      return "No matching approver group was found.";
    case "removed":
      return "Approver group removed.";
  }
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
    const orgUnitIdRaw = readOptionalFormField(formData, "orgUnitId");
    const orgUnitId = orgUnitIdRaw === undefined || orgUnitIdRaw.length === 0 ? null : orgUnitIdRaw;
    const stepTargetType = readOptionalFormField(formData, "stepTargetType");
    const requiredRole = readOptionalFormField(formData, "requiredRole");
    const targetUserId = readOptionalFormField(formData, "targetUserId");
    const targetApproverGroupId = readOptionalFormField(formData, "targetApproverGroupId");
    const recertificationIntervalMonthsRaw = readOptionalFormField(
      formData,
      "recertificationIntervalMonths",
    );
    const recertificationIntervalMonths =
      recertificationIntervalMonthsRaw === undefined
        ? null
        : Number.parseInt(recertificationIntervalMonthsRaw, 10);
    const allowSelfCertification = approvalRequirement === "never" ? true : undefined;

    let request: ReturnType<typeof parseUpsertBadgeRuleApprovalPolicyRequest>;

    try {
      request = parseUpsertBadgeRuleApprovalPolicyRequest({
        approvalRequirement,
        orgUnitId,
        ...(stepTargetType === undefined ? {} : { stepTargetType }),
        ...(requiredRole === undefined ? {} : { requiredRole }),
        ...(targetUserId === undefined || targetUserId.length === 0 ? {} : { targetUserId }),
        ...(targetApproverGroupId === undefined || targetApproverGroupId.length === 0
          ? {}
          : { targetApproverGroupId }),
        recertificationIntervalMonths,
        ...(allowSelfCertification === undefined ? {} : { allowSelfCertification }),
      });
    } catch {
      return redirectToGovernance(c, {
        tenantId: pathParams.tenantId,
        userId: session.userId,
        tone: "error",
        message: "Choose an approval requirement and reviewer before saving.",
      });
    }

    const approvalSteps = approvalPolicyStepsFromUpsertRequest(request);
    const db = resolveDatabase(c.env);

    try {
      const policy = await upsertBadgeRuleApprovalPolicy(db, {
        tenantId: pathParams.tenantId,
        orgUnitId: request.orgUnitId ?? null,
        approvalRequirement: request.approvalRequirement,
        allowSelfCertification:
          request.approvalRequirement === "never" ? request.allowSelfCertification : false,
        recertificationIntervalMonths: request.recertificationIntervalMonths ?? null,
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
          orgUnitId: policy.orgUnitId,
          approvalRequirement: policy.approvalRequirement,
          allowSelfCertification: policy.allowSelfCertification,
          recertificationIntervalMonths: policy.recertificationIntervalMonths,
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

  app.post("/tenants/:tenantId/admin/access/governance/approver-groups", async (c) => {
    const pathParams = parseTenantPathParams(c.req.param());
    const nextPath = buildAccessGovernanceAdminPath(pathParams.tenantId);
    const roleCheck = await resolveInstitutionAdminAdminRole(c, pathParams.tenantId, nextPath);

    if (roleCheck instanceof Response) {
      return roleCheck;
    }

    const { session, membershipRole } = roleCheck;
    const formData = await c.req.formData();
    const name = readOptionalFormField(formData, "name");
    const orgUnitIdRaw = readOptionalFormField(formData, "orgUnitId");
    const orgUnitId = orgUnitIdRaw === undefined || orgUnitIdRaw.length === 0 ? null : orgUnitIdRaw;

    let request: ReturnType<typeof parseCreateBadgeRuleApproverGroupRequest>;

    try {
      request = parseCreateBadgeRuleApproverGroupRequest({ name, orgUnitId });
    } catch {
      return redirectToGovernance(c, {
        tenantId: pathParams.tenantId,
        userId: session.userId,
        tone: "error",
        message: "Enter a group name before creating an approver group.",
      });
    }

    const db = resolveDatabase(c.env);

    try {
      const group = await createBadgeRuleApproverGroup(db, {
        tenantId: pathParams.tenantId,
        orgUnitId: request.orgUnitId ?? null,
        name: request.name,
        createdByUserId: session.userId,
      });

      await createAuditLog(db, {
        tenantId: pathParams.tenantId,
        actorUserId: session.userId,
        action: "badge_rule.approver_group_created",
        targetType: "badge_rule_approver_group",
        targetId: group.id,
        metadata: {
          role: membershipRole,
          orgUnitId: group.orgUnitId,
          name: group.name,
        },
      });

      return redirectToGovernance(c, {
        tenantId: pathParams.tenantId,
        userId: session.userId,
        tone: "success",
        message: "Approver group created.",
      });
    } catch {
      return redirectToGovernance(c, {
        tenantId: pathParams.tenantId,
        userId: session.userId,
        tone: "error",
        message: "Unable to create the approver group. Check the name and org unit.",
      });
    }
  });

  app.post("/tenants/:tenantId/admin/access/governance/approver-groups/members", async (c) => {
    const pathParams = parseTenantPathParams(c.req.param());
    const nextPath = buildAccessGovernanceAdminPath(pathParams.tenantId);
    const roleCheck = await resolveInstitutionAdminAdminRole(c, pathParams.tenantId, nextPath);

    if (roleCheck instanceof Response) {
      return roleCheck;
    }

    const { session, membershipRole } = roleCheck;
    const formData = await c.req.formData();

    let request: ReturnType<typeof parseAddBadgeRuleApproverGroupMemberRequest>;

    try {
      request = parseAddBadgeRuleApproverGroupMemberRequest({
        groupId: readOptionalFormField(formData, "groupId"),
        userId: readOptionalFormField(formData, "userId"),
      });
    } catch {
      return redirectToGovernance(c, {
        tenantId: pathParams.tenantId,
        userId: session.userId,
        tone: "error",
        message: "Choose an approver group and member before saving.",
      });
    }

    const db = resolveDatabase(c.env);

    let result: Awaited<ReturnType<typeof addBadgeRuleApproverGroupMember>>;

    try {
      result = await addBadgeRuleApproverGroupMember(db, {
        tenantId: pathParams.tenantId,
        groupId: request.groupId,
        userId: request.userId,
        createdByUserId: session.userId,
      });
    } catch {
      return redirectToGovernance(c, {
        tenantId: pathParams.tenantId,
        userId: session.userId,
        tone: "error",
        message: "Unable to add that member to the approver group.",
      });
    }

    if (result.status !== "added") {
      return redirectToGovernance(c, {
        tenantId: pathParams.tenantId,
        userId: session.userId,
        tone: "error",
        message: mapAddApproverGroupMemberResultMessage(result.status),
      });
    }

    await createAuditLog(db, {
      tenantId: pathParams.tenantId,
      actorUserId: session.userId,
      action: "badge_rule.approver_group_member_added",
      targetType: "badge_rule_approver_group",
      targetId: request.groupId,
      metadata: {
        role: membershipRole,
        userId: request.userId,
      },
    });

    return redirectToGovernance(c, {
      tenantId: pathParams.tenantId,
      userId: session.userId,
      tone: "success",
      message: mapAddApproverGroupMemberResultMessage(result.status),
    });
  });

  app.post(
    "/tenants/:tenantId/admin/access/governance/approver-groups/members/remove",
    async (c) => {
      const pathParams = parseTenantPathParams(c.req.param());
      const nextPath = buildAccessGovernanceAdminPath(pathParams.tenantId);
      const roleCheck = await resolveInstitutionAdminAdminRole(c, pathParams.tenantId, nextPath);

      if (roleCheck instanceof Response) {
        return roleCheck;
      }

      const { session, membershipRole } = roleCheck;
      const formData = await c.req.formData();

      let request: ReturnType<typeof parseRemoveBadgeRuleApproverGroupMemberRequest>;

      try {
        request = parseRemoveBadgeRuleApproverGroupMemberRequest({
          groupId: readOptionalFormField(formData, "groupId"),
          userId: readOptionalFormField(formData, "userId"),
        });
      } catch {
        return redirectToGovernance(c, {
          tenantId: pathParams.tenantId,
          userId: session.userId,
          tone: "error",
          message: "Approver group member identifiers are missing.",
        });
      }

      const db = resolveDatabase(c.env);
      const result = await removeBadgeRuleApproverGroupMember(db, {
        tenantId: pathParams.tenantId,
        groupId: request.groupId,
        userId: request.userId,
      });

      if (result.status !== "removed") {
        return redirectToGovernance(c, {
          tenantId: pathParams.tenantId,
          userId: session.userId,
          tone: "error",
          message: mapRemoveApproverGroupMemberResultMessage(result.status),
        });
      }

      await createAuditLog(db, {
        tenantId: pathParams.tenantId,
        actorUserId: session.userId,
        action: "badge_rule.approver_group_member_removed",
        targetType: "badge_rule_approver_group",
        targetId: request.groupId,
        metadata: {
          role: membershipRole,
          userId: request.userId,
        },
      });

      return redirectToGovernance(c, {
        tenantId: pathParams.tenantId,
        userId: session.userId,
        tone: "success",
        message: mapRemoveApproverGroupMemberResultMessage(result.status),
      });
    },
  );

  app.post("/tenants/:tenantId/admin/access/governance/approver-groups/remove", async (c) => {
    const pathParams = parseTenantPathParams(c.req.param());
    const nextPath = buildAccessGovernanceAdminPath(pathParams.tenantId);
    const roleCheck = await resolveInstitutionAdminAdminRole(c, pathParams.tenantId, nextPath);

    if (roleCheck instanceof Response) {
      return roleCheck;
    }

    const { session, membershipRole } = roleCheck;
    const formData = await c.req.formData();

    let request: ReturnType<typeof parseRemoveBadgeRuleApproverGroupRequest>;

    try {
      request = parseRemoveBadgeRuleApproverGroupRequest({
        groupId: readOptionalFormField(formData, "groupId"),
      });
    } catch {
      return redirectToGovernance(c, {
        tenantId: pathParams.tenantId,
        userId: session.userId,
        tone: "error",
        message: "Approver group identifier is missing.",
      });
    }

    const db = resolveDatabase(c.env);
    const result = await removeBadgeRuleApproverGroup(db, {
      tenantId: pathParams.tenantId,
      groupId: request.groupId,
    });

    if (result.status !== "removed") {
      return redirectToGovernance(c, {
        tenantId: pathParams.tenantId,
        userId: session.userId,
        tone: "error",
        message: mapRemoveApproverGroupResultMessage(result.status),
      });
    }

    await createAuditLog(db, {
      tenantId: pathParams.tenantId,
      actorUserId: session.userId,
      action: "badge_rule.approver_group_removed",
      targetType: "badge_rule_approver_group",
      targetId: request.groupId,
      metadata: {
        role: membershipRole,
      },
    });

    return redirectToGovernance(c, {
      tenantId: pathParams.tenantId,
      userId: session.userId,
      tone: "success",
      message: mapRemoveApproverGroupResultMessage(result.status),
    });
  });

  app.post("/tenants/:tenantId/admin/access/governance/scopes", async (c) => {
    const pathParams = parseTenantPathParams(c.req.param());
    const nextPath = buildAccessOrgUnitAccessAdminPath(pathParams.tenantId);
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
      return redirectToOrgUnitAccess(c, {
        tenantId: pathParams.tenantId,
        userId: session.userId,
        tone: "error",
        message: "Choose a member, org unit, and scoped role before saving.",
      });
    }

    if (userId.length === 0 || orgUnitId.length === 0) {
      return redirectToOrgUnitAccess(c, {
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

      return redirectToOrgUnitAccess(c, {
        tenantId: pathParams.tenantId,
        userId: session.userId,
        tone: "success",
        message: `Saved scoped role ${result.scope.role} for ${userId}.`,
      });
    } catch (error: unknown) {
      return redirectToOrgUnitAccess(c, {
        tenantId: pathParams.tenantId,
        userId: session.userId,
        tone: "error",
        message: mapScopeErrorMessage(error),
      });
    }
  });

  app.post("/tenants/:tenantId/admin/access/governance/scopes/remove", async (c) => {
    const pathParams = parseTenantPathParams(c.req.param());
    const nextPath = buildAccessOrgUnitAccessAdminPath(pathParams.tenantId);
    const roleCheck = await resolveInstitutionAdminAdminRole(c, pathParams.tenantId, nextPath);

    if (roleCheck instanceof Response) {
      return roleCheck;
    }

    const { session, membershipRole } = roleCheck;
    const formData = await c.req.formData();
    const userId = readOptionalFormField(formData, "userId") ?? "";
    const orgUnitId = readOptionalFormField(formData, "orgUnitId") ?? "";

    if (userId.length === 0 || orgUnitId.length === 0) {
      return redirectToOrgUnitAccess(c, {
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
      return redirectToOrgUnitAccess(c, {
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

    return redirectToOrgUnitAccess(c, {
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

      return redirectToDelegations(c, {
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
    const nextPath = buildAccessDelegationsAdminPath(pathParams.tenantId);
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
      return redirectToDelegations(c, {
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
      return redirectToDelegations(c, {
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
      return redirectToDelegations(c, {
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
      return redirectToDelegations(c, {
        tenantId: pathParams.tenantId,
        userId: session.userId,
        tone: "error",
        message: "That delegation is no longer active.",
      });
    }

    if (revokeResult.status !== "revoked") {
      return redirectToDelegations(c, {
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

    return redirectToDelegations(c, {
      tenantId: pathParams.tenantId,
      userId: session.userId,
      tone: "success",
      message: "Delegation removed.",
    });
  });
};

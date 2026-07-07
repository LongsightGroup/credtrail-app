import {
  addBadgeRuleApproverGroupMember,
  createAuditLog,
  createBadgeRuleApproverGroup,
  approvalPolicyStepsFromUpsertRequest,
  removeBadgeRuleApproverGroup,
  removeBadgeRuleApproverGroupMember,
  upsertBadgeRuleApprovalPolicy,
} from "@credtrail/db";
import {
  parseAddBadgeRuleApproverGroupMemberRequest,
  parseCreateBadgeRuleApproverGroupRequest,
  parseRemoveBadgeRuleApproverGroupMemberRequest,
  parseRemoveBadgeRuleApproverGroupRequest,
  parseTenantPathParams,
  parseUpsertBadgeRuleApprovalPolicyRequest,
} from "@credtrail/validation";
import { buildAccessGovernanceAdminPath } from "../admin/access-admin-helpers";
import { readOptionalFormField } from "../admin/admin-form-helpers";
import { redirectWithAdminListFlash } from "../admin/admin-list-flash-redirect";
import type { AppContext } from "../app";
import type { TenantAccessAdminRouteDeps } from "./tenant-access-admin-route-deps";

const redirectToRuleApproval = (
  c: AppContext,
  input: {
    tenantId: string;
    userId: string;
    tone: "success" | "error";
    message: string;
  },
): Promise<Response> => {
  return redirectWithAdminListFlash(c, {
    ...input,
    workspace: "access_governance",
    path: buildAccessGovernanceAdminPath(input.tenantId),
  });
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

export const registerTenantAccessRuleApprovalAdminRoutes = (
  input: TenantAccessAdminRouteDeps,
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
      return redirectToRuleApproval(c, {
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

      return redirectToRuleApproval(c, {
        tenantId: pathParams.tenantId,
        userId: session.userId,
        tone: "success",
        message: "Badge rule approval policy saved.",
      });
    } catch {
      return redirectToRuleApproval(c, {
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
      return redirectToRuleApproval(c, {
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

      return redirectToRuleApproval(c, {
        tenantId: pathParams.tenantId,
        userId: session.userId,
        tone: "success",
        message: "Approver group created.",
      });
    } catch {
      return redirectToRuleApproval(c, {
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
      return redirectToRuleApproval(c, {
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
      return redirectToRuleApproval(c, {
        tenantId: pathParams.tenantId,
        userId: session.userId,
        tone: "error",
        message: "Unable to add that member to the approver group.",
      });
    }

    if (result.status !== "added") {
      return redirectToRuleApproval(c, {
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

    return redirectToRuleApproval(c, {
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
        return redirectToRuleApproval(c, {
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
        return redirectToRuleApproval(c, {
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

      return redirectToRuleApproval(c, {
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
      return redirectToRuleApproval(c, {
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
      return redirectToRuleApproval(c, {
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

    return redirectToRuleApproval(c, {
      tenantId: pathParams.tenantId,
      userId: session.userId,
      tone: "success",
      message: mapRemoveApproverGroupResultMessage(result.status),
    });
  });
};

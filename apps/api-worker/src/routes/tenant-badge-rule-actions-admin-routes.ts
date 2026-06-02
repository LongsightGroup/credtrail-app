import {
  activateBadgeIssuanceRuleVersion,
  createAuditLog,
  deleteDraftBadgeIssuanceRule,
  decideBadgeIssuanceRuleVersion,
  findBadgeIssuanceRuleVersionById,
  listBadgeIssuanceRuleVersionApprovalSteps,
  submitBadgeIssuanceRuleVersionForApproval,
  tenantMembershipRoleSatisfiesMinimumRole,
  type SessionRecord,
  type SqlDatabase,
  type TenantMembershipRole,
} from "@credtrail/db";
import {
  parseBadgeIssuanceRulePathParams,
  parseBadgeIssuanceRuleVersionPathParams,
  parseDecideBadgeIssuanceRuleVersionRequest,
} from "@credtrail/validation";
import type { Hono } from "hono";
import { readOptionalFormField } from "../admin/admin-form-helpers";
import { setAdminListMessageFlash } from "../admin/admin-list-message-flash";
import { buildRulesAdminPath } from "../admin/access-admin-helpers";
import type { AppBindings, AppContext, AppEnv } from "../app";

interface RegisterTenantBadgeRuleActionsAdminRoutesInput {
  app: Hono<AppEnv>;
  resolveDatabase: (bindings: AppBindings) => SqlDatabase;
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

const redirectToRules = async (
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
    workspace: "rules",
    tone: input.tone,
    message: input.message,
  });

  return c.redirect(buildRulesAdminPath(input.tenantId), 303);
};

export const registerTenantBadgeRuleActionsAdminRoutes = (
  input: RegisterTenantBadgeRuleActionsAdminRoutesInput,
): void => {
  const { app, resolveDatabase, resolveInstitutionAdminAdminRole } = input;

  app.post(
    "/tenants/:tenantId/admin/rules/:ruleId/versions/:versionId/submit-approval",
    async (c) => {
      const pathParams = parseBadgeIssuanceRuleVersionPathParams(c.req.param());
      const nextPath = buildRulesAdminPath(pathParams.tenantId);
      const roleCheck = await resolveInstitutionAdminAdminRole(c, pathParams.tenantId, nextPath);

      if (roleCheck instanceof Response) {
        return roleCheck;
      }

      const { session, membershipRole } = roleCheck;
      const db = resolveDatabase(c.env);
      const currentVersion = await findBadgeIssuanceRuleVersionById(db, {
        tenantId: pathParams.tenantId,
        ruleId: pathParams.ruleId,
        versionId: pathParams.versionId,
      });

      if (currentVersion === null) {
        return redirectToRules(c, {
          tenantId: pathParams.tenantId,
          userId: session.userId,
          tone: "error",
          message: "That rule version was not found.",
        });
      }

      if (currentVersion.status !== "draft" && currentVersion.status !== "rejected") {
        return redirectToRules(c, {
          tenantId: pathParams.tenantId,
          userId: session.userId,
          tone: "error",
          message: "Only draft or rejected versions can be marked ready for review.",
        });
      }

      const updatedVersion = await submitBadgeIssuanceRuleVersionForApproval(db, {
        tenantId: pathParams.tenantId,
        ruleId: pathParams.ruleId,
        versionId: pathParams.versionId,
        actorUserId: session.userId,
        actorRole: membershipRole,
      });

      if (updatedVersion === null) {
        return redirectToRules(c, {
          tenantId: pathParams.tenantId,
          userId: session.userId,
          tone: "error",
          message: "That rule version was not found.",
        });
      }

      await createAuditLog(db, {
        tenantId: pathParams.tenantId,
        actorUserId: session.userId,
        action: "badge_rule.version_submitted_for_approval",
        targetType: "badge_rule_version",
        targetId: updatedVersion.id,
        metadata: {
          role: membershipRole,
          ruleId: pathParams.ruleId,
          versionNumber: updatedVersion.versionNumber,
          status: updatedVersion.status,
        },
      });

      return redirectToRules(c, {
        tenantId: pathParams.tenantId,
        userId: session.userId,
        tone: "success",
        message: "Draft is ready for review. It is not active yet.",
      });
    },
  );

  app.post("/tenants/:tenantId/admin/rules/:ruleId/versions/:versionId/decision", async (c) => {
    const pathParams = parseBadgeIssuanceRuleVersionPathParams(c.req.param());
    const nextPath = buildRulesAdminPath(pathParams.tenantId);
    const roleCheck = await resolveInstitutionAdminAdminRole(c, pathParams.tenantId, nextPath);

    if (roleCheck instanceof Response) {
      return roleCheck;
    }

    const { session, membershipRole } = roleCheck;
    const formData = await c.req.formData();
    const decision = readOptionalFormField(formData, "decision");
    const comment = readOptionalFormField(formData, "comment");

    let request: ReturnType<typeof parseDecideBadgeIssuanceRuleVersionRequest>;

    try {
      request = parseDecideBadgeIssuanceRuleVersionRequest({
        decision,
        ...(comment !== undefined ? { comment } : {}),
      });
    } catch {
      return redirectToRules(c, {
        tenantId: pathParams.tenantId,
        userId: session.userId,
        tone: "error",
        message: "Choose approve or reject before continuing.",
      });
    }

    const db = resolveDatabase(c.env);
    const currentVersion = await findBadgeIssuanceRuleVersionById(db, {
      tenantId: pathParams.tenantId,
      ruleId: pathParams.ruleId,
      versionId: pathParams.versionId,
    });

    if (currentVersion === null) {
      return redirectToRules(c, {
        tenantId: pathParams.tenantId,
        userId: session.userId,
        tone: "error",
        message: "That rule version was not found.",
      });
    }

    if (currentVersion.status !== "pending_approval") {
      return redirectToRules(c, {
        tenantId: pathParams.tenantId,
        userId: session.userId,
        tone: "error",
        message: "Only versions waiting for approval can be approved or rejected.",
      });
    }

    const approvalSteps = await listBadgeIssuanceRuleVersionApprovalSteps(db, {
      tenantId: pathParams.tenantId,
      ruleId: pathParams.ruleId,
      versionId: pathParams.versionId,
    });
    const currentApprovalStep = approvalSteps.find((step) => step.status === "pending");

    if (currentApprovalStep === undefined) {
      return redirectToRules(c, {
        tenantId: pathParams.tenantId,
        userId: session.userId,
        tone: "error",
        message: "No pending approval step exists for this rule version.",
      });
    }

    if (
      !tenantMembershipRoleSatisfiesMinimumRole(membershipRole, currentApprovalStep.requiredRole)
    ) {
      return redirectToRules(c, {
        tenantId: pathParams.tenantId,
        userId: session.userId,
        tone: "error",
        message: `Your role cannot ${request.decision} this approval step.`,
      });
    }

    const decidedVersion = await decideBadgeIssuanceRuleVersion(db, {
      tenantId: pathParams.tenantId,
      ruleId: pathParams.ruleId,
      versionId: pathParams.versionId,
      decision: request.decision,
      actorUserId: session.userId,
      actorRole: membershipRole,
      comment: request.comment,
    });

    if (decidedVersion === null) {
      return redirectToRules(c, {
        tenantId: pathParams.tenantId,
        userId: session.userId,
        tone: "error",
        message: "That rule version is no longer waiting for approval.",
      });
    }

    await createAuditLog(db, {
      tenantId: pathParams.tenantId,
      actorUserId: session.userId,
      action: "badge_rule.version_approval_decided",
      targetType: "badge_rule_version",
      targetId: decidedVersion.id,
      metadata: {
        role: membershipRole,
        ruleId: pathParams.ruleId,
        versionNumber: decidedVersion.versionNumber,
        stepNumber: currentApprovalStep.stepNumber,
        requiredRole: currentApprovalStep.requiredRole,
        decision: request.decision,
        comment: request.comment ?? null,
        status: decidedVersion.status,
      },
    });

    return redirectToRules(c, {
      tenantId: pathParams.tenantId,
      userId: session.userId,
      tone: "success",
      message:
        request.decision === "approved" ? "Rule version approved." : "Rule version rejected.",
    });
  });

  app.post("/tenants/:tenantId/admin/rules/:ruleId/versions/:versionId/activate", async (c) => {
    const pathParams = parseBadgeIssuanceRuleVersionPathParams(c.req.param());
    const nextPath = buildRulesAdminPath(pathParams.tenantId);
    const roleCheck = await resolveInstitutionAdminAdminRole(c, pathParams.tenantId, nextPath);

    if (roleCheck instanceof Response) {
      return roleCheck;
    }

    const { session, membershipRole } = roleCheck;
    const db = resolveDatabase(c.env);
    const currentVersion = await findBadgeIssuanceRuleVersionById(db, {
      tenantId: pathParams.tenantId,
      ruleId: pathParams.ruleId,
      versionId: pathParams.versionId,
    });

    if (currentVersion === null) {
      return redirectToRules(c, {
        tenantId: pathParams.tenantId,
        userId: session.userId,
        tone: "error",
        message: "That rule version was not found.",
      });
    }

    if (currentVersion.status !== "approved" && currentVersion.status !== "active") {
      return redirectToRules(c, {
        tenantId: pathParams.tenantId,
        userId: session.userId,
        tone: "error",
        message: "Only approved versions can be activated.",
      });
    }

    const activatedVersion = await activateBadgeIssuanceRuleVersion(db, {
      tenantId: pathParams.tenantId,
      ruleId: pathParams.ruleId,
      versionId: pathParams.versionId,
      actorUserId: session.userId,
    });

    if (activatedVersion === null) {
      return redirectToRules(c, {
        tenantId: pathParams.tenantId,
        userId: session.userId,
        tone: "error",
        message: "That rule version could not be activated.",
      });
    }

    await createAuditLog(db, {
      tenantId: pathParams.tenantId,
      actorUserId: session.userId,
      action: "badge_rule.version_activated",
      targetType: "badge_rule_version",
      targetId: activatedVersion.id,
      metadata: {
        role: membershipRole,
        ruleId: pathParams.ruleId,
        versionNumber: activatedVersion.versionNumber,
        status: activatedVersion.status,
      },
    });

    return redirectToRules(c, {
      tenantId: pathParams.tenantId,
      userId: session.userId,
      tone: "success",
      message: "Rule version activated.",
    });
  });

  app.post("/tenants/:tenantId/admin/rules/:ruleId/delete", async (c) => {
    const pathParams = parseBadgeIssuanceRulePathParams(c.req.param());
    const nextPath = buildRulesAdminPath(pathParams.tenantId);
    const roleCheck = await resolveInstitutionAdminAdminRole(c, pathParams.tenantId, nextPath);

    if (roleCheck instanceof Response) {
      return roleCheck;
    }

    const { session, membershipRole } = roleCheck;
    const db = resolveDatabase(c.env);
    const deleted = await deleteDraftBadgeIssuanceRule(db, {
      tenantId: pathParams.tenantId,
      ruleId: pathParams.ruleId,
    });

    if (deleted.status === "not_found") {
      return redirectToRules(c, {
        tenantId: pathParams.tenantId,
        userId: session.userId,
        tone: "error",
        message: "That rule was not found.",
      });
    }

    if (deleted.status === "not_deletable") {
      return redirectToRules(c, {
        tenantId: pathParams.tenantId,
        userId: session.userId,
        tone: "error",
        message: "Only never-active draft or rejected rules can be deleted.",
      });
    }

    await createAuditLog(db, {
      tenantId: pathParams.tenantId,
      actorUserId: session.userId,
      action: "badge_rule.deleted",
      targetType: "badge_rule",
      targetId: deleted.rule.id,
      metadata: {
        role: membershipRole,
        ruleName: deleted.rule.name,
        versions: deleted.versions.map((version) => ({
          id: version.id,
          versionNumber: version.versionNumber,
          status: version.status,
        })),
      },
    });

    return redirectToRules(c, {
      tenantId: pathParams.tenantId,
      userId: session.userId,
      tone: "success",
      message: "Draft rule deleted.",
    });
  });
};

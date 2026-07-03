import {
  activateBadgeIssuanceRuleVersion,
  createAuditLog,
  decideBadgeIssuanceRuleVersion,
  deleteDraftBadgeIssuanceRule,
  findBadgeIssuanceRuleVersionById,
  listBadgeIssuanceRuleVersionApprovalSteps,
  submitBadgeIssuanceRuleVersionForApproval,
  tenantMembershipRoleSatisfiesMinimumRole,
  type BadgeIssuanceRuleVersionRecord,
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
import { buildRulesAdminPath } from "../admin/access-admin-helpers";
import { readOptionalFormField } from "../admin/admin-form-helpers";
import { setAdminListMessageFlash } from "../admin/admin-list-message-flash";
import type { AppContext, AppEnv } from "../app";
import type { ResolveDatabase } from "../app/route-deps";

interface RegisterTenantBadgeRuleActionsAdminRoutesInput {
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

type AdminApprovalDecisionResult =
  | {
      status: "decided";
      version: BadgeIssuanceRuleVersionRecord;
    }
  | { status: "not_found" }
  | { status: "not_pending" }
  | { status: "no_pending_step" }
  | { status: "forbidden"; requiredRole: TenantMembershipRole }
  | { status: "stale" };

type AdminApprovalDecisionFailureResult = Exclude<
  AdminApprovalDecisionResult,
  { status: "decided" }
>;

const decideCurrentApprovalStepForAdmin = async (
  db: SqlDatabase,
  input: {
    tenantId: string;
    ruleId: string;
    versionId: string;
    decision: "approved" | "rejected";
    actorUserId: string;
    actorRole: TenantMembershipRole;
    comment?: string | undefined;
  },
): Promise<AdminApprovalDecisionResult> => {
  const currentVersion = await findBadgeIssuanceRuleVersionById(db, {
    tenantId: input.tenantId,
    ruleId: input.ruleId,
    versionId: input.versionId,
  });

  if (currentVersion === null) {
    return { status: "not_found" };
  }

  if (currentVersion.status !== "pending_approval") {
    return { status: "not_pending" };
  }

  const approvalSteps = await listBadgeIssuanceRuleVersionApprovalSteps(db, {
    tenantId: input.tenantId,
    ruleId: input.ruleId,
    versionId: input.versionId,
  });
  const currentApprovalStep = approvalSteps.find((step) => step.status === "pending");

  if (currentApprovalStep === undefined) {
    return { status: "no_pending_step" };
  }

  if (
    !tenantMembershipRoleSatisfiesMinimumRole(input.actorRole, currentApprovalStep.requiredRole)
  ) {
    return {
      status: "forbidden",
      requiredRole: currentApprovalStep.requiredRole,
    };
  }

  const decidedVersion = await decideBadgeIssuanceRuleVersion(db, {
    tenantId: input.tenantId,
    ruleId: input.ruleId,
    versionId: input.versionId,
    decision: input.decision,
    actorUserId: input.actorUserId,
    actorRole: input.actorRole,
    ...(input.comment !== undefined ? { comment: input.comment } : {}),
  });

  if (decidedVersion === null) {
    return { status: "stale" };
  }

  await createAuditLog(db, {
    tenantId: input.tenantId,
    actorUserId: input.actorUserId,
    action: "badge_rule.version_approval_decided",
    targetType: "badge_rule_version",
    targetId: decidedVersion.id,
    metadata: {
      role: input.actorRole,
      ruleId: input.ruleId,
      versionNumber: decidedVersion.versionNumber,
      stepNumber: currentApprovalStep.stepNumber,
      requiredRole: currentApprovalStep.requiredRole,
      decision: input.decision,
      comment: input.comment ?? null,
      status: decidedVersion.status,
    },
  });

  return {
    status: "decided",
    version: decidedVersion,
  };
};

const redirectAdminApprovalDecisionFailure = async (
  c: AppContext,
  input: {
    tenantId: string;
    userId: string;
    result: AdminApprovalDecisionFailureResult;
    notPendingMessage: string;
    forbiddenMessage: (result: { requiredRole: TenantMembershipRole }) => string;
  },
): Promise<Response> => {
  if (input.result.status === "not_found") {
    return redirectToRules(c, {
      tenantId: input.tenantId,
      userId: input.userId,
      tone: "error",
      message: "That rule version was not found.",
    });
  }

  if (input.result.status === "not_pending") {
    return redirectToRules(c, {
      tenantId: input.tenantId,
      userId: input.userId,
      tone: "error",
      message: input.notPendingMessage,
    });
  }

  if (input.result.status === "no_pending_step") {
    return redirectToRules(c, {
      tenantId: input.tenantId,
      userId: input.userId,
      tone: "error",
      message: "No pending approval step exists for this rule version.",
    });
  }

  if (input.result.status === "forbidden") {
    return redirectToRules(c, {
      tenantId: input.tenantId,
      userId: input.userId,
      tone: "error",
      message: input.forbiddenMessage(input.result),
    });
  }

  return redirectToRules(c, {
    tenantId: input.tenantId,
    userId: input.userId,
    tone: "error",
    message: "That rule version is no longer waiting for approval.",
  });
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
          message: "Only draft or rejected versions can be submitted from this action.",
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
        message:
          updatedVersion.status === "approved"
            ? "Rule version approved by policy. Activate it from the rules table when ready."
            : "Rule version submitted for approval.",
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
    const decisionResult = await decideCurrentApprovalStepForAdmin(db, {
      tenantId: pathParams.tenantId,
      ruleId: pathParams.ruleId,
      versionId: pathParams.versionId,
      decision: request.decision,
      actorUserId: session.userId,
      actorRole: membershipRole,
      ...(request.comment !== undefined ? { comment: request.comment } : {}),
    });

    if (decisionResult.status !== "decided") {
      return redirectAdminApprovalDecisionFailure(c, {
        tenantId: pathParams.tenantId,
        userId: session.userId,
        result: decisionResult,
        notPendingMessage: "Only versions waiting for approval can be approved or rejected.",
        forbiddenMessage: () => `Your role cannot ${request.decision} this approval step.`,
      });
    }

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

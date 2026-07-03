import {
  activateBadgeIssuanceRuleVersion,
  createAuditLog,
  decideBadgeIssuanceRuleVersion,
  deleteDraftBadgeIssuanceRule,
  findBadgeIssuanceRuleVersionById,
  parseOptionalDateTimeInputToIso,
  resumeBadgeIssuanceRuleVersion,
  submitBadgeIssuanceRuleVersionForApproval,
  suspendBadgeIssuanceRuleVersion,
  updateBadgeIssuanceRuleVersionLifecycleWindow,
  type BadgeIssuanceRuleVersionRecord,
  type SessionRecord,
  type TenantMembershipRole,
} from "@credtrail/db";
import {
  parseBadgeIssuanceRulePathParams,
  parseBadgeIssuanceRuleVersionPathParams,
  parseDecideBadgeIssuanceRuleVersionRequest,
} from "@credtrail/validation";
import type { Hono } from "hono";
import {
  buildBadgeRuleApprovalsPath,
  buildBadgeRuleVersionReviewPath,
  buildRulesAdminPath,
} from "../admin/access-admin-helpers";
import { readOptionalFormField } from "../admin/admin-form-helpers";
import { setAdminListMessageFlash } from "../admin/admin-list-message-flash";
import type { AppContext, AppEnv } from "../app";
import type { ResolveDatabase } from "../app/route-deps";
import {
  notifyBadgeRuleApprovalDecision,
  notifyBadgeRuleApprovalSubmitted,
} from "../badges/badge-rule-approval-notifications";
import {
  adminApprovalDecisionFailureMessage,
  submitBadgeRuleVersionForApprovalFailureMessage,
} from "../badges/badge-rule-approval-outcomes";

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

interface BadgeRuleVersionPathParams {
  readonly tenantId: string;
  readonly ruleId: string;
  readonly versionId: string;
}

interface DecisionRedirectInput {
  readonly tenantId: string;
  readonly userId: string;
  readonly tone: "success" | "error";
  readonly message: string;
}

type DecisionRedirect = (input: DecisionRedirectInput) => Promise<Response>;

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

const readLifecycleWindowFields = (
  formData: FormData,
): { effectiveStartsAt?: string; expiresAt?: string } => {
  const effectiveStartsAt = parseOptionalDateTimeInputToIso(
    readOptionalFormField(formData, "effectiveStartsAt"),
  );
  const expiresAt = parseOptionalDateTimeInputToIso(readOptionalFormField(formData, "expiresAt"));

  return {
    ...(effectiveStartsAt === undefined ? {} : { effectiveStartsAt }),
    ...(expiresAt === undefined ? {} : { expiresAt }),
  };
};

const redirectToApprovals = async (
  c: AppContext,
  input: {
    tenantId: string;
    userId: string;
    tone: "success" | "error";
    message: string;
    reviewPath?: string | undefined;
  },
): Promise<Response> => {
  await setAdminListMessageFlash(c, {
    tenantId: input.tenantId,
    userId: input.userId,
    workspace: "rule_approvals",
    tone: input.tone,
    message: input.message,
  });

  return c.redirect(input.reviewPath ?? buildBadgeRuleApprovalsPath(input.tenantId), 303);
};

const absoluteUrlForPath = (c: AppContext, path: string): string => {
  return new URL(path, c.req.url).toString();
};

const decisionSuccessMessage = (
  decision: ReturnType<typeof parseDecideBadgeIssuanceRuleVersionRequest>["decision"],
): string => {
  if (decision === "approved") {
    return "Rule version approved.";
  }

  if (decision === "changes_requested") {
    return "Rule version returned to draft for changes.";
  }

  return "Rule version rejected.";
};

export const registerTenantBadgeRuleActionsAdminRoutes = (
  input: RegisterTenantBadgeRuleActionsAdminRoutesInput,
): void => {
  const { app, resolveDatabase, resolveInstitutionAdminAdminRole } = input;

  const handleDecisionPost = async (
    c: AppContext,
    routeInput: {
      pathParams: BadgeRuleVersionPathParams;
      nextPath: string;
      redirect: DecisionRedirect;
    },
  ): Promise<Response> => {
    const { pathParams } = routeInput;
    const roleCheck = await resolveInstitutionAdminAdminRole(
      c,
      pathParams.tenantId,
      routeInput.nextPath,
    );

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
      return routeInput.redirect({
        tenantId: pathParams.tenantId,
        userId: session.userId,
        tone: "error",
        message: "Choose approve, request changes, or reject before continuing.",
      });
    }

    const db = resolveDatabase(c.env);
    const decisionResult = await decideBadgeIssuanceRuleVersion(db, {
      tenantId: pathParams.tenantId,
      ruleId: pathParams.ruleId,
      versionId: pathParams.versionId,
      decision: request.decision,
      actorUserId: session.userId,
      actorRole: membershipRole,
      ...(request.comment !== undefined ? { comment: request.comment } : {}),
    });

    if (decisionResult.status !== "decided") {
      return routeInput.redirect({
        tenantId: pathParams.tenantId,
        userId: session.userId,
        tone: "error",
        message: adminApprovalDecisionFailureMessage(request.decision, decisionResult),
      });
    }

    await createAuditLog(db, {
      tenantId: pathParams.tenantId,
      actorUserId: session.userId,
      action: "badge_rule.version_approval_decided",
      targetType: "badge_rule_version",
      targetId: decisionResult.version.id,
      metadata: {
        role: membershipRole,
        ruleId: pathParams.ruleId,
        versionNumber: decisionResult.version.versionNumber,
        decision: request.decision,
        comment: request.comment ?? null,
        status: decisionResult.version.status,
      },
    });

    await notifyBadgeRuleApprovalDecision(db, {
      env: c.env,
      tenantId: pathParams.tenantId,
      ruleId: pathParams.ruleId,
      version: decisionResult.version,
      decision: request.decision,
      comment: request.comment ?? null,
      reviewUrl: absoluteUrlForPath(
        c,
        buildBadgeRuleVersionReviewPath(
          pathParams.tenantId,
          pathParams.ruleId,
          pathParams.versionId,
        ),
      ),
    });

    return routeInput.redirect({
      tenantId: pathParams.tenantId,
      userId: session.userId,
      tone: "success",
      message: decisionSuccessMessage(request.decision),
    });
  };

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
      const submitResult = await submitBadgeIssuanceRuleVersionForApproval(db, {
        tenantId: pathParams.tenantId,
        ruleId: pathParams.ruleId,
        versionId: pathParams.versionId,
        actorUserId: session.userId,
        actorRole: membershipRole,
      });

      if (submitResult.status !== "submitted") {
        return redirectToRules(c, {
          tenantId: pathParams.tenantId,
          userId: session.userId,
          tone: "error",
          message: submitBadgeRuleVersionForApprovalFailureMessage(submitResult),
        });
      }

      const updatedVersion: BadgeIssuanceRuleVersionRecord = submitResult.version;

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

      await notifyBadgeRuleApprovalSubmitted(db, {
        env: c.env,
        tenantId: pathParams.tenantId,
        ruleId: pathParams.ruleId,
        version: updatedVersion,
        reviewUrl: absoluteUrlForPath(
          c,
          buildBadgeRuleVersionReviewPath(
            pathParams.tenantId,
            pathParams.ruleId,
            pathParams.versionId,
          ),
        ),
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
    return handleDecisionPost(c, {
      pathParams,
      nextPath: buildRulesAdminPath(pathParams.tenantId),
      redirect: (redirectInput) => redirectToRules(c, redirectInput),
    });
  });

  app.post(
    "/tenants/:tenantId/admin/rules/approvals/:ruleId/versions/:versionId/decision",
    async (c) => {
      const pathParams = parseBadgeIssuanceRuleVersionPathParams(c.req.param());
      const reviewPath = buildBadgeRuleVersionReviewPath(
        pathParams.tenantId,
        pathParams.ruleId,
        pathParams.versionId,
      );

      return handleDecisionPost(c, {
        pathParams,
        nextPath: reviewPath,
        redirect: (redirectInput) =>
          redirectToApprovals(c, {
            ...redirectInput,
            reviewPath,
          }),
      });
    },
  );

  app.post("/tenants/:tenantId/admin/rules/:ruleId/versions/:versionId/activate", async (c) => {
    const pathParams = parseBadgeIssuanceRuleVersionPathParams(c.req.param());
    const nextPath = buildRulesAdminPath(pathParams.tenantId);
    const roleCheck = await resolveInstitutionAdminAdminRole(c, pathParams.tenantId, nextPath);

    if (roleCheck instanceof Response) {
      return roleCheck;
    }

    const { session, membershipRole } = roleCheck;
    const db = resolveDatabase(c.env);
    const formData = await c.req.formData();
    const lifecycleWindow = readLifecycleWindowFields(formData);
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

    if (currentVersion.status !== "approved") {
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
      ...lifecycleWindow,
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
        effectiveStartsAt: activatedVersion.effectiveStartsAt ?? null,
        expiresAt: activatedVersion.expiresAt ?? null,
      },
    });

    return redirectToRules(c, {
      tenantId: pathParams.tenantId,
      userId: session.userId,
      tone: "success",
      message: "Rule version activated.",
    });
  });

  app.post(
    "/tenants/:tenantId/admin/rules/:ruleId/versions/:versionId/update-lifecycle",
    async (c) => {
      const pathParams = parseBadgeIssuanceRuleVersionPathParams(c.req.param());
      const nextPath = buildRulesAdminPath(pathParams.tenantId);
      const roleCheck = await resolveInstitutionAdminAdminRole(c, pathParams.tenantId, nextPath);

      if (roleCheck instanceof Response) {
        return roleCheck;
      }

      const { session, membershipRole } = roleCheck;
      const db = resolveDatabase(c.env);
      const formData = await c.req.formData();
      const lifecycleWindow = readLifecycleWindowFields(formData);
      const updatedVersion = await updateBadgeIssuanceRuleVersionLifecycleWindow(db, {
        tenantId: pathParams.tenantId,
        ruleId: pathParams.ruleId,
        versionId: pathParams.versionId,
        actorUserId: session.userId,
        ...lifecycleWindow,
      });

      if (updatedVersion === null) {
        return redirectToRules(c, {
          tenantId: pathParams.tenantId,
          userId: session.userId,
          tone: "error",
          message: "Only active rule versions can update lifecycle windows.",
        });
      }

      await createAuditLog(db, {
        tenantId: pathParams.tenantId,
        actorUserId: session.userId,
        action: "badge_rule.lifecycle_window_updated",
        targetType: "badge_rule_version",
        targetId: updatedVersion.id,
        metadata: {
          role: membershipRole,
          ruleId: pathParams.ruleId,
          versionNumber: updatedVersion.versionNumber,
          effectiveStartsAt: updatedVersion.effectiveStartsAt ?? null,
          expiresAt: updatedVersion.expiresAt ?? null,
        },
      });

      return redirectToRules(c, {
        tenantId: pathParams.tenantId,
        userId: session.userId,
        tone: "success",
        message: "Rule lifecycle window updated.",
      });
    },
  );

  app.post("/tenants/:tenantId/admin/rules/:ruleId/versions/:versionId/suspend", async (c) => {
    const pathParams = parseBadgeIssuanceRuleVersionPathParams(c.req.param());
    const nextPath = buildRulesAdminPath(pathParams.tenantId);
    const roleCheck = await resolveInstitutionAdminAdminRole(c, pathParams.tenantId, nextPath);

    if (roleCheck instanceof Response) {
      return roleCheck;
    }

    const { session, membershipRole } = roleCheck;
    const formData = await c.req.formData();
    const reason = readOptionalFormField(formData, "reason");

    if (reason === undefined) {
      return redirectToRules(c, {
        tenantId: pathParams.tenantId,
        userId: session.userId,
        tone: "error",
        message: "Enter a suspension reason before halting issuance.",
      });
    }

    const db = resolveDatabase(c.env);
    const suspendedVersion = await suspendBadgeIssuanceRuleVersion(db, {
      tenantId: pathParams.tenantId,
      ruleId: pathParams.ruleId,
      versionId: pathParams.versionId,
      actorUserId: session.userId,
      reason,
    });

    if (suspendedVersion === null) {
      return redirectToRules(c, {
        tenantId: pathParams.tenantId,
        userId: session.userId,
        tone: "error",
        message: "Only active rule versions can be suspended.",
      });
    }

    await createAuditLog(db, {
      tenantId: pathParams.tenantId,
      actorUserId: session.userId,
      action: "badge_rule.version_suspended",
      targetType: "badge_rule_version",
      targetId: suspendedVersion.id,
      metadata: {
        role: membershipRole,
        ruleId: pathParams.ruleId,
        versionNumber: suspendedVersion.versionNumber,
        reason,
      },
    });

    return redirectToRules(c, {
      tenantId: pathParams.tenantId,
      userId: session.userId,
      tone: "success",
      message: "Rule issuance suspended.",
    });
  });

  app.post("/tenants/:tenantId/admin/rules/:ruleId/versions/:versionId/resume", async (c) => {
    const pathParams = parseBadgeIssuanceRuleVersionPathParams(c.req.param());
    const nextPath = buildRulesAdminPath(pathParams.tenantId);
    const roleCheck = await resolveInstitutionAdminAdminRole(c, pathParams.tenantId, nextPath);

    if (roleCheck instanceof Response) {
      return roleCheck;
    }

    const { session, membershipRole } = roleCheck;
    const db = resolveDatabase(c.env);
    const resumedVersion = await resumeBadgeIssuanceRuleVersion(db, {
      tenantId: pathParams.tenantId,
      ruleId: pathParams.ruleId,
      versionId: pathParams.versionId,
      actorUserId: session.userId,
    });

    if (resumedVersion === null) {
      return redirectToRules(c, {
        tenantId: pathParams.tenantId,
        userId: session.userId,
        tone: "error",
        message: "Only suspended rule versions can be resumed.",
      });
    }

    await createAuditLog(db, {
      tenantId: pathParams.tenantId,
      actorUserId: session.userId,
      action: "badge_rule.version_resumed",
      targetType: "badge_rule_version",
      targetId: resumedVersion.id,
      metadata: {
        role: membershipRole,
        ruleId: pathParams.ruleId,
        versionNumber: resumedVersion.versionNumber,
      },
    });

    return redirectToRules(c, {
      tenantId: pathParams.tenantId,
      userId: session.userId,
      tone: "success",
      message: "Rule issuance resumed.",
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

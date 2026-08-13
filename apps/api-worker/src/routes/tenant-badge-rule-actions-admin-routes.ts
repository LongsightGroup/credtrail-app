import {
  activateBadgeIssuanceRuleVersion,
  createAuditLog,
  decideBadgeIssuanceRuleVersion,
  deleteBadgeIssuanceRuleBuilderDraftById,
  deleteDraftBadgeIssuanceRule,
  parseOptionalDateTimeInputToIso,
  recertifyBadgeIssuanceRuleVersion,
  reopenApprovedBadgeIssuanceRuleVersion,
  resumeBadgeIssuanceRuleVersion,
  submitBadgeIssuanceRuleVersionForApproval,
  suspendBadgeIssuanceRuleVersion,
  updateBadgeIssuanceRuleVersionLifecycleWindow,
  withdrawBadgeIssuanceRuleVersionSubmission,
  type BadgeIssuanceRuleVersionRecord,
  type TenantMembershipRole,
} from "@credtrail/db";
import {
  parseBadgeIssuanceRulePathParams,
  parseBadgeIssuanceRuleBuilderDraftPathParams,
  parseBadgeIssuanceRuleVersionPathParams,
  parseDecideBadgeIssuanceRuleVersionRequest,
  parseReopenApprovedBadgeIssuanceRuleVersionRequest,
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
import type { AuthenticatedPrincipal } from "../auth/auth-context";
import {
  adminApprovalDecisionRequestFailureMessage,
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
        principal: AuthenticatedPrincipal;
        membershipRole: TenantMembershipRole;
      }
  >;
  resolveBadgeRuleApprovalWorkspaceRole: (
    c: AppContext,
    tenantId: string,
    nextPath: string,
  ) => Promise<
    | Response
    | {
        principal: AuthenticatedPrincipal;
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

interface BadgeRuleLifecycleAdminActionInput {
  readonly c: AppContext;
  readonly pathParams: BadgeRuleVersionPathParams;
  readonly notAppliedMessage: string;
  readonly successMessage: string;
  readonly auditAction: string;
  readonly run: (input: {
    readonly principal: AuthenticatedPrincipal;
    readonly membershipRole: TenantMembershipRole;
    readonly formData: FormData;
  }) => Promise<BadgeIssuanceRuleVersionRecord | null | Response>;
  readonly auditMetadata?: (
    version: BadgeIssuanceRuleVersionRecord,
    input: {
      readonly membershipRole: TenantMembershipRole;
      readonly formData: FormData;
    },
  ) => Record<string, unknown>;
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

  c.header("Cache-Control", "no-store");
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

  c.header("Cache-Control", "no-store");
  return c.redirect(input.reviewPath ?? buildBadgeRuleApprovalsPath(input.tenantId), 303);
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

const withdrawalFailureMessage = (
  status: Exclude<
    Awaited<ReturnType<typeof withdrawBadgeIssuanceRuleVersionSubmission>>["status"],
    "withdrawn"
  >,
): string => {
  switch (status) {
    case "not_found":
      return "That rule version was not found.";
    case "not_pending":
      return "Only a version waiting for approval can be withdrawn.";
    case "forbidden":
      return "Only the person who submitted this version can withdraw it.";
    case "stale":
      return "That rule version is no longer waiting for approval.";
  }
};

const reopenFailureMessage = (
  status: Exclude<
    Awaited<ReturnType<typeof reopenApprovedBadgeIssuanceRuleVersion>>["status"],
    "reopened"
  >,
): string => {
  switch (status) {
    case "not_found":
      return "That rule version was not found.";
    case "not_approved":
      return "Only an approved version that has not been activated can be reopened.";
    case "forbidden":
      return "Only the final approver or an institution administrator can reopen this version.";
    case "comment_required":
      return "Explain why this approval is being reopened.";
    case "stale":
      return "That rule version is no longer approved.";
  }
};

export const registerTenantBadgeRuleActionsAdminRoutes = (
  input: RegisterTenantBadgeRuleActionsAdminRoutesInput,
): void => {
  const {
    app,
    resolveDatabase,
    resolveBadgeRuleApprovalWorkspaceRole,
    resolveInstitutionAdminAdminRole,
  } = input;

  const handleDecisionPost = async (
    c: AppContext,
    routeInput: {
      pathParams: BadgeRuleVersionPathParams;
      nextPath: string;
      redirect: DecisionRedirect;
    },
  ): Promise<Response> => {
    const { pathParams } = routeInput;
    const roleCheck = await resolveBadgeRuleApprovalWorkspaceRole(
      c,
      pathParams.tenantId,
      routeInput.nextPath,
    );

    if (roleCheck instanceof Response) {
      return roleCheck;
    }

    const { principal, membershipRole } = roleCheck;
    const formData = await c.req.formData();
    const decision = readOptionalFormField(formData, "decision");
    const comment = readOptionalFormField(formData, "comment");

    let request: ReturnType<typeof parseDecideBadgeIssuanceRuleVersionRequest>;

    try {
      request = parseDecideBadgeIssuanceRuleVersionRequest({
        decision,
        ...(comment !== undefined ? { comment } : {}),
      });
    } catch (error: unknown) {
      return routeInput.redirect({
        tenantId: pathParams.tenantId,
        userId: principal.userId,
        tone: "error",
        message: adminApprovalDecisionRequestFailureMessage(error),
      });
    }

    const db = resolveDatabase(c.env);
    const decisionResult = await decideBadgeIssuanceRuleVersion(db, {
      tenantId: pathParams.tenantId,
      ruleId: pathParams.ruleId,
      versionId: pathParams.versionId,
      decision: request.decision,
      actorUserId: principal.userId,
      actorRole: membershipRole,
      ...(request.comment !== undefined ? { comment: request.comment } : {}),
    });

    if (decisionResult.status !== "decided") {
      return routeInput.redirect({
        tenantId: pathParams.tenantId,
        userId: principal.userId,
        tone: "error",
        message: adminApprovalDecisionFailureMessage(request.decision, decisionResult),
      });
    }

    return routeInput.redirect({
      tenantId: pathParams.tenantId,
      userId: principal.userId,
      tone: "success",
      message: decisionSuccessMessage(request.decision),
    });
  };

  const runLifecycleAdminAction = async (
    actionInput: BadgeRuleLifecycleAdminActionInput,
  ): Promise<Response> => {
    const { c, pathParams } = actionInput;
    const nextPath = buildRulesAdminPath(pathParams.tenantId);
    const roleCheck = await resolveInstitutionAdminAdminRole(c, pathParams.tenantId, nextPath);

    if (roleCheck instanceof Response) {
      return roleCheck;
    }

    const { principal, membershipRole } = roleCheck;
    const formData = await c.req.formData();
    const result = await actionInput.run({
      principal,
      membershipRole,
      formData,
    });

    if (result instanceof Response) {
      return result;
    }

    if (result === null) {
      return redirectToRules(c, {
        tenantId: pathParams.tenantId,
        userId: principal.userId,
        tone: "error",
        message: actionInput.notAppliedMessage,
      });
    }

    await createAuditLog(resolveDatabase(c.env), {
      tenantId: pathParams.tenantId,
      actorUserId: principal.userId,
      action: actionInput.auditAction,
      targetType: "badge_rule_version",
      targetId: result.id,
      metadata: {
        role: membershipRole,
        ruleId: pathParams.ruleId,
        versionNumber: result.versionNumber,
        ...actionInput.auditMetadata?.(result, { membershipRole, formData }),
      },
    });

    return redirectToRules(c, {
      tenantId: pathParams.tenantId,
      userId: principal.userId,
      tone: "success",
      message: actionInput.successMessage,
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

      const { principal, membershipRole } = roleCheck;
      const db = resolveDatabase(c.env);
      const submitResult = await submitBadgeIssuanceRuleVersionForApproval(db, {
        tenantId: pathParams.tenantId,
        ruleId: pathParams.ruleId,
        versionId: pathParams.versionId,
        actorUserId: principal.userId,
        actorRole: membershipRole,
      });

      if (submitResult.status !== "submitted") {
        return redirectToRules(c, {
          tenantId: pathParams.tenantId,
          userId: principal.userId,
          tone: "error",
          message: submitBadgeRuleVersionForApprovalFailureMessage(submitResult),
        });
      }

      const updatedVersion: BadgeIssuanceRuleVersionRecord = submitResult.version;

      return redirectToRules(c, {
        tenantId: pathParams.tenantId,
        userId: principal.userId,
        tone: "success",
        message:
          updatedVersion.status === "approved"
            ? "Rule version approved by policy. Activate it from the rules table when ready."
            : "Rule version submitted for approval.",
      });
    },
  );

  app.post(
    "/tenants/:tenantId/admin/rules/:ruleId/versions/:versionId/withdraw-submission",
    async (c) => {
      const pathParams = parseBadgeIssuanceRuleVersionPathParams(c.req.param());
      const nextPath = buildRulesAdminPath(pathParams.tenantId);
      const roleCheck = await resolveInstitutionAdminAdminRole(c, pathParams.tenantId, nextPath);

      if (roleCheck instanceof Response) {
        return roleCheck;
      }

      const { principal, membershipRole } = roleCheck;
      const result = await withdrawBadgeIssuanceRuleVersionSubmission(resolveDatabase(c.env), {
        ...pathParams,
        actorUserId: principal.userId,
        actorRole: membershipRole,
      });

      return redirectToRules(c, {
        tenantId: pathParams.tenantId,
        userId: principal.userId,
        tone: result.status === "withdrawn" ? "success" : "error",
        message:
          result.status === "withdrawn"
            ? "Submission withdrawn. The rule version is a draft again."
            : withdrawalFailureMessage(result.status),
      });
    },
  );

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

  app.post(
    "/tenants/:tenantId/admin/rules/approvals/:ruleId/versions/:versionId/reopen",
    async (c) => {
      const pathParams = parseBadgeIssuanceRuleVersionPathParams(c.req.param());
      const reviewPath = buildBadgeRuleVersionReviewPath(
        pathParams.tenantId,
        pathParams.ruleId,
        pathParams.versionId,
      );
      const roleCheck = await resolveBadgeRuleApprovalWorkspaceRole(
        c,
        pathParams.tenantId,
        reviewPath,
      );

      if (roleCheck instanceof Response) {
        return roleCheck;
      }

      const { principal, membershipRole } = roleCheck;
      const formData = await c.req.formData();
      const comment = readOptionalFormField(formData, "comment");

      let request: ReturnType<typeof parseReopenApprovedBadgeIssuanceRuleVersionRequest>;

      try {
        request = parseReopenApprovedBadgeIssuanceRuleVersionRequest({ comment });
      } catch {
        return redirectToApprovals(c, {
          tenantId: pathParams.tenantId,
          userId: principal.userId,
          tone: "error",
          message: "Explain why this approval is being reopened.",
          reviewPath,
        });
      }

      const result = await reopenApprovedBadgeIssuanceRuleVersion(resolveDatabase(c.env), {
        ...pathParams,
        actorUserId: principal.userId,
        actorRole: membershipRole,
        comment: request.comment,
      });

      return redirectToApprovals(c, {
        tenantId: pathParams.tenantId,
        userId: principal.userId,
        tone: result.status === "reopened" ? "success" : "error",
        message:
          result.status === "reopened"
            ? "Approval reopened. The rule version is a draft again."
            : reopenFailureMessage(result.status),
        reviewPath: result.status === "reopened" ? undefined : reviewPath,
      });
    },
  );

  app.post("/tenants/:tenantId/admin/rules/:ruleId/versions/:versionId/activate", async (c) => {
    const pathParams = parseBadgeIssuanceRuleVersionPathParams(c.req.param());
    return runLifecycleAdminAction({
      c,
      pathParams,
      notAppliedMessage: "Only approved versions can be activated.",
      successMessage: "Rule version activated. CredTrail is checking eligible learners now.",
      auditAction: "badge_rule.version_activated",
      run: ({ principal, formData }) =>
        activateBadgeIssuanceRuleVersion(resolveDatabase(c.env), {
          tenantId: pathParams.tenantId,
          ruleId: pathParams.ruleId,
          versionId: pathParams.versionId,
          actorUserId: principal.userId,
          ...readLifecycleWindowFields(formData),
        }),
      auditMetadata: (version) => ({
        status: version.status,
        effectiveStartsAt: version.effectiveStartsAt,
        expiresAt: version.expiresAt,
      }),
    });
  });

  app.post(
    "/tenants/:tenantId/admin/rules/:ruleId/versions/:versionId/update-lifecycle",
    async (c) => {
      const pathParams = parseBadgeIssuanceRuleVersionPathParams(c.req.param());
      return runLifecycleAdminAction({
        c,
        pathParams,
        notAppliedMessage: "Only active rule versions can update lifecycle windows.",
        successMessage: "Rule lifecycle window updated.",
        auditAction: "badge_rule.lifecycle_window_updated",
        run: ({ principal, formData }) =>
          updateBadgeIssuanceRuleVersionLifecycleWindow(resolveDatabase(c.env), {
            tenantId: pathParams.tenantId,
            ruleId: pathParams.ruleId,
            versionId: pathParams.versionId,
            actorUserId: principal.userId,
            ...readLifecycleWindowFields(formData),
          }),
        auditMetadata: (version) => ({
          effectiveStartsAt: version.effectiveStartsAt,
          expiresAt: version.expiresAt,
        }),
      });
    },
  );

  app.post("/tenants/:tenantId/admin/rules/:ruleId/versions/:versionId/suspend", async (c) => {
    const pathParams = parseBadgeIssuanceRuleVersionPathParams(c.req.param());
    return runLifecycleAdminAction({
      c,
      pathParams,
      notAppliedMessage: "Only active rule versions can be suspended.",
      successMessage: "Rule issuance suspended.",
      auditAction: "badge_rule.version_suspended",
      run: ({ principal, formData }) => {
        const reason = readOptionalFormField(formData, "reason");

        if (reason === undefined) {
          return redirectToRules(c, {
            tenantId: pathParams.tenantId,
            userId: principal.userId,
            tone: "error",
            message: "Enter a suspension reason before halting issuance.",
          });
        }

        return suspendBadgeIssuanceRuleVersion(resolveDatabase(c.env), {
          tenantId: pathParams.tenantId,
          ruleId: pathParams.ruleId,
          versionId: pathParams.versionId,
          actorUserId: principal.userId,
          reason,
        });
      },
      auditMetadata: (_version, { formData }) => ({
        reason: readOptionalFormField(formData, "reason") ?? "",
      }),
    });
  });

  app.post("/tenants/:tenantId/admin/rules/:ruleId/versions/:versionId/resume", async (c) => {
    const pathParams = parseBadgeIssuanceRuleVersionPathParams(c.req.param());
    return runLifecycleAdminAction({
      c,
      pathParams,
      notAppliedMessage: "Only suspended rule versions can be resumed.",
      successMessage: "Rule issuance resumed.",
      auditAction: "badge_rule.version_resumed",
      run: ({ principal }) =>
        resumeBadgeIssuanceRuleVersion(resolveDatabase(c.env), {
          tenantId: pathParams.tenantId,
          ruleId: pathParams.ruleId,
          versionId: pathParams.versionId,
          actorUserId: principal.userId,
        }),
    });
  });

  app.post("/tenants/:tenantId/admin/rules/:ruleId/versions/:versionId/recertify", async (c) => {
    const pathParams = parseBadgeIssuanceRuleVersionPathParams(c.req.param());
    return runLifecycleAdminAction({
      c,
      pathParams,
      notAppliedMessage:
        "Only active rule versions with recertification policy can be recertified.",
      successMessage: "Rule version recertified.",
      auditAction: "badge_rule.version_recertified",
      run: ({ principal }) =>
        recertifyBadgeIssuanceRuleVersion(resolveDatabase(c.env), {
          tenantId: pathParams.tenantId,
          ruleId: pathParams.ruleId,
          versionId: pathParams.versionId,
          actorUserId: principal.userId,
        }),
      auditMetadata: (version) => ({
        recertifiedAt: version.recertifiedAt,
        recertificationDueAt: version.recertificationDueAt,
      }),
    });
  });

  app.post("/tenants/:tenantId/admin/rules/:ruleId/delete", async (c) => {
    const pathParams = parseBadgeIssuanceRulePathParams(c.req.param());
    const nextPath = buildRulesAdminPath(pathParams.tenantId);
    const roleCheck = await resolveInstitutionAdminAdminRole(c, pathParams.tenantId, nextPath);

    if (roleCheck instanceof Response) {
      return roleCheck;
    }

    const { principal, membershipRole } = roleCheck;
    const db = resolveDatabase(c.env);
    const deleted = await deleteDraftBadgeIssuanceRule(db, {
      tenantId: pathParams.tenantId,
      ruleId: pathParams.ruleId,
    });

    if (deleted.status === "not_found") {
      return redirectToRules(c, {
        tenantId: pathParams.tenantId,
        userId: principal.userId,
        tone: "error",
        message: "That rule was not found.",
      });
    }

    if (deleted.status === "not_deletable") {
      return redirectToRules(c, {
        tenantId: pathParams.tenantId,
        userId: principal.userId,
        tone: "error",
        message: "Only never-active draft or rejected rules can be deleted.",
      });
    }

    await createAuditLog(db, {
      tenantId: pathParams.tenantId,
      actorUserId: principal.userId,
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
      userId: principal.userId,
      tone: "success",
      message: "Draft rule deleted.",
    });
  });

  app.post("/tenants/:tenantId/admin/rules/drafts/:draftId/delete", async (c) => {
    const pathParams = parseBadgeIssuanceRuleBuilderDraftPathParams(c.req.param());
    const nextPath = buildRulesAdminPath(pathParams.tenantId);
    const roleCheck = await resolveInstitutionAdminAdminRole(c, pathParams.tenantId, nextPath);

    if (roleCheck instanceof Response) {
      return roleCheck;
    }

    const { principal, membershipRole } = roleCheck;
    const db = resolveDatabase(c.env);
    const deleted = await deleteBadgeIssuanceRuleBuilderDraftById(db, {
      tenantId: pathParams.tenantId,
      userId: principal.userId,
      draftId: pathParams.draftId,
    });

    if (deleted === null) {
      return redirectToRules(c, {
        tenantId: pathParams.tenantId,
        userId: principal.userId,
        tone: "error",
        message: "That unfinished draft was not found.",
      });
    }

    await createAuditLog(db, {
      tenantId: pathParams.tenantId,
      actorUserId: principal.userId,
      action: "badge_rule.builder_draft_deleted",
      targetType: "badge_rule_builder_draft",
      targetId: deleted.id,
      metadata: {
        role: membershipRole,
      },
    });

    return redirectToRules(c, {
      tenantId: pathParams.tenantId,
      userId: principal.userId,
      tone: "success",
      message: "Unfinished draft deleted.",
    });
  });
};

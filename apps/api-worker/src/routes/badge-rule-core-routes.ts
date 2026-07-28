import { logError } from "@credtrail/core-domain";
import {
  BADGE_ISSUANCE_RULE_BUILDER_EDIT_DENIED_MESSAGE,
  createAuditLog,
  createBadgeIssuanceRuleWithAction,
  findBadgeIssuanceRuleById,
  listAuditLogs,
  listBadgeIssuanceRules,
  resolveListBadgeIssuanceRulesInput,
  listBadgeIssuanceRuleVersions,
  saveBadgeIssuanceRuleBuilderDraft,
  updateBadgeIssuanceRuleWithAction,
  type BadgeIssuanceRuleAuthoringResult,
  type BadgeIssuanceRuleRecord,
  type BadgeIssuanceRuleVersionRecord,
  type SessionRecord,
  type SqlDatabase,
  type TenantMembershipRole,
} from "@credtrail/db";
import {
  parseBadgeIssuanceRuleAuditLogQuery,
  parseBadgeIssuanceRuleBuilderDraftPathParams,
  parseBadgeIssuanceRuleDefinition,
  parseBadgeIssuanceRulePathParams,
  parseCreateBadgeIssuanceRuleRequest,
  parseSaveBadgeIssuanceRuleBuilderDraftRequest,
  parseTenantPathParams,
  parseUpdateBadgeIssuanceRuleDraftRequest,
  serializeBadgeIssuanceRuleBuilderDraftPayload,
} from "@credtrail/validation";
import type { Hono } from "hono";
import type { AppContext, AppEnv } from "../app";
import { observabilityContext } from "../app/observability";
import type { RequireTenantRole, ResolveDatabase } from "../app/route-deps";
import { recordBadgeRuleApprovalSubmissionSideEffects } from "../badges/badge-rule-approval-submission-side-effects";
import {
  apiSubmitBadgeRuleVersionStatusCode,
  submitBadgeRuleVersionForApprovalFailureMessage,
} from "../badges/badge-rule-approval-outcomes";
import {
  GradebookProviderResolutionError,
  resolveGradebookProviderWithConnection,
  type ResolvedGradebookProvider,
} from "../lms/gradebook-provider-resolution";
import { lmsLookupErrorMessage } from "../lms/gradebook-picker";
import { authorizeBadgeRuleCourses } from "../rules/badge-rule-course-authorization";
import { resolveBadgeIssuanceRuleDefinitionValueLists } from "../rules/badge-rule-definition-resolver";
import { validateBadgeRuleReferences } from "../rules/badge-rule-reference-validator";
import { extractBadgeIssuanceRuleRequirements } from "../rules/engine";

type BadgeRuleDraftRequest =
  | ReturnType<typeof parseCreateBadgeIssuanceRuleRequest>
  | ReturnType<typeof parseUpdateBadgeIssuanceRuleDraftRequest>;

interface PersistedBadgeRuleDraft {
  rule: BadgeIssuanceRuleRecord;
  version: BadgeIssuanceRuleVersionRecord;
}

type BadgeRuleAuthoringFailure = Exclude<
  BadgeIssuanceRuleAuthoringResult,
  { readonly status: "completed" }
>;

const badgeRuleAuthoringFailure = (
  result: BadgeRuleAuthoringFailure,
): {
  readonly error: string;
  readonly statusCode: 404 | 409 | 500;
} => {
  switch (result.status) {
    case "unavailable":
      return {
        error: "That unfinished draft is no longer available.",
        statusCode: 409,
      };
    case "replay_conflict":
      return {
        error: "This unfinished rule has already been promoted. Continue from the saved rule.",
        statusCode: 409,
      };
    case "not_found":
      return {
        error: "Badge rule not found",
        statusCode: 404,
      };
    case "not_editable":
      return {
        error: BADGE_ISSUANCE_RULE_BUILDER_EDIT_DENIED_MESSAGE,
        statusCode: 409,
      };
    case "not_submittable":
    case "self_certification_required":
    case "policy_missing_steps":
      return {
        error: submitBadgeRuleVersionForApprovalFailureMessage(result),
        statusCode: apiSubmitBadgeRuleVersionStatusCode(result),
      };
  }
};

type PrepareBadgeRuleDraftResult =
  | {
      status: "prepared";
      resolvedProvider: ResolvedGradebookProvider;
      ruleJson: string;
    }
  | {
      status: "error";
      statusCode: 403 | 409 | 422 | 502;
      error: string;
    };

const prepareBadgeRuleDraft = async (input: {
  db: SqlDatabase;
  tenantId: string;
  userId: string;
  request: BadgeRuleDraftRequest;
  missingLmsConnectionMessage: string;
}): Promise<PrepareBadgeRuleDraftResult> => {
  let resolvedDefinition: Parameters<typeof extractBadgeIssuanceRuleRequirements>[0];

  try {
    resolvedDefinition = await resolveBadgeIssuanceRuleDefinitionValueLists(
      input.db,
      input.tenantId,
      input.request.definition,
    );
  } catch (error) {
    return {
      status: "error",
      statusCode: 422,
      error: error instanceof Error ? error.message : "Failed to resolve rule value lists",
    };
  }

  let resolvedProvider: ResolvedGradebookProvider;

  try {
    resolvedProvider = await resolveGradebookProviderWithConnection({
      db: input.db,
      tenantId: input.tenantId,
      lmsConnectionId: input.request.lmsConnectionId,
      nowIso: new Date().toISOString(),
    });
  } catch (error) {
    if (
      error instanceof GradebookProviderResolutionError &&
      (error.reason === "missing_connection" || error.reason === "not_found")
    ) {
      return {
        status: "error",
        statusCode: 422,
        error: input.missingLmsConnectionMessage,
      };
    }

    return {
      status: "error",
      statusCode: 409,
      error: error instanceof Error ? error.message : "Unable to use LMS connection",
    };
  }

  try {
    const authorization = await authorizeBadgeRuleCourses({
      db: input.db,
      resolvedProvider,
      userId: input.userId,
      definition: resolvedDefinition,
    });

    if (authorization.status !== "authorized") {
      return {
        status: "error",
        statusCode: 403,
        error: authorization.error,
      };
    }
  } catch (error) {
    return {
      status: "error",
      statusCode: 502,
      error: lmsLookupErrorMessage(
        resolvedProvider.connection,
        error,
        "Unable to verify LMS course access",
      ),
    };
  }

  const referenceValidation = await validateBadgeRuleReferences({
    provider: resolvedProvider.provider,
    definition: resolvedDefinition,
  });

  if (referenceValidation.status === "gradebook_unavailable") {
    return {
      status: "error",
      statusCode: 502,
      error: lmsLookupErrorMessage(
        resolvedProvider.connection,
        referenceValidation.cause,
        `Unable to read the gradebook for course ${referenceValidation.courseId}`,
      ),
    };
  }

  if (referenceValidation.status === "assignment_missing") {
    return {
      status: "error",
      statusCode: 422,
      error: `Selected LMS connection does not include gradebook item ${referenceValidation.assignmentId} in course ${referenceValidation.courseId}`,
    };
  }

  return {
    status: "prepared",
    resolvedProvider,
    ruleJson: JSON.stringify(input.request.definition),
  };
};

const recordBadgeRuleDraftAudit = async (input: {
  c: AppContext;
  db: SqlDatabase;
  tenantId: string;
  session: SessionRecord;
  membershipRole: TenantMembershipRole;
  action: "badge_rule.created" | "badge_rule.draft_updated";
  draft: PersistedBadgeRuleDraft;
  resolvedProvider: ResolvedGradebookProvider;
}): Promise<void> => {
  try {
    await createAuditLog(input.db, {
      tenantId: input.tenantId,
      actorUserId: input.session.userId,
      action: input.action,
      targetType: "badge_rule",
      targetId: input.draft.rule.id,
      metadata: {
        role: input.membershipRole,
        versionId: input.draft.version.id,
        versionNumber: input.draft.version.versionNumber,
        status: input.draft.version.status,
        lmsConnectionId: input.resolvedProvider.connection.id,
        lmsProviderKind: input.resolvedProvider.connection.providerKind,
      },
    });
  } catch (cause: unknown) {
    logError(observabilityContext(input.c.env), "badge_rule_authoring_side_effect_failed", {
      tenantId: input.tenantId,
      ruleId: input.draft.rule.id,
      versionId: input.draft.version.id,
      sideEffect: "audit_log",
      authoringAction: input.action,
      errorKind: cause instanceof Error ? cause.name : typeof cause,
    });
  }
};

const recordAuthoredSubmissionSideEffects = async (input: {
  readonly c: AppContext;
  readonly db: SqlDatabase;
  readonly tenantId: string;
  readonly session: SessionRecord;
  readonly membershipRole: TenantMembershipRole;
  readonly authored: Extract<BadgeIssuanceRuleAuthoringResult, { readonly status: "completed" }>;
}): Promise<void> => {
  if (input.authored.outcome === "draft_saved") {
    return;
  }

  await recordBadgeRuleApprovalSubmissionSideEffects({
    c: input.c,
    db: input.db,
    tenantId: input.tenantId,
    ruleId: input.authored.rule.id,
    actorUserId: input.session.userId,
    actorRole: input.membershipRole,
    version: input.authored.version,
    pendingStepNumber: input.authored.pendingStepNumber,
    audit: input.authored.writeStatus === "replayed" ? "already_recorded" : "record",
  });
};

interface RegisterBadgeRuleCoreRoutesInput {
  app: Hono<AppEnv>;
  resolveDatabase: ResolveDatabase;
  requireTenantRole: RequireTenantRole;
  ISSUER_ROLES: readonly TenantMembershipRole[];
}

// Badge rule authoring APIs are issuer-capable for automation and non-admin
// authoring tools. The server-rendered admin builder remains owner/admin-only.
export const registerBadgeRuleCoreRoutes = (input: RegisterBadgeRuleCoreRoutesInput): void => {
  const { app, resolveDatabase, requireTenantRole, ISSUER_ROLES } = input;

  app.get("/v1/tenants/:tenantId/badge-rules", async (c) => {
    const pathParams = parseTenantPathParams(c.req.param());
    const roleCheck = await requireTenantRole(c, pathParams.tenantId, ISSUER_ROLES);

    if (roleCheck instanceof Response) {
      return roleCheck;
    }

    const db = resolveDatabase(c.env);
    const listInput = await resolveListBadgeIssuanceRulesInput(db, {
      tenantId: pathParams.tenantId,
      userId: roleCheck.session.userId,
      membershipRole: roleCheck.membershipRole,
    });
    const rules = await listBadgeIssuanceRules(db, listInput);

    return c.json({
      tenantId: pathParams.tenantId,
      rules,
    });
  });

  app.post("/v1/tenants/:tenantId/badge-rules", async (c) => {
    const tenantParams = parseTenantPathParams(c.req.param());
    let request;

    try {
      request = parseCreateBadgeIssuanceRuleRequest(await c.req.json<unknown>());
    } catch {
      return c.json(
        {
          error: "Invalid badge issuance rule payload",
        },
        400,
      );
    }

    const roleCheck = await requireTenantRole(c, tenantParams.tenantId, ISSUER_ROLES);

    if (roleCheck instanceof Response) {
      return roleCheck;
    }

    const { session, membershipRole } = roleCheck;
    const db = resolveDatabase(c.env);
    const prepared = await prepareBadgeRuleDraft({
      db,
      tenantId: tenantParams.tenantId,
      userId: session.userId,
      request,
      missingLmsConnectionMessage:
        "Select a connected LMS gradebook source before creating a rule.",
    });

    if (prepared.status === "error") {
      return c.json(
        {
          error: prepared.error,
        },
        prepared.statusCode,
      );
    }

    const authored = await createBadgeIssuanceRuleWithAction(db, {
      tenantId: tenantParams.tenantId,
      name: request.name,
      description: request.description,
      badgeTemplateId: request.badgeTemplateId,
      lmsProviderKind: prepared.resolvedProvider.connection.providerKind,
      lmsConnectionId: prepared.resolvedProvider.connection.id,
      ruleJson: prepared.ruleJson,
      changeSummary: request.changeSummary,
      action: request.action,
      actorUserId: session.userId,
      actorRole: membershipRole,
      ...(request.builderDraftId === undefined ? {} : { builderDraftId: request.builderDraftId }),
    });

    if (authored.status !== "completed") {
      const failure = badgeRuleAuthoringFailure(authored);
      return c.json(
        {
          error: failure.error,
        },
        failure.statusCode,
      );
    }

    if (authored.writeStatus === "created") {
      await recordBadgeRuleDraftAudit({
        c,
        db,
        tenantId: tenantParams.tenantId,
        session,
        membershipRole,
        action: "badge_rule.created",
        draft: authored,
        resolvedProvider: prepared.resolvedProvider,
      });
    }
    await recordAuthoredSubmissionSideEffects({
      c,
      db,
      tenantId: tenantParams.tenantId,
      session,
      membershipRole,
      authored,
    });
    const responseDefinition =
      authored.writeStatus === "replayed"
        ? parseBadgeIssuanceRuleDefinition(JSON.parse(authored.version.ruleJson))
        : request.definition;

    return c.json(
      {
        tenantId: tenantParams.tenantId,
        outcome: authored.outcome,
        rule: authored.rule,
        version: {
          ...authored.version,
          definition: responseDefinition,
        },
      },
      201,
    );
  });

  app.put("/v1/tenants/:tenantId/badge-rule-builder-drafts/:draftId", async (c) => {
    const pathParams = parseBadgeIssuanceRuleBuilderDraftPathParams(c.req.param());
    let request;

    try {
      request = parseSaveBadgeIssuanceRuleBuilderDraftRequest(await c.req.json<unknown>());
    } catch {
      return c.json({ error: "Invalid rule builder draft payload" }, 400);
    }

    const roleCheck = await requireTenantRole(c, pathParams.tenantId, ISSUER_ROLES);

    if (roleCheck instanceof Response) {
      return roleCheck;
    }

    const draftJson = serializeBadgeIssuanceRuleBuilderDraftPayload(request);
    const saved = await saveBadgeIssuanceRuleBuilderDraft(resolveDatabase(c.env), {
      id: pathParams.draftId,
      tenantId: pathParams.tenantId,
      userId: roleCheck.session.userId,
      target: request.target,
      currentStep: request.currentStep,
      draftJson,
    });

    c.header("Cache-Control", "no-store");

    if (saved.status === "unavailable") {
      return c.json({ error: "That rule builder draft identity is no longer available." }, 409);
    }

    return c.json({
      tenantId: pathParams.tenantId,
      draft: saved.draft,
    });
  });

  app.post("/v1/tenants/:tenantId/badge-rules/:ruleId/draft", async (c) => {
    const pathParams = parseBadgeIssuanceRulePathParams(c.req.param());
    let request;

    try {
      request = parseUpdateBadgeIssuanceRuleDraftRequest(await c.req.json<unknown>());
    } catch {
      return c.json(
        {
          error: "Invalid badge issuance rule draft payload",
        },
        400,
      );
    }

    const roleCheck = await requireTenantRole(c, pathParams.tenantId, ISSUER_ROLES);

    if (roleCheck instanceof Response) {
      return roleCheck;
    }

    const { session, membershipRole } = roleCheck;
    const db = resolveDatabase(c.env);
    const prepared = await prepareBadgeRuleDraft({
      db,
      tenantId: pathParams.tenantId,
      userId: session.userId,
      request,
      missingLmsConnectionMessage:
        "Select a connected LMS gradebook source before saving a rule draft.",
    });

    if (prepared.status === "error") {
      return c.json(
        {
          error: prepared.error,
        },
        prepared.statusCode,
      );
    }

    const description = request.description?.trim();
    const authored = await updateBadgeIssuanceRuleWithAction(db, {
      tenantId: pathParams.tenantId,
      ruleId: pathParams.ruleId,
      name: request.name,
      ...(description === undefined || description.length === 0 ? {} : { description }),
      badgeTemplateId: request.badgeTemplateId,
      lmsProviderKind: prepared.resolvedProvider.connection.providerKind,
      lmsConnectionId: prepared.resolvedProvider.connection.id,
      ruleJson: prepared.ruleJson,
      changeSummary: request.changeSummary,
      action: request.action,
      actorUserId: session.userId,
      actorRole: membershipRole,
    });

    if (authored.status !== "completed") {
      const failure = badgeRuleAuthoringFailure(authored);
      return c.json(
        {
          error: failure.error,
        },
        failure.statusCode,
      );
    }

    await recordBadgeRuleDraftAudit({
      c,
      db,
      tenantId: pathParams.tenantId,
      session,
      membershipRole,
      action: "badge_rule.draft_updated",
      draft: authored,
      resolvedProvider: prepared.resolvedProvider,
    });
    await recordAuthoredSubmissionSideEffects({
      c,
      db,
      tenantId: pathParams.tenantId,
      session,
      membershipRole,
      authored,
    });

    return c.json(
      {
        tenantId: pathParams.tenantId,
        outcome: authored.outcome,
        rule: authored.rule,
        version: {
          ...authored.version,
          definition: request.definition,
        },
      },
      200,
    );
  });

  app.get("/v1/tenants/:tenantId/badge-rules/:ruleId", async (c) => {
    const pathParams = parseBadgeIssuanceRulePathParams(c.req.param());
    const roleCheck = await requireTenantRole(c, pathParams.tenantId, ISSUER_ROLES);

    if (roleCheck instanceof Response) {
      return roleCheck;
    }

    const db = resolveDatabase(c.env);
    const rule = await findBadgeIssuanceRuleById(db, pathParams.tenantId, pathParams.ruleId);

    if (rule === null) {
      return c.json(
        {
          error: "Badge rule not found",
        },
        404,
      );
    }

    const versions = await listBadgeIssuanceRuleVersions(db, {
      tenantId: pathParams.tenantId,
      ruleId: pathParams.ruleId,
    });

    return c.json({
      tenantId: pathParams.tenantId,
      rule,
      versions,
    });
  });

  app.get("/v1/tenants/:tenantId/badge-rules/:ruleId/audit-log", async (c) => {
    const pathParams = parseBadgeIssuanceRulePathParams(c.req.param());
    let query;

    try {
      query = parseBadgeIssuanceRuleAuditLogQuery(c.req.query());
    } catch {
      return c.json(
        {
          error: "Invalid badge rule audit log query",
        },
        400,
      );
    }

    const roleCheck = await requireTenantRole(c, pathParams.tenantId, ISSUER_ROLES);

    if (roleCheck instanceof Response) {
      return roleCheck;
    }

    const db = resolveDatabase(c.env);
    const rule = await findBadgeIssuanceRuleById(db, pathParams.tenantId, pathParams.ruleId);

    if (rule === null) {
      return c.json(
        {
          error: "Badge rule not found",
        },
        404,
      );
    }

    const versions = await listBadgeIssuanceRuleVersions(db, {
      tenantId: pathParams.tenantId,
      ruleId: pathParams.ruleId,
    });
    const versionIds = new Set(versions.map((version) => version.id));
    const requestedLimit = query.limit ?? 100;
    const logs = await listAuditLogs(db, {
      tenantId: pathParams.tenantId,
      limit: Math.min(500, requestedLimit * 5),
    });
    const filteredLogs = logs
      .filter((log) => {
        if (log.targetType === "badge_rule") {
          return log.targetId === pathParams.ruleId;
        }

        if (log.targetType === "badge_rule_version") {
          return versionIds.has(log.targetId);
        }

        return false;
      })
      .slice(0, requestedLimit);

    return c.json({
      tenantId: pathParams.tenantId,
      ruleId: pathParams.ruleId,
      logs: filteredLogs,
    });
  });
};

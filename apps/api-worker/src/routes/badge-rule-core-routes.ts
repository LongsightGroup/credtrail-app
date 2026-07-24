import {
  BADGE_ISSUANCE_RULE_BUILDER_EDIT_DENIED_MESSAGE,
  createAuditLog,
  createBadgeIssuanceRule,
  createBadgeIssuanceRuleFromBuilderDraft,
  deleteBadgeIssuanceRuleBuilderDraftForRule,
  findBadgeIssuanceRuleById,
  listAuditLogs,
  listBadgeIssuanceRules,
  resolveListBadgeIssuanceRulesInput,
  listBadgeIssuanceRuleVersions,
  saveBadgeIssuanceRuleBuilderDraft,
  updateBadgeIssuanceRuleDraft,
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
import type { AppEnv } from "../app";
import type { RequireTenantRole, ResolveDatabase } from "../app/route-deps";
import {
  GradebookProviderResolutionError,
  resolveGradebookProviderWithConnection,
  type ResolvedGradebookProvider,
} from "../lms/gradebook-provider-resolution";
import { lmsLookupErrorMessage } from "../lms/gradebook-picker";
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

type PrepareBadgeRuleDraftResult =
  | {
      status: "prepared";
      resolvedProvider: ResolvedGradebookProvider;
      ruleJson: string;
    }
  | {
      status: "error";
      statusCode: 409 | 422 | 502;
      error: string;
    };

const prepareBadgeRuleDraft = async (input: {
  db: SqlDatabase;
  tenantId: string;
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
  db: SqlDatabase;
  tenantId: string;
  session: SessionRecord;
  membershipRole: TenantMembershipRole;
  action: "badge_rule.created" | "badge_rule.draft_updated";
  draft: PersistedBadgeRuleDraft;
  resolvedProvider: ResolvedGradebookProvider;
}): Promise<void> => {
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

    const createInput = {
      tenantId: tenantParams.tenantId,
      name: request.name,
      description: request.description,
      badgeTemplateId: request.badgeTemplateId,
      lmsProviderKind: prepared.resolvedProvider.connection.providerKind,
      lmsConnectionId: prepared.resolvedProvider.connection.id,
      ruleJson: prepared.ruleJson,
      changeSummary: request.changeSummary,
      createdByUserId: session.userId,
    };
    const creation =
      request.builderDraftId === undefined
        ? {
            status: "created" as const,
            draft: await createBadgeIssuanceRule(db, createInput),
          }
        : await createBadgeIssuanceRuleFromBuilderDraft(db, {
            ...createInput,
            builderDraftId: request.builderDraftId,
            builderUserId: session.userId,
          });

    if (creation.status === "unavailable") {
      return c.json({ error: "That unfinished draft is no longer available." }, 409);
    }

    if (creation.status === "created") {
      await recordBadgeRuleDraftAudit({
        db,
        tenantId: tenantParams.tenantId,
        session,
        membershipRole,
        action: "badge_rule.created",
        draft: creation.draft,
        resolvedProvider: prepared.resolvedProvider,
      });
    }
    const responseDefinition =
      creation.status === "replayed"
        ? parseBadgeIssuanceRuleDefinition(JSON.parse(creation.draft.version.ruleJson))
        : request.definition;

    return c.json(
      {
        tenantId: tenantParams.tenantId,
        rule: creation.draft.rule,
        version: {
          ...creation.draft.version,
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
    const updated = await updateBadgeIssuanceRuleDraft(db, {
      tenantId: pathParams.tenantId,
      ruleId: pathParams.ruleId,
      name: request.name,
      ...(description === undefined || description.length === 0 ? {} : { description }),
      badgeTemplateId: request.badgeTemplateId,
      lmsProviderKind: prepared.resolvedProvider.connection.providerKind,
      lmsConnectionId: prepared.resolvedProvider.connection.id,
      ruleJson: prepared.ruleJson,
      changeSummary: request.changeSummary,
      createdByUserId: session.userId,
    });

    if (updated.status === "not_found") {
      return c.json({ error: "Badge rule not found" }, 404);
    }

    if (updated.status === "not_editable") {
      return c.json({ error: BADGE_ISSUANCE_RULE_BUILDER_EDIT_DENIED_MESSAGE }, 409);
    }

    const persisted = {
      rule: updated.rule,
      version: updated.version,
    };
    await recordBadgeRuleDraftAudit({
      db,
      tenantId: pathParams.tenantId,
      session,
      membershipRole,
      action: "badge_rule.draft_updated",
      draft: persisted,
      resolvedProvider: prepared.resolvedProvider,
    });
    await deleteBadgeIssuanceRuleBuilderDraftForRule(db, {
      tenantId: pathParams.tenantId,
      userId: session.userId,
      ruleId: pathParams.ruleId,
    });

    return c.json(
      {
        tenantId: pathParams.tenantId,
        rule: persisted.rule,
        version: {
          ...persisted.version,
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

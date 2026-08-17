import {
  findBadgeIssuanceRuleById,
  listAuditLogs,
  listBadgeIssuanceRules,
  resolveListBadgeIssuanceRulesInput,
  listBadgeIssuanceRuleVersions,
  saveBadgeIssuanceRuleBuilderDraft,
  type SqlDatabase,
  type TenantMembershipRole,
} from "@credtrail/db";
import {
  badgeIssuanceRuleHasCompleteLmsLearnerPopulation,
  parseBadgeIssuanceRuleAuditLogQuery,
  parseBadgeIssuanceRuleBuilderDraftPathParams,
  parseBadgeIssuanceRulePathParams,
  parseCreateBadgeIssuanceRuleRequest,
  parseSaveBadgeIssuanceRuleBuilderDraftRequest,
  parseTenantPathParams,
  parseUpdateBadgeIssuanceRuleDraftRequest,
  resolveAutomatedBadgeRuleIssuanceTiming,
  serializeBadgeIssuanceRuleBuilderDraftPayload,
} from "@credtrail/validation";
import type { Hono } from "hono";
import type { AppEnv } from "../app/types";
import type { RequireTenantRole, ResolveDatabase } from "../app/route-deps";
import { badgeRuleAuthoringHttpFailure } from "../badges/badge-rule-authoring-http";
import {
  authorPreparedBadgeRule,
  findPreparedBadgeRuleReplay,
  type PreparedBadgeRuleAuthoringResult,
} from "../badges/badge-rule-authoring-service";
import {
  GradebookProviderResolutionError,
  resolveGradebookProviderWithConnection,
  type ResolvedGradebookProvider,
} from "../lms/gradebook-provider-resolution";
import { isGradebookProviderRequestCancelled } from "../lms/gradebook-provider-error";
import { gradebookRequestOptionsWithDeadline } from "../lms/gradebook-request-options";
import type { GradebookRequestOptions } from "../lms/gradebook-types";
import { lmsLookupErrorMessage } from "../lms/gradebook-picker";
import { authorizeBadgeRuleCourses } from "../rules/badge-rule-course-authorization";
import { resolveBadgeIssuanceRuleDefinitionValueLists } from "../rules/badge-rule-definition-resolver";
import { validateBadgeRuleReferences } from "../rules/badge-rule-reference-validator";
import { extractBadgeIssuanceRuleRequirements } from "../rules/engine";

type BadgeRuleDraftRequest =
  | ReturnType<typeof parseCreateBadgeIssuanceRuleRequest>
  | ReturnType<typeof parseUpdateBadgeIssuanceRuleDraftRequest>;

type PrepareBadgeRuleDraftResult =
  | {
      status: "prepared";
      resolvedProvider: ResolvedGradebookProvider;
      ruleJson: string;
    }
  | {
      status: "error";
      statusCode: 403 | 408 | 409 | 422 | 502;
      error: string;
    };

const prepareBadgeRuleDraft = async (
  input: {
    db: SqlDatabase;
    tenantId: string;
    userId: string;
    request: BadgeRuleDraftRequest;
    missingLmsConnectionMessage: string;
  },
  options: GradebookRequestOptions = {},
): Promise<PrepareBadgeRuleDraftResult> => {
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

  if (
    resolveAutomatedBadgeRuleIssuanceTiming(resolvedDefinition) !== null &&
    !badgeIssuanceRuleHasCompleteLmsLearnerPopulation(resolvedDefinition)
  ) {
    return {
      status: "error",
      statusCode: 422,
      error:
        "Automatic issuance requires an LMS course requirement that identifies every learner who could match. Add an LMS course requirement or choose Instructor confirmation.",
    };
  }

  let resolvedProvider: ResolvedGradebookProvider;

  try {
    resolvedProvider = await resolveGradebookProviderWithConnection(
      {
        db: input.db,
        tenantId: input.tenantId,
        lmsConnectionId: input.request.lmsConnectionId,
        nowIso: new Date().toISOString(),
      },
      options,
    );
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

    if (
      (error instanceof GradebookProviderResolutionError && error.reason === "cancelled") ||
      isGradebookProviderRequestCancelled(error, options)
    ) {
      return {
        status: "error",
        statusCode: 408,
        error: "LMS request was cancelled",
      };
    }

    return {
      status: "error",
      statusCode: 409,
      error: error instanceof Error ? error.message : "Unable to use LMS connection",
    };
  }

  try {
    const authorization = await authorizeBadgeRuleCourses(
      {
        db: input.db,
        resolvedProvider,
        userId: input.userId,
        definition: resolvedDefinition,
      },
      options,
    );

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
      statusCode: isGradebookProviderRequestCancelled(error, options) ? 408 : 502,
      error: isGradebookProviderRequestCancelled(error, options)
        ? "LMS request was cancelled"
        : lmsLookupErrorMessage(
            resolvedProvider.connection,
            error,
            "Unable to verify LMS course access",
          ),
    };
  }

  const referenceValidation = await validateBadgeRuleReferences(
    {
      provider: resolvedProvider.provider,
      definition: resolvedDefinition,
    },
    options,
  );

  if (referenceValidation.status === "gradebook_unavailable") {
    const requestCancelled = isGradebookProviderRequestCancelled(
      referenceValidation.cause,
      options,
    );

    return {
      status: "error",
      statusCode: requestCancelled ? 408 : 502,
      error: requestCancelled
        ? "LMS request was cancelled"
        : lmsLookupErrorMessage(
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
      userId: roleCheck.principal.userId,
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

    const { principal, membershipRole } = roleCheck;
    const db = resolveDatabase(c.env);
    let result: PreparedBadgeRuleAuthoringResult | null =
      request.builderDraftId === undefined
        ? null
        : await findPreparedBadgeRuleReplay({
            db,
            tenantId: tenantParams.tenantId,
            actorUserId: principal.userId,
            builderDraftId: request.builderDraftId,
          });

    if (result === null) {
      const prepared = await prepareBadgeRuleDraft(
        {
          db,
          tenantId: tenantParams.tenantId,
          userId: principal.userId,
          request,
          missingLmsConnectionMessage:
            "Select a connected LMS gradebook source before creating a rule.",
        },
        gradebookRequestOptionsWithDeadline({ signal: c.req.raw.signal }),
      );

      if (prepared.status === "error") {
        const replay =
          request.builderDraftId === undefined
            ? null
            : await findPreparedBadgeRuleReplay({
                db,
                tenantId: tenantParams.tenantId,
                actorUserId: principal.userId,
                builderDraftId: request.builderDraftId,
              });

        if (replay === null) {
          return c.json(
            {
              error: prepared.error,
            },
            prepared.statusCode,
          );
        }

        result = replay;
      } else {
        result = await authorPreparedBadgeRule({
          kind: "create",
          db,
          store: c.env.BADGE_OBJECTS,
          publicAppOrigin: c.env.PUBLIC_APP_ORIGIN,
          tenantId: tenantParams.tenantId,
          actorUserId: principal.userId,
          actorRole: membershipRole,
          lmsConnection: prepared.resolvedProvider.connection,
          ruleJson: prepared.ruleJson,
          request,
        });
      }
    }

    if (result.status === "failed") {
      const failure = badgeRuleAuthoringHttpFailure(result.reason);
      return c.json(
        {
          error: failure.error,
        },
        failure.statusCode,
      );
    }

    return c.json(
      {
        tenantId: tenantParams.tenantId,
        outcome: result.outcome,
        rule: result.rule,
        version: {
          ...result.version,
          definition: result.definition,
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
      userId: roleCheck.principal.userId,
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

    const { principal, membershipRole } = roleCheck;
    const db = resolveDatabase(c.env);
    const prepared = await prepareBadgeRuleDraft(
      {
        db,
        tenantId: pathParams.tenantId,
        userId: principal.userId,
        request,
        missingLmsConnectionMessage:
          "Select a connected LMS gradebook source before saving a rule draft.",
      },
      gradebookRequestOptionsWithDeadline({ signal: c.req.raw.signal }),
    );

    if (prepared.status === "error") {
      return c.json(
        {
          error: prepared.error,
        },
        prepared.statusCode,
      );
    }

    const result = await authorPreparedBadgeRule({
      kind: "update",
      db,
      store: c.env.BADGE_OBJECTS,
      publicAppOrigin: c.env.PUBLIC_APP_ORIGIN,
      tenantId: pathParams.tenantId,
      ruleId: pathParams.ruleId,
      actorUserId: principal.userId,
      actorRole: membershipRole,
      lmsConnection: prepared.resolvedProvider.connection,
      ruleJson: prepared.ruleJson,
      request,
    });

    if (result.status === "failed") {
      const failure = badgeRuleAuthoringHttpFailure(result.reason);
      return c.json(
        {
          error: failure.error,
        },
        failure.statusCode,
      );
    }

    return c.json(
      {
        tenantId: pathParams.tenantId,
        outcome: result.outcome,
        rule: result.rule,
        version: {
          ...result.version,
          definition: result.definition,
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

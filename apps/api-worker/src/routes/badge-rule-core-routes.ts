import {
  createAuditLog,
  createBadgeIssuanceRule,
  findBadgeIssuanceRuleById,
  listAuditLogs,
  listBadgeIssuanceRules,
  listBadgeIssuanceRuleVersions,
  updateBadgeIssuanceRuleDraft,
  type BadgeIssuanceRuleRecord,
  type BadgeIssuanceRuleVersionRecord,
  type SessionRecord,
  type SqlDatabase,
  type TenantMembershipRole,
} from "@credtrail/db";
import {
  parseBadgeIssuanceRuleAuditLogQuery,
  parseBadgeIssuanceRulePathParams,
  parseCreateBadgeIssuanceRuleRequest,
  parseTenantPathParams,
  parseUpdateBadgeIssuanceRuleDraftRequest,
} from "@credtrail/validation";
import type { Hono } from "hono";
import type { AppEnv } from "../app";
import type { RequireTenantRole, ResolveDatabase } from "../app/route-deps";
import {
  GradebookProviderResolutionError,
  resolveGradebookProviderWithConnection,
  type ResolvedGradebookProvider,
} from "../lms/gradebook-provider-resolution";
import type { GradebookProvider } from "../lms/gradebook-types";
import { resolveBadgeIssuanceRuleDefinitionValueLists } from "../rules/badge-rule-definition-resolver";
import { extractBadgeIssuanceRuleRequirements } from "../rules/engine";

class BadgeRuleLmsReferenceError extends Error {
  public readonly statusCode: 422 | 502;

  public constructor(message: string, statusCode: 422 | 502) {
    super(message);
    this.name = "BadgeRuleLmsReferenceError";
    this.statusCode = statusCode;
  }
}

const validateRuleReferencesAgainstConnection = async (input: {
  provider: GradebookProvider;
  definition: Parameters<typeof extractBadgeIssuanceRuleRequirements>[0];
}): Promise<void> => {
  const requirements = extractBadgeIssuanceRuleRequirements(input.definition);
  const requiredCourseIds = new Set(requirements.courseIds);

  if (requiredCourseIds.size === 0 && requirements.assignmentRefs.length === 0) {
    return;
  }

  let courses;

  try {
    courses = await input.provider.listCourses();
  } catch (error) {
    throw new BadgeRuleLmsReferenceError(
      error instanceof Error ? error.message : "Unable to list LMS courses",
      502,
    );
  }

  const availableCourseIds = new Set(courses.map((course) => course.courseId));
  const missingCourseIds = [...requiredCourseIds].filter(
    (courseId) => !availableCourseIds.has(courseId),
  );

  if (missingCourseIds.length > 0) {
    throw new BadgeRuleLmsReferenceError(
      `Selected LMS connection does not include course: ${missingCourseIds.join(", ")}`,
      422,
    );
  }

  const assignmentsByCourseId = new Map<string, Set<string>>();

  for (const assignmentRef of requirements.assignmentRefs) {
    let assignmentIds = assignmentsByCourseId.get(assignmentRef.courseId);

    if (assignmentIds === undefined) {
      try {
        const assignments = await input.provider.listAssignments({
          courseId: assignmentRef.courseId,
        });
        assignmentIds = new Set(assignments.map((assignment) => assignment.assignmentId));
        assignmentsByCourseId.set(assignmentRef.courseId, assignmentIds);
      } catch (error) {
        throw new BadgeRuleLmsReferenceError(
          error instanceof Error
            ? error.message
            : `Unable to list gradebook items for course ${assignmentRef.courseId}`,
          502,
        );
      }
    }

    if (!assignmentIds.has(assignmentRef.assignmentId)) {
      throw new BadgeRuleLmsReferenceError(
        `Selected LMS connection does not include gradebook item ${assignmentRef.assignmentId} in course ${assignmentRef.courseId}`,
        422,
      );
    }
  }
};

type BadgeRuleDraftRequest =
  | ReturnType<typeof parseCreateBadgeIssuanceRuleRequest>
  | ReturnType<typeof parseUpdateBadgeIssuanceRuleDraftRequest>;

interface PersistedBadgeRuleDraft {
  rule: BadgeIssuanceRuleRecord;
  version: BadgeIssuanceRuleVersionRecord;
}

type PersistBadgeRuleDraftPersistenceResult =
  | {
      status: "persisted";
      draft: PersistedBadgeRuleDraft;
    }
  | {
      status: "not_found" | "not_editable";
    };

type PersistBadgeRuleDraftResult =
  | {
      status: "ok";
      draft: PersistedBadgeRuleDraft;
      definition: BadgeRuleDraftRequest["definition"];
    }
  | {
      status: "error";
      statusCode: 404 | 409 | 422 | 502;
      error: string;
    };

const persistBadgeRuleDraft = async (input: {
  db: SqlDatabase;
  tenantId: string;
  request: BadgeRuleDraftRequest;
  session: SessionRecord;
  membershipRole: TenantMembershipRole;
  missingLmsConnectionMessage: string;
  auditAction: "badge_rule.created" | "badge_rule.draft_updated";
  persist: (resolved: {
    resolvedProvider: ResolvedGradebookProvider;
    ruleJson: string;
  }) => Promise<PersistBadgeRuleDraftPersistenceResult>;
}): Promise<PersistBadgeRuleDraftResult> => {
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
    await validateRuleReferencesAgainstConnection({
      provider: resolvedProvider.provider,
      definition: resolvedDefinition,
    });
  } catch (error) {
    if (error instanceof BadgeRuleLmsReferenceError) {
      return {
        status: "error",
        statusCode: error.statusCode,
        error: error.message,
      };
    }

    return {
      status: "error",
      statusCode: 502,
      error: "Failed to validate LMS references",
    };
  }

  const persisted = await input.persist({
    resolvedProvider,
    ruleJson: JSON.stringify(input.request.definition),
  });

  if (persisted.status !== "persisted") {
    if (persisted.status === "not_found") {
      return {
        status: "error",
        statusCode: 404,
        error: "Badge rule not found",
      };
    }

    return {
      status: "error",
      statusCode: 409,
      error: "Only never-active draft or rejected rules can be edited from the builder.",
    };
  }

  await createAuditLog(input.db, {
    tenantId: input.tenantId,
    actorUserId: input.session.userId,
    action: input.auditAction,
    targetType: "badge_rule",
    targetId: persisted.draft.rule.id,
    metadata: {
      role: input.membershipRole,
      versionId: persisted.draft.version.id,
      versionNumber: persisted.draft.version.versionNumber,
      status: persisted.draft.version.status,
      lmsConnectionId: resolvedProvider.connection.id,
      lmsProviderKind: resolvedProvider.connection.providerKind,
    },
  });

  return {
    status: "ok",
    draft: persisted.draft,
    definition: input.request.definition,
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

    const rules = await listBadgeIssuanceRules(resolveDatabase(c.env), {
      tenantId: pathParams.tenantId,
    });

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
    const persisted = await persistBadgeRuleDraft({
      db,
      tenantId: tenantParams.tenantId,
      request,
      session,
      membershipRole,
      missingLmsConnectionMessage:
        "Select a connected LMS gradebook source before creating a rule.",
      auditAction: "badge_rule.created",
      persist: async ({ resolvedProvider, ruleJson }) => {
        const draft = await createBadgeIssuanceRule(db, {
          tenantId: tenantParams.tenantId,
          name: request.name,
          description: request.description,
          badgeTemplateId: request.badgeTemplateId,
          lmsProviderKind: resolvedProvider.connection.providerKind,
          lmsConnectionId: resolvedProvider.connection.id,
          ruleJson,
          approvalChain: request.approvalChain,
          changeSummary: request.changeSummary,
          createdByUserId: session.userId,
        });

        return {
          status: "persisted",
          draft,
        };
      },
    });

    if (persisted.status === "error") {
      return c.json(
        {
          error: persisted.error,
        },
        persisted.statusCode,
      );
    }

    return c.json(
      {
        tenantId: tenantParams.tenantId,
        rule: persisted.draft.rule,
        version: {
          ...persisted.draft.version,
          definition: persisted.definition,
        },
      },
      201,
    );
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
    const persisted = await persistBadgeRuleDraft({
      db,
      tenantId: pathParams.tenantId,
      request,
      session,
      membershipRole,
      missingLmsConnectionMessage:
        "Select a connected LMS gradebook source before saving a rule draft.",
      auditAction: "badge_rule.draft_updated",
      persist: async ({ resolvedProvider, ruleJson }) => {
        const description = request.description?.trim();
        const updated = await updateBadgeIssuanceRuleDraft(db, {
          tenantId: pathParams.tenantId,
          ruleId: pathParams.ruleId,
          name: request.name,
          ...(description === undefined || description.length === 0 ? {} : { description }),
          badgeTemplateId: request.badgeTemplateId,
          lmsProviderKind: resolvedProvider.connection.providerKind,
          lmsConnectionId: resolvedProvider.connection.id,
          ruleJson,
          approvalChain: request.approvalChain,
          changeSummary: request.changeSummary,
          createdByUserId: session.userId,
        });

        if (updated.status !== "updated") {
          return updated;
        }

        return {
          status: "persisted",
          draft: {
            rule: updated.rule,
            version: updated.version,
          },
        };
      },
    });

    if (persisted.status === "error") {
      return c.json(
        {
          error: persisted.error,
        },
        persisted.statusCode,
      );
    }

    return c.json(
      {
        tenantId: pathParams.tenantId,
        rule: persisted.draft.rule,
        version: {
          ...persisted.draft.version,
          definition: persisted.definition,
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

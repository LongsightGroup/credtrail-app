import {
  createAuditLog,
  createBadgeIssuanceRule,
  findBadgeIssuanceRuleById,
  listAuditLogs,
  listBadgeIssuanceRules,
  listBadgeIssuanceRuleVersions,
  type SessionRecord,
  type SqlDatabase,
  type TenantMembershipRole,
} from "@credtrail/db";
import {
  parseBadgeIssuanceRuleAuditLogQuery,
  parseBadgeIssuanceRulePathParams,
  parseCreateBadgeIssuanceRuleRequest,
  parseTenantPathParams,
} from "@credtrail/validation";
import type { Hono } from "hono";
import type { AppBindings, AppContext, AppEnv } from "../app";
import type { GradebookProvider } from "../lms/gradebook-types";
import { extractBadgeIssuanceRuleRequirements } from "../rules/engine";
import { resolveBadgeIssuanceRuleDefinitionValueLists } from "./badge-rule-definition-resolver";
import {
  GradebookProviderResolutionError,
  resolveGradebookProviderWithConnection,
  type ResolvedGradebookProvider,
} from "./tenant-lms-connection-helpers";

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

interface RegisterBadgeRuleCoreRoutesInput {
  app: Hono<AppEnv>;
  resolveDatabase: (bindings: AppBindings) => SqlDatabase;
  requireTenantRole: (
    c: AppContext,
    tenantId: string,
    allowedRoles: readonly TenantMembershipRole[],
  ) => Promise<
    | {
        session: SessionRecord;
        membershipRole: TenantMembershipRole;
      }
    | Response
  >;
  ISSUER_ROLES: readonly TenantMembershipRole[];
}

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

    let resolvedDefinition;

    try {
      resolvedDefinition = await resolveBadgeIssuanceRuleDefinitionValueLists(
        db,
        tenantParams.tenantId,
        request.definition,
      );
    } catch (error) {
      return c.json(
        {
          error: error instanceof Error ? error.message : "Failed to resolve rule value lists",
        },
        422,
      );
    }

    let resolvedProvider: ResolvedGradebookProvider;

    try {
      resolvedProvider = await resolveGradebookProviderWithConnection({
        db,
        tenantId: tenantParams.tenantId,
        lmsConnectionId: request.lmsConnectionId,
        nowIso: new Date().toISOString(),
      });
    } catch (error) {
      if (
        error instanceof GradebookProviderResolutionError &&
        (error.reason === "missing_connection" || error.reason === "not_found")
      ) {
        return c.json(
          {
            error: "Select a connected LMS gradebook source before creating a rule.",
          },
          422,
        );
      }

      return c.json(
        {
          error: error instanceof Error ? error.message : "Unable to use LMS connection",
        },
        409,
      );
    }

    try {
      await validateRuleReferencesAgainstConnection({
        provider: resolvedProvider.provider,
        definition: resolvedDefinition,
      });
    } catch (error) {
      if (error instanceof BadgeRuleLmsReferenceError) {
        return c.json({ error: error.message }, error.statusCode);
      }

      return c.json(
        {
          error: "Failed to validate LMS references",
        },
        502,
      );
    }

    const definitionJson = JSON.stringify(request.definition);
    const created = await createBadgeIssuanceRule(db, {
      tenantId: tenantParams.tenantId,
      name: request.name,
      description: request.description,
      badgeTemplateId: request.badgeTemplateId,
      lmsProviderKind: resolvedProvider.connection.providerKind,
      lmsConnectionId: resolvedProvider.connection.id,
      ruleJson: definitionJson,
      approvalChain: request.approvalChain,
      changeSummary: request.changeSummary,
      createdByUserId: session.userId,
    });

    await createAuditLog(db, {
      tenantId: tenantParams.tenantId,
      actorUserId: session.userId,
      action: "badge_rule.created",
      targetType: "badge_rule",
      targetId: created.rule.id,
      metadata: {
        role: membershipRole,
        versionId: created.version.id,
        versionNumber: created.version.versionNumber,
        status: created.version.status,
        lmsConnectionId: resolvedProvider.connection.id,
        lmsProviderKind: resolvedProvider.connection.providerKind,
      },
    });

    return c.json(
      {
        tenantId: tenantParams.tenantId,
        rule: created.rule,
        version: {
          ...created.version,
          definition: request.definition,
        },
      },
      201,
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

import {
  createAuditLog,
  findTenantLmsConnectionById,
  listTenantLmsConnections,
  upsertTenantLmsConnection,
  type SqlDatabase,
  type TenantMembershipRole,
} from "@credtrail/db";
import {
  parseTenantLmsConnectionCoursePathParams,
  parseTenantLmsConnectionCourseSearchQuery,
  parseTenantLmsConnectionGradebookItemPathParams,
  parseTenantLmsConnectionPathParams,
  parseTenantPathParams,
  parseUpsertTenantLmsConnectionRequest,
} from "@credtrail/validation";
import type { Hono } from "hono";
import type { AppEnv } from "../app";
import type { RequireTenantRole, ResolveDatabase } from "../app/route-deps";
import { jsonError } from "../http/json-responses";
import {
  listGradebookItemsForCourse,
  listWorkflowStatesForAssignment,
  lmsLookupErrorMessage,
} from "../lms/gradebook-picker";
import {
  GradebookProviderResolutionError,
  publicTenantLmsConnection,
  resolveGradebookProviderWithConnection,
  type ResolvedGradebookProvider,
} from "../lms/gradebook-provider-resolution";
import { authorizeLmsUserCourses, resolveLmsCourseAccessScope } from "../lms/user-course-access";

interface RegisterTenantLmsConnectionRoutesInput {
  app: Hono<AppEnv>;
  resolveDatabase: ResolveDatabase;
  requireTenantRole: RequireTenantRole;
  ISSUER_ROLES: readonly TenantMembershipRole[];
  ADMIN_ROLES: readonly TenantMembershipRole[];
}

/** Admin LMS pickers load results into HTML selects; keep HTTP payloads bounded. */
const LMS_PICKER_MAX_COURSES = 100;
const LMS_PICKER_MAX_LEARNERS = 100;

const resolvedProviderForTenantConnection = async (input: {
  db: SqlDatabase;
  tenantId: string;
  connectionId: string;
}): Promise<ResolvedGradebookProvider | Response> => {
  try {
    return await resolveGradebookProviderWithConnection({
      db: input.db,
      tenantId: input.tenantId,
      lmsConnectionId: input.connectionId,
      nowIso: new Date().toISOString(),
    });
  } catch (error) {
    const status =
      error instanceof GradebookProviderResolutionError && error.reason === "not_found" ? 404 : 409;

    return Response.json(
      {
        error: error instanceof Error ? error.message : "Unable to use LMS connection",
      },
      { status },
    );
  }
};

const authorizeCourseForUser = async (input: {
  db: SqlDatabase;
  resolved: ResolvedGradebookProvider;
  userId: string;
  courseId: string;
}): Promise<Response | null> => {
  try {
    const authorization = await authorizeLmsUserCourses({
      db: input.db,
      connection: input.resolved.connection,
      provider: input.resolved.provider,
      userId: input.userId,
      courseIds: [input.courseId],
    });

    if (authorization.status === "authorized") {
      return null;
    }

    return Response.json({ error: authorization.error }, { status: 403 });
  } catch (error) {
    return Response.json(
      {
        error: lmsLookupErrorMessage(
          input.resolved.connection,
          error,
          "Unable to verify LMS course access",
        ),
      },
      { status: 502 },
    );
  }
};

export const registerTenantLmsConnectionRoutes = (
  input: RegisterTenantLmsConnectionRoutesInput,
): void => {
  const { app, resolveDatabase, requireTenantRole, ISSUER_ROLES, ADMIN_ROLES } = input;

  app.get("/v1/tenants/:tenantId/lms/connections", async (c) => {
    const pathParams = parseTenantPathParams(c.req.param());
    const roleCheck = await requireTenantRole(c, pathParams.tenantId, ISSUER_ROLES);

    if (roleCheck instanceof Response) {
      return roleCheck;
    }

    const connections = await listTenantLmsConnections(resolveDatabase(c.env), pathParams.tenantId);

    c.header("Cache-Control", "no-store");
    return c.json({
      tenantId: pathParams.tenantId,
      connections: connections.map((connection) => publicTenantLmsConnection(connection)),
    });
  });

  app.post("/v1/tenants/:tenantId/lms/connections", async (c) => {
    const pathParams = parseTenantPathParams(c.req.param());
    let request;

    try {
      request = parseUpsertTenantLmsConnectionRequest(await c.req.json<unknown>());
    } catch {
      return jsonError(c, 400, "Invalid LMS connection payload");
    }

    const roleCheck = await requireTenantRole(c, pathParams.tenantId, ADMIN_ROLES);

    if (roleCheck instanceof Response) {
      return roleCheck;
    }

    const { principal, membershipRole } = roleCheck;
    const db = resolveDatabase(c.env);
    const connection = await upsertTenantLmsConnection(db, {
      tenantId: pathParams.tenantId,
      ...request,
    });

    await createAuditLog(db, {
      tenantId: pathParams.tenantId,
      actorUserId: principal.userId,
      action: "tenant.lms_connection.created",
      targetType: "tenant_lms_connection",
      targetId: connection.id,
      metadata: {
        role: membershipRole,
        providerKind: connection.providerKind,
      },
    });

    c.header("Cache-Control", "no-store");
    return c.json(
      {
        tenantId: pathParams.tenantId,
        connection: publicTenantLmsConnection(connection),
      },
      201,
    );
  });

  app.put("/v1/tenants/:tenantId/lms/connections/:connectionId", async (c) => {
    const pathParams = parseTenantLmsConnectionPathParams(c.req.param());
    let request;

    try {
      request = parseUpsertTenantLmsConnectionRequest(await c.req.json<unknown>());
    } catch {
      return jsonError(c, 400, "Invalid LMS connection payload");
    }

    const roleCheck = await requireTenantRole(c, pathParams.tenantId, ADMIN_ROLES);

    if (roleCheck instanceof Response) {
      return roleCheck;
    }

    const db = resolveDatabase(c.env);
    const existing = await findTenantLmsConnectionById(db, pathParams);

    if (existing === null) {
      return jsonError(c, 404, "LMS connection not found");
    }

    const { principal, membershipRole } = roleCheck;
    const connection = await upsertTenantLmsConnection(db, {
      id: existing.id,
      tenantId: pathParams.tenantId,
      ...request,
    });

    await createAuditLog(db, {
      tenantId: pathParams.tenantId,
      actorUserId: principal.userId,
      action: "tenant.lms_connection.updated",
      targetType: "tenant_lms_connection",
      targetId: connection.id,
      metadata: {
        role: membershipRole,
        providerKind: connection.providerKind,
      },
    });

    c.header("Cache-Control", "no-store");
    return c.json({
      tenantId: pathParams.tenantId,
      connection: publicTenantLmsConnection(connection),
    });
  });

  app.get("/v1/tenants/:tenantId/lms/connections/:connectionId/courses", async (c) => {
    const pathParams = parseTenantLmsConnectionPathParams(c.req.param());
    const query = parseTenantLmsConnectionCourseSearchQuery(c.req.query());
    c.header("Cache-Control", "no-store");
    const roleCheck = await requireTenantRole(c, pathParams.tenantId, ISSUER_ROLES);

    if (roleCheck instanceof Response) {
      return roleCheck;
    }

    const db = resolveDatabase(c.env);
    const resolved = await resolvedProviderForTenantConnection({
      db,
      tenantId: pathParams.tenantId,
      connectionId: pathParams.connectionId,
    });

    if (resolved instanceof Response) {
      return resolved;
    }

    const scope = await resolveLmsCourseAccessScope({
      db,
      connection: resolved.connection,
      userId: roleCheck.principal.userId,
    });

    if (scope.status === "identity_unlinked") {
      return c.json({ error: scope.error }, 403);
    }

    try {
      const result = await resolved.provider.listCourses({
        accessScope: scope.accessScope,
        limit: LMS_PICKER_MAX_COURSES,
        ...(query.q === undefined ? {} : { searchTerm: query.q }),
      });

      return c.json({
        tenantId: pathParams.tenantId,
        connectionId: pathParams.connectionId,
        courses: result.courses,
        hasMore: result.hasMore,
      });
    } catch (error) {
      return c.json(
        {
          error: lmsLookupErrorMessage(resolved.connection, error, "Unable to search LMS courses"),
        },
        502,
      );
    }
  });

  app.get(
    "/v1/tenants/:tenantId/lms/connections/:connectionId/courses/:courseId/learners",
    async (c) => {
      const pathParams = parseTenantLmsConnectionCoursePathParams(c.req.param());
      const query = parseTenantLmsConnectionCourseSearchQuery(c.req.query());
      const roleCheck = await requireTenantRole(c, pathParams.tenantId, ISSUER_ROLES);

      if (roleCheck instanceof Response) {
        return roleCheck;
      }

      const db = resolveDatabase(c.env);
      const resolved = await resolvedProviderForTenantConnection({
        db,
        tenantId: pathParams.tenantId,
        connectionId: pathParams.connectionId,
      });

      if (resolved instanceof Response) {
        return resolved;
      }

      const courseAuthorization = await authorizeCourseForUser({
        db,
        resolved,
        userId: roleCheck.principal.userId,
        courseId: pathParams.courseId,
      });

      if (courseAuthorization !== null) {
        return courseAuthorization;
      }

      try {
        const matchingLearners = await resolved.provider.listLearners({
          courseId: pathParams.courseId,
          ...(query.q === undefined ? {} : { searchTerm: query.q }),
        });
        const learners = matchingLearners.slice(0, LMS_PICKER_MAX_LEARNERS);

        c.header("Cache-Control", "no-store");
        return c.json({
          tenantId: pathParams.tenantId,
          connectionId: pathParams.connectionId,
          courseId: pathParams.courseId,
          learners,
          hasMore: matchingLearners.length > LMS_PICKER_MAX_LEARNERS,
        });
      } catch (error) {
        return c.json(
          {
            error: lmsLookupErrorMessage(
              resolved.connection,
              error,
              "Unable to search LMS learners",
            ),
          },
          502,
        );
      }
    },
  );

  app.get(
    "/v1/tenants/:tenantId/lms/connections/:connectionId/courses/:courseId/gradebook-items",
    async (c) => {
      const pathParams = parseTenantLmsConnectionCoursePathParams(c.req.param());
      const query = parseTenantLmsConnectionCourseSearchQuery(c.req.query());
      const roleCheck = await requireTenantRole(c, pathParams.tenantId, ISSUER_ROLES);

      if (roleCheck instanceof Response) {
        return roleCheck;
      }

      const db = resolveDatabase(c.env);
      const resolved = await resolvedProviderForTenantConnection({
        db,
        tenantId: pathParams.tenantId,
        connectionId: pathParams.connectionId,
      });

      if (resolved instanceof Response) {
        return resolved;
      }

      const courseAuthorization = await authorizeCourseForUser({
        db,
        resolved,
        userId: roleCheck.principal.userId,
        courseId: pathParams.courseId,
      });

      if (courseAuthorization !== null) {
        return courseAuthorization;
      }

      try {
        const items = await listGradebookItemsForCourse({
          provider: resolved.provider,
          courseId: pathParams.courseId,
          query: query.q,
        });

        return c.json({
          tenantId: pathParams.tenantId,
          connectionId: pathParams.connectionId,
          courseId: pathParams.courseId,
          items,
        });
      } catch (error) {
        return c.json(
          {
            error: lmsLookupErrorMessage(
              resolved.connection,
              error,
              "Unable to list gradebook items",
            ),
          },
          502,
        );
      }
    },
  );

  app.get(
    "/v1/tenants/:tenantId/lms/connections/:connectionId/courses/:courseId/gradebook-items/:assignmentId/workflow-states",
    async (c) => {
      const pathParams = parseTenantLmsConnectionGradebookItemPathParams(c.req.param());
      const roleCheck = await requireTenantRole(c, pathParams.tenantId, ISSUER_ROLES);

      if (roleCheck instanceof Response) {
        return roleCheck;
      }

      const db = resolveDatabase(c.env);
      const resolved = await resolvedProviderForTenantConnection({
        db,
        tenantId: pathParams.tenantId,
        connectionId: pathParams.connectionId,
      });

      if (resolved instanceof Response) {
        return resolved;
      }

      const courseAuthorization = await authorizeCourseForUser({
        db,
        resolved,
        userId: roleCheck.principal.userId,
        courseId: pathParams.courseId,
      });

      if (courseAuthorization !== null) {
        return courseAuthorization;
      }

      try {
        const states = await listWorkflowStatesForAssignment({
          provider: resolved.provider,
          connection: resolved.connection,
          courseId: pathParams.courseId,
          assignmentId: pathParams.assignmentId,
        });

        return c.json({
          tenantId: pathParams.tenantId,
          connectionId: pathParams.connectionId,
          courseId: pathParams.courseId,
          assignmentId: pathParams.assignmentId,
          states,
        });
      } catch (error) {
        return c.json(
          {
            error: lmsLookupErrorMessage(
              resolved.connection,
              error,
              "Unable to list workflow state options",
            ),
          },
          502,
        );
      }
    },
  );
};

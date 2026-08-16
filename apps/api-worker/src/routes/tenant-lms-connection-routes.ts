import {
  createAuditLog,
  findTenantLmsConnectionById,
  listTenantLmsConnections,
  upsertTenantLmsConnection,
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
import { publicTenantLmsConnection } from "../lms/gradebook-provider-resolution";
import type {
  LmsCourseAuthoringFailure,
  LmsCourseAuthoringService,
} from "../lms/lms-course-authoring-service";

interface RegisterTenantLmsConnectionRoutesInput {
  app: Hono<AppEnv>;
  resolveDatabase: ResolveDatabase;
  requireTenantRole: RequireTenantRole;
  lmsCourseAuthoring: LmsCourseAuthoringService;
  ISSUER_ROLES: readonly TenantMembershipRole[];
  ADMIN_ROLES: readonly TenantMembershipRole[];
}

/** Admin LMS pickers load results into HTML selects; keep HTTP payloads bounded. */
const LMS_PICKER_MAX_COURSES = 100;
const LMS_PICKER_MAX_LEARNERS = 100;

const lmsCourseAuthoringFailureStatus = (
  failure: LmsCourseAuthoringFailure,
): 403 | 404 | 408 | 409 | 502 | 503 => {
  switch (failure.status) {
    case "connection_not_found":
      return 404;
    case "connection_unusable":
      return 409;
    case "dependency_unavailable":
      return 503;
    case "identity_unlinked":
    case "course_unauthorized":
      return 403;
    case "request_cancelled":
      return 408;
    case "provider_unavailable":
      return 502;
  }
};

const lmsCourseAuthoringFailureResponse = (failure: LmsCourseAuthoringFailure): Response => {
  return Response.json(
    { error: failure.error },
    {
      status: lmsCourseAuthoringFailureStatus(failure),
      headers: { "Cache-Control": "no-store" },
    },
  );
};

export const registerTenantLmsConnectionRoutes = (
  input: RegisterTenantLmsConnectionRoutesInput,
): void => {
  const { app, resolveDatabase, requireTenantRole, lmsCourseAuthoring, ISSUER_ROLES, ADMIN_ROLES } =
    input;

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
    const result = await lmsCourseAuthoring.searchCourses(
      {
        db,
        tenantId: pathParams.tenantId,
        connectionId: pathParams.connectionId,
        userId: roleCheck.principal.userId,
        limit: LMS_PICKER_MAX_COURSES,
        ...(query.q === undefined ? {} : { searchTerm: query.q }),
      },
      { signal: c.req.raw.signal },
    );

    if (result.status !== "resolved") {
      return lmsCourseAuthoringFailureResponse(result);
    }

    return c.json({
      tenantId: pathParams.tenantId,
      connectionId: pathParams.connectionId,
      courses: result.courses,
      hasMore: result.hasMore,
    });
  });

  app.get(
    "/v1/tenants/:tenantId/lms/connections/:connectionId/courses/:courseId/learners",
    async (c) => {
      const pathParams = parseTenantLmsConnectionCoursePathParams(c.req.param());
      const query = parseTenantLmsConnectionCourseSearchQuery(c.req.query());
      c.header("Cache-Control", "no-store");
      const roleCheck = await requireTenantRole(c, pathParams.tenantId, ISSUER_ROLES);

      if (roleCheck instanceof Response) {
        return roleCheck;
      }

      const db = resolveDatabase(c.env);
      const result = await lmsCourseAuthoring.searchLearners(
        {
          db,
          tenantId: pathParams.tenantId,
          connectionId: pathParams.connectionId,
          userId: roleCheck.principal.userId,
          courseId: pathParams.courseId,
          limit: LMS_PICKER_MAX_LEARNERS,
          ...(query.q === undefined ? {} : { searchTerm: query.q }),
        },
        { signal: c.req.raw.signal },
      );

      if (result.status !== "resolved") {
        return lmsCourseAuthoringFailureResponse(result);
      }

      return c.json({
        tenantId: pathParams.tenantId,
        connectionId: pathParams.connectionId,
        courseId: pathParams.courseId,
        learners: result.learners,
        hasMore: result.hasMore,
      });
    },
  );

  app.get(
    "/v1/tenants/:tenantId/lms/connections/:connectionId/courses/:courseId/gradebook-items",
    async (c) => {
      const pathParams = parseTenantLmsConnectionCoursePathParams(c.req.param());
      const query = parseTenantLmsConnectionCourseSearchQuery(c.req.query());
      c.header("Cache-Control", "no-store");
      const roleCheck = await requireTenantRole(c, pathParams.tenantId, ISSUER_ROLES);

      if (roleCheck instanceof Response) {
        return roleCheck;
      }

      const db = resolveDatabase(c.env);
      const result = await lmsCourseAuthoring.listGradebookItems(
        {
          db,
          tenantId: pathParams.tenantId,
          connectionId: pathParams.connectionId,
          userId: roleCheck.principal.userId,
          courseId: pathParams.courseId,
          ...(query.q === undefined ? {} : { searchTerm: query.q }),
        },
        { signal: c.req.raw.signal },
      );

      if (result.status !== "resolved") {
        return lmsCourseAuthoringFailureResponse(result);
      }

      return c.json({
        tenantId: pathParams.tenantId,
        connectionId: pathParams.connectionId,
        courseId: pathParams.courseId,
        items: result.items,
      });
    },
  );

  app.get(
    "/v1/tenants/:tenantId/lms/connections/:connectionId/courses/:courseId/gradebook-items/:assignmentId/workflow-states",
    async (c) => {
      const pathParams = parseTenantLmsConnectionGradebookItemPathParams(c.req.param());
      c.header("Cache-Control", "no-store");
      const roleCheck = await requireTenantRole(c, pathParams.tenantId, ISSUER_ROLES);

      if (roleCheck instanceof Response) {
        return roleCheck;
      }

      const db = resolveDatabase(c.env);
      const result = await lmsCourseAuthoring.listWorkflowStates(
        {
          db,
          tenantId: pathParams.tenantId,
          connectionId: pathParams.connectionId,
          userId: roleCheck.principal.userId,
          courseId: pathParams.courseId,
          assignmentId: pathParams.assignmentId,
        },
        { signal: c.req.raw.signal },
      );

      if (result.status !== "resolved") {
        return lmsCourseAuthoringFailureResponse(result);
      }

      return c.json({
        tenantId: pathParams.tenantId,
        connectionId: pathParams.connectionId,
        courseId: pathParams.courseId,
        assignmentId: pathParams.assignmentId,
        states: result.states,
      });
    },
  );
};

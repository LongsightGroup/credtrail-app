import {
  createAuditLog,
  findTenantLmsConnectionById,
  listTenantLmsConnections,
  upsertTenantLmsConnection,
  type SessionRecord,
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
import type { AppBindings, AppContext, AppEnv } from "../app";
import type { GradebookAssignmentRecord, GradebookSubmissionRecord } from "../lms/gradebook-types";
import {
  GradebookProviderResolutionError,
  publicTenantLmsConnection,
  type ResolvedGradebookProvider,
  resolveGradebookProviderWithConnection,
} from "./tenant-lms-connection-helpers";

interface RegisterTenantLmsConnectionRoutesInput {
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
  ADMIN_ROLES: readonly TenantMembershipRole[];
}

interface WorkflowStateOption {
  value: string;
  label: string;
  source: "default" | "observed";
  preselected: boolean;
}

const searchMatches = (query: string | undefined, values: readonly (string | null)[]): boolean => {
  if (query === undefined || query.trim().length === 0) {
    return true;
  }

  const normalizedQuery = query.trim().toLowerCase();
  return values.some((value) => value !== null && value.toLowerCase().includes(normalizedQuery));
};

const assignmentMatches = (
  query: string | undefined,
  assignment: GradebookAssignmentRecord,
): boolean => {
  return searchMatches(query, [
    assignment.assignmentId,
    assignment.courseId,
    assignment.title,
    assignment.workflowState,
  ]);
};

const workflowStateLabel = (value: string): string => {
  return value
    .split("_")
    .map((part) => (part.length === 0 ? part : part[0]?.toUpperCase() + part.slice(1)))
    .join(" ");
};

const defaultWorkflowStates = (
  providerKind: "canvas" | "sakai",
): readonly WorkflowStateOption[] => {
  if (providerKind === "canvas") {
    return [
      { value: "submitted", label: "Submitted", source: "default", preselected: true },
      { value: "unsubmitted", label: "Unsubmitted", source: "default", preselected: false },
      { value: "graded", label: "Graded", source: "default", preselected: true },
      { value: "pending_review", label: "Pending review", source: "default", preselected: false },
    ];
  }

  return [{ value: "graded", label: "Graded", source: "default", preselected: true }];
};

const mergeWorkflowStates = (input: {
  defaults: readonly WorkflowStateOption[];
  observedStates: Iterable<string>;
}): WorkflowStateOption[] => {
  const byValue = new Map<string, WorkflowStateOption>();

  for (const option of input.defaults) {
    byValue.set(option.value, option);
  }

  for (const observedState of input.observedStates) {
    const value = observedState.trim();

    if (value.length === 0 || byValue.has(value)) {
      continue;
    }

    byValue.set(value, {
      value,
      label: workflowStateLabel(value),
      source: "observed",
      preselected: false,
    });
  }

  return Array.from(byValue.values()).sort((left, right) => {
    if (left.source !== right.source) {
      return left.source === "default" ? -1 : 1;
    }

    return left.label.localeCompare(right.label);
  });
};

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

const lmsLookupErrorMessage = (
  connection: ResolvedGradebookProvider["connection"],
  error: unknown,
  fallback: string,
): string => {
  const rawMessage = error instanceof Error ? error.message : fallback;

  if (
    connection.providerKind === "sakai" &&
    rawMessage.includes("(403)") &&
    rawMessage.includes("/api/users/me/sites")
  ) {
    return "Sakai blocked CredTrail from reading your site list (403). Sign in to Sakai with an account that can view the target site and gradebook, copy a fresh SAKAIID session value, then update this LMS connection. If it still fails, ask a Sakai administrator to allow REST API access to Sites and Gradebook.";
  }

  return rawMessage;
};

const observedWorkflowStates = (submissions: readonly GradebookSubmissionRecord[]): Set<string> => {
  const states = new Set<string>();

  for (const submission of submissions) {
    if (submission.workflowState !== null && submission.workflowState.length > 0) {
      states.add(submission.workflowState);
    }
  }

  return states;
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
      return c.json({ error: "Invalid LMS connection payload" }, 400);
    }

    const roleCheck = await requireTenantRole(c, pathParams.tenantId, ADMIN_ROLES);

    if (roleCheck instanceof Response) {
      return roleCheck;
    }

    const { session, membershipRole } = roleCheck;
    const db = resolveDatabase(c.env);
    const connection = await upsertTenantLmsConnection(db, {
      tenantId: pathParams.tenantId,
      ...request,
    });

    await createAuditLog(db, {
      tenantId: pathParams.tenantId,
      actorUserId: session.userId,
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
      return c.json({ error: "Invalid LMS connection payload" }, 400);
    }

    const roleCheck = await requireTenantRole(c, pathParams.tenantId, ADMIN_ROLES);

    if (roleCheck instanceof Response) {
      return roleCheck;
    }

    const db = resolveDatabase(c.env);
    const existing = await findTenantLmsConnectionById(db, pathParams);

    if (existing === null) {
      return c.json({ error: "LMS connection not found" }, 404);
    }

    const { session, membershipRole } = roleCheck;
    const connection = await upsertTenantLmsConnection(db, {
      id: existing.id,
      tenantId: pathParams.tenantId,
      ...request,
    });

    await createAuditLog(db, {
      tenantId: pathParams.tenantId,
      actorUserId: session.userId,
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
    const roleCheck = await requireTenantRole(c, pathParams.tenantId, ISSUER_ROLES);

    if (roleCheck instanceof Response) {
      return roleCheck;
    }

    const resolved = await resolvedProviderForTenantConnection({
      db: resolveDatabase(c.env),
      tenantId: pathParams.tenantId,
      connectionId: pathParams.connectionId,
    });

    if (resolved instanceof Response) {
      return resolved;
    }

    try {
      const courses = (
        await (query.q === undefined
          ? resolved.provider.listCourses()
          : resolved.provider.listCourses({ searchTerm: query.q }))
      ).slice(0, 100);

      return c.json({
        tenantId: pathParams.tenantId,
        connectionId: pathParams.connectionId,
        courses,
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
    "/v1/tenants/:tenantId/lms/connections/:connectionId/courses/:courseId/gradebook-items",
    async (c) => {
      const pathParams = parseTenantLmsConnectionCoursePathParams(c.req.param());
      const query = parseTenantLmsConnectionCourseSearchQuery(c.req.query());
      const roleCheck = await requireTenantRole(c, pathParams.tenantId, ISSUER_ROLES);

      if (roleCheck instanceof Response) {
        return roleCheck;
      }

      const resolved = await resolvedProviderForTenantConnection({
        db: resolveDatabase(c.env),
        tenantId: pathParams.tenantId,
        connectionId: pathParams.connectionId,
      });

      if (resolved instanceof Response) {
        return resolved;
      }

      try {
        const items = (await resolved.provider.listAssignments({ courseId: pathParams.courseId }))
          .filter((assignment) => assignmentMatches(query.q, assignment))
          .slice(0, 200);

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

      const resolved = await resolvedProviderForTenantConnection({
        db: resolveDatabase(c.env),
        tenantId: pathParams.tenantId,
        connectionId: pathParams.connectionId,
      });

      if (resolved instanceof Response) {
        return resolved;
      }

      try {
        const submissions = await resolved.provider.listSubmissions({
          courseId: pathParams.courseId,
          assignmentId: pathParams.assignmentId,
        });
        const states = mergeWorkflowStates({
          defaults: defaultWorkflowStates(resolved.connection.providerKind),
          observedStates: observedWorkflowStates(submissions),
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

import {
  upsertTenantLmsConnection,
  type SqlDatabase,
  type TenantLmsConnectionRecord,
  type TenantMembershipRole,
} from "@credtrail/db";
import { Hono } from "hono";
import { afterEach, expect, it, vi } from "vitest";
import {
  cleanupTestResources,
  createTestPostgresDatabase,
  createTestTenantFixture,
  describeDbIntegration,
  type TestTenantFixture,
} from "../../../../packages/db/src/postgres-test-support";
import type { AppEnv } from "../app/types";
import type { RequireTenantRole } from "../app/route-deps";
import { createLmsCourseAuthoringService } from "../lms/lms-course-authoring-service";
import { registerTenantLmsConnectionRoutes } from "./tenant-lms-connection-routes";

const tenantIds: string[] = [];

afterEach(async () => {
  await cleanupTestResources(createTestPostgresDatabase(), { tenantIds });
  tenantIds.length = 0;
});

const createSakaiConnection = async (
  fixture: TestTenantFixture,
): Promise<TenantLmsConnectionRecord> => {
  const connection = await upsertTenantLmsConnection(fixture.db, {
    tenantId: fixture.tenantId,
    displayName: "Institution Sakai",
    providerKind: "sakai",
    apiBaseUrl: "https://sakai.example.edu",
    accessToken: "SAKAIID=session",
  });
  return connection;
};

const createRouteApp = (input: {
  readonly db: SqlDatabase;
  readonly tenantId: string;
  readonly fetchImpl: typeof fetch;
  readonly membershipRole?: TenantMembershipRole;
}): Hono<AppEnv> => {
  const app = new Hono<AppEnv>();
  const membershipRole = input.membershipRole ?? "admin";
  const requireTenantRole: RequireTenantRole = (_context, tenantId, allowedRoles) => {
    if (tenantId !== input.tenantId || !allowedRoles.includes(membershipRole)) {
      return Promise.resolve(Response.json({ error: "Forbidden" }, { status: 403 }));
    }

    return Promise.resolve({
      principal: {
        userId: "usr_route_integration",
        authSessionId: "auth_session_route_integration",
        authMethod: "better_auth",
        expiresAt: "2026-08-16T10:00:00.000Z",
      },
      requestedTenant: { tenantId },
      membershipRole,
    });
  };

  registerTenantLmsConnectionRoutes({
    app,
    resolveDatabase: () => input.db,
    requireTenantRole,
    lmsCourseAuthoring: createLmsCourseAuthoringService({
      currentTimestamp: () => "2026-08-16T09:00:00.000Z",
      fetchImpl: input.fetchImpl,
      requestTimeoutMs: 15_000,
    }),
    ISSUER_ROLES: ["owner", "admin", "issuer"],
    ADMIN_ROLES: ["owner", "admin"],
  });

  return app;
};

const createSakaiPickerFetch = (requests: Request[]): typeof fetch => {
  return async (requestInput, requestInit) => {
    const request = new Request(requestInput, requestInit);
    const url = new URL(request.url);
    requests.push(request);

    if (url.pathname === "/direct/site.json") {
      return Response.json({
        site_collection: url.searchParams.has("_start")
          ? []
          : [
              {
                id: "course-101",
                title: "Course 101",
                shortDescription: "CS101",
                type: "course",
                published: true,
              },
            ],
      });
    }

    if (url.pathname === "/direct/site/course-101.json") {
      return Response.json({
        id: "course-101",
        title: "Course 101",
        shortDescription: "CS101",
        type: "course",
        published: true,
      });
    }

    if (url.pathname === "/api/sites/course-101/grading/full-gradebook") {
      return Response.json({
        siteId: "course-101",
        columns: [
          {
            id: "assignment-1",
            name: "Final project",
            points: 100,
            released: true,
          },
          {
            id: "assignment-2",
            name: "Weekly quiz",
            points: 10,
            released: true,
          },
        ],
        students: [
          {
            userEid: "ada",
            grades: {
              "assignment-1": {
                grade: "95",
                gradeReleased: true,
                dateRecorded: "2026-08-15T09:00:00.000Z",
                excused: false,
              },
            },
          },
          {
            userEid: "grace",
            grades: {},
          },
        ],
      });
    }

    if (url.pathname === "/direct/membership/site/course-101.json") {
      return Response.json({
        membership_collection: [
          {
            userEid: "ada",
            userDisplayName: "Ada Lovelace",
            userEmail: "ada@example.edu",
          },
          {
            userEid: "grace",
            userDisplayName: "Grace Hopper",
            userEmail: "grace@example.edu",
          },
        ],
      });
    }

    throw new Error(`Unexpected Sakai request: ${url.pathname}${url.search}`);
  };
};

describeDbIntegration("tenant LMS connection routes", () => {
  it("serves picker workflows from saved Postgres state through the Sakai transport", async () => {
    const fixture = await createTestTenantFixture({ displayName: "Route LMS Picker" });
    tenantIds.push(fixture.tenantId);
    const connection = await createSakaiConnection(fixture);
    const requests: Request[] = [];
    const app = createRouteApp({
      db: fixture.db,
      tenantId: fixture.tenantId,
      fetchImpl: createSakaiPickerFetch(requests),
    });
    const routeBase = `/v1/tenants/${fixture.tenantId}/lms/connections/${connection.id}`;

    const coursesResponse = await app.request(`${routeBase}/courses?q=course`);
    const coursesBody = await coursesResponse.json<{
      courses: Array<{ courseId: string; title: string }>;
      hasMore: boolean;
    }>();
    const learnersResponse = await app.request(`${routeBase}/courses/course-101/learners?q=ada`);
    const learnersBody = await learnersResponse.json<{
      learners: Array<{ learnerId: string; displayName: string; email: string | null }>;
      hasMore: boolean;
    }>();
    const itemsResponse = await app.request(
      `${routeBase}/courses/course-101/gradebook-items?q=final`,
    );
    const itemsBody = await itemsResponse.json<{
      items: Array<{ assignmentId: string; title: string }>;
    }>();
    const statesResponse = await app.request(
      `${routeBase}/courses/course-101/gradebook-items/assignment-1/workflow-states`,
    );
    const statesBody = await statesResponse.json<{
      states: Array<{ value: string; preselected: boolean }>;
    }>();

    expect(coursesResponse.status).toBe(200);
    expect(coursesBody).toMatchObject({
      courses: [expect.objectContaining({ courseId: "course-101", title: "Course 101" })],
      hasMore: false,
    });
    expect(learnersResponse.status).toBe(200);
    expect(learnersBody).toMatchObject({
      learners: [
        {
          courseId: "course-101",
          learnerId: "ada",
          displayName: "Ada Lovelace",
          email: "ada@example.edu",
        },
      ],
      hasMore: false,
    });
    expect(itemsResponse.status).toBe(200);
    expect(itemsBody.items).toEqual([
      expect.objectContaining({ assignmentId: "assignment-1", title: "Final project" }),
    ]);
    expect(statesResponse.status).toBe(200);
    expect(statesBody.states).toContainEqual(
      expect.objectContaining({ value: "graded", preselected: true }),
    );
    expect(
      [coursesResponse, learnersResponse, itemsResponse, statesResponse].every(
        (response) => response.headers.get("cache-control") === "no-store",
      ),
    ).toBe(true);
    expect(requests.every((request) => request.headers.get("cookie") === "SAKAIID=session")).toBe(
      true,
    );
    expect(
      requests.some((request) => new URL(request.url).searchParams.get("search") === "course"),
    ).toBe(true);
  });

  it("bounds course picker responses at the route contract", async () => {
    const fixture = await createTestTenantFixture({ displayName: "Bounded LMS Picker" });
    tenantIds.push(fixture.tenantId);
    const connection = await createSakaiConnection(fixture);
    const fetchImpl: typeof fetch = async () => {
      return Response.json({
        site_collection: Array.from({ length: 101 }, (_, index) => ({
          id: `course-${String(index).padStart(3, "0")}`,
          title: `Course ${String(index).padStart(3, "0")}`,
          type: "course",
        })),
      });
    };
    const app = createRouteApp({
      db: fixture.db,
      tenantId: fixture.tenantId,
      fetchImpl,
    });

    const response = await app.request(
      `/v1/tenants/${fixture.tenantId}/lms/connections/${connection.id}/courses`,
    );
    const body = await response.json<{ courses: Array<{ courseId: string }>; hasMore: boolean }>();

    expect(response.status).toBe(200);
    expect(body.courses).toHaveLength(100);
    expect(body.courses.at(-1)?.courseId).toBe("course-099");
    expect(body.hasMore).toBe(true);
  });

  it("returns actionable Sakai guidance from a real provider failure", async () => {
    const fixture = await createTestTenantFixture({ displayName: "Blocked LMS Picker" });
    tenantIds.push(fixture.tenantId);
    const connection = await createSakaiConnection(fixture);
    const fetchImpl: typeof fetch = async () => {
      return Response.json({ message: "Forbidden" }, { status: 403 });
    };
    const app = createRouteApp({
      db: fixture.db,
      tenantId: fixture.tenantId,
      fetchImpl,
    });

    const response = await app.request(
      `/v1/tenants/${fixture.tenantId}/lms/connections/${connection.id}/courses?q=cs`,
    );
    const body = await response.json<{ error: string }>();

    expect(response.status).toBe(502);
    expect(response.headers.get("cache-control")).toBe("no-store");
    expect(body.error).toContain("Sakai blocked CredTrail from searching courses (403).");
    expect(body.error).toContain("Save a Sakai administrator username and password");
  });

  it("rejects roles outside the issuer boundary before reading LMS state", async () => {
    const fixture = await createTestTenantFixture({ displayName: "Forbidden LMS Picker" });
    tenantIds.push(fixture.tenantId);
    const fetchImpl = vi.fn<typeof fetch>();
    const app = createRouteApp({
      db: fixture.db,
      tenantId: fixture.tenantId,
      fetchImpl,
      membershipRole: "approver",
    });

    const response = await app.request(
      `/v1/tenants/${fixture.tenantId}/lms/connections/not-read/courses`,
    );

    expect(response.status).toBe(403);
    expect(fetchImpl).not.toHaveBeenCalled();
  });
});

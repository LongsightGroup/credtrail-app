import { upsertTenantLmsConnection } from "@credtrail/db";
import { afterEach, expect, it } from "vitest";
import {
  cleanupTestResources,
  createTestPostgresDatabase,
  createTestTenantFixture,
  describeDbIntegration,
} from "../../../../packages/db/src/postgres-test-support";
import { createLmsCourseAuthoringService } from "./lms-course-authoring-service";

const tenantIds: string[] = [];

afterEach(async () => {
  await cleanupTestResources(createTestPostgresDatabase(), { tenantIds });
  tenantIds.length = 0;
});

describeDbIntegration("LMS course authoring service", () => {
  it("resolves exact authorized courses in requested order", async () => {
    const fixture = await createTestTenantFixture({ displayName: "Exact LMS Courses" });
    tenantIds.push(fixture.tenantId);
    const connection = await upsertTenantLmsConnection(fixture.db, {
      tenantId: fixture.tenantId,
      displayName: "Institution Sakai",
      providerKind: "sakai",
      apiBaseUrl: "https://sakai.example.edu",
      accessToken: "SAKAIID=session",
    });
    const requestedPaths: string[] = [];
    const fetchImpl: typeof fetch = async (requestInput, requestInit) => {
      const request = new Request(requestInput, requestInit);
      const url = new URL(request.url);
      requestedPaths.push(url.pathname);
      const courseId = url.pathname.match(/^\/direct\/site\/(?<courseId>[^/]+)\.json$/)?.groups
        ?.courseId;

      if (courseId === undefined) {
        throw new Error(`Unexpected Sakai request: ${url.pathname}${url.search}`);
      }

      return Response.json({
        id: courseId,
        title: courseId === "course-202" ? "Course 202" : "Course 101",
        shortDescription: courseId === "course-202" ? "CS202" : "CS101",
        type: "course",
        published: true,
      });
    };
    const service = createLmsCourseAuthoringService({
      currentTimestamp: () => "2026-08-16T09:00:00.000Z",
      fetchImpl,
      requestTimeoutMs: 15_000,
    });

    await expect(
      service.resolveCourses({
        db: fixture.db,
        tenantId: fixture.tenantId,
        connectionId: connection.id,
        userId: "user-with-provider-access",
        courseIds: ["course-202", "course-101"],
      }),
    ).resolves.toEqual({
      status: "resolved",
      courses: [
        {
          courseId: "course-202",
          title: "Course 202",
          courseCode: "CS202",
          workflowState: "published",
          startsAt: null,
          endsAt: null,
        },
        {
          courseId: "course-101",
          title: "Course 101",
          courseCode: "CS101",
          workflowState: "published",
          startsAt: null,
          endsAt: null,
        },
      ],
    });
    expect(requestedPaths).toEqual([
      "/direct/site/course-202.json",
      "/direct/site/course-101.json",
    ]);
  });

  it("returns typed cancellation when the provider deadline expires", async () => {
    const fixture = await createTestTenantFixture({ displayName: "LMS Request Deadline" });
    tenantIds.push(fixture.tenantId);
    const connection = await upsertTenantLmsConnection(fixture.db, {
      tenantId: fixture.tenantId,
      displayName: "Institution Sakai",
      providerKind: "sakai",
      apiBaseUrl: "https://sakai.example.edu",
      accessToken: "SAKAIID=session",
    });
    const fetchImpl: typeof fetch = async (_input, init) => {
      const signal = init?.signal;

      if (signal === undefined || signal === null) {
        throw new Error("Expected the LMS deadline signal to reach fetch");
      }

      return new Promise<Response>((_resolve, reject) => {
        signal.addEventListener("abort", () => reject(signal.reason), { once: true });
      });
    };
    const service = createLmsCourseAuthoringService({
      currentTimestamp: () => "2026-08-16T09:00:00.000Z",
      fetchImpl,
      requestTimeoutMs: 10,
    });

    await expect(
      service.searchCourses({
        db: fixture.db,
        tenantId: fixture.tenantId,
        connectionId: connection.id,
        userId: "user-without-sakai-identity",
        limit: 100,
      }),
    ).resolves.toEqual({
      status: "request_cancelled",
      error: "LMS request was cancelled",
    });
  });

  it("stops before provider I/O when the caller has already cancelled", async () => {
    const fixture = await createTestTenantFixture({ displayName: "Cancelled LMS Request" });
    tenantIds.push(fixture.tenantId);
    const connection = await upsertTenantLmsConnection(fixture.db, {
      tenantId: fixture.tenantId,
      displayName: "Institution Sakai",
      providerKind: "sakai",
      apiBaseUrl: "https://sakai.example.edu",
      accessToken: "SAKAIID=session",
    });
    let providerRequestCount = 0;
    const fetchImpl: typeof fetch = () => {
      providerRequestCount += 1;
      return Promise.reject(new Error("Provider I/O must not run"));
    };
    const service = createLmsCourseAuthoringService({
      currentTimestamp: () => "2026-08-16T09:00:00.000Z",
      fetchImpl,
      requestTimeoutMs: 15_000,
    });
    const controller = new AbortController();
    controller.abort();

    await expect(
      service.resolveCourses(
        {
          db: fixture.db,
          tenantId: fixture.tenantId,
          connectionId: connection.id,
          userId: "user-without-sakai-identity",
          courseIds: ["course-101"],
        },
        { signal: controller.signal },
      ),
    ).resolves.toEqual({
      status: "request_cancelled",
      error: "LMS request was cancelled",
    });
    expect(providerRequestCount).toBe(0);
  });
});

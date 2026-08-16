import { upsertTenantLmsConnection } from "@credtrail/db";
import { afterEach, expect, it, vi } from "vitest";
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
    const fetchImpl = vi.fn<typeof fetch>();
    const service = createLmsCourseAuthoringService({
      currentTimestamp: () => "2026-08-16T09:00:00.000Z",
      fetchImpl,
      requestTimeoutMs: 15_000,
    });
    const controller = new AbortController();
    controller.abort();

    await expect(
      service.searchCourses(
        {
          db: fixture.db,
          tenantId: fixture.tenantId,
          connectionId: connection.id,
          userId: "user-without-sakai-identity",
          limit: 100,
        },
        { signal: controller.signal },
      ),
    ).resolves.toEqual({
      status: "request_cancelled",
      error: "LMS request was cancelled",
    });
    expect(fetchImpl).not.toHaveBeenCalled();
  });
});

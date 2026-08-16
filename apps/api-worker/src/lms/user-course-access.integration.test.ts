import { upsertTenantLmsConnection } from "@credtrail/db";
import { afterEach, expect, it } from "vitest";
import {
  cleanupTestResources,
  createTestPostgresDatabase,
  createTestTenantFixture,
  describeDbIntegration,
} from "../../../../packages/db/src/postgres-test-support";
import { resolveGradebookProviderWithConnection } from "./gradebook-provider-resolution";
import { resolveLmsCourseCatalog } from "./user-course-access";

const tenantIds: string[] = [];

afterEach(async () => {
  await cleanupTestResources(createTestPostgresDatabase(), { tenantIds });
  tenantIds.length = 0;
});

describeDbIntegration("LMS course authoring access", () => {
  it("lists administrator-visible Sakai courses without an LMS user identity", async () => {
    const fixture = await createTestTenantFixture({ displayName: "Sakai Course Access" });
    tenantIds.push(fixture.tenantId);
    const connection = await upsertTenantLmsConnection(fixture.db, {
      tenantId: fixture.tenantId,
      displayName: "Institution Sakai",
      providerKind: "sakai",
      apiBaseUrl: "https://sakai.example.edu",
      accessToken: "SAKAIID=session",
    });
    const requestedPaths: string[] = [];
    const fetchImpl: typeof fetch = async (requestInput) => {
      const request = new Request(requestInput);
      const url = new URL(request.url);
      requestedPaths.push(`${url.pathname}${url.search}`);

      return new Response(
        JSON.stringify({
          site_collection: url.searchParams.has("_start")
            ? []
            : [
                {
                  id: "course-101",
                  title: "Course 101",
                  shortDescription: "Institution course",
                  type: "course",
                },
              ],
        }),
        {
          status: 200,
          headers: { "content-type": "application/json" },
        },
      );
    };
    const resolvedProvider = await resolveGradebookProviderWithConnection({
      db: fixture.db,
      tenantId: fixture.tenantId,
      lmsConnectionId: connection.id,
      nowIso: "2026-08-16T09:00:00.000Z",
      fetchImpl,
    });

    const catalogResult = await resolveLmsCourseCatalog({
      db: fixture.db,
      resolvedProvider,
      userId: "user-without-sakai-identity",
    });

    expect(catalogResult.status).toBe("resolved");

    if (catalogResult.status !== "resolved") {
      throw new Error("Expected Sakai course catalog to resolve");
    }

    await expect(catalogResult.catalog.listCourses({ limit: 100 })).resolves.toEqual({
      courses: [
        {
          courseId: "course-101",
          title: "Course 101",
          courseCode: "Institution course",
          workflowState: null,
          startsAt: null,
          endsAt: null,
        },
      ],
      hasMore: false,
    });
    expect(requestedPaths).toEqual([
      "/direct/site.json?select=any&_limit=101",
      "/direct/site.json?select=any&_limit=101&_start=1",
    ]);
  });

  it("requires a linked provider identity before binding a Canvas course catalog", async () => {
    const fixture = await createTestTenantFixture({ displayName: "Canvas Course Access" });
    tenantIds.push(fixture.tenantId);
    const connection = await upsertTenantLmsConnection(fixture.db, {
      tenantId: fixture.tenantId,
      displayName: "Institution Canvas",
      providerKind: "canvas",
      apiBaseUrl: "https://canvas.example.edu",
      accessToken: "canvas-access-token",
    });
    const resolvedProvider = await resolveGradebookProviderWithConnection({
      db: fixture.db,
      tenantId: fixture.tenantId,
      lmsConnectionId: connection.id,
      nowIso: "2026-08-16T09:00:00.000Z",
    });

    await expect(
      resolveLmsCourseCatalog({
        db: fixture.db,
        resolvedProvider,
        userId: "user-without-canvas-identity",
      }),
    ).resolves.toEqual({
      status: "identity_unlinked",
      error: "Open CredTrail from Canvas once to link your account before choosing courses.",
    });
  });
});

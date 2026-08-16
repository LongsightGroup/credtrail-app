import { findTenantLmsConnectionById, upsertTenantLmsConnection } from "@credtrail/db";
import { afterEach, expect, it } from "vitest";
import {
  cleanupTestResources,
  createTestPostgresDatabase,
  createTestTenantFixture,
  describeDbIntegration,
} from "../../../../packages/db/src/postgres-test-support";
import { resolveGradebookProviderWithConnection } from "./gradebook-provider-resolution";

const tenantIds: string[] = [];

afterEach(async () => {
  await cleanupTestResources(createTestPostgresDatabase(), { tenantIds });
  tenantIds.length = 0;
});

describeDbIntegration("gradebook provider resolution", () => {
  it("uses the configured transport when refreshing an expired Canvas token", async () => {
    const fixture = await createTestTenantFixture({ displayName: "Canvas Token Refresh" });
    tenantIds.push(fixture.tenantId);
    const connection = await upsertTenantLmsConnection(fixture.db, {
      tenantId: fixture.tenantId,
      displayName: "Institution Canvas",
      providerKind: "canvas",
      apiBaseUrl: "https://canvas.example.edu",
      accessToken: "expired-access-token",
      accessTokenExpiresAt: "2026-08-16T08:00:00.000Z",
      refreshToken: "canvas-refresh-token",
      tokenEndpoint: "https://canvas.example.edu/login/oauth2/token",
      clientId: "canvas-client-id",
      clientSecret: "canvas-client-secret",
    });
    const requests: Request[] = [];
    const fetchImpl: typeof fetch = async (requestInput, requestInit) => {
      requests.push(new Request(requestInput, requestInit));
      return new Response(
        JSON.stringify({
          access_token: "refreshed-access-token",
          refresh_token: "rotated-refresh-token",
          expires_in: 3_600,
        }),
        {
          status: 200,
          headers: { "content-type": "application/json" },
        },
      );
    };

    const resolved = await resolveGradebookProviderWithConnection({
      db: fixture.db,
      tenantId: fixture.tenantId,
      lmsConnectionId: connection.id,
      nowIso: "2026-08-16T09:00:00.000Z",
      fetchImpl,
    });
    const refreshedConnection = await findTenantLmsConnectionById(fixture.db, {
      tenantId: fixture.tenantId,
      connectionId: connection.id,
    });

    expect(resolved.providerKind).toBe("canvas");
    expect(requests).toHaveLength(1);
    const refreshRequest = requests[0];

    if (refreshRequest === undefined) {
      throw new Error("Expected one Canvas token refresh request");
    }

    expect(refreshRequest.url).toBe("https://canvas.example.edu/login/oauth2/token");
    await expect(refreshRequest.text()).resolves.toContain("grant_type=refresh_token");
    expect(refreshedConnection).toMatchObject({
      accessToken: "refreshed-access-token",
      refreshToken: "rotated-refresh-token",
      accessTokenExpiresAt: "2026-08-16T10:00:00.000Z",
    });
  });
});

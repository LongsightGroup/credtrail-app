import type { SqlDatabase } from "@credtrail/db";
import { Hono } from "hono";
import { describe, expect, it } from "vitest";
import type { AppEnv } from "../app/types";
import type { RequireTenantRole } from "../app/route-deps";
import type { LoadBadgeRuleVersionReferenceLabels } from "../lms/badge-rule-version-reference-label-service";
import { registerBadgeRuleVersionReferenceRoutes } from "./badge-rule-version-reference-routes";

const requireTenantRole: RequireTenantRole = () =>
  Promise.resolve({
    principal: {
      userId: "usr_reviewer",
      authSessionId: "auth_session_123",
      authMethod: "better_auth",
      expiresAt: "2026-08-08T00:00:00.000Z",
    },
    requestedTenant: {
      tenantId: "tenant_123",
    },
    session: {
      id: "session_123",
      tenantId: "tenant_123",
      userId: "usr_reviewer",
      sessionTokenHash: "hash",
      expiresAt: "2026-08-08T00:00:00.000Z",
      lastSeenAt: "2026-08-07T00:00:00.000Z",
      revokedAt: null,
      createdAt: "2026-08-07T00:00:00.000Z",
    },
    membershipRole: "approver",
  });

const createApp = (loadReferenceLabels: LoadBadgeRuleVersionReferenceLabels): Hono<AppEnv> => {
  const app = new Hono<AppEnv>();
  registerBadgeRuleVersionReferenceRoutes({
    app,
    resolveDatabase: () => ({}) as SqlDatabase,
    requireTenantRole,
    APPROVAL_WORKSPACE_ROLES: ["owner", "admin", "approver"],
    loadReferenceLabels,
  });
  return app;
};

describe("badge rule version reference routes", () => {
  it("projects resolved labels with no-store caching", async () => {
    const inputs: Parameters<LoadBadgeRuleVersionReferenceLabels>[0][] = [];
    const app = createApp((serviceInput) => {
      inputs.push(serviceInput);
      return Promise.resolve({
        status: "resolved",
        labels: {
          courses: [{ courseId: "course_101", title: "Advanced TypeScript" }],
          assignments: [],
        },
      });
    });

    const response = await app.request(
      "/v1/tenants/tenant_123/badge-rules/brl_123/versions/brv_123/lms-reference-labels",
    );

    expect(response.status).toBe(200);
    expect(response.headers.get("cache-control")).toBe("no-store");
    expect(await response.json()).toEqual({
      tenantId: "tenant_123",
      ruleId: "brl_123",
      versionId: "brv_123",
      courses: [{ courseId: "course_101", title: "Advanced TypeScript" }],
      assignments: [],
    });
    expect(inputs).toHaveLength(1);
    expect(inputs[0]).toMatchObject({
      tenantId: "tenant_123",
      ruleId: "brl_123",
      versionId: "brv_123",
      actorUserId: "usr_reviewer",
      actorRole: "approver",
    });
  });

  it("maps typed service failures to HTTP responses", async () => {
    const app = createApp(() =>
      Promise.resolve({ status: "conflict", error: "Saved badge rule definition is invalid" }),
    );

    const response = await app.request(
      "/v1/tenants/tenant_123/badge-rules/brl_123/versions/brv_123/lms-reference-labels",
    );

    expect(response.status).toBe(409);
    expect(await response.json()).toEqual({ error: "Saved badge rule definition is invalid" });
  });
});

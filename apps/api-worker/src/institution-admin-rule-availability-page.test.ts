import {
  createDepartmentCourseOrgUnitHierarchy,
  createBadgeRuleIntegrationFixture,
  cleanupTestResources,
  createTestPostgresDatabase,
  describeDbIntegration,
} from "../../../packages/db/src/postgres-test-support";
import { createFixtureRule } from "../../../packages/db/src/badge-issuance-rule-test-fixtures";
import {
  findBadgeRulePlacementAvailability,
  findTenantById,
  listTenantLmsCourseContexts,
  type BadgeIssuanceRuleRecord,
  type BadgeIssuanceRuleVersionRecord,
  type BadgeRulePlacementAvailabilityRecord,
  type TenantLmsCourseContextRecord,
  type TenantOrgUnitRecord,
  type TenantRecord,
} from "@credtrail/db";
import { Hono } from "hono";
import { afterEach, describe, expect, it } from "vitest";
import {
  badgeRulePlacementAvailabilityPage,
  type BadgeRulePlacementAvailabilityPageInput,
} from "./admin/badge-rule-placement-availability-page";
import type { AppEnv } from "./app/types";
import type { LmsCourseAuthoringService } from "./lms/lms-course-authoring-service";
import { registerTenantBadgeRuleAvailabilityAdminRoutes } from "./routes/tenant-badge-rule-availability-admin-routes";
import { registerAppPageRenderer, renderAppPageToString } from "./ui/render-page";

const tenant: TenantRecord = {
  id: "tenant_123",
  slug: "tenant-123",
  displayName: "Example University",
  planTier: "institution",
  issuerDomain: "credentials.example.edu",
  didWeb: "did:web:credentials.example.edu",
  isActive: true,
  createdAt: "2026-09-02T12:00:00.000Z",
  updatedAt: "2026-09-02T12:00:00.000Z",
};

const rule: BadgeIssuanceRuleRecord = {
  id: "brl_123",
  tenantId: tenant.id,
  name: "Capstone completion",
  description: null,
  badgeTemplateId: "bt_123",
  orgUnitId: "ou_institution",
  ownerOrgUnitId: "ou_institution",
  lmsProviderKind: "canvas",
  lmsConnectionId: "lms_canvas",
  activeVersionId: "brv_active",
  createdByUserId: "usr_admin",
  createdAt: "2026-09-02T12:00:00.000Z",
  updatedAt: "2026-09-02T12:00:00.000Z",
};

const activeVersion: BadgeIssuanceRuleVersionRecord = {
  id: "brv_active",
  tenantId: tenant.id,
  ruleId: rule.id,
  versionNumber: 2,
  status: "active",
  ruleJson: '{"conditions":{"type":"course_completion","courseId":"course-101"}}',
  changeSummary: "Approved requirements",
  createdByUserId: "usr_admin",
  submittedByUserId: "usr_admin",
  submittedAt: "2026-09-02T12:00:00.000Z",
  approvedByUserId: "usr_owner",
  approvedAt: "2026-09-02T12:10:00.000Z",
  activatedByUserId: "usr_owner",
  activatedAt: "2026-09-02T12:15:00.000Z",
  effectiveStartsAt: null,
  expiresAt: null,
  expiredAt: null,
  suspendedAt: null,
  suspendedByUserId: null,
  suspensionReason: null,
  recertifiedAt: null,
  recertificationDueAt: null,
  expiryReminderSentAt: null,
  recertificationReminderSentAt: null,
  snapshot: {
    name: rule.name,
    description: null,
    badgeTemplateId: rule.badgeTemplateId,
    badgeTemplateTitle: "Capstone badge",
    badgeTemplateDescription: null,
    badgeTemplateCriteriaUri: null,
    badgeTemplateImageUri: null,
    badgeTemplateTrustedCredentialMetadataJson: null,
    orgUnitId: rule.orgUnitId,
    ownerOrgUnitId: rule.ownerOrgUnitId,
    lmsProviderKind: rule.lmsProviderKind,
    lmsConnectionId: rule.lmsConnectionId,
  },
  createdAt: "2026-09-02T12:00:00.000Z",
  updatedAt: "2026-09-02T12:15:00.000Z",
};

const institution: TenantOrgUnitRecord = {
  id: "ou_institution",
  tenantId: tenant.id,
  unitType: "institution",
  slug: "institution",
  displayName: "Example University",
  parentOrgUnitId: null,
  createdByUserId: null,
  isActive: true,
  createdAt: "2026-09-02T12:00:00.000Z",
  updatedAt: "2026-09-02T12:00:00.000Z",
};

const department: TenantOrgUnitRecord = {
  ...institution,
  id: "ou_biology",
  unitType: "department",
  slug: "biology",
  displayName: "Biology",
  parentOrgUnitId: institution.id,
};

const courseContext: TenantLmsCourseContextRecord = {
  id: "lctx_101",
  tenantId: tenant.id,
  lmsConnectionId: "lms_canvas",
  contextId: "course-101",
  displayName: "Biology & Society <Honors>",
  courseCode: "BIO 101",
  courseOrgUnitId: null,
  createdByUserId: "usr_admin",
  firstSeenAt: null,
  lastSeenAt: null,
  createdAt: "2026-09-02T12:00:00.000Z",
  updatedAt: "2026-09-02T12:00:00.000Z",
};

const selectedAvailability: BadgeRulePlacementAvailabilityRecord = {
  id: "brpa_123",
  tenantId: tenant.id,
  ruleId: rule.id,
  scope: "selected_courses",
  rootOrgUnitId: null,
  courseContextIds: [courseContext.id],
  createdByUserId: "usr_admin",
  updatedByUserId: "usr_admin",
  createdAt: "2026-09-02T12:00:00.000Z",
  updatedAt: "2026-09-02T12:00:00.000Z",
};

const pageInput = (
  overrides: Partial<BadgeRulePlacementAvailabilityPageInput> = {},
): BadgeRulePlacementAvailabilityPageInput => ({
  tenant,
  userId: "usr_admin",
  userEmail: "admin@example.edu",
  membershipRole: "admin",
  switchOrganizationPath: null,
  rule,
  activeVersion,
  activeReferenceInvalid: false,
  availability: null,
  selectedCourses: [],
  activeScopeRoots: [institution, department],
  activeMappingParents: [department],
  connections: [{ id: "lms_canvas", displayName: "Institution Canvas" }],
  defaultConnectionId: "lms_canvas",
  orgCoverageCount: 0,
  mappedCourseCount: 0,
  unmappedCourseCount: 1,
  catalogedCourseCount: 1,
  search: null,
  flash: null,
  ...overrides,
});

describe("badge rule placement availability page", () => {
  it("renders a calm, server-owned no-policy workflow without implementation labels", () => {
    const html = renderAppPageToString(badgeRulePlacementAvailabilityPage(pageInput()));

    expect(html).toContain("Current availability");
    expect(html).toContain("Not offered");
    expect(html).toContain("where faculty can add this rule");
    expect(html).toContain("who earns the badge");
    expect(html).toContain("Selected courses");
    expect(html).toContain("An organizational area");
    expect(html).toContain("Every course in this institution");
    expect(html).toContain("Update course availability");
    expect(html).toContain("Search courses");
    expect(html).toMatch(/institution-admin-rule-availability\.[a-f0-9]{10}\.css/);
    expect(html).not.toMatch(/scope_type|root_org_unit_id|course_context_id|context_id|Open form/);
  });

  it("renders selected courses, escaped LMS results, mapping, and row-owned removal", () => {
    const html = renderAppPageToString(
      badgeRulePlacementAvailabilityPage(
        pageInput({
          availability: selectedAvailability,
          selectedCourses: [{ context: courseContext, connectionName: "Institution Canvas" }],
          search: {
            connectionId: "lms_canvas",
            connectionName: "Institution Canvas",
            query: "Biology",
            courses: [
              {
                courseId: "course-101",
                title: "Biology & Society <Honors>",
                courseCode: "BIO 101",
                workflowState: "available",
                startsAt: null,
                endsAt: null,
              },
            ],
            hasMore: false,
            error: null,
          },
        }),
      ),
    );

    expect(html).toContain("1 selected course");
    expect(html).toContain("Biology &amp; Society &lt;Honors&gt;");
    expect(html).toContain("Add course");
    expect(html).toContain("Map LMS course");
    expect(html).toContain(
      'aria-label="Remove Biology &amp; Society &lt;Honors&gt; from selected courses"',
    );
    expect(html).toContain("Stop offering in courses");
    expect(html).not.toContain("https://canvas.example.test");
  });

  it("summarizes broad scopes and blocks changes for inactive or corrupt active state", () => {
    const orgHtml = renderAppPageToString(
      badgeRulePlacementAvailabilityPage(
        pageInput({
          availability: {
            ...selectedAvailability,
            scope: "org_unit_subtree",
            rootOrgUnitId: department.id,
            courseContextIds: [],
          },
          orgCoverageCount: 3,
        }),
      ),
    );
    const tenantHtml = renderAppPageToString(
      badgeRulePlacementAvailabilityPage(
        pageInput({
          availability: {
            ...selectedAvailability,
            scope: "tenant",
            rootOrgUnitId: null,
            courseContextIds: [],
          },
          catalogedCourseCount: 12,
        }),
      ),
    );
    const inactiveHtml = renderAppPageToString(
      badgeRulePlacementAvailabilityPage(pageInput({ activeVersion: null })),
    );
    const corruptHtml = renderAppPageToString(
      badgeRulePlacementAvailabilityPage(
        pageInput({ activeVersion: null, activeReferenceInvalid: true }),
      ),
    );

    expect(orgHtml).toContain("Organizational area: Biology");
    expect(orgHtml).toContain("3 mapped courses");
    expect(tenantHtml).toContain("Every course in this institution");
    expect(tenantHtml).toContain("12 courses");
    expect(inactiveHtml).toContain("Activate a valid rule version");
    expect(inactiveHtml).toContain("disabled");
    expect(corruptHtml).toContain("saved active version could not be found");
  });
});

const routeTenantIds: string[] = [];

afterEach(async () => {
  if (routeTenantIds.length === 0) {
    return;
  }

  await cleanupTestResources(createTestPostgresDatabase(), { tenantIds: routeTenantIds });
  routeTenantIds.length = 0;
});

const activateRule = async (
  fixture: Awaited<ReturnType<typeof createBadgeRuleIntegrationFixture>>,
) => {
  const created = await createFixtureRule(fixture);
  await fixture.db
    .prepare(
      `
      UPDATE badge_issuance_rule_versions
      SET status = 'active',
          effective_starts_at = NULL,
          expires_at = NULL
      WHERE tenant_id = ?
        AND rule_id = ?
        AND id = ?
    `,
    )
    .bind(fixture.tenantId, created.rule.id, created.version.id)
    .run();
  await fixture.db
    .prepare(
      `
      UPDATE badge_issuance_rules
      SET active_version_id = ?
      WHERE tenant_id = ?
        AND id = ?
    `,
    )
    .bind(created.version.id, fixture.tenantId, created.rule.id)
    .run();
  return { ...created, rule: { ...created.rule, activeVersionId: created.version.id } };
};

const courseService = (): LmsCourseAuthoringService => ({
  searchCourses: async (input) => ({
    status: "resolved",
    courses: ["course-101", "course-202"]
      .filter((courseId) =>
        input.searchTerm === undefined
          ? true
          : `${courseId} Biology Capstone`.toLowerCase().includes(input.searchTerm.toLowerCase()),
      )
      .map((courseId) => ({
        courseId,
        title: courseId === "course-101" ? "Biology 101" : "Biology Capstone",
        courseCode: courseId === "course-101" ? "BIO 101" : "BIO 202",
        workflowState: "available",
        startsAt: null,
        endsAt: null,
      })),
    hasMore: false,
  }),
  resolveCourses: async (input) => ({
    status: "resolved",
    courses: input.courseIds
      .filter((courseId) => courseId === "course-101" || courseId === "course-202")
      .map((courseId) => ({
        courseId,
        title: courseId === "course-101" ? "Biology 101" : "Biology Capstone",
        courseCode: courseId === "course-101" ? "BIO 101" : "BIO 202",
        workflowState: "available",
        startsAt: null,
        endsAt: null,
      })),
  }),
  searchLearners: async () => {
    throw new Error("Unused test service operation");
  },
  listGradebookItems: async () => {
    throw new Error("Unused test service operation");
  },
  resolveGradebookItems: async () => {
    throw new Error("Unused test service operation");
  },
  listWorkflowStates: async () => {
    throw new Error("Unused test service operation");
  },
  resolveReferenceLabels: async () => {
    throw new Error("Unused test service operation");
  },
});

const createRouteApp = async (input: {
  readonly fixture: Awaited<ReturnType<typeof createBadgeRuleIntegrationFixture>>;
  readonly membershipRole?: "owner" | "admin" | "issuer" | "viewer";
}) => {
  const app = new Hono<AppEnv>();
  const persistedTenant = await findTenantById(input.fixture.db, input.fixture.tenantId);

  if (persistedTenant === null) {
    throw new Error("Test tenant was not created");
  }

  registerAppPageRenderer(app);
  registerTenantBadgeRuleAvailabilityAdminRoutes({
    app,
    resolveDatabase: () => input.fixture.db,
    lmsCourseAuthoring: courseService(),
    resolveInstitutionAdminAdminRole: (_c, tenantId) => {
      const role = input.membershipRole ?? "admin";

      if (tenantId !== input.fixture.tenantId || (role !== "owner" && role !== "admin")) {
        return Promise.resolve(Response.json({ error: "Forbidden" }, { status: 403 }));
      }

      return Promise.resolve({
        principal: {
          userId: input.fixture.userId,
          authSessionId: "auth_session_test",
          authMethod: "better_auth" as const,
          expiresAt: "2026-09-03T12:00:00.000Z",
        },
        membershipRole: role,
      });
    },
    loadInstitutionAdminShellData: (_c, tenantId, userId, membershipRole) => {
      if (tenantId !== persistedTenant.id) {
        return Promise.resolve(Response.json({ error: "Tenant not found" }, { status: 404 }));
      }

      return Promise.resolve({
        tenant: persistedTenant,
        userId,
        userEmail: "availability-admin@example.edu",
        membershipRole,
        switchOrganizationPath: null,
      });
    },
  });

  return app;
};

const testEnv = {
  APP_ENV: "development",
  BETTER_AUTH_SECRET: "availability-route-test-secret",
} as AppEnv["Bindings"];

const postForm = (
  app: Hono<AppEnv>,
  path: string,
  fields: Record<string, string>,
): Promise<Response> => {
  return Promise.resolve(
    app.request(
      path,
      {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams(fields),
      },
      testEnv,
    ),
  );
};

describeDbIntegration("badge rule placement availability administrator routes", () => {
  it("supports selected, mapping, broad-scope, replay, and removal workflows", async () => {
    const fixture = await createBadgeRuleIntegrationFixture();
    routeTenantIds.push(fixture.tenantId);
    const created = await activateRule(fixture);
    const hierarchy = await createDepartmentCourseOrgUnitHierarchy(fixture.db, {
      tenantId: fixture.tenantId,
      userId: fixture.userId,
    });
    const app = await createRouteApp({ fixture });
    const path = `/tenants/${fixture.tenantId}/admin/rules/${created.rule.id}/availability`;

    const pageResponse = await app.request(
      `${path}?connectionId=${fixture.lmsConnectionId}&q=biology`,
      {},
      testEnv,
    );
    const pageBody = await pageResponse.text();

    expect(pageResponse.status).toBe(200);
    expect(pageBody).toContain("Biology 101");
    expect(pageBody).toContain("Add course");
    expect(pageBody).not.toContain("https://canvas.example.test");

    const addFirst = await postForm(app, `${path}/courses`, {
      connectionId: fixture.lmsConnectionId,
      courseId: "course-101",
    });
    const addReplay = await postForm(app, `${path}/courses`, {
      connectionId: fixture.lmsConnectionId,
      courseId: "course-101",
    });
    const addSecond = await postForm(app, `${path}/courses`, {
      connectionId: fixture.lmsConnectionId,
      courseId: "course-202",
    });

    expect(addFirst.status).toBe(303);
    expect(addReplay.status).toBe(303);
    expect(addSecond.status).toBe(303);
    expect(
      await findBadgeRulePlacementAvailability(fixture.db, {
        tenantId: fixture.tenantId,
        ruleId: created.rule.id,
      }),
    ).toMatchObject({ scope: "selected_courses", courseContextIds: expect.any(Array) });

    const contexts = await listTenantLmsCourseContexts(fixture.db, {
      tenantId: fixture.tenantId,
    });
    const firstContext = contexts.find((context) => context.contextId === "course-101");

    if (firstContext === undefined) {
      throw new Error("Expected the selected course context");
    }

    const removeFirst = await postForm(app, `${path}/courses/remove`, {
      courseContextId: firstContext.id,
    });
    expect(removeFirst.status).toBe(303);
    expect(
      await findBadgeRulePlacementAvailability(fixture.db, {
        tenantId: fixture.tenantId,
        ruleId: created.rule.id,
      }),
    ).toMatchObject({ scope: "selected_courses", courseContextIds: [expect.any(String)] });

    const selectedAfterRemoval = await findBadgeRulePlacementAvailability(fixture.db, {
      tenantId: fixture.tenantId,
      ruleId: created.rule.id,
    });

    if (selectedAfterRemoval?.scope !== "selected_courses") {
      throw new Error("Expected selected-course availability after removing one course");
    }

    const lastRemoval = await postForm(app, `${path}/courses/remove`, {
      courseContextId: selectedAfterRemoval.courseContextIds[0] ?? "missing",
    });
    expect(lastRemoval.status).toBe(303);
    expect(
      await findBadgeRulePlacementAvailability(fixture.db, {
        tenantId: fixture.tenantId,
        ruleId: created.rule.id,
      }),
    ).toMatchObject({ scope: "selected_courses", courseContextIds: [expect.any(String)] });

    const mapResponse = await postForm(app, `${path}/course-mappings`, {
      connectionId: fixture.lmsConnectionId,
      courseId: "course-101",
      parentOrgUnitId: hierarchy.department.id,
    });
    expect(mapResponse.status).toBe(303);
    const mappedContext = (
      await listTenantLmsCourseContexts(fixture.db, {
        tenantId: fixture.tenantId,
      })
    ).find((context) => context.contextId === "course-101");
    expect(mappedContext?.courseOrgUnitId).not.toBeNull();

    const orgResponse = await postForm(app, `${path}/update`, {
      scope: "org_unit_subtree",
      rootOrgUnitId: hierarchy.department.id,
      confirmImpact: "confirmed",
    });
    expect(orgResponse.status).toBe(303);
    expect(
      await findBadgeRulePlacementAvailability(fixture.db, {
        tenantId: fixture.tenantId,
        ruleId: created.rule.id,
      }),
    ).toMatchObject({ scope: "org_unit_subtree", rootOrgUnitId: hierarchy.department.id });

    const tenantResponse = await postForm(app, `${path}/update`, {
      scope: "tenant",
      confirmImpact: "confirmed",
    });
    expect(tenantResponse.status).toBe(303);
    expect(
      await findBadgeRulePlacementAvailability(fixture.db, {
        tenantId: fixture.tenantId,
        ruleId: created.rule.id,
      }),
    ).toMatchObject({ scope: "tenant" });

    const removeResponse = await postForm(app, `${path}/remove`, {
      confirmRemoval: "confirmed",
    });
    expect(removeResponse.status).toBe(303);
    expect(
      await findBadgeRulePlacementAvailability(fixture.db, {
        tenantId: fixture.tenantId,
        ruleId: created.rule.id,
      }),
    ).toBeNull();

    const availabilityAuditCount = await fixture.db
      .prepare(
        `
        SELECT COUNT(*)::INTEGER AS count
        FROM audit_logs
        WHERE tenant_id = ?
          AND target_id = ?
          AND action = 'badge_rule.placement_availability_updated'
      `,
      )
      .bind(fixture.tenantId, created.rule.id)
      .first<{ readonly count: number }>();
    const removalAuditCount = await fixture.db
      .prepare(
        `
        SELECT COUNT(*)::INTEGER AS count
        FROM audit_logs
        WHERE tenant_id = ?
          AND target_id = ?
          AND action = 'badge_rule.placement_availability_removed'
      `,
      )
      .bind(fixture.tenantId, created.rule.id)
      .first<{ readonly count: number }>();

    expect(availabilityAuditCount?.count).toBe(5);
    expect(removalAuditCount?.count).toBe(1);
  });

  it("denies non-admin roles and stale or cross-rule course submissions", async () => {
    const fixture = await createBadgeRuleIntegrationFixture();
    routeTenantIds.push(fixture.tenantId);
    const created = await activateRule(fixture);
    const issuerApp = await createRouteApp({ fixture, membershipRole: "issuer" });
    const adminApp = await createRouteApp({ fixture });
    const path = `/tenants/${fixture.tenantId}/admin/rules/${created.rule.id}/availability`;

    expect((await issuerApp.request(path, {}, testEnv)).status).toBe(403);
    expect(
      (
        await postForm(adminApp, `${path}/courses`, {
          connectionId: fixture.lmsConnectionId,
          courseId: "course-stale",
        })
      ).status,
    ).toBe(303);
    expect(
      await findBadgeRulePlacementAvailability(fixture.db, {
        tenantId: fixture.tenantId,
        ruleId: created.rule.id,
      }),
    ).toBeNull();
    expect(
      (
        await postForm(adminApp, `${path}/update`, {
          scope: "tenant",
        })
      ).status,
    ).toBe(303);
    expect(
      await findBadgeRulePlacementAvailability(fixture.db, {
        tenantId: fixture.tenantId,
        ruleId: created.rule.id,
      }),
    ).toBeNull();
    expect(
      (
        await adminApp.request(
          `/tenants/${fixture.tenantId}/admin/rules/brl_missing/availability`,
          {},
          testEnv,
        )
      ).status,
    ).toBe(404);
  });
});

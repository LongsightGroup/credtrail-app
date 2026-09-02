import {
  createTenantOrgUnit,
  ensureInstitutionOrgUnitForTenant,
  upsertTenant,
  upsertTenantLmsConnection,
  upsertTenantMembershipRole,
  upsertUserByEmail,
  type SqlDatabase,
} from "@credtrail/db";
import { createPostgresDatabase } from "@credtrail/db/postgres";
import { managedBadgeTemplateImagePath } from "@credtrail/validation";
import { createServer } from "node:http";

import { createTestBadgeIssuanceRule } from "../../../packages/db/src/badge-issuance-rule-test-fixtures";
import { loadLocalDevEnv, requireEnv } from "../../../scripts/local-dev-env.mjs";

export interface LiveRulePlacementAvailabilityFixture {
  readonly tenantId: string;
  readonly adminEmail: string;
  readonly ruleName: string;
  readonly departmentId: string;
  readonly departmentName: string;
  readonly courseTitle: string;
  readonly secondCourseTitle: string;
  readonly rulesPath: string;
  readonly initialRuleState: LiveRuleState;
  readonly readRuleState: () => Promise<LiveRuleState>;
  readonly dispose: () => Promise<void>;
}

export interface LiveRuleState {
  readonly activeVersionId: string | null;
  readonly ruleJson: string;
  readonly versionCount: number;
}

const deleteFixture = async (
  db: SqlDatabase,
  input: { readonly tenantId: string; readonly userId: string },
): Promise<void> => {
  const authUsers = await db
    .prepare(
      `
        SELECT auth_user_id AS authUserId
        FROM auth_identity_links
        WHERE credtrail_user_id = ?
      `,
    )
    .bind(input.userId)
    .all<{ readonly authUserId: string }>();

  await db.prepare("DELETE FROM tenants WHERE id = ?").bind(input.tenantId).run();
  await db.prepare("DELETE FROM users WHERE id = ?").bind(input.userId).run();

  for (const authUser of authUsers.results) {
    await db.prepare("DELETE FROM auth.user WHERE id = ?").bind(authUser.authUserId).run();
  }
};

const startMockSakai = async (): Promise<{
  readonly apiBaseUrl: string;
  readonly courseTitle: string;
  readonly secondCourseTitle: string;
  readonly close: () => Promise<void>;
}> => {
  const courses = [
    {
      id: "course-placement-e2e",
      title: "Community Data Capstone",
      type: "course",
      maintainRole: "Instructor",
      shortDescription: "DATA 490",
      published: true,
    },
    {
      id: "course-placement-studio-e2e",
      title: "Community Data Studio",
      type: "course",
      maintainRole: "Instructor",
      shortDescription: "DATA 390",
      published: true,
    },
  ];
  const server = createServer((request, response) => {
    const requestUrl = new URL(request.url ?? "/", "http://127.0.0.1");
    const resolvedCourse = courses.find(
      (course) => requestUrl.pathname === `/direct/site/${course.id}.json`,
    );
    const body =
      requestUrl.pathname === "/direct/site.json"
        ? { site_collection: requestUrl.searchParams.has("_start") ? [] : courses }
        : resolvedCourse !== undefined
          ? resolvedCourse
          : { error: `No mock route configured for ${requestUrl.pathname}` };
    const statusCode = "error" in body ? 404 : 200;
    response.writeHead(statusCode, { "content-type": "application/json" });
    response.end(JSON.stringify(body));
  });

  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  const address = server.address();

  if (address === null || typeof address === "string") {
    server.close();
    throw new Error("Mock Sakai server did not bind to a TCP port");
  }

  return {
    apiBaseUrl: `http://127.0.0.1:${String(address.port)}`,
    courseTitle: courses[0]?.title ?? "Community Data Capstone",
    secondCourseTitle: courses[1]?.title ?? "Community Data Studio",
    close: () =>
      new Promise<void>((resolve, reject) => {
        server.close((error) => {
          if (error === undefined) {
            resolve();
          } else {
            reject(error);
          }
        });
      }),
  };
};

/** Creates a disposable tenant and LMS for the live course-availability browser workflow. */
export const createLiveRulePlacementAvailabilityFixture =
  async (): Promise<LiveRulePlacementAvailabilityFixture> => {
    loadLocalDevEnv();
    const db = createPostgresDatabase({
      databaseUrl: requireEnv("DATABASE_URL"),
      connectionMode: "single-use",
    });
    const suffix = crypto.randomUUID().replaceAll("-", "");
    const tenantId = `tenant_e2e_availability_${suffix}`;
    const adminEmail = `availability-admin-${suffix}@example.edu`;
    const badgeTemplateId = `badge_template_e2e_availability_${suffix}`;
    const lmsConnectionId = `lms_e2e_availability_${suffix}`;
    const ruleName = `Course availability ${suffix.slice(0, 8)}`;
    const departmentName = "Applied Data Studies";
    const ruleJson = JSON.stringify({
      conditions: {
        type: "course_completion",
        courseId: "course-placement-e2e",
        minCompletionPercent: 100,
      },
    });
    const mockSakai = await startMockSakai();
    let tenantCreated = false;
    let adminUserId: string | null = null;

    try {
      await upsertTenant(db, {
        id: tenantId,
        slug: `availability-e2e-${suffix}`,
        displayName: "Availability E2E University",
        planTier: "institution",
        issuerDomain: `availability-e2e-${suffix}.issuer.test`,
        didWeb: `did:web:availability-e2e-${suffix}.issuer.test`,
        isActive: true,
      });
      tenantCreated = true;
      const institutionId = await ensureInstitutionOrgUnitForTenant(db, tenantId);
      const admin = await upsertUserByEmail(db, adminEmail);
      adminUserId = admin.id;
      await upsertTenantMembershipRole(db, { tenantId, userId: admin.id, role: "owner" });
      const college = await createTenantOrgUnit(db, {
        tenantId,
        unitType: "college",
        slug: "community-studies",
        displayName: "College of Community Studies",
        parentOrgUnitId: institutionId,
        createdByUserId: admin.id,
      });
      const department = await createTenantOrgUnit(db, {
        tenantId,
        unitType: "department",
        slug: "applied-data-studies",
        displayName: departmentName,
        parentOrgUnitId: college.id,
        createdByUserId: admin.id,
      });
      await db
        .prepare(
          `
          INSERT INTO badge_templates (
            id,
            tenant_id,
            slug,
            title,
            description,
            criteria_uri,
            image_uri,
            created_by_user_id,
            owner_org_unit_id,
            governance_metadata_json
          )
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `,
        )
        .bind(
          badgeTemplateId,
          tenantId,
          `course-availability-${suffix}`,
          "Community Data Badge",
          "Awarded after the governed community data capstone.",
          "https://credtrail.org/criteria/community-data",
          `https://credtrail.org${managedBadgeTemplateImagePath({
            tenantId,
            badgeTemplateId,
            assetId: `asset_${suffix}`,
          })}`,
          admin.id,
          institutionId,
          '{"source":"e2e_test"}',
        )
        .run();
      await upsertTenantLmsConnection(db, {
        id: lmsConnectionId,
        tenantId,
        displayName: "Availability E2E LMS",
        providerKind: "sakai",
        apiBaseUrl: mockSakai.apiBaseUrl,
        accessToken: "SAKAIID=availability-e2e-session",
      });
      const created = await createTestBadgeIssuanceRule(db, {
        tenantId,
        name: ruleName,
        description: "A disposable active rule used to verify placement availability.",
        badgeTemplateId,
        lmsProviderKind: "sakai",
        lmsConnectionId,
        ruleJson,
        changeSummary: "Create course-availability browser fixture",
        createdByUserId: admin.id,
      });
      await db
        .prepare(
          `
          UPDATE badge_issuance_rule_versions
          SET status = 'active', effective_starts_at = NULL, expires_at = NULL
          WHERE tenant_id = ? AND rule_id = ? AND id = ?
        `,
        )
        .bind(tenantId, created.rule.id, created.version.id)
        .run();
      await db
        .prepare(
          `
          UPDATE badge_issuance_rules
          SET active_version_id = ?
          WHERE tenant_id = ? AND id = ?
        `,
        )
        .bind(created.version.id, tenantId, created.rule.id)
        .run();

      return {
        tenantId,
        adminEmail,
        ruleName,
        departmentId: department.id,
        departmentName,
        courseTitle: mockSakai.courseTitle,
        secondCourseTitle: mockSakai.secondCourseTitle,
        rulesPath: `/tenants/${encodeURIComponent(tenantId)}/admin/rules`,
        initialRuleState: {
          activeVersionId: created.version.id,
          ruleJson,
          versionCount: 1,
        },
        readRuleState: async () => {
          const state = await db
            .prepare(
              `
              SELECT
                rule.active_version_id AS activeVersionId,
                version.rule_json AS ruleJson,
                (
                  SELECT COUNT(*)::INTEGER
                  FROM badge_issuance_rule_versions counted
                  WHERE counted.tenant_id = rule.tenant_id
                    AND counted.rule_id = rule.id
                ) AS versionCount
              FROM badge_issuance_rules rule
              JOIN badge_issuance_rule_versions version
                ON version.tenant_id = rule.tenant_id
               AND version.id = rule.active_version_id
              WHERE rule.tenant_id = ? AND rule.id = ?
            `,
            )
            .bind(tenantId, created.rule.id)
            .first<LiveRuleState>();

          if (state === null) {
            throw new Error("Course-availability browser fixture rule no longer exists");
          }

          return state;
        },
        dispose: async () => {
          await deleteFixture(db, { tenantId, userId: admin.id });
          await mockSakai.close();
        },
      };
    } catch (error) {
      if (tenantCreated) {
        if (adminUserId === null) {
          await db.prepare("DELETE FROM tenants WHERE id = ?").bind(tenantId).run();
        } else {
          await deleteFixture(db, { tenantId, userId: adminUserId });
        }
      }
      await mockSakai.close();
      throw error;
    }
  };

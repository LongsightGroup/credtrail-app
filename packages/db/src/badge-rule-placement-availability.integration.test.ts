import { readFile } from "node:fs/promises";

import pg from "pg";
import { expect, it } from "vitest";

import { createFixtureRule } from "./badge-issuance-rule-test-fixtures.js";
import {
  findBadgeRulePlacementAvailability,
  listActiveBadgeRulesAvailableForContext,
  removeBadgeRulePlacementAvailability,
  replaceBadgeRulePlacementAvailability,
  resolveBadgeRulePlacementAvailabilityForContext,
} from "./badge-rule-placement-availability.js";
import type {
  BadgeRuleIntegrationFixture,
  createDepartmentCourseOrgUnitHierarchy,
} from "./postgres-test-support.js";
import {
  cleanupTestResources,
  createBadgeRuleIntegrationFixture,
  createDepartmentCourseOrgUnitHierarchy as createOrgHierarchy,
  describeDbIntegration,
  requireTestDatabaseUrl,
  selectCount,
  uniqueTestId,
} from "./postgres-test-support.js";
import {
  assignLmsCourseContextOrgUnit,
  upsertCatalogLmsCourseContext,
} from "./lti-course-contexts.js";
import { upsertTenantLmsConnection } from "./tenant-lms-connections.js";
import { createTenantOrgUnit } from "./tenant-org-units.js";

type OrgHierarchy = Awaited<ReturnType<typeof createDepartmentCourseOrgUnitHierarchy>>;

const createMigrationPrerequisites = async (client: pg.PoolClient): Promise<void> => {
  await client.query(`
    CREATE TABLE tenants (
      id TEXT PRIMARY KEY
    );
    CREATE TABLE users (
      id TEXT PRIMARY KEY
    );
    CREATE TABLE tenant_org_units (
      id TEXT PRIMARY KEY,
      tenant_id TEXT NOT NULL,
      unit_type TEXT NOT NULL,
      display_name TEXT NOT NULL,
      is_active INTEGER NOT NULL,
      UNIQUE (tenant_id, id),
      FOREIGN KEY (tenant_id) REFERENCES tenants (id) ON DELETE CASCADE
    );
    CREATE TABLE tenant_lms_connections (
      id TEXT PRIMARY KEY,
      tenant_id TEXT NOT NULL,
      UNIQUE (tenant_id, id),
      FOREIGN KEY (tenant_id) REFERENCES tenants (id) ON DELETE CASCADE
    );
    CREATE TABLE badge_issuance_rules (
      id TEXT PRIMARY KEY,
      tenant_id TEXT NOT NULL,
      lms_connection_id TEXT,
      org_unit_id TEXT NOT NULL,
      UNIQUE (tenant_id, id),
      FOREIGN KEY (tenant_id) REFERENCES tenants (id) ON DELETE CASCADE,
      FOREIGN KEY (tenant_id, lms_connection_id)
        REFERENCES tenant_lms_connections (tenant_id, id) ON DELETE RESTRICT,
      FOREIGN KEY (tenant_id, org_unit_id)
        REFERENCES tenant_org_units (tenant_id, id) ON DELETE RESTRICT
    );
    CREATE TABLE lti_resource_link_placements (
      id TEXT PRIMARY KEY,
      tenant_id TEXT NOT NULL,
      rule_id TEXT,
      context_id TEXT,
      status TEXT NOT NULL,
      last_seen_at TEXT NOT NULL,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL,
      FOREIGN KEY (tenant_id) REFERENCES tenants (id) ON DELETE CASCADE,
      FOREIGN KEY (rule_id) REFERENCES badge_issuance_rules (id) ON DELETE CASCADE
    );
  `);
};

const withMigrationSchema = async (
  run: (client: pg.PoolClient, migrationSql: string) => Promise<void>,
): Promise<void> => {
  const schemaName = `availability_${crypto.randomUUID().replaceAll("-", "")}`;
  const pool = new pg.Pool({ connectionString: requireTestDatabaseUrl() });
  const client = await pool.connect();

  try {
    await client.query(`CREATE SCHEMA ${schemaName}`);
    await client.query(`SET search_path TO ${schemaName}`);
    await createMigrationPrerequisites(client);
    const migrationSql = await readFile(
      new URL("../migrations/0082_badge_rule_placement_availability.sql", import.meta.url),
      "utf8",
    );
    await run(client, migrationSql);
  } finally {
    await client.query("ROLLBACK");
    await client.query("RESET search_path");
    await client.query(`DROP SCHEMA IF EXISTS ${schemaName} CASCADE`);
    client.release();
    await pool.end();
  }
};

const activateFixtureRule = async (
  fixture: BadgeRuleIntegrationFixture,
  options: { readonly expiresAt?: string | null | undefined } = {},
): Promise<Awaited<ReturnType<typeof createFixtureRule>>> => {
  const created = await createFixtureRule(fixture);
  await fixture.db
    .prepare(
      `
      UPDATE badge_issuance_rule_versions
      SET status = 'active',
          effective_starts_at = '2026-01-01T00:00:00.000Z',
          expires_at = ?
      WHERE tenant_id = ?
        AND rule_id = ?
        AND id = ?
    `,
    )
    .bind(options.expiresAt ?? null, fixture.tenantId, created.rule.id, created.version.id)
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
  return created;
};

const createCourseContext = async (
  fixture: BadgeRuleIntegrationFixture,
  contextId: string,
  displayName = contextId,
) => {
  return upsertCatalogLmsCourseContext(fixture.db, {
    tenantId: fixture.tenantId,
    lmsConnectionId: fixture.lmsConnectionId,
    contextId,
    displayName,
    createdByUserId: fixture.userId,
  });
};

const mapContextToCourse = async (
  fixture: BadgeRuleIntegrationFixture,
  input: { readonly contextId: string; readonly courseOrgUnitId: string },
) => {
  const context = await createCourseContext(fixture, input.contextId);
  const result = await assignLmsCourseContextOrgUnit(fixture.db, {
    tenantId: fixture.tenantId,
    courseContextId: context.id,
    courseOrgUnitId: input.courseOrgUnitId,
  });

  if (result.status !== "assigned" && result.status !== "unchanged") {
    throw new Error(`Unable to map test course context: ${result.status}`);
  }

  return result.courseContext;
};

describeDbIntegration("badge rule placement availability with Postgres", () => {
  it("backfills exact contexts and selected-course policies from active and retired placements", async () => {
    await withMigrationSchema(async (client, migrationSql) => {
      await client.query(`
        INSERT INTO tenants (id) VALUES ('tenant_one');
        INSERT INTO users (id) VALUES ('user_one');
        INSERT INTO tenant_org_units (id, tenant_id, unit_type, display_name, is_active)
        VALUES
          ('org_institution', 'tenant_one', 'institution', 'Institution', 1),
          ('org_course', 'tenant_one', 'course', 'Mapped course', 1);
        INSERT INTO tenant_lms_connections (id, tenant_id)
        VALUES ('lms_one', 'tenant_one');
        INSERT INTO badge_issuance_rules (
          id,
          tenant_id,
          lms_connection_id,
          org_unit_id
        )
        VALUES
          ('rule_course', 'tenant_one', 'lms_one', 'org_course'),
          ('rule_institution', 'tenant_one', 'lms_one', 'org_institution'),
          ('rule_without_placement', 'tenant_one', 'lms_one', 'org_institution');
        INSERT INTO lti_resource_link_placements (
          id,
          tenant_id,
          rule_id,
          context_id,
          status,
          last_seen_at,
          created_at,
          updated_at
        )
        VALUES
          (
            'placement_active_a', 'tenant_one', 'rule_course', 'context_a', 'active',
            '2026-08-02T00:00:00.000Z', '2026-08-01T00:00:00.000Z', '2026-08-02T00:00:00.000Z'
          ),
          (
            'placement_active_a_second_link', 'tenant_one', 'rule_course', 'context_a', 'active',
            '2026-08-03T00:00:00.000Z', '2026-08-02T00:00:00.000Z', '2026-08-03T00:00:00.000Z'
          ),
          (
            'placement_retired_b', 'tenant_one', 'rule_course', 'context_b', 'retired',
            '2026-08-04T00:00:00.000Z', '2026-08-03T00:00:00.000Z', '2026-08-04T00:00:00.000Z'
          ),
          (
            'placement_institution', 'tenant_one', 'rule_institution', 'context_c', 'active',
            '2026-08-05T00:00:00.000Z', '2026-08-05T00:00:00.000Z', '2026-08-05T00:00:00.000Z'
          );
      `);

      await client.query(migrationSql);

      const contexts = await client.query<{
        context_id: string;
        course_org_unit_id: string | null;
        display_name: string;
        first_seen_at: string;
        last_seen_at: string;
      }>(`
        SELECT
          context_id,
          course_org_unit_id,
          display_name,
          first_seen_at,
          last_seen_at
        FROM tenant_lms_course_contexts
        ORDER BY context_id
      `);
      const policies = await client.query<{ rule_id: string; target_count: number }>(`
        SELECT availability.rule_id, COUNT(target.course_context_id)::integer AS target_count
        FROM badge_rule_placement_availabilities AS availability
        INNER JOIN badge_rule_placement_available_courses AS target
          ON target.tenant_id = availability.tenant_id
          AND target.availability_id = availability.id
        GROUP BY availability.rule_id
        ORDER BY availability.rule_id
      `);

      expect(contexts.rows).toEqual([
        {
          context_id: "context_a",
          course_org_unit_id: "org_course",
          display_name: "Mapped course",
          first_seen_at: "2026-08-01T00:00:00.000Z",
          last_seen_at: "2026-08-03T00:00:00.000Z",
        },
        {
          context_id: "context_b",
          course_org_unit_id: "org_course",
          display_name: "Mapped course",
          first_seen_at: "2026-08-03T00:00:00.000Z",
          last_seen_at: "2026-08-04T00:00:00.000Z",
        },
        {
          context_id: "context_c",
          course_org_unit_id: null,
          display_name: "context_c",
          first_seen_at: "2026-08-05T00:00:00.000Z",
          last_seen_at: "2026-08-05T00:00:00.000Z",
        },
      ]);
      expect(policies.rows).toEqual([
        { rule_id: "rule_course", target_count: 2 },
        { rule_id: "rule_institution", target_count: 1 },
      ]);
    });
  });

  it("aborts backfill for a missing LMS connection or conflicting course mapping", async () => {
    await withMigrationSchema(async (client, migrationSql) => {
      await client.query(`
        INSERT INTO tenants (id) VALUES ('tenant_one');
        INSERT INTO tenant_org_units (id, tenant_id, unit_type, display_name, is_active)
        VALUES ('org_institution', 'tenant_one', 'institution', 'Institution', 1);
        INSERT INTO badge_issuance_rules (id, tenant_id, lms_connection_id, org_unit_id)
        VALUES ('rule_missing_connection', 'tenant_one', NULL, 'org_institution');
        INSERT INTO lti_resource_link_placements (
          id, tenant_id, rule_id, context_id, status, last_seen_at, created_at, updated_at
        )
        VALUES (
          'placement_one', 'tenant_one', 'rule_missing_connection', 'context_one', 'active',
          '2026-08-01T00:00:00.000Z', '2026-08-01T00:00:00.000Z', '2026-08-01T00:00:00.000Z'
        );
      `);

      await expect(client.query(migrationSql)).rejects.toThrow(/exact tenant LMS connection/i);
    });

    await withMigrationSchema(async (client, migrationSql) => {
      await client.query(`
        INSERT INTO tenants (id) VALUES ('tenant_one');
        INSERT INTO tenant_org_units (id, tenant_id, unit_type, display_name, is_active)
        VALUES
          ('org_course_one', 'tenant_one', 'course', 'Course one', 1),
          ('org_course_two', 'tenant_one', 'course', 'Course two', 1);
        INSERT INTO tenant_lms_connections (id, tenant_id)
        VALUES ('lms_one', 'tenant_one');
        INSERT INTO badge_issuance_rules (id, tenant_id, lms_connection_id, org_unit_id)
        VALUES
          ('rule_one', 'tenant_one', 'lms_one', 'org_course_one'),
          ('rule_two', 'tenant_one', 'lms_one', 'org_course_two');
        INSERT INTO lti_resource_link_placements (
          id, tenant_id, rule_id, context_id, status, last_seen_at, created_at, updated_at
        )
        VALUES
          (
            'placement_one', 'tenant_one', 'rule_one', 'shared_context', 'active',
            '2026-08-01T00:00:00.000Z', '2026-08-01T00:00:00.000Z', '2026-08-01T00:00:00.000Z'
          ),
          (
            'placement_two', 'tenant_one', 'rule_two', 'shared_context', 'active',
            '2026-08-01T00:00:00.000Z', '2026-08-01T00:00:00.000Z', '2026-08-01T00:00:00.000Z'
          );
      `);

      await expect(client.query(migrationSql)).rejects.toThrow(/conflicting course org-unit/i);
    });
  });

  it("requires owner/admin authority, a usable active rule, and tenant-local references", async () => {
    const fixture = await createBadgeRuleIntegrationFixture();
    const otherFixture = await createBadgeRuleIntegrationFixture();

    try {
      const inactive = await createFixtureRule(fixture);
      const localContext = await createCourseContext(fixture, "local-course");
      const otherContext = await createCourseContext(otherFixture, "other-course");

      expect(
        await replaceBadgeRulePlacementAvailability(fixture.db, {
          tenantId: fixture.tenantId,
          ruleId: inactive.rule.id,
          availability: { scope: "selected_courses", courseContextIds: [localContext.id] },
          actorUserId: fixture.userId,
          actorRole: "admin",
          evaluatedAt: "2026-09-02T12:00:00.000Z",
        }),
      ).toEqual({ status: "rule_not_active" });

      await fixture.db
        .prepare(
          "UPDATE badge_issuance_rule_versions SET status = 'active' WHERE tenant_id = ? AND id = ?",
        )
        .bind(fixture.tenantId, inactive.version.id)
        .run();
      await fixture.db
        .prepare(
          "UPDATE badge_issuance_rules SET active_version_id = ? WHERE tenant_id = ? AND id = ?",
        )
        .bind(inactive.version.id, fixture.tenantId, inactive.rule.id)
        .run();

      expect(
        await replaceBadgeRulePlacementAvailability(fixture.db, {
          tenantId: fixture.tenantId,
          ruleId: inactive.rule.id,
          availability: { scope: "selected_courses", courseContextIds: [localContext.id] },
          actorUserId: fixture.userId,
          actorRole: "issuer",
          evaluatedAt: "2026-09-02T12:00:00.000Z",
        }),
      ).toEqual({ status: "not_authorized" });
      expect(
        await replaceBadgeRulePlacementAvailability(fixture.db, {
          tenantId: fixture.tenantId,
          ruleId: inactive.rule.id,
          availability: { scope: "selected_courses", courseContextIds: [otherContext.id] },
          actorUserId: fixture.userId,
          actorRole: "admin",
          evaluatedAt: "2026-09-02T12:00:00.000Z",
        }),
      ).toEqual({ status: "course_context_not_found" });

      const expired = await activateFixtureRule(fixture, {
        expiresAt: "2026-08-01T00:00:00.000Z",
      });
      expect(
        await replaceBadgeRulePlacementAvailability(fixture.db, {
          tenantId: fixture.tenantId,
          ruleId: expired.rule.id,
          availability: { scope: "tenant" },
          actorUserId: fixture.userId,
          actorRole: "owner",
          evaluatedAt: "2026-09-02T12:00:00.000Z",
        }),
      ).toEqual({ status: "rule_not_active" });
    } finally {
      await cleanupTestResources(fixture.db, {
        tenantIds: [fixture.tenantId, otherFixture.tenantId],
        userIds: [fixture.userId, otherFixture.userId],
      });
    }
  });

  it("replaces selected-course policies atomically, resolves exact identities, and audits replay once", async () => {
    const fixture = await createBadgeRuleIntegrationFixture();

    try {
      const created = await activateFixtureRule(fixture);
      const firstContext = await createCourseContext(fixture, "selected-one");
      const secondContext = await createCourseContext(fixture, "selected-two");
      const outsideContext = await createCourseContext(fixture, "selected-outside");
      const otherConnection = await upsertTenantLmsConnection(fixture.db, {
        id: uniqueTestId("lms_selected_other"),
        tenantId: fixture.tenantId,
        displayName: "Selected other LMS",
        providerKind: "sakai",
        apiBaseUrl: "https://sakai.example.test",
      });
      await upsertCatalogLmsCourseContext(fixture.db, {
        tenantId: fixture.tenantId,
        lmsConnectionId: otherConnection.id,
        contextId: firstContext.contextId,
        displayName: "Same context string on another LMS",
        createdByUserId: fixture.userId,
      });
      const request = {
        tenantId: fixture.tenantId,
        ruleId: created.rule.id,
        availability: {
          scope: "selected_courses" as const,
          courseContextIds: [secondContext.id, firstContext.id],
        },
        actorUserId: fixture.userId,
        actorRole: "admin" as const,
        evaluatedAt: "2026-09-02T12:00:00.000Z",
      };
      const [first, replay] = await Promise.all([
        replaceBadgeRulePlacementAvailability(fixture.db, request),
        replaceBadgeRulePlacementAvailability(fixture.db, request),
      ]);

      expect([first.status, replay.status].sort()).toEqual(["unchanged", "updated"]);
      expect(await findBadgeRulePlacementAvailability(fixture.db, request)).toMatchObject({
        scope: "selected_courses",
        courseContextIds: [firstContext.id, secondContext.id].sort(),
      });
      expect(
        await resolveBadgeRulePlacementAvailabilityForContext(fixture.db, {
          tenantId: fixture.tenantId,
          ruleId: created.rule.id,
          lmsConnectionId: fixture.lmsConnectionId,
          contextId: firstContext.contextId,
        }),
      ).toMatchObject({ status: "allowed", courseContext: { id: firstContext.id } });
      expect(
        await resolveBadgeRulePlacementAvailabilityForContext(fixture.db, {
          tenantId: fixture.tenantId,
          ruleId: created.rule.id,
          lmsConnectionId: fixture.lmsConnectionId,
          contextId: outsideContext.contextId,
        }),
      ).toEqual({ status: "outside_availability" });
      expect(
        await resolveBadgeRulePlacementAvailabilityForContext(fixture.db, {
          tenantId: fixture.tenantId,
          ruleId: created.rule.id,
          lmsConnectionId: otherConnection.id,
          contextId: firstContext.contextId,
        }),
      ).toEqual({ status: "outside_availability" });
      expect(
        await selectCount(
          fixture.db,
          "SELECT COUNT(*) AS totalCount FROM audit_logs WHERE tenant_id = ? AND target_id = ? AND action = 'badge_rule.placement_availability_updated'",
          [fixture.tenantId, created.rule.id],
        ),
      ).toBe(1);

      const available = await listActiveBadgeRulesAvailableForContext(fixture.db, {
        tenantId: fixture.tenantId,
        lmsConnectionId: fixture.lmsConnectionId,
        contextId: firstContext.contextId,
        evaluatedAt: "2026-09-02T12:00:00.000Z",
      });
      expect(available.rules.map((rule) => rule.id)).toContain(created.rule.id);

      expect(
        await removeBadgeRulePlacementAvailability(fixture.db, {
          tenantId: fixture.tenantId,
          ruleId: created.rule.id,
          actorUserId: fixture.userId,
          actorRole: "admin",
        }),
      ).toEqual({ status: "removed" });
      expect(
        await removeBadgeRulePlacementAvailability(fixture.db, {
          tenantId: fixture.tenantId,
          ruleId: created.rule.id,
          actorUserId: fixture.userId,
          actorRole: "admin",
        }),
      ).toEqual({ status: "unchanged" });
      expect(
        await selectCount(
          fixture.db,
          "SELECT COUNT(*) AS totalCount FROM audit_logs WHERE tenant_id = ? AND target_id = ? AND action = 'badge_rule.placement_availability_removed'",
          [fixture.tenantId, created.rule.id],
        ),
      ).toBe(1);
    } finally {
      await cleanupTestResources(fixture.db, {
        tenantIds: [fixture.tenantId],
        userIds: [fixture.userId],
      });
    }
  });

  it("resolves active org-subtree mappings and denies unmapped, sibling, or inactive paths", async () => {
    const fixture = await createBadgeRuleIntegrationFixture();

    try {
      const created = await activateFixtureRule(fixture);
      const hierarchy: OrgHierarchy = await createOrgHierarchy(fixture.db, {
        tenantId: fixture.tenantId,
        userId: fixture.userId,
        includeProgram: true,
      });

      if (hierarchy.programCourse === undefined) {
        throw new Error("Expected program course fixture");
      }

      const siblingCollege = await createTenantOrgUnit(fixture.db, {
        tenantId: fixture.tenantId,
        unitType: "college",
        slug: "arts",
        displayName: "Arts",
        parentOrgUnitId: `${fixture.tenantId}:org:institution`,
        createdByUserId: fixture.userId,
      });
      const siblingDepartment = await createTenantOrgUnit(fixture.db, {
        tenantId: fixture.tenantId,
        unitType: "department",
        slug: "history",
        displayName: "History",
        parentOrgUnitId: siblingCollege.id,
        createdByUserId: fixture.userId,
      });
      const siblingCourse = await createTenantOrgUnit(fixture.db, {
        tenantId: fixture.tenantId,
        unitType: "course",
        slug: "hist-101",
        displayName: "History 101",
        parentOrgUnitId: siblingDepartment.id,
        createdByUserId: fixture.userId,
      });
      const inactiveCollege = await createTenantOrgUnit(fixture.db, {
        tenantId: fixture.tenantId,
        unitType: "college",
        slug: "inactive-college",
        displayName: "Inactive college",
        parentOrgUnitId: `${fixture.tenantId}:org:institution`,
        createdByUserId: fixture.userId,
      });
      await fixture.db
        .prepare("UPDATE tenant_org_units SET is_active = 0 WHERE tenant_id = ? AND id = ?")
        .bind(fixture.tenantId, inactiveCollege.id)
        .run();
      const descendantContext = await mapContextToCourse(fixture, {
        contextId: "org-descendant",
        courseOrgUnitId: hierarchy.programCourse.id,
      });
      const siblingContext = await mapContextToCourse(fixture, {
        contextId: "org-sibling",
        courseOrgUnitId: siblingCourse.id,
      });
      const unmappedContext = await createCourseContext(fixture, "org-unmapped");

      expect(
        await replaceBadgeRulePlacementAvailability(fixture.db, {
          tenantId: fixture.tenantId,
          ruleId: created.rule.id,
          availability: { scope: "org_unit_subtree", rootOrgUnitId: hierarchy.course.id },
          actorUserId: fixture.userId,
          actorRole: "admin",
          evaluatedAt: "2026-09-02T12:00:00.000Z",
        }),
      ).toEqual({ status: "org_unit_not_course" });
      expect(
        await replaceBadgeRulePlacementAvailability(fixture.db, {
          tenantId: fixture.tenantId,
          ruleId: created.rule.id,
          availability: { scope: "org_unit_subtree", rootOrgUnitId: inactiveCollege.id },
          actorUserId: fixture.userId,
          actorRole: "admin",
          evaluatedAt: "2026-09-02T12:00:00.000Z",
        }),
      ).toEqual({ status: "org_unit_inactive" });
      expect(
        await replaceBadgeRulePlacementAvailability(fixture.db, {
          tenantId: fixture.tenantId,
          ruleId: created.rule.id,
          availability: { scope: "org_unit_subtree", rootOrgUnitId: hierarchy.college.id },
          actorUserId: fixture.userId,
          actorRole: "admin",
          evaluatedAt: "2026-09-02T12:00:00.000Z",
        }),
      ).toMatchObject({ status: "updated", availability: { scope: "org_unit_subtree" } });

      expect(
        await resolveBadgeRulePlacementAvailabilityForContext(fixture.db, {
          tenantId: fixture.tenantId,
          ruleId: created.rule.id,
          lmsConnectionId: fixture.lmsConnectionId,
          contextId: descendantContext.contextId,
        }),
      ).toMatchObject({ status: "allowed" });
      expect(
        await resolveBadgeRulePlacementAvailabilityForContext(fixture.db, {
          tenantId: fixture.tenantId,
          ruleId: created.rule.id,
          lmsConnectionId: fixture.lmsConnectionId,
          contextId: siblingContext.contextId,
        }),
      ).toEqual({ status: "outside_availability" });
      expect(
        await resolveBadgeRulePlacementAvailabilityForContext(fixture.db, {
          tenantId: fixture.tenantId,
          ruleId: created.rule.id,
          lmsConnectionId: fixture.lmsConnectionId,
          contextId: unmappedContext.contextId,
        }),
      ).toEqual({ status: "course_unmapped" });

      await fixture.db
        .prepare("UPDATE tenant_org_units SET is_active = 0 WHERE tenant_id = ? AND id = ?")
        .bind(fixture.tenantId, hierarchy.programCourse.id)
        .run();
      expect(
        await resolveBadgeRulePlacementAvailabilityForContext(fixture.db, {
          tenantId: fixture.tenantId,
          ruleId: created.rule.id,
          lmsConnectionId: fixture.lmsConnectionId,
          contextId: descendantContext.contextId,
        }),
      ).toEqual({ status: "org_unit_inactive" });
    } finally {
      await cleanupTestResources(fixture.db, {
        tenantIds: [fixture.tenantId],
        userIds: [fixture.userId],
      });
    }
  });

  it("allows tenant reach while picker listing stays on the rule's matched LMS connection", async () => {
    const fixture = await createBadgeRuleIntegrationFixture();

    try {
      const created = await activateFixtureRule(fixture);
      const first = await createCourseContext(fixture, "tenant-one");
      const second = await createCourseContext(fixture, "tenant-two");
      const noPolicyRule = await activateFixtureRule(fixture);
      const otherConnection = await upsertTenantLmsConnection(fixture.db, {
        id: uniqueTestId("lms_other"),
        tenantId: fixture.tenantId,
        displayName: "Other LMS",
        providerKind: "sakai",
        apiBaseUrl: "https://sakai.example.test",
      });
      await createCourseContext(fixture, "same-context");
      await upsertCatalogLmsCourseContext(fixture.db, {
        tenantId: fixture.tenantId,
        lmsConnectionId: otherConnection.id,
        contextId: "same-context",
        displayName: "Other connection context",
        createdByUserId: fixture.userId,
      });

      expect(
        await replaceBadgeRulePlacementAvailability(fixture.db, {
          tenantId: fixture.tenantId,
          ruleId: created.rule.id,
          availability: { scope: "tenant" },
          actorUserId: fixture.userId,
          actorRole: "owner",
          evaluatedAt: "2026-09-02T12:00:00.000Z",
        }),
      ).toMatchObject({ status: "updated", availability: { scope: "tenant" } });

      for (const context of [first, second]) {
        expect(
          await resolveBadgeRulePlacementAvailabilityForContext(fixture.db, {
            tenantId: fixture.tenantId,
            ruleId: created.rule.id,
            lmsConnectionId: fixture.lmsConnectionId,
            contextId: context.contextId,
          }),
        ).toMatchObject({ status: "allowed" });
      }

      const list = await listActiveBadgeRulesAvailableForContext(fixture.db, {
        tenantId: fixture.tenantId,
        lmsConnectionId: fixture.lmsConnectionId,
        contextId: first.contextId,
        evaluatedAt: "2026-09-02T12:00:00.000Z",
      });
      expect(list.rules.map((rule) => rule.id)).toEqual([created.rule.id]);
      expect(list.exclusionCounts.noPolicy).toBe(1);
      expect(list.rules.map((rule) => rule.id)).not.toContain(noPolicyRule.rule.id);

      const otherConnectionList = await listActiveBadgeRulesAvailableForContext(fixture.db, {
        tenantId: fixture.tenantId,
        lmsConnectionId: otherConnection.id,
        contextId: "same-context",
        evaluatedAt: "2026-09-02T12:00:00.000Z",
      });
      expect(otherConnectionList.rules).toEqual([]);
      expect(otherConnectionList.exclusionCounts).toEqual({
        noPolicy: 0,
        courseContextNotFound: 0,
        courseUnmapped: 0,
        orgUnitInactive: 0,
        outsideAvailability: 0,
      });
    } finally {
      await cleanupTestResources(fixture.db, {
        tenantIds: [fixture.tenantId],
        userIds: [fixture.userId],
      });
    }
  });
});

import { createRequire } from "node:module";

import { afterAll, describe } from "vitest";

import { createPostgresDatabase } from "./postgres";
import { upsertTenant, type SqlDatabase, type TenantPlanTier } from "./index";
import { createTenantOrgUnit, type TenantOrgUnitRecord } from "./tenant-org-units";

type PgPoolLike = import("pg").Pool;

const testDatabaseUrl = process.env.TEST_DATABASE_URL?.trim();

export const hasTestDatabaseUrl = testDatabaseUrl !== undefined && testDatabaseUrl.length > 0;

/** Skips the suite when `TEST_DATABASE_URL` is unset (local runs without Postgres). */
export const describeDbIntegration = hasTestDatabaseUrl ? describe : describe.skip;

export interface TestTenantFixture {
  db: SqlDatabase;
  tenantId: string;
  slug: string;
}

export interface CleanupTestResourcesInput {
  tenantIds?: readonly string[];
  userIds?: readonly string[];
  betterAuthUserIds?: readonly string[];
}

export interface BadgeRuleIntegrationFixture {
  db: SqlDatabase;
  tenantId: string;
  userId: string;
  badgeTemplateId: string;
  lmsConnectionId: string;
}

const COUNTABLE_TABLES = new Set([
  "assertions",
  "auth_identity_links",
  "badge_issuance_rule_approval_steps",
  "badge_issuance_rule_versions",
  "badge_issuance_rules",
  "job_queue_messages",
  "users",
]);

export const requireTestDatabaseUrl = (): string => {
  if (!hasTestDatabaseUrl || testDatabaseUrl === undefined) {
    throw new Error("TEST_DATABASE_URL is required for DB integration tests.");
  }

  return testDatabaseUrl;
};

let sharedTestPool: PgPoolLike | undefined;
let sharedTestDatabase: SqlDatabase | undefined;

const nodeRequire = createRequire(import.meta.url);

const getSharedTestPostgresDatabase = (): SqlDatabase => {
  if (sharedTestDatabase === undefined) {
    const databaseUrl = requireTestDatabaseUrl();
    const pgModule = nodeRequire("pg") as typeof import("pg");
    sharedTestPool = new pgModule.Pool({
      connectionString: databaseUrl,
    });
    sharedTestDatabase = createPostgresDatabase({
      databaseUrl,
      connectionMode: "pool",
      pool: sharedTestPool,
    });
  }

  return sharedTestDatabase;
};

export const createTestPostgresDatabase = (): SqlDatabase => {
  return getSharedTestPostgresDatabase();
};

if (hasTestDatabaseUrl) {
  afterAll(async () => {
    if (sharedTestPool !== undefined) {
      await sharedTestPool.end();
      sharedTestPool = undefined;
      sharedTestDatabase = undefined;
    }
  });
}

export const uniqueTestId = (prefix: string): string => {
  return `${prefix}_${crypto.randomUUID().replace(/-/g, "")}`;
};

export const selectCount = async (
  db: SqlDatabase,
  sql: string,
  params: readonly unknown[],
): Promise<number> => {
  const row = await db
    .prepare(sql)
    .bind(...params)
    .first<{ totalCount: number | string }>();

  return Number(row?.totalCount ?? 0);
};

export const deleteTestTenant = async (db: SqlDatabase, tenantId: string): Promise<void> => {
  await db.prepare("DELETE FROM job_queue_messages WHERE tenant_id = ?").bind(tenantId).run();
  await db.prepare("DELETE FROM assertions WHERE tenant_id = ?").bind(tenantId).run();
  await db.prepare("DELETE FROM tenants WHERE id = ?").bind(tenantId).run();
};

export const deleteTestUsers = async (
  db: SqlDatabase,
  userIds: readonly string[],
): Promise<void> => {
  for (const userId of userIds) {
    await db.prepare("DELETE FROM users WHERE id = ?").bind(userId).run();
  }
};

export const deleteBetterAuthCredentialUsers = async (
  db: SqlDatabase,
  authUserIds: readonly string[],
): Promise<void> => {
  for (const authUserId of authUserIds) {
    await db.prepare("DELETE FROM auth.account WHERE user_id = ?").bind(authUserId).run();
    await db.prepare("DELETE FROM auth.user WHERE id = ?").bind(authUserId).run();
  }
};

export const cleanupTestResources = async (
  db: SqlDatabase,
  input: CleanupTestResourcesInput,
): Promise<void> => {
  const tenantIds = input.tenantIds ?? [];
  const userIds = input.userIds ?? [];
  const betterAuthUserIds = input.betterAuthUserIds ?? [];

  for (const tenantId of tenantIds) {
    await deleteTestTenant(db, tenantId);
  }

  await deleteBetterAuthCredentialUsers(db, betterAuthUserIds);
  await deleteTestUsers(db, userIds);
};

export const createTestTenantFixture = async (
  options: {
    tenantId?: string | undefined;
    slug?: string | undefined;
    displayName?: string | undefined;
    planTier?: TenantPlanTier | undefined;
    isActive?: boolean | undefined;
  } = {},
): Promise<TestTenantFixture> => {
  const db = createTestPostgresDatabase();
  const tenantId = options.tenantId ?? uniqueTestId("tenant");
  const slug = options.slug ?? uniqueTestId("tenant").replace(/_/g, "-");

  await upsertTenant(db, {
    id: tenantId,
    slug,
    displayName: options.displayName ?? "Test Tenant",
    planTier: options.planTier ?? "institution",
    issuerDomain: `${slug}.issuer.test`,
    didWeb: `did:web:${slug}.issuer.test`,
    isActive: options.isActive,
  });
  await seedDefaultTenantOrgUnit(db, tenantId, options.displayName ?? "Test Tenant");

  return {
    db,
    tenantId,
    slug,
  };
};

export const createBadgeRuleIntegrationFixture = async (): Promise<BadgeRuleIntegrationFixture> => {
  const fixture = await createTestTenantFixture({
    displayName: "Badge Rule Test Tenant",
  });
  const suffix = crypto.randomUUID().replace(/-/g, "");
  const userId = uniqueTestId("usr_badge_rule");
  const badgeTemplateId = uniqueTestId("bt_badge_rule");
  const lmsConnectionId = uniqueTestId("lms_badge_rule");
  const ownerOrgUnitId = `${fixture.tenantId}:org:institution`;

  await fixture.db
    .prepare(
      `
      INSERT INTO users (id, email)
      VALUES (?, ?)
    `,
    )
    .bind(userId, `badge-rule-test-${suffix}@example.edu`)
    .run();

  await fixture.db
    .prepare(
      `
      INSERT INTO memberships (tenant_id, user_id, role)
      VALUES (?, ?, 'admin')
    `,
    )
    .bind(fixture.tenantId, userId)
    .run();

  await fixture.db
    .prepare(
      `
      UPDATE tenant_org_units
      SET created_by_user_id = ?
      WHERE id = ?
    `,
    )
    .bind(userId, ownerOrgUnitId)
    .run();

  await fixture.db
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
      VALUES (?, ?, 'badge-rule-template', 'Badge Rule Template', NULL, NULL, NULL, ?, ?, ?)
    `,
    )
    .bind(
      badgeTemplateId,
      fixture.tenantId,
      userId,
      ownerOrgUnitId,
      '{"stability":"institution_registry"}',
    )
    .run();

  await fixture.db
    .prepare(
      `
      INSERT INTO tenant_lms_connections (
        id,
        tenant_id,
        display_name,
        provider_kind,
        api_base_url,
        connected_at
      )
      VALUES (?, ?, 'Canvas Test', 'canvas', 'https://canvas.example.test', CURRENT_TIMESTAMP)
    `,
    )
    .bind(lmsConnectionId, fixture.tenantId)
    .run();

  return {
    db: fixture.db,
    tenantId: fixture.tenantId,
    userId,
    badgeTemplateId,
    lmsConnectionId,
  };
};

export const seedDefaultTenantOrgUnit = async (
  db: SqlDatabase,
  tenantId: string,
  displayName: string,
): Promise<string> => {
  const orgUnitId = `${tenantId}:org:institution`;
  const nowIso = new Date().toISOString();

  await db
    .prepare(
      `
      INSERT INTO tenant_org_units (
        id,
        tenant_id,
        unit_type,
        slug,
        display_name,
        parent_org_unit_id,
        created_by_user_id,
        is_active,
        created_at,
        updated_at
      )
      VALUES (?, ?, 'institution', 'institution', ?, NULL, NULL, 1, ?, ?)
      ON CONFLICT (tenant_id, slug)
      DO UPDATE SET
        display_name = excluded.display_name,
        is_active = excluded.is_active,
        updated_at = excluded.updated_at
    `,
    )
    .bind(orgUnitId, tenantId, `${displayName} Institution`, nowIso, nowIso)
    .run();

  return orgUnitId;
};

export const createDepartmentCourseOrgUnitHierarchy = async (
  db: SqlDatabase,
  input: {
    tenantId: string;
    userId: string;
    includeProgram?: boolean | undefined;
  },
): Promise<{
  college: TenantOrgUnitRecord;
  department: TenantOrgUnitRecord;
  course: TenantOrgUnitRecord;
  program?: TenantOrgUnitRecord;
  programCourse?: TenantOrgUnitRecord;
}> => {
  const college = await createTenantOrgUnit(db, {
    tenantId: input.tenantId,
    unitType: "college",
    slug: "engineering",
    displayName: "Engineering",
    parentOrgUnitId: `${input.tenantId}:org:institution`,
    createdByUserId: input.userId,
  });
  const department = await createTenantOrgUnit(db, {
    tenantId: input.tenantId,
    unitType: "department",
    slug: "computer-science",
    displayName: "Computer Science",
    parentOrgUnitId: college.id,
    createdByUserId: input.userId,
  });
  const course = await createTenantOrgUnit(db, {
    tenantId: input.tenantId,
    unitType: "course",
    slug: "cs-101",
    displayName: "CS 101",
    parentOrgUnitId: department.id,
    createdByUserId: input.userId,
  });

  if (input.includeProgram !== true) {
    return { college, department, course };
  }

  const program = await createTenantOrgUnit(db, {
    tenantId: input.tenantId,
    unitType: "program",
    slug: "cs-undergrad",
    displayName: "CS Undergraduate",
    parentOrgUnitId: department.id,
    createdByUserId: input.userId,
  });
  const programCourse = await createTenantOrgUnit(db, {
    tenantId: input.tenantId,
    unitType: "course",
    slug: "cs-201",
    displayName: "CS 201",
    parentOrgUnitId: program.id,
    createdByUserId: input.userId,
  });

  return {
    college,
    department,
    course,
    program,
    programCourse,
  };
};

export const seedBadgeTemplate = async (
  db: SqlDatabase,
  input: {
    tenantId: string;
    id?: string | undefined;
    slug?: string | undefined;
    title?: string | undefined;
    description?: string | null | undefined;
    criteriaUri?: string | null | undefined;
    imageUri?: string | null | undefined;
  },
): Promise<string> => {
  const id = input.id ?? uniqueTestId("badge_template");
  const slug = input.slug ?? uniqueTestId("badge-template").replace(/_/g, "-");
  const nowIso = new Date().toISOString();

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
        owner_org_unit_id,
        governance_metadata_json,
        created_at,
        updated_at
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `,
    )
    .bind(
      id,
      input.tenantId,
      slug,
      input.title ?? "Test Badge",
      input.description ?? null,
      input.criteriaUri ?? null,
      input.imageUri ?? null,
      `${input.tenantId}:org:institution`,
      '{"stability":"institution_registry"}',
      nowIso,
      nowIso,
    )
    .run();

  return id;
};

export const seedTenantOrgUnit = async (
  db: SqlDatabase,
  input: {
    tenantId: string;
    id: string;
    unitType: "institution" | "college" | "department" | "program" | "course";
    slug: string;
    displayName: string;
    parentOrgUnitId?: string | null | undefined;
  },
): Promise<void> => {
  const nowIso = new Date().toISOString();

  await db
    .prepare(
      `
      INSERT INTO tenant_org_units (
        id,
        tenant_id,
        unit_type,
        slug,
        display_name,
        parent_org_unit_id,
        created_by_user_id,
        is_active,
        created_at,
        updated_at
      )
      VALUES (?, ?, ?, ?, ?, ?, NULL, 1, ?, ?)
      ON CONFLICT (tenant_id, slug)
      DO UPDATE SET
        unit_type = excluded.unit_type,
        display_name = excluded.display_name,
        parent_org_unit_id = excluded.parent_org_unit_id,
        is_active = excluded.is_active,
        updated_at = excluded.updated_at
    `,
    )
    .bind(
      input.id,
      input.tenantId,
      input.unitType,
      input.slug,
      input.displayName,
      input.parentOrgUnitId ?? null,
      nowIso,
      nowIso,
    )
    .run();
};

export const seedLedgerOrgTree = async (
  db: SqlDatabase,
  tenantId: string,
): Promise<{
  institutionId: string;
  collegeId: string;
  departmentId: string;
  microbiologyProgramId: string;
  biochemistryProgramId: string;
}> => {
  const institutionId = `${tenantId}:org:institution`;
  const collegeId = `${tenantId}:org:science`;
  const departmentId = `${tenantId}:org:biology`;
  const microbiologyProgramId = `${tenantId}:org:microbiology`;
  const biochemistryProgramId = `${tenantId}:org:biochemistry`;

  await seedTenantOrgUnit(db, {
    tenantId,
    id: collegeId,
    unitType: "college",
    slug: "science",
    displayName: "College of Science",
    parentOrgUnitId: institutionId,
  });
  await seedTenantOrgUnit(db, {
    tenantId,
    id: departmentId,
    unitType: "department",
    slug: "biology",
    displayName: "Biology Department",
    parentOrgUnitId: collegeId,
  });
  await seedTenantOrgUnit(db, {
    tenantId,
    id: microbiologyProgramId,
    unitType: "program",
    slug: "microbiology",
    displayName: "Microbiology Program",
    parentOrgUnitId: departmentId,
  });
  await seedTenantOrgUnit(db, {
    tenantId,
    id: biochemistryProgramId,
    unitType: "program",
    slug: "biochemistry",
    displayName: "Biochemistry Program",
    parentOrgUnitId: departmentId,
  });

  return {
    institutionId,
    collegeId,
    departmentId,
    microbiologyProgramId,
    biochemistryProgramId,
  };
};

export const seedAssertionAttribution = async (
  db: SqlDatabase,
  input: {
    assertionId: string;
    tenantId: string;
    badgeTemplateId: string;
    orgUnitId: string;
    attributionSource: "historical_backfill" | "issuance_snapshot" | "current_owner_fallback";
    attributedAt: string;
  },
): Promise<void> => {
  const nowIso = new Date().toISOString();

  await db
    .prepare(
      `
      INSERT INTO assertion_reporting_attributions (
        assertion_id,
        tenant_id,
        badge_template_id,
        org_unit_id,
        attribution_source,
        attributed_at,
        created_at,
        updated_at
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `,
    )
    .bind(
      input.assertionId,
      input.tenantId,
      input.badgeTemplateId,
      input.orgUnitId,
      input.attributionSource,
      input.attributedAt,
      nowIso,
      nowIso,
    )
    .run();
};

export const seedLifecycleEvent = async (
  db: SqlDatabase,
  input: {
    tenantId: string;
    assertionId: string;
    fromState: "active" | "suspended" | "revoked" | "expired";
    toState: "active" | "suspended" | "revoked" | "expired";
    reasonCode:
      | "administrative_hold"
      | "policy_violation"
      | "appeal_pending"
      | "appeal_resolved"
      | "credential_expired"
      | "issuer_requested"
      | "other";
    reason: string;
    transitionedAt: string;
  },
): Promise<void> => {
  await db
    .prepare(
      `
      INSERT INTO assertion_lifecycle_events (
        id,
        tenant_id,
        assertion_id,
        from_state,
        to_state,
        reason_code,
        reason,
        transition_source,
        actor_user_id,
        transitioned_at,
        created_at
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, 'manual', NULL, ?, ?)
    `,
    )
    .bind(
      uniqueTestId("ale"),
      input.tenantId,
      input.assertionId,
      input.fromState,
      input.toState,
      input.reasonCode,
      input.reason,
      input.transitionedAt,
      input.transitionedAt,
    )
    .run();
};

export const seedAssertion = async (
  db: SqlDatabase,
  input: {
    tenantId: string;
    badgeTemplateId: string;
    id?: string | undefined;
    publicId?: string | null | undefined;
    learnerProfileId?: string | null | undefined;
    recipientIdentity: string;
    recipientIdentityType?: "email" | "email_sha256" | "did" | "url" | undefined;
    vcR2Key?: string | undefined;
    statusListIndex?: number | null | undefined;
    idempotencyKey?: string | undefined;
    issuedAt: string;
    issuedByUserId?: string | null | undefined;
    revokedAt?: string | null | undefined;
  },
): Promise<string> => {
  const id = input.id ?? uniqueTestId("assertion");
  const nowIso = new Date().toISOString();

  await db
    .prepare(
      `
      INSERT INTO assertions (
        id,
        tenant_id,
        public_id,
        learner_profile_id,
        badge_template_id,
        recipient_identity,
        recipient_identity_type,
        vc_r2_key,
        status_list_index,
        idempotency_key,
        issued_at,
        issued_by_user_id,
        revoked_at,
        created_at,
        updated_at
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `,
    )
    .bind(
      id,
      input.tenantId,
      input.publicId ?? null,
      input.learnerProfileId ?? null,
      input.badgeTemplateId,
      input.recipientIdentity,
      input.recipientIdentityType ?? "email",
      input.vcR2Key ?? `tenants/${input.tenantId}/assertions/${id}.jsonld`,
      input.statusListIndex ?? null,
      input.idempotencyKey ?? uniqueTestId("idem"),
      input.issuedAt,
      input.issuedByUserId ?? null,
      input.revokedAt ?? null,
      nowIso,
      nowIso,
    )
    .run();

  return id;
};

export const seedBetterAuthCredentialUser = async (
  db: SqlDatabase,
  input: {
    id?: string | undefined;
    email: string;
    twoFactorEnabled?: boolean | undefined;
  },
): Promise<string> => {
  const authUserId = input.id ?? uniqueTestId("ba_usr");
  const nowIso = new Date().toISOString();

  await db
    .prepare(
      `
      INSERT INTO auth.user (
        id,
        email,
        email_verified,
        two_factor_enabled,
        created_at,
        updated_at
      )
      VALUES (?, ?, TRUE, ?, ?, ?)
    `,
    )
    .bind(authUserId, input.email, input.twoFactorEnabled ?? false, nowIso, nowIso)
    .run();

  await db
    .prepare(
      `
      INSERT INTO auth.account (
        id,
        account_id,
        provider_id,
        user_id,
        password,
        created_at,
        updated_at
      )
      VALUES (?, ?, 'credential', ?, 'hashed-password', ?, ?)
    `,
    )
    .bind(uniqueTestId("ba_account"), authUserId, authUserId, nowIso, nowIso)
    .run();

  return authUserId;
};

export const countRows = async (
  db: SqlDatabase,
  tableName: string,
  whereSql: string,
  params: readonly unknown[],
): Promise<number> => {
  if (!COUNTABLE_TABLES.has(tableName)) {
    throw new Error(`countRows does not allow table: ${tableName}`);
  }

  const row = await db
    .prepare(`SELECT COUNT(*) AS totalCount FROM ${tableName} WHERE ${whereSql}`)
    .bind(...params)
    .first<{ totalCount: number | string }>();

  if (row === null) {
    return 0;
  }

  return Number(row.totalCount);
};

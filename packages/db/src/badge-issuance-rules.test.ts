import { readFileSync } from "node:fs";

import { describe, expect, it } from "vitest";

import * as dbModule from "./index";
import {
  mapBadgeIssuanceRuleVersionRow,
  type BadgeIssuanceRuleVersionRow,
} from "./badge-issuance-rule-version-sql";
import type {
  SqlDatabase,
  SqlPreparedStatement,
  SqlQueryResult,
  SqlRunResult,
} from "./tenant-scope";

describe("badge rule review queue schema", () => {
  it("adds badge rule review queue columns through a forward migration", () => {
    const sql = readFileSync(
      new URL("../migrations/0040_badge_rule_review_queue.sql", import.meta.url),
      "utf8",
    );

    expect(sql).toContain("ALTER TABLE badge_issuance_rule_evaluations");
    expect(sql).toContain("ADD COLUMN IF NOT EXISTS review_status TEXT");
    expect(sql).toContain("ADD COLUMN IF NOT EXISTS review_decision TEXT");
    expect(sql).toContain("ADD COLUMN IF NOT EXISTS review_comment TEXT");
    expect(sql).toContain("ADD COLUMN IF NOT EXISTS reviewed_by_user_id TEXT");
    expect(sql).toContain("ADD COLUMN IF NOT EXISTS reviewed_at TEXT");
    expect(sql).toContain("idx_badge_issuance_rule_evaluations_review_queue");
  });

  it("adds badge rule approval policy and rule org-unit scope through a forward migration", () => {
    const schemaSql = readFileSync(
      new URL("../migrations/0050_badge_rule_approval_policies.sql", import.meta.url),
      "utf8",
    );
    const defaultsSql = readFileSync(
      new URL("../migrations/0064_badge_rule_approval_policy_defaults.sql", import.meta.url),
      "utf8",
    );

    expect(schemaSql).toContain("ADD COLUMN IF NOT EXISTS owner_org_unit_id TEXT");
    expect(schemaSql).toContain("CREATE TABLE IF NOT EXISTS badge_rule_approval_policies");
    expect(schemaSql).toContain("approval_requirement TEXT NOT NULL");
    expect(schemaSql).toContain("approval_steps_json TEXT NOT NULL");
    expect(schemaSql).toContain("idx_badge_rule_approval_policies_tenant_default");
    expect(schemaSql).toContain("idx_badge_rule_approval_policies_tenant_org_unit");
    expect(defaultsSql).toContain("Snapshot of the selected badge template owner org unit");
    expect(defaultsSql).toContain("tenants.id || ':badge-rule-approval-policy:default'");
    expect(defaultsSql).toContain(
      '\'[{"requiredRole":"admin","label":"Administrative approval"}]\'',
    );
    expect(defaultsSql).toContain("ON CONFLICT DO NOTHING");
  });

  it("adds separation-of-duties and named target approval schema through a forward migration", () => {
    const sql = readFileSync(
      new URL("../migrations/0051_badge_rule_approval_separation_of_duties.sql", import.meta.url),
      "utf8",
    );

    expect(sql).toContain("ADD COLUMN IF NOT EXISTS allow_self_certification");
    expect(sql).toContain("ADD COLUMN IF NOT EXISTS submitted_by_user_id");
    expect(sql).toContain("ADD COLUMN IF NOT EXISTS target_type");
    expect(sql).toContain("CREATE TABLE IF NOT EXISTS badge_rule_approver_groups");
    expect(sql).toContain("CREATE TABLE IF NOT EXISTS badge_rule_approver_group_members");
    expect(sql).toContain("FOREIGN KEY (tenant_id, group_id)");
    expect(sql).toContain("REFERENCES memberships (tenant_id, user_id)");
    expect(sql).toContain("changes_requested");
  });

  it("adds lifecycle governance schema through a forward migration", () => {
    const sql = readFileSync(
      new URL("../migrations/0053_badge_rule_lifecycle_governance.sql", import.meta.url),
      "utf8",
    );

    expect(sql).toContain("'suspended'");
    expect(sql).toContain("'expired'");
    expect(sql).toContain("effective_starts_at");
    expect(sql).toContain("expires_at");
    expect(sql).toContain("recertification_interval_months");
    expect(sql).toContain("CREATE TABLE IF NOT EXISTS badge_rule_recertification_reviews");
    expect(sql).toContain("'process_badge_rule_lifecycle'");
    expect(sql).toContain("'process_end_of_term_badge_rule'");
  });

  it("replaces placement-bound end-of-term jobs with automated rule processing", () => {
    const sql = readFileSync(
      new URL("../migrations/0060_automated_badge_rule_processing.sql", import.meta.url),
      "utf8",
    );

    expect(sql).toContain("DELETE FROM job_queue_messages");
    expect(sql).toContain("WHERE job_type = 'process_end_of_term_badge_rule'");
    expect(sql).toContain("'process_automated_badge_rule'");
  });

  it("adds author builder drafts and approver membership role through a forward migration", () => {
    const sql = readFileSync(
      new URL("../migrations/0054_author_experience_governance.sql", import.meta.url),
      "utf8",
    );

    expect(sql).toContain("'approver'");
    expect(sql).toContain("CREATE TABLE IF NOT EXISTS badge_issuance_rule_builder_drafts");
    expect(sql).not.toContain("'changes_requested', 'deprecated'");
  });

  it("adds assertion issuance provenance and evaluation assertion index through a forward migration", () => {
    const sql = readFileSync(
      new URL("../migrations/0055_assertion_issuance_provenance.sql", import.meta.url),
      "utf8",
    );

    expect(sql).toContain("CREATE TABLE IF NOT EXISTS assertion_issuance_provenance");
    expect(sql).toContain("source IN ('lti_roster', 'rule_evaluate', 'manual', 'programmatic')");
    expect(sql).toContain("idx_badge_issuance_rule_evaluations_assertion");
  });

  it("gives unfinished rule-builder drafts stable identities", () => {
    const sql = readFileSync(
      new URL("../migrations/0056_badge_rule_builder_draft_identity.sql", import.meta.url),
      "utf8",
    );

    expect(sql).toContain("ADD COLUMN id TEXT");
    expect(sql).toContain("DROP COLUMN rule_id_key");
    expect(sql).toContain("ADD PRIMARY KEY (tenant_id, id)");
    expect(sql).toContain("WHERE rule_id IS NOT NULL");
  });

  it("constrains builder drafts to unfinished or matching formal-rule targets", () => {
    const sql = readFileSync(
      new URL("../migrations/0057_badge_rule_builder_draft_target.sql", import.meta.url),
      "utf8",
    );

    expect(sql).toContain("badge_rule_builder_drafts_target_check");
    expect(sql).toContain("(rule_id IS NULL AND version_id IS NULL)");
    expect(sql).toContain("(tenant_id, rule_id, version_id)");
    expect(sql).toContain("REFERENCES badge_issuance_rule_versions (tenant_id, rule_id, id)");
  });

  it("adds explicit approval withdrawal and reopening history actions", () => {
    const sql = readFileSync(
      new URL("../migrations/0059_badge_rule_approval_corrections.sql", import.meta.url),
      "utf8",
    );

    expect(sql).toContain("'withdrawn'");
    expect(sql).toContain("'reopened'");
  });

  it("requires truthful immutable badge-rule version snapshots", () => {
    const versionSnapshotSql = readFileSync(
      new URL("../migrations/0062_badge_rule_version_snapshots.sql", import.meta.url),
      "utf8",
    );
    const achievementSnapshotSql = readFileSync(
      new URL("../migrations/0063_badge_rule_achievement_snapshots.sql", import.meta.url),
      "utf8",
    );

    expect(versionSnapshotSql).toContain("UPDATE badge_issuance_rule_versions");
    expect(versionSnapshotSql).toContain("JOIN badge_templates");
    expect(versionSnapshotSql).toContain("ALTER COLUMN snapshot_name SET NOT NULL");
    expect(versionSnapshotSql).toContain("badge_rule_version_snapshot_lms_provider_kind_check");
    expect(versionSnapshotSql).not.toContain("DEFAULT ''");
    expect(achievementSnapshotSql).toContain(
      "requires empty badge rule version and assertion tables",
    );
  });

  it("snapshots every credential-bearing badge template field for governed versions", () => {
    const sql = readFileSync(
      new URL("../migrations/0063_badge_rule_achievement_snapshots.sql", import.meta.url),
      "utf8",
    );

    expect(sql).toContain("snapshot_badge_template_description");
    expect(sql).toContain("snapshot_badge_template_criteria_uri");
    expect(sql).toContain("snapshot_badge_template_trusted_credential_metadata_json");
    expect(sql).toContain("achievement_snapshot_json TEXT NOT NULL");
    expect(sql).toContain("assertions_achievement_snapshot_template_check");
    expect(sql).toContain("assertion_issuance_provenance_source_shape_check");
    expect(sql).toContain("FOREIGN KEY (tenant_id, rule_id, version_id)");
    expect(sql).toContain("REFERENCES badge_issuance_rule_versions (tenant_id, rule_id, id)");
    expect(sql).toContain("ON DELETE RESTRICT");
    expect(sql).not.toContain("JOIN badge_templates");
    expect(sql).not.toContain("UPDATE assertions");
  });
});

const sampleBadgeIssuanceRuleVersionRow = (): BadgeIssuanceRuleVersionRow => ({
  id: "brv_123",
  tenantId: "tenant_123",
  ruleId: "bir_123",
  versionNumber: 1,
  status: "draft",
  ruleJson: '{"all":[]}',
  snapshotName: "Course completion",
  snapshotDescription: null,
  snapshotBadgeTemplateId: "badge_template_123",
  snapshotBadgeTemplateTitle: "Course badge",
  snapshotBadgeTemplateDescription: "Course badge description",
  snapshotBadgeTemplateCriteriaUri: "https://example.edu/criteria/course-badge",
  snapshotBadgeTemplateImageUri: null,
  snapshotBadgeTemplateTrustedCredentialMetadataJson: null,
  snapshotOrgUnitId: "org_course_123",
  snapshotOwnerOrgUnitId: "org_department_123",
  snapshotLmsProviderKind: "sakai",
  snapshotLmsConnectionId: "lms_connection_123",
  changeSummary: null,
  createdByUserId: "user_123",
  submittedByUserId: null,
  submittedAt: null,
  approvedByUserId: null,
  approvedAt: null,
  activatedByUserId: null,
  activatedAt: null,
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
  createdAt: "2026-08-07T12:00:00.000Z",
  updatedAt: "2026-08-07T12:00:00.000Z",
});

describe("mapBadgeIssuanceRuleVersionRow", () => {
  it("rejects a blank required snapshot field", () => {
    expect(() =>
      mapBadgeIssuanceRuleVersionRow({
        ...sampleBadgeIssuanceRuleVersionRow(),
        snapshotName: "   ",
      }),
    ).toThrow("Stored badge-rule snapshot text must not be blank");
  });

  it("rejects an unknown stored LMS provider", () => {
    expect(() =>
      mapBadgeIssuanceRuleVersionRow({
        ...sampleBadgeIssuanceRuleVersionRow(),
        snapshotLmsProviderKind: "unknown_lms",
      }),
    ).toThrow("Invalid option");
  });
});

describe("batch badge rule reads", () => {
  it("does not query when no rule or version IDs are requested", async () => {
    const db = {
      prepare(): never {
        throw new Error("Empty batch reads must not prepare SQL");
      },
    } satisfies SqlDatabase;

    await expect(
      Promise.all([
        dbModule.listBadgeIssuanceRuleVersionsForRules(db, {
          tenantId: "tenant_123",
          ruleIds: [],
        }),
        dbModule.listBadgeIssuanceRuleVersionApprovalStepsForVersions(db, {
          tenantId: "tenant_123",
          versionIds: [],
        }),
        dbModule.listBadgeIssuanceRuleVersionApprovalEventsForVersions(db, {
          tenantId: "tenant_123",
          versionIds: [],
        }),
      ]),
    ).resolves.toEqual([[], [], []]);
  });
});

describe("resolveListBadgeIssuanceRulesInput", () => {
  it("returns an empty scope for non-admin members with no org-unit memberships", async () => {
    const localSuccessfulRunResult: SqlRunResult = {
      success: true,
      meta: {
        rowsRead: 0,
        rowsWritten: 0,
      },
    };
    const db: SqlDatabase = {
      prepare() {
        return {
          bind() {
            return this;
          },
          async first<T>() {
            return null as T | null;
          },
          async all<T>() {
            return {
              ...localSuccessfulRunResult,
              results: [] as T[],
            } satisfies SqlQueryResult<T>;
          },
          async run() {
            return localSuccessfulRunResult;
          },
        };
      },
    };

    await expect(
      dbModule.resolveListBadgeIssuanceRulesInput(db, {
        tenantId: "tenant_123",
        userId: "usr_approver",
        membershipRole: "approver",
      }),
    ).resolves.toEqual({
      tenantId: "tenant_123",
      scope: {
        type: "descendants",
        rootOrgUnitIds: [],
      },
    });
  });
});

describe("badge issuance rule draft predicates", () => {
  const sampleRule = (
    overrides?: Partial<dbModule.BadgeIssuanceRuleRecord>,
  ): dbModule.BadgeIssuanceRuleRecord => {
    return {
      id: "brl_123",
      tenantId: "tenant_123",
      name: "CS101 Rule",
      description: "Award for CS101 completion.",
      badgeTemplateId: "badge_template_123",
      orgUnitId: "tenant_123:org:institution",
      ownerOrgUnitId: "tenant_123:org:institution",
      lmsProviderKind: "canvas",
      lmsConnectionId: "lms_123",
      activeVersionId: null,
      createdByUserId: "usr_admin",
      createdAt: "2026-02-18T12:00:00.000Z",
      updatedAt: "2026-02-18T12:00:00.000Z",
      ...overrides,
    };
  };
  const sampleVersionSnapshot: dbModule.BadgeIssuanceRuleVersionSnapshot = {
    name: "CS101 Rule",
    description: "Award for CS101 completion.",
    badgeTemplateId: "badge_template_123",
    badgeTemplateTitle: "CS101 badge",
    badgeTemplateDescription: "CS101 badge description",
    badgeTemplateCriteriaUri: "https://example.edu/criteria/cs101",
    badgeTemplateImageUri: null,
    badgeTemplateTrustedCredentialMetadataJson: null,
    orgUnitId: "tenant_123:org:institution",
    ownerOrgUnitId: "tenant_123:org:institution",
    lmsProviderKind: "canvas",
    lmsConnectionId: "lms_123",
  };
  const sampleVersion = (
    overrides?: Partial<dbModule.BadgeIssuanceRuleVersionRecord>,
  ): dbModule.BadgeIssuanceRuleVersionRecord => {
    return {
      id: "brv_123",
      tenantId: "tenant_123",
      ruleId: "brl_123",
      versionNumber: 1,
      status: "draft",
      ruleJson: '{"conditions":{"type":"grade_threshold","courseId":"course_101","minScore":80}}',
      snapshot: sampleVersionSnapshot,
      changeSummary: "Initial draft",
      createdByUserId: "usr_admin",
      submittedByUserId: null,
      submittedAt: null,
      approvedByUserId: null,
      approvedAt: null,
      activatedByUserId: null,
      activatedAt: null,
      createdAt: "2026-02-18T12:00:00.000Z",
      updatedAt: "2026-02-18T12:00:00.000Z",
      ...overrides,
      effectiveStartsAt: overrides?.effectiveStartsAt ?? null,
      expiresAt: overrides?.expiresAt ?? null,
      expiredAt: overrides?.expiredAt ?? null,
      suspendedAt: overrides?.suspendedAt ?? null,
      suspendedByUserId: overrides?.suspendedByUserId ?? null,
      suspensionReason: overrides?.suspensionReason ?? null,
      recertifiedAt: overrides?.recertifiedAt ?? null,
      recertificationDueAt: overrides?.recertificationDueAt ?? null,
      expiryReminderSentAt: overrides?.expiryReminderSentAt ?? null,
      recertificationReminderSentAt: overrides?.recertificationReminderSentAt ?? null,
    };
  };

  it("uses shared editability helpers for draft, rejected, pending, and historical rules", () => {
    const neverActiveRule = sampleRule();
    const historicalRule = sampleRule({
      activeVersionId: "brv_active",
    });

    expect(
      dbModule.canEditBadgeIssuanceRuleDraft(neverActiveRule, [
        sampleVersion({
          id: "brv_rejected",
          versionNumber: 2,
          status: "rejected",
        }),
        sampleVersion({
          id: "brv_draft",
          versionNumber: 1,
          status: "draft",
        }),
      ]),
    ).toBe(true);
    expect(
      dbModule.canEditBadgeIssuanceRuleDraft(neverActiveRule, [
        sampleVersion({
          id: "brv_pending",
          versionNumber: 2,
          status: "pending_approval",
        }),
        sampleVersion({
          id: "brv_rejected",
          versionNumber: 1,
          status: "rejected",
        }),
      ]),
    ).toBe(false);
    expect(
      dbModule.canDeleteBadgeIssuanceRuleDraft(historicalRule, [
        sampleVersion({
          id: "brv_rejected",
          versionNumber: 2,
          status: "rejected",
        }),
        sampleVersion({
          id: "brv_active",
          versionNumber: 1,
          status: "active",
        }),
      ]),
    ).toBe(false);
  });

  it("indexes each rule's versions newest first without mutating the input", () => {
    const versions = [
      sampleVersion({ id: "brv_alpha_1", ruleId: "brl_alpha", versionNumber: 1 }),
      sampleVersion({ id: "brv_beta_1", ruleId: "brl_beta", versionNumber: 1 }),
      sampleVersion({ id: "brv_alpha_3", ruleId: "brl_alpha", versionNumber: 3 }),
      sampleVersion({ id: "brv_alpha_2", ruleId: "brl_alpha", versionNumber: 2 }),
    ];

    const indexed = dbModule.indexBadgeIssuanceRuleVersionsByRuleId(versions);

    expect(indexed.get("brl_alpha")?.map((version) => version.id)).toEqual([
      "brv_alpha_3",
      "brv_alpha_2",
      "brv_alpha_1",
    ]);
    expect(indexed.get("brl_beta")?.map((version) => version.id)).toEqual(["brv_beta_1"]);
    expect(versions.map((version) => version.id)).toEqual([
      "brv_alpha_1",
      "brv_beta_1",
      "brv_alpha_3",
      "brv_alpha_2",
    ]);
  });
});

describe("badge issuance rule approval transactions", () => {
  const successfulRunResult: SqlRunResult = {
    success: true,
    meta: {
      rowsWritten: 1,
    },
  };
  const sampleVersionSnapshotRow = {
    snapshotName: "CS101 Rule",
    snapshotDescription: null,
    snapshotBadgeTemplateId: "badge_template_123",
    snapshotBadgeTemplateTitle: "CS101 Badge",
    snapshotBadgeTemplateDescription: "CS101 badge description",
    snapshotBadgeTemplateCriteriaUri: "https://example.edu/criteria/cs101",
    snapshotBadgeTemplateImageUri: null,
    snapshotBadgeTemplateTrustedCredentialMetadataJson: null,
    snapshotOrgUnitId: "tenant_123:org:institution",
    snapshotOwnerOrgUnitId: "tenant_123:org:institution",
    snapshotLmsProviderKind: "canvas",
    snapshotLmsConnectionId: "lms_123",
  } as const;

  const createRecordedStatement = (
    sql: string,
    writes: string[],
    reads: string[],
    isTransaction: boolean,
  ): SqlPreparedStatement => {
    const normalizedSql = sql.replace(/\s+/g, " ").trim();

    return {
      bind() {
        return this;
      },
      async first<T>() {
        if (normalizedSql.includes("FROM audit_logs")) {
          return {
            id: "aud_123",
            tenantId: "tenant_123",
            actorUserId: "usr_admin",
            action: "badge_rule.version_submitted_for_approval",
            targetType: "badge_rule_version",
            targetId: "brv_123",
            metadataJson: "{}",
            occurredAt: "2026-02-18T12:30:00.000Z",
            createdAt: "2026-02-18T12:30:00.000Z",
          } as T;
        }

        if (normalizedSql.includes("INSERT INTO job_queue_messages")) {
          writes.push(`${isTransaction ? "transaction" : "outer"}:${normalizedSql}`);
          return { id: "job_123" } as T;
        }

        if (normalizedSql.includes("FROM badge_issuance_rule_versions")) {
          return {
            id: "brv_123",
            tenantId: "tenant_123",
            ruleId: "brl_123",
            versionNumber: 1,
            status: "draft",
            ruleJson: "{}",
            ...sampleVersionSnapshotRow,
            changeSummary: null,
            createdByUserId: "usr_admin",
            approvedByUserId: null,
            approvedAt: null,
            activatedByUserId: null,
            activatedAt: null,
            createdAt: "2026-02-18T12:00:00.000Z",
            updatedAt: "2026-02-18T12:00:00.000Z",
          } as T;
        }

        if (normalizedSql.includes("FROM badge_issuance_rules")) {
          return {
            id: "brl_123",
            tenantId: "tenant_123",
            name: "CS101 Rule",
            description: null,
            badgeTemplateId: "badge_template_123",
            orgUnitId: "tenant_123:org:institution",
            ownerOrgUnitId: "tenant_123:org:institution",
            lmsProviderKind: "canvas",
            lmsConnectionId: "lms_123",
            activeVersionId: null,
            createdByUserId: "usr_admin",
            createdAt: "2026-02-18T12:00:00.000Z",
            updatedAt: "2026-02-18T12:00:00.000Z",
          } as T;
        }

        if (normalizedSql.includes("FROM badge_rule_approval_policies")) {
          return {
            id: "brap_123",
            tenantId: "tenant_123",
            orgUnitId: "tenant_123:org:institution",
            approvalRequirement: "always",
            allowSelfCertification: false,
            recertificationIntervalMonths: null,
            approvalStepsJson: JSON.stringify([
              {
                requiredRole: "admin",
                label: "Registrar review",
              },
            ]),
            createdByUserId: "usr_admin",
            createdAt: "2026-02-18T12:00:00.000Z",
            updatedAt: "2026-02-18T12:00:00.000Z",
          } as T;
        }

        return null;
      },
      async all<T>() {
        reads.push(`${isTransaction ? "transaction" : "outer"}:${normalizedSql}`);
        const results = normalizedSql.includes("FROM badge_issuance_rule_approval_steps")
          ? [
              {
                id: "bras_123",
                tenantId: "tenant_123",
                versionId: "brv_123",
                stepNumber: 1,
                requiredRole: "admin",
                label: "Registrar review",
                status: "queued",
                decidedByUserId: null,
                decidedAt: null,
                decisionComment: null,
                createdAt: "2026-02-18T12:00:00.000Z",
                updatedAt: "2026-02-18T12:00:00.000Z",
              },
            ]
          : [];

        return {
          ...successfulRunResult,
          results: results as T[],
        } satisfies SqlQueryResult<T>;
      },
      async run() {
        if (
          normalizedSql.includes("badge_issuance_rule_approval_steps") ||
          normalizedSql.includes("audit_logs")
        ) {
          writes.push(`${isTransaction ? "transaction" : "outer"}:${normalizedSql}`);
        }

        return successfulRunResult;
      },
    };
  };

  it("materializes submit approval writes inside one SQL transaction", async () => {
    const writes: string[] = [];
    const reads: string[] = [];
    let transactionCallCount = 0;
    const transaction = async <T>(callback: (db: SqlDatabase) => Promise<T>): Promise<T> => {
      transactionCallCount += 1;
      const transactionDb: SqlDatabase = {
        prepare(sql) {
          return createRecordedStatement(sql, writes, reads, true);
        },
      };

      return callback(transactionDb);
    };
    const db: SqlDatabase = {
      prepare(sql) {
        return createRecordedStatement(sql, writes, reads, false);
      },
      transaction,
    };

    await dbModule.submitBadgeIssuanceRuleVersionForApproval(db, {
      tenantId: "tenant_123",
      ruleId: "brl_123",
      versionId: "brv_123",
      actorUserId: "usr_admin",
      actorRole: "admin",
      occurredAt: "2026-02-18T12:30:00.000Z",
    });

    expect(transactionCallCount).toBe(1);
    expect(writes.some((entry) => entry.startsWith("outer:"))).toBe(false);
    expect(
      writes.some(
        (entry) =>
          entry.startsWith("transaction:") &&
          entry.includes("DELETE FROM badge_issuance_rule_approval_steps"),
      ),
    ).toBe(true);
    expect(reads.some((entry) => entry.includes("FROM badge_issuance_rule_approval_steps"))).toBe(
      false,
    );
    expect(writes.some((entry) => entry.includes("INSERT INTO audit_logs"))).toBe(true);
    expect(writes.some((entry) => entry.includes("INSERT INTO job_queue_messages"))).toBe(true);
  });

  it("records approval decisions inside one SQL transaction", async () => {
    const writes: string[] = [];
    const reads: string[] = [];
    let versionStatus: dbModule.BadgeIssuanceRuleVersionStatus = "pending_approval";
    let transactionCallCount = 0;
    const createDecisionStatement = (sql: string, isTransaction: boolean): SqlPreparedStatement => {
      const normalizedSql = sql.replace(/\s+/g, " ").trim();

      return {
        bind() {
          return this;
        },
        async first<T>() {
          if (normalizedSql.includes("FROM audit_logs")) {
            return {
              id: "aud_123",
              tenantId: "tenant_123",
              actorUserId: "usr_reviewer",
              action: "badge_rule.version_approval_decided",
              targetType: "badge_rule_version",
              targetId: "brv_123",
              metadataJson: "{}",
              occurredAt: "2026-02-18T12:30:00.000Z",
              createdAt: "2026-02-18T12:30:00.000Z",
            } as T;
          }

          if (normalizedSql.includes("INSERT INTO job_queue_messages")) {
            writes.push(`${isTransaction ? "transaction" : "outer"}:${normalizedSql}`);
            return { id: "job_123" } as T;
          }

          if (normalizedSql.includes("FROM badge_issuance_rules")) {
            reads.push(`${isTransaction ? "transaction" : "outer"}:${normalizedSql}`);
            return {
              id: "brl_123",
              tenantId: "tenant_123",
              name: "Approval rule",
              description: null,
              badgeTemplateId: "badge_template_123",
              orgUnitId: "org_123",
              ownerOrgUnitId: "org_123",
              lmsProviderKind: "canvas",
              lmsConnectionId: "lms_123",
              activeVersionId: null,
              createdByUserId: "usr_admin",
              createdAt: "2026-02-18T12:00:00.000Z",
              updatedAt: "2026-02-18T12:00:00.000Z",
            } as T;
          }

          if (normalizedSql.includes("FROM badge_issuance_rule_versions")) {
            reads.push(`${isTransaction ? "transaction" : "outer"}:${normalizedSql}`);
            return {
              id: "brv_123",
              tenantId: "tenant_123",
              ruleId: "brl_123",
              versionNumber: 1,
              status: versionStatus,
              ruleJson: "{}",
              ...sampleVersionSnapshotRow,
              changeSummary: null,
              createdByUserId: "usr_admin",
              submittedByUserId: "usr_submitter",
              submittedAt: "2026-02-18T12:10:00.000Z",
              approvedByUserId: null,
              approvedAt: null,
              activatedByUserId: null,
              activatedAt: null,
              createdAt: "2026-02-18T12:00:00.000Z",
              updatedAt: "2026-02-18T12:00:00.000Z",
            } as T;
          }

          return null;
        },
        async all<T>() {
          const results = normalizedSql.includes("FROM badge_issuance_rule_approval_steps")
            ? [
                {
                  id: "bras_123",
                  tenantId: "tenant_123",
                  versionId: "brv_123",
                  stepNumber: 1,
                  targetType: "role_threshold",
                  requiredRole: "admin",
                  targetUserId: null,
                  targetApproverGroupId: null,
                  orgUnitId: null,
                  label: "Registrar review",
                  status: "pending",
                  decidedByUserId: null,
                  decidedAt: null,
                  decisionComment: null,
                  createdAt: "2026-02-18T12:00:00.000Z",
                  updatedAt: "2026-02-18T12:00:00.000Z",
                },
              ]
            : [];

          return {
            ...successfulRunResult,
            results: results as T[],
          } satisfies SqlQueryResult<T>;
        },
        async run() {
          if (
            normalizedSql.includes("badge_issuance_rule_approval_steps") ||
            normalizedSql.includes("badge_issuance_rule_versions") ||
            normalizedSql.includes("badge_issuance_rule_approval_events") ||
            normalizedSql.includes("audit_logs")
          ) {
            writes.push(`${isTransaction ? "transaction" : "outer"}:${normalizedSql}`);
          }

          if (
            normalizedSql.includes("UPDATE badge_issuance_rule_versions SET status = 'approved'")
          ) {
            versionStatus = "approved";
          }

          return successfulRunResult;
        },
      };
    };
    const transaction = async <T>(callback: (db: SqlDatabase) => Promise<T>): Promise<T> => {
      transactionCallCount += 1;
      const transactionDb: SqlDatabase = {
        prepare(sql) {
          return createDecisionStatement(sql, true);
        },
      };

      return callback(transactionDb);
    };
    const db: SqlDatabase = {
      prepare(sql) {
        return createDecisionStatement(sql, false);
      },
      transaction,
    };

    const decided = await dbModule.decideBadgeIssuanceRuleVersion(db, {
      tenantId: "tenant_123",
      ruleId: "brl_123",
      versionId: "brv_123",
      decision: "approved",
      actorUserId: "usr_reviewer",
      actorRole: "admin",
      occurredAt: "2026-02-18T12:30:00.000Z",
    });

    expect(decided.status).toBe("decided");
    expect(decided).toMatchObject({
      status: "decided",
      version: { status: "approved" },
    });
    expect(transactionCallCount).toBe(1);
    expect(writes.some((entry) => entry.startsWith("outer:"))).toBe(false);
    expect(writes.some((entry) => entry.includes("UPDATE badge_issuance_rule_versions"))).toBe(
      true,
    );
    expect(
      writes.some((entry) => entry.includes("INSERT INTO badge_issuance_rule_approval_events")),
    ).toBe(true);
    expect(writes.some((entry) => entry.includes("INSERT INTO audit_logs"))).toBe(true);
    expect(writes.some((entry) => entry.includes("INSERT INTO job_queue_messages"))).toBe(true);
    expect(
      reads.some(
        (entry) =>
          entry.startsWith("transaction:") &&
          entry.includes("FROM badge_issuance_rule_versions") &&
          entry.includes("FOR UPDATE"),
      ),
    ).toBe(true);
  });
});

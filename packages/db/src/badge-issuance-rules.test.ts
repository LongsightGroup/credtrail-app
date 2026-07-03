import { readFileSync } from "node:fs";

import { describe, expect, it } from "vitest";

import * as dbModule from "./index";
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
    const sql = readFileSync(
      new URL("../migrations/0050_badge_rule_approval_policies.sql", import.meta.url),
      "utf8",
    );

    expect(sql).toContain("ADD COLUMN IF NOT EXISTS owner_org_unit_id TEXT");
    expect(sql).toContain("Snapshot of the selected badge template owner org unit");
    expect(sql).toContain("CREATE TABLE IF NOT EXISTS badge_rule_approval_policies");
    expect(sql).toContain("approval_requirement TEXT NOT NULL");
    expect(sql).toContain("approval_steps_json TEXT NOT NULL");
    expect(sql).toContain("idx_badge_rule_approval_policies_tenant_default");
    expect(sql).toContain("idx_badge_rule_approval_policies_tenant_org_unit");
    expect(sql).toContain("tenants.id || ':badge-rule-approval-policy:default'");
    expect(sql).toContain('\'[{"requiredRole":"admin","label":"Administrative approval"}]\'');
    expect(sql).toContain("ON CONFLICT DO NOTHING");
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
});

describe("badge issuance rule approval transactions", () => {
  const successfulRunResult: SqlRunResult = {
    success: true,
    meta: {
      rowsWritten: 1,
    },
  };

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
        if (normalizedSql.includes("FROM badge_issuance_rule_versions")) {
          return {
            id: "brv_123",
            tenantId: "tenant_123",
            ruleId: "brl_123",
            versionNumber: 1,
            status: "draft",
            ruleJson: "{}",
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
        if (normalizedSql.includes("badge_issuance_rule_approval_steps")) {
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
  });

  it("records approval decisions inside one SQL transaction", async () => {
    const writes: string[] = [];
    let versionStatus: dbModule.BadgeIssuanceRuleVersionStatus = "pending_approval";
    let transactionCallCount = 0;
    const createDecisionStatement = (sql: string, isTransaction: boolean): SqlPreparedStatement => {
      const normalizedSql = sql.replace(/\s+/g, " ").trim();

      return {
        bind() {
          return this;
        },
        async first<T>() {
          if (normalizedSql.includes("FROM badge_issuance_rule_versions")) {
            return {
              id: "brv_123",
              tenantId: "tenant_123",
              ruleId: "brl_123",
              versionNumber: 1,
              status: versionStatus,
              ruleJson: "{}",
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
            normalizedSql.includes("badge_issuance_rule_approval_events")
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
  });
});

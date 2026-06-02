/* oxlint-disable no-unused-vars */
import { readFileSync } from "node:fs";

import { describe, expect, it } from "vitest";
import * as dbModule from "./index";
import * as validationModule from "../../validation/src/index";

import {
  ASSERTION_ENGAGEMENT_EVENT_TYPES,
  addLearnerIdentityAlias,
  type AccessibleTenantContextRecord,
  countTenantMembershipsByRole,
  createLearnerRecordImportContext,
  createLearnerRecordEntry,
  createTenantAuthProvider,
  createAuthIdentityLink,
  createLearnerProfile,
  enqueueJobQueueMessageOnce,
  findActiveTenantBreakGlassAccountByEmail,
  findLearnerRecordImportContextByEntryId,
  listLearnerRecordEntries,
  listLearnerRecordAssertionExports,
  listImportLearnerRecordBatchQueueMessages,
  findTenantAuthPolicy,
  listAccessibleTenantContextsForUser,
  listTenantAuthProviders,
  listTenantMembers,
  findLearnerProfileByIdentity,
  findTenantAuthProviderById,
  findAuthIdentityLinkByAuthUserId,
  findAuthIdentityLinkByCredtrailUserId,
  findUserByEmail,
  listTenantBreakGlassAccounts,
  listLearnerIdentitiesByProfile,
  markLearnerRecordImportPreviewQueued,
  markTenantBreakGlassAccountUsed,
  markTenantBreakGlassEnrollmentEmailSent,
  normalizeLearnerIdentityValue,
  patchLearnerRecordEntry,
  removeTenantMembership,
  retryFailedImportLearnerRecordBatchQueueMessages,
  revokeTenantBreakGlassAccount,
  resolveTenantAuthPolicy,
  resolveLearnerProfileForIdentity,
  resolveLearnerProfileFromSaml,
  resolveAssertionReportingAttribution,
  summarizeTenantExecutiveRollup,
  summarizeTenantReportingComparisonRows,
  summarizeTenantReportingOverviewRows,
  summarizeTenantReportingTrendRows,
  updateTenantAuthProvider,
  upsertTenantMembershipRole,
  upsertTenantBreakGlassAccount,
  upsertTenantAuthPolicy,
  upsertUserByEmail,
  type LearnerIdentityType,
  type SqlDatabase,
  type SqlExecutionMeta,
  type SqlPreparedStatement,
  type SqlQueryResult,
  type SqlRunResult,
} from "./index";
import { REPORTING_METRIC_DEFINITIONS } from "../../../apps/api-worker/src/reporting/metric-definitions";

import {
  createFakeAuthIdentityDb,
  createFakeDb,
  createFakeTenantAuthDb,
  type FakeSqlDatabase,
} from "./test-support";

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
});

type FakeBadgeRuleApprovalStepRow = Pick<
  dbModule.BadgeIssuanceRuleApprovalStepRecord,
  "id" | "tenantId" | "versionId" | "stepNumber" | "requiredRole" | "label" | "status"
> & {
  createdAt: string;
  updatedAt: string;
};

class FakeBadgeRuleStatement implements SqlPreparedStatement {
  private readonly db: FakeBadgeRuleSqlDatabase;
  private readonly sql: string;
  private boundParams: unknown[] = [];

  constructor(db: FakeBadgeRuleSqlDatabase, sql: string) {
    this.db = db;
    this.sql = sql;
  }

  bind(...params: unknown[]): SqlPreparedStatement {
    this.boundParams = params;
    return this;
  }

  async run(): Promise<SqlRunResult> {
    const normalizedSql = this.normalizedSql();

    if (normalizedSql === "BEGIN" || normalizedSql === "COMMIT" || normalizedSql === "ROLLBACK") {
      return this.successResult();
    }

    if (normalizedSql.includes("UPDATE badge_issuance_rules SET name = ?")) {
      this.updateBadgeRule();
      return this.successResult(1);
    }

    if (normalizedSql.includes("INSERT INTO badge_issuance_rule_versions")) {
      this.insertBadgeRuleVersion();
      return this.successResult(1);
    }

    if (normalizedSql.includes("INSERT INTO badge_issuance_rule_approval_steps")) {
      this.insertApprovalStep();
      return this.successResult(1);
    }

    if (normalizedSql.includes("DELETE FROM badge_issuance_rules")) {
      const deleted = this.deleteBadgeRule();
      return this.successResult(deleted ? 1 : 0);
    }

    throw new Error(`Unsupported badge rule fake run SQL: ${normalizedSql}`);
  }

  async first<T>(): Promise<T | null> {
    const normalizedSql = this.normalizedSql();

    if (normalizedSql.includes("SELECT MAX(version_number) AS maxVersionNumber")) {
      return this.maxRuleVersionNumber() as T;
    }

    if (
      normalizedSql.includes("FROM badge_issuance_rule_versions") &&
      normalizedSql.includes("AND id = ?")
    ) {
      return (this.selectBadgeRuleVersionById() as T | undefined) ?? null;
    }

    if (
      normalizedSql.includes("FROM badge_issuance_rules") &&
      normalizedSql.includes("WHERE tenant_id = ?") &&
      normalizedSql.includes("AND id = ?")
    ) {
      return (this.selectBadgeRuleById() as T | undefined) ?? null;
    }

    throw new Error(`Unsupported badge rule fake first SQL: ${normalizedSql}`);
  }

  async all<T>(): Promise<SqlQueryResult<T>> {
    const normalizedSql = this.normalizedSql();

    if (
      normalizedSql.includes("FROM badge_issuance_rule_versions") &&
      normalizedSql.includes("ORDER BY version_number DESC")
    ) {
      return this.queryResult(this.selectBadgeRuleVersions() as T[]);
    }

    throw new Error(`Unsupported badge rule fake all SQL: ${normalizedSql}`);
  }

  private normalizedSql(): string {
    return this.sql.trim().replace(/\s+/g, " ");
  }

  private successResult(rowsWritten = 0): SqlRunResult {
    return {
      success: true,
      meta: {
        rowsWritten,
      } satisfies SqlExecutionMeta,
    };
  }

  private queryResult<T>(results: T[]): SqlQueryResult<T> {
    return {
      success: true,
      meta: {
        rowsRead: results.length,
      },
      results,
    };
  }

  private updateBadgeRule(): void {
    const [
      name,
      description,
      badgeTemplateId,
      lmsProviderKind,
      lmsConnectionId,
      updatedAt,
      tenantId,
      ruleId,
    ] = this.boundParams;
    const rule = this.db.badgeRules.find(
      (candidate) => candidate.tenantId === tenantId && candidate.id === ruleId,
    );

    if (rule === undefined) {
      return;
    }

    rule.name = String(name);
    rule.description = typeof description === "string" ? description : null;
    rule.badgeTemplateId = String(badgeTemplateId);
    rule.lmsProviderKind = lmsProviderKind as dbModule.BadgeIssuanceRuleLmsProviderKind;
    rule.lmsConnectionId = String(lmsConnectionId);
    rule.updatedAt = String(updatedAt);
  }

  private insertBadgeRuleVersion(): void {
    if (this.db.failOnVersionInsert) {
      throw new Error("Simulated badge rule version insert failure");
    }

    const [
      id,
      tenantId,
      ruleId,
      versionNumber,
      ruleJson,
      changeSummary,
      createdByUserId,
      createdAt,
      updatedAt,
    ] = this.boundParams;

    this.db.badgeRuleVersions.push({
      id: String(id),
      tenantId: String(tenantId),
      ruleId: String(ruleId),
      versionNumber: Number(versionNumber),
      status: "draft",
      ruleJson: String(ruleJson),
      changeSummary: typeof changeSummary === "string" ? changeSummary : null,
      createdByUserId: typeof createdByUserId === "string" ? createdByUserId : null,
      approvedByUserId: null,
      approvedAt: null,
      activatedByUserId: null,
      activatedAt: null,
      createdAt: String(createdAt),
      updatedAt: String(updatedAt),
    });
  }

  private insertApprovalStep(): void {
    const [id, tenantId, versionId, stepNumber, requiredRole, label, createdAt, updatedAt] =
      this.boundParams;

    this.db.approvalSteps.push({
      id: String(id),
      tenantId: String(tenantId),
      versionId: String(versionId),
      stepNumber: Number(stepNumber),
      requiredRole: requiredRole as dbModule.TenantMembershipRole,
      label: typeof label === "string" ? label : null,
      status: "queued",
      createdAt: String(createdAt),
      updatedAt: String(updatedAt),
    });
  }

  private deleteBadgeRule(): boolean {
    const [tenantId, ruleId] = this.boundParams;
    const beforeCount = this.db.badgeRules.length;
    const deletedVersionIds = new Set(
      this.db.badgeRuleVersions
        .filter((version) => version.tenantId === tenantId && version.ruleId === ruleId)
        .map((version) => version.id),
    );

    this.db.badgeRules = this.db.badgeRules.filter(
      (rule) => !(rule.tenantId === tenantId && rule.id === ruleId),
    );
    this.db.badgeRuleVersions = this.db.badgeRuleVersions.filter(
      (version) => !(version.tenantId === tenantId && version.ruleId === ruleId),
    );
    this.db.approvalSteps = this.db.approvalSteps.filter(
      (step) => !deletedVersionIds.has(step.versionId),
    );

    return this.db.badgeRules.length < beforeCount;
  }

  private selectBadgeRuleById(): dbModule.BadgeIssuanceRuleRecord | undefined {
    const [tenantId, ruleId] = this.boundParams;
    const rule = this.db.badgeRules.find(
      (candidate) => candidate.tenantId === tenantId && candidate.id === ruleId,
    );

    return rule === undefined ? undefined : { ...rule };
  }

  private selectBadgeRuleVersionById(): dbModule.BadgeIssuanceRuleVersionRecord | undefined {
    const [tenantId, ruleId, versionId] = this.boundParams;
    const version = this.db.badgeRuleVersions.find(
      (candidate) =>
        candidate.tenantId === tenantId &&
        candidate.ruleId === ruleId &&
        candidate.id === versionId,
    );

    return version === undefined ? undefined : { ...version };
  }

  private selectBadgeRuleVersions(): dbModule.BadgeIssuanceRuleVersionRecord[] {
    const [tenantId, ruleId] = this.boundParams;

    return this.db.badgeRuleVersions
      .filter((version) => version.tenantId === tenantId && version.ruleId === ruleId)
      .sort((left, right) => right.versionNumber - left.versionNumber)
      .map((version) => ({ ...version }));
  }

  private maxRuleVersionNumber(): { maxVersionNumber: number | null } {
    const versions = this.selectBadgeRuleVersions();
    const maxVersionNumber = versions[0]?.versionNumber ?? null;

    return { maxVersionNumber };
  }
}

class FakeBadgeRuleSqlDatabase implements SqlDatabase {
  badgeRules: dbModule.BadgeIssuanceRuleRecord[] = [];
  badgeRuleVersions: dbModule.BadgeIssuanceRuleVersionRecord[] = [];
  approvalSteps: FakeBadgeRuleApprovalStepRow[] = [];
  failOnVersionInsert = false;
  transactionCount = 0;
  rollbackCount = 0;
  commitCount = 0;

  prepare(sql: string): SqlPreparedStatement {
    return new FakeBadgeRuleStatement(this, sql);
  }

  async transaction<T>(callback: (db: SqlDatabase) => Promise<T>): Promise<T> {
    const snapshot = {
      badgeRules: this.badgeRules.map((rule) => ({ ...rule })),
      badgeRuleVersions: this.badgeRuleVersions.map((version) => ({ ...version })),
      approvalSteps: this.approvalSteps.map((step) => ({ ...step })),
    };

    this.transactionCount += 1;

    try {
      const result = await callback(this);
      this.commitCount += 1;
      return result;
    } catch (error) {
      this.rollbackCount += 1;
      this.badgeRules = snapshot.badgeRules;
      this.badgeRuleVersions = snapshot.badgeRuleVersions;
      this.approvalSteps = snapshot.approvalSteps;
      throw error;
    }
  }
}

const sampleBadgeRule = (
  overrides?: Partial<dbModule.BadgeIssuanceRuleRecord>,
): dbModule.BadgeIssuanceRuleRecord => {
  return {
    id: "brl_123",
    tenantId: "tenant_123",
    name: "CS101 Rule",
    description: "Award for CS101 completion.",
    badgeTemplateId: "badge_template_123",
    lmsProviderKind: "canvas",
    lmsConnectionId: "lms_123",
    activeVersionId: null,
    createdByUserId: "usr_admin",
    createdAt: "2026-02-18T12:00:00.000Z",
    updatedAt: "2026-02-18T12:00:00.000Z",
    ...overrides,
  };
};

const sampleBadgeRuleVersion = (
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
    approvedByUserId: null,
    approvedAt: null,
    activatedByUserId: null,
    activatedAt: null,
    createdAt: "2026-02-18T12:00:00.000Z",
    updatedAt: "2026-02-18T12:00:00.000Z",
    ...overrides,
  };
};

describe("badge issuance rule draft DB helpers", () => {
  it("uses shared editability helpers for draft, rejected, pending, and historical rules", () => {
    const neverActiveRule = sampleBadgeRule();
    const historicalRule = sampleBadgeRule({
      activeVersionId: "brv_active",
    });

    expect(
      dbModule.canEditBadgeIssuanceRuleDraft(neverActiveRule, [
        sampleBadgeRuleVersion({
          id: "brv_rejected",
          versionNumber: 2,
          status: "rejected",
        }),
        sampleBadgeRuleVersion({
          id: "brv_draft",
          versionNumber: 1,
          status: "draft",
        }),
      ]),
    ).toBe(true);
    expect(
      dbModule.canEditBadgeIssuanceRuleDraft(neverActiveRule, [
        sampleBadgeRuleVersion({
          id: "brv_pending",
          versionNumber: 2,
          status: "pending_approval",
        }),
        sampleBadgeRuleVersion({
          id: "brv_rejected",
          versionNumber: 1,
          status: "rejected",
        }),
      ]),
    ).toBe(false);
    expect(
      dbModule.canDeleteBadgeIssuanceRuleDraft(historicalRule, [
        sampleBadgeRuleVersion({
          id: "brv_rejected",
          versionNumber: 2,
          status: "rejected",
        }),
        sampleBadgeRuleVersion({
          id: "brv_active",
          versionNumber: 1,
          status: "active",
        }),
      ]),
    ).toBe(false);
  });

  it("updates a rejected latest version by creating the next draft version", async () => {
    const db = new FakeBadgeRuleSqlDatabase();
    db.badgeRules = [sampleBadgeRule()];
    db.badgeRuleVersions = [
      sampleBadgeRuleVersion({
        id: "brv_rejected",
        status: "rejected",
      }),
    ];

    const result = await dbModule.updateBadgeIssuanceRuleDraft(db, {
      tenantId: "tenant_123",
      ruleId: "brl_123",
      name: "CS101 Rule Revised",
      description: "Updated description.",
      badgeTemplateId: "badge_template_456",
      lmsProviderKind: "canvas",
      lmsConnectionId: "lms_456",
      ruleJson: '{"conditions":{"type":"grade_threshold","courseId":"course_101","minScore":90}}',
      changeSummary: "Raise score threshold",
      createdByUserId: "usr_admin",
    });

    expect(result.status).toBe("updated");
    expect(result.status === "updated" ? result.version.versionNumber : null).toBe(2);
    expect(result.status === "updated" ? result.version.status : null).toBe("draft");
    expect(db.transactionCount).toBe(1);
    expect(db.commitCount).toBe(1);
    expect(db.badgeRules[0]?.name).toBe("CS101 Rule Revised");
    expect(db.badgeRules[0]?.badgeTemplateId).toBe("badge_template_456");
    expect(db.badgeRuleVersions).toHaveLength(2);
    expect(db.approvalSteps).toHaveLength(1);
  });

  it("blocks pending latest versions without changing metadata", async () => {
    const db = new FakeBadgeRuleSqlDatabase();
    db.badgeRules = [sampleBadgeRule()];
    db.badgeRuleVersions = [
      sampleBadgeRuleVersion({
        id: "brv_pending",
        status: "pending_approval",
      }),
    ];

    const result = await dbModule.updateBadgeIssuanceRuleDraft(db, {
      tenantId: "tenant_123",
      ruleId: "brl_123",
      name: "Should not save",
      badgeTemplateId: "badge_template_456",
      lmsProviderKind: "canvas",
      lmsConnectionId: "lms_456",
      ruleJson: '{"conditions":{"type":"grade_threshold","courseId":"course_101","minScore":90}}',
      createdByUserId: "usr_admin",
    });

    expect(result.status).toBe("not_editable");
    expect(db.transactionCount).toBe(0);
    expect(db.badgeRules[0]?.name).toBe("CS101 Rule");
    expect(db.badgeRuleVersions).toHaveLength(1);
  });

  it("rolls back metadata updates when draft version creation fails", async () => {
    const db = new FakeBadgeRuleSqlDatabase();
    db.badgeRules = [sampleBadgeRule()];
    db.badgeRuleVersions = [
      sampleBadgeRuleVersion({
        id: "brv_rejected",
        status: "rejected",
      }),
    ];
    db.failOnVersionInsert = true;

    await expect(
      dbModule.updateBadgeIssuanceRuleDraft(db, {
        tenantId: "tenant_123",
        ruleId: "brl_123",
        name: "Partially saved name",
        badgeTemplateId: "badge_template_456",
        lmsProviderKind: "canvas",
        lmsConnectionId: "lms_456",
        ruleJson: '{"conditions":{"type":"grade_threshold","courseId":"course_101","minScore":90}}',
        createdByUserId: "usr_admin",
      }),
    ).rejects.toThrow("Simulated badge rule version insert failure");

    expect(db.transactionCount).toBe(1);
    expect(db.rollbackCount).toBe(1);
    expect(db.badgeRules[0]?.name).toBe("CS101 Rule");
    expect(db.badgeRules[0]?.badgeTemplateId).toBe("badge_template_123");
    expect(db.badgeRuleVersions).toHaveLength(1);
  });

  it("blocks historical active rules from draft delete", async () => {
    const db = new FakeBadgeRuleSqlDatabase();
    db.badgeRules = [
      sampleBadgeRule({
        activeVersionId: "brv_active",
      }),
    ];
    db.badgeRuleVersions = [
      sampleBadgeRuleVersion({
        id: "brv_rejected",
        versionNumber: 2,
        status: "rejected",
      }),
      sampleBadgeRuleVersion({
        id: "brv_active",
        versionNumber: 1,
        status: "active",
        activatedByUserId: "usr_admin",
        activatedAt: "2026-02-18T12:30:00.000Z",
      }),
    ];

    const result = await dbModule.deleteDraftBadgeIssuanceRule(db, {
      tenantId: "tenant_123",
      ruleId: "brl_123",
    });

    expect(result.status).toBe("not_deletable");
    expect(db.badgeRules).toHaveLength(1);
    expect(db.badgeRuleVersions).toHaveLength(2);
  });

  it("deletes never-active draft and rejected rules with cascade", async () => {
    const db = new FakeBadgeRuleSqlDatabase();
    db.badgeRules = [sampleBadgeRule()];
    db.badgeRuleVersions = [
      sampleBadgeRuleVersion({
        id: "brv_rejected",
        versionNumber: 2,
        status: "rejected",
      }),
      sampleBadgeRuleVersion({
        id: "brv_draft",
        versionNumber: 1,
        status: "draft",
      }),
    ];
    db.approvalSteps = [
      {
        id: "bras_123",
        tenantId: "tenant_123",
        versionId: "brv_draft",
        stepNumber: 1,
        requiredRole: "admin",
        label: "Admin approval",
        status: "queued",
        createdAt: "2026-02-18T12:00:00.000Z",
        updatedAt: "2026-02-18T12:00:00.000Z",
      },
    ];

    const result = await dbModule.deleteDraftBadgeIssuanceRule(db, {
      tenantId: "tenant_123",
      ruleId: "brl_123",
    });

    expect(result.status).toBe("deleted");
    expect(db.badgeRules).toHaveLength(0);
    expect(db.badgeRuleVersions).toHaveLength(0);
    expect(db.approvalSteps).toHaveLength(0);
  });
});

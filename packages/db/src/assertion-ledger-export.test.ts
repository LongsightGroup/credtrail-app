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

describe("ledger export foundation", () => {
  type LedgerExportRow = {
    assertionId: string;
    tenantId: string;
    publicId: string | null;
    badgeTemplateId: string;
    badgeTitle: string;
    recipientIdentity: string;
    recipientIdentityType: "email" | "email_sha256" | "did" | "url";
    issuedAt: string;
    issuedByUserId: string | null;
    revokedAt: string | null;
    state: "active" | "suspended" | "revoked" | "expired";
    source: "default_active" | "assertion_revocation" | "lifecycle_event";
    reasonCode:
      | "administrative_hold"
      | "policy_violation"
      | "appeal_pending"
      | "appeal_resolved"
      | "credential_expired"
      | "issuer_requested"
      | "other"
      | null;
    reason: string | null;
    transitionedAt: string | null;
    orgUnitId: string;
    orgUnitDisplayName: string;
    attributionSource: "ownership_event" | "historical_backfill";
    currentInstitutionName: string | null;
    currentCollegeName: string | null;
    currentDepartmentName: string | null;
    currentProgramName: string | null;
  };

  type LedgerExportResult =
    | {
        status: "ok";
        rowLimit: number;
        rows: LedgerExportRow[];
      }
    | {
        status: "too_large";
        rowLimit: number;
      };

  type FakeLedgerExportRow = {
    assertionId: string;
    tenantId: string;
    publicId: string | null;
    badgeTemplateId: string;
    badgeTitle: string;
    recipientIdentity: string;
    recipientIdentityType: "email" | "email_sha256" | "did" | "url";
    issuedAt: string;
    issuedByUserId: string | null;
    revokedAt: string | null;
    latestToState: "active" | "suspended" | "revoked" | "expired" | null;
    latestReasonCode:
      | "administrative_hold"
      | "policy_violation"
      | "appeal_pending"
      | "appeal_resolved"
      | "credential_expired"
      | "issuer_requested"
      | "other"
      | null;
    latestReason: string | null;
    latestTransitionedAt: string | null;
    orgUnitId: string;
    orgUnitDisplayName: string;
    attributionSource: "ownership_event" | "historical_backfill";
    currentInstitutionName: string | null;
    currentCollegeName: string | null;
    currentDepartmentName: string | null;
    currentProgramName: string | null;
  };

  type FakeLedgerOrgUnitRow = {
    id: string;
    tenantId: string;
    unitType: "institution" | "college" | "department" | "program";
    slug: string;
    displayName: string;
    parentOrgUnitId: string | null;
    createdByUserId: string | null;
    isActive: number | boolean;
    createdAt: string;
    updatedAt: string;
  };

  class FakeLedgerExportStatement {
    private readonly sql: string;
    private readonly db: FakeLedgerExportDatabase;
    private boundParams: unknown[] = [];

    constructor(db: FakeLedgerExportDatabase, sql: string) {
      this.db = db;
      this.sql = sql;
    }

    bind(...params: unknown[]): this {
      this.boundParams = params;
      return this;
    }

    first<T>(): Promise<T | null> {
      throw new Error(`Unsupported first SQL in fake ledger export DB: ${this.normalizedSql()}`);
    }

    run(): Promise<SqlRunResult> {
      throw new Error(`Unsupported run SQL in fake ledger export DB: ${this.normalizedSql()}`);
    }

    all<T>(): Promise<SqlQueryResult<T>> {
      const normalizedSql = this.normalizedSql();

      if (
        normalizedSql.includes("FROM assertions") &&
        normalizedSql.includes("LEFT JOIN assertion_reporting_attributions attribution") &&
        normalizedSql.includes("attribution.assertion_id IS NULL")
      ) {
        return Promise.resolve({
          success: true,
          meta: {} as SqlExecutionMeta,
          results: [] as T[],
        });
      }

      if (normalizedSql.includes("FROM badge_template_ownership_events")) {
        return Promise.resolve({
          success: true,
          meta: {} as SqlExecutionMeta,
          results: [] as T[],
        });
      }

      if (
        normalizedSql.includes("FROM assertions") &&
        normalizedSql.includes("assertion_reporting_attributions")
      ) {
        return Promise.resolve({
          success: true,
          meta: {} as SqlExecutionMeta,
          results: this.selectLedgerRows() as T[],
        });
      }

      if (normalizedSql.includes("FROM tenant_org_units")) {
        return Promise.resolve({
          success: true,
          meta: {} as SqlExecutionMeta,
          results: this.selectOrgUnits() as T[],
        });
      }

      throw new Error(`Unsupported all SQL in fake ledger export DB: ${normalizedSql}`);
    }

    private normalizedSql(): string {
      return this.sql.replace(/\s+/g, " ").trim();
    }

    private selectLedgerRows(): FakeLedgerExportRow[] {
      let paramIndex = 0;
      const tenantId = this.expectString(this.boundParams[paramIndex], "tenantId");
      paramIndex += 1;

      let issuedFrom: string | undefined;
      let issuedTo: string | undefined;
      let badgeTemplateId: string | undefined;
      let orgUnitId: string | undefined;
      let state: string | undefined;
      let recipientQuery: string | undefined;

      const normalizedSql = this.normalizedSql();

      if (normalizedSql.includes("assertions.issued_at >= ?")) {
        issuedFrom = this.expectString(this.boundParams[paramIndex], "issuedFrom");
        paramIndex += 1;
      }

      if (normalizedSql.includes("assertions.issued_at <= ?")) {
        issuedTo = this.expectString(this.boundParams[paramIndex], "issuedTo");
        paramIndex += 1;
      }

      if (
        normalizedSql.includes("assertions.badge_template_id = ?") ||
        normalizedSql.includes("attribution.badge_template_id = ?")
      ) {
        badgeTemplateId = this.expectString(this.boundParams[paramIndex], "badgeTemplateId");
        paramIndex += 1;
      }

      if (normalizedSql.includes("attribution.org_unit_id = ?")) {
        orgUnitId = this.expectString(this.boundParams[paramIndex], "orgUnitId");
        paramIndex += 1;
      }

      if (normalizedSql.includes("LOWER(assertions.recipient_identity) LIKE ?")) {
        recipientQuery = this.expectString(this.boundParams[paramIndex], "recipientQuery");
        paramIndex += 3;
      }

      if (normalizedSql.includes("CASE") || normalizedSql.includes("COALESCE(lifecycle.to_state")) {
        state = this.expectString(this.boundParams[paramIndex], "state");
        paramIndex += 1;
      }

      let queryLimit = Number.POSITIVE_INFINITY;
      const maybeLimit = this.boundParams[paramIndex];

      if (typeof maybeLimit === "number") {
        queryLimit = maybeLimit;
      }

      return this.db.rows
        .filter((row) => row.tenantId === tenantId)
        .filter((row) => (issuedFrom === undefined ? true : row.issuedAt >= issuedFrom))
        .filter((row) => (issuedTo === undefined ? true : row.issuedAt <= issuedTo))
        .filter((row) =>
          badgeTemplateId === undefined ? true : row.badgeTemplateId === badgeTemplateId,
        )
        .filter((row) => (orgUnitId === undefined ? true : row.orgUnitId === orgUnitId))
        .filter((row) => (state === undefined ? true : this.resolveState(row).state === state))
        .filter((row) => {
          if (recipientQuery === undefined) {
            return true;
          }

          const normalizedQuery = recipientQuery.toLowerCase().replace(/%/g, "");
          return (
            row.recipientIdentity.toLowerCase().includes(normalizedQuery) ||
            row.assertionId.toLowerCase().includes(normalizedQuery) ||
            (row.publicId ?? "").toLowerCase().includes(normalizedQuery)
          );
        })
        .sort((left, right) => {
          if (left.issuedAt === right.issuedAt) {
            return right.assertionId.localeCompare(left.assertionId);
          }

          return right.issuedAt.localeCompare(left.issuedAt);
        })
        .slice(0, queryLimit);
    }

    private selectOrgUnits(): FakeLedgerOrgUnitRow[] {
      const tenantId = this.expectString(this.boundParams[0], "tenantId");
      const includeInactive = this.boundParams[1] === 1;

      return this.db.orgUnits.filter((row) => {
        return (
          row.tenantId === tenantId &&
          (includeInactive || row.isActive === 1 || row.isActive === true)
        );
      });
    }

    private resolveState(row: FakeLedgerExportRow): Pick<LedgerExportRow, "state" | "source"> {
      if (row.revokedAt !== null && row.latestToState === "revoked") {
        return {
          state: "revoked",
          source: "lifecycle_event",
        };
      }

      if (row.revokedAt !== null) {
        return {
          state: "revoked",
          source: "assertion_revocation",
        };
      }

      if (row.latestToState !== null) {
        return {
          state: row.latestToState,
          source: "lifecycle_event",
        };
      }

      return {
        state: "active",
        source: "default_active",
      };
    }

    private expectString(value: unknown, label: string): string {
      if (typeof value !== "string") {
        throw new Error(`Expected ${label} to be a string in fake ledger export DB`);
      }

      return value;
    }
  }

  class FakeLedgerExportDatabase {
    constructor(
      readonly rows: FakeLedgerExportRow[],
      readonly orgUnits: FakeLedgerOrgUnitRow[],
    ) {}

    prepare(sql: string): FakeLedgerExportStatement {
      return new FakeLedgerExportStatement(this, sql);
    }
  }

  const createFakeLedgerExportDb = (rows: FakeLedgerExportRow[]): SqlDatabase => {
    const orgUnits: FakeLedgerOrgUnitRow[] = [
      {
        id: "org_institution",
        tenantId: "tenant_export",
        unitType: "institution",
        slug: "credtrail-university",
        displayName: "CredTrail University",
        parentOrgUnitId: null,
        createdByUserId: "user_admin",
        isActive: 1,
        createdAt: "2026-01-01T00:00:00.000Z",
        updatedAt: "2026-01-01T00:00:00.000Z",
      },
      {
        id: "org_college_science",
        tenantId: "tenant_export",
        unitType: "college",
        slug: "science",
        displayName: "College of Science",
        parentOrgUnitId: "org_institution",
        createdByUserId: "user_admin",
        isActive: 1,
        createdAt: "2026-01-01T00:00:00.000Z",
        updatedAt: "2026-01-01T00:00:00.000Z",
      },
      {
        id: "org_department_biology",
        tenantId: "tenant_export",
        unitType: "department",
        slug: "biology",
        displayName: "Biology Department",
        parentOrgUnitId: "org_college_science",
        createdByUserId: "user_admin",
        isActive: 1,
        createdAt: "2026-01-01T00:00:00.000Z",
        updatedAt: "2026-01-01T00:00:00.000Z",
      },
      {
        id: "org_program_microbiology",
        tenantId: "tenant_export",
        unitType: "program",
        slug: "microbiology",
        displayName: "Microbiology Program",
        parentOrgUnitId: "org_department_biology",
        createdByUserId: "user_admin",
        isActive: 1,
        createdAt: "2026-01-01T00:00:00.000Z",
        updatedAt: "2026-01-01T00:00:00.000Z",
      },
      {
        id: "org_program_biochemistry",
        tenantId: "tenant_export",
        unitType: "program",
        slug: "biochemistry",
        displayName: "Biochemistry Program",
        parentOrgUnitId: "org_department_biology",
        createdByUserId: "user_admin",
        isActive: 1,
        createdAt: "2026-01-01T00:00:00.000Z",
        updatedAt: "2026-01-01T00:00:00.000Z",
      },
    ];

    return new FakeLedgerExportDatabase(rows, orgUnits) as unknown as SqlDatabase;
  };

  const listTenantAssertionLedgerExportRows = (
    dbModule as {
      listTenantAssertionLedgerExportRows?: (
        db: SqlDatabase,
        input: {
          tenantId: string;
          issuedFrom?: string;
          issuedTo?: string;
          badgeTemplateId?: string;
          orgUnitId?: string;
          state?: "active" | "suspended" | "revoked" | "expired";
          recipientQuery?: string;
        },
      ) => Promise<LedgerExportResult>;
      SYNCHRONOUS_EXPORT_ROW_LIMIT?: number;
    }
  ).listTenantAssertionLedgerExportRows;

  const synchronousExportRowLimit =
    (dbModule as { SYNCHRONOUS_EXPORT_ROW_LIMIT?: number }).SYNCHRONOUS_EXPORT_ROW_LIMIT ?? 5000;

  const baseLedgerRows: FakeLedgerExportRow[] = [
    {
      assertionId: "assertion_match",
      tenantId: "tenant_export",
      publicId: "public_match",
      badgeTemplateId: "badge_template_science",
      badgeTitle: "Foundations of Microbiology",
      recipientIdentity: "learner.one@example.edu",
      recipientIdentityType: "email",
      issuedAt: "2026-03-10T15:45:00.000Z",
      issuedByUserId: "user_issuer",
      revokedAt: null,
      latestToState: "suspended",
      latestReasonCode: "administrative_hold",
      latestReason: "Paused during registrar review",
      latestTransitionedAt: "2026-03-12T10:15:00.000Z",
      orgUnitId: "org_program_microbiology",
      orgUnitDisplayName: "Microbiology Program",
      attributionSource: "historical_backfill",
      currentInstitutionName: "CredTrail University",
      currentCollegeName: "College of Science",
      currentDepartmentName: "Biology Department",
      currentProgramName: "Microbiology Program",
    },
    {
      assertionId: "assertion_old_issue_date",
      tenantId: "tenant_export",
      publicId: "public_old",
      badgeTemplateId: "badge_template_science",
      badgeTitle: "Foundations of Microbiology",
      recipientIdentity: "learner.old@example.edu",
      recipientIdentityType: "email",
      issuedAt: "2026-02-01T09:00:00.000Z",
      issuedByUserId: "user_issuer",
      revokedAt: null,
      latestToState: "suspended",
      latestReasonCode: "administrative_hold",
      latestReason: "Paused during registrar review",
      latestTransitionedAt: "2026-03-12T10:15:00.000Z",
      orgUnitId: "org_program_microbiology",
      orgUnitDisplayName: "Microbiology Program",
      attributionSource: "historical_backfill",
      currentInstitutionName: "CredTrail University",
      currentCollegeName: "College of Science",
      currentDepartmentName: "Biology Department",
      currentProgramName: "Microbiology Program",
    },
    {
      assertionId: "assertion_wrong_state",
      tenantId: "tenant_export",
      publicId: "public_revoked",
      badgeTemplateId: "badge_template_science",
      badgeTitle: "Foundations of Microbiology",
      recipientIdentity: "learner.revoked@example.edu",
      recipientIdentityType: "email",
      issuedAt: "2026-03-11T08:00:00.000Z",
      issuedByUserId: "user_issuer",
      revokedAt: "2026-03-15T00:00:00.000Z",
      latestToState: "revoked",
      latestReasonCode: "issuer_requested",
      latestReason: "Credential revoked after policy violation",
      latestTransitionedAt: "2026-03-15T00:00:00.000Z",
      orgUnitId: "org_program_microbiology",
      orgUnitDisplayName: "Microbiology Program",
      attributionSource: "ownership_event",
      currentInstitutionName: "CredTrail University",
      currentCollegeName: "College of Science",
      currentDepartmentName: "Biology Department",
      currentProgramName: "Microbiology Program",
    },
    {
      assertionId: "assertion_wrong_leaf",
      tenantId: "tenant_export",
      publicId: "public_other_leaf",
      badgeTemplateId: "badge_template_science",
      badgeTitle: "Foundations of Microbiology",
      recipientIdentity: "learner.two@example.edu",
      recipientIdentityType: "email",
      issuedAt: "2026-03-11T09:00:00.000Z",
      issuedByUserId: "user_issuer",
      revokedAt: null,
      latestToState: "suspended",
      latestReasonCode: "administrative_hold",
      latestReason: "Paused during registrar review",
      latestTransitionedAt: "2026-03-12T10:15:00.000Z",
      orgUnitId: "org_program_biochemistry",
      orgUnitDisplayName: "Biochemistry Program",
      attributionSource: "historical_backfill",
      currentInstitutionName: "CredTrail University",
      currentCollegeName: "College of Science",
      currentDepartmentName: "Biology Department",
      currentProgramName: "Biochemistry Program",
    },
  ];

  it("filters ledger export rows by issued date, template, state, and exact-match leaf orgUnitId", async () => {
    expect(listTenantAssertionLedgerExportRows).toBeTypeOf("function");

    const result = await listTenantAssertionLedgerExportRows?.(
      createFakeLedgerExportDb(baseLedgerRows),
      {
        tenantId: "tenant_export",
        issuedFrom: "2026-03-01",
        issuedTo: "2026-03-31",
        badgeTemplateId: "badge_template_science",
        orgUnitId: "org_program_microbiology",
        state: "suspended",
      },
    );

    expect(result).toEqual({
      status: "ok",
      rowLimit: synchronousExportRowLimit,
      rows: [
        expect.objectContaining({
          assertionId: "assertion_match",
          orgUnitId: "org_program_microbiology",
          state: "suspended",
        }),
      ],
    });
  });

  it("returns stable leaf attribution, lifecycle details, and current-tree lineage convenience fields", async () => {
    expect(listTenantAssertionLedgerExportRows).toBeTypeOf("function");

    const result = await listTenantAssertionLedgerExportRows?.(
      createFakeLedgerExportDb(baseLedgerRows),
      {
        tenantId: "tenant_export",
        recipientQuery: "learner.one",
      },
    );

    expect(result).toEqual({
      status: "ok",
      rowLimit: synchronousExportRowLimit,
      rows: [
        expect.objectContaining({
          assertionId: "assertion_match",
          publicId: "public_match",
          badgeTemplateId: "badge_template_science",
          badgeTitle: "Foundations of Microbiology",
          recipientIdentity: "learner.one@example.edu",
          recipientIdentityType: "email",
          issuedAt: "2026-03-10T15:45:00.000Z",
          issuedByUserId: "user_issuer",
          orgUnitId: "org_program_microbiology",
          orgUnitDisplayName: "Microbiology Program",
          attributionSource: "historical_backfill",
          state: "suspended",
          source: "lifecycle_event",
          reasonCode: "administrative_hold",
          reason: "Paused during registrar review",
          transitionedAt: "2026-03-12T10:15:00.000Z",
          currentInstitutionName: "CredTrail University",
          currentCollegeName: "College of Science",
          currentDepartmentName: "Biology Department",
          currentProgramName: "Microbiology Program",
        }),
      ],
    });
  });

  it("returns an explicit too_large status above the synchronous export cap", async () => {
    expect(listTenantAssertionLedgerExportRows).toBeTypeOf("function");

    const firstBaseLedgerRow = baseLedgerRows[0];

    if (firstBaseLedgerRow === undefined) {
      throw new Error("Expected at least one base ledger row fixture");
    }

    const overCapRows = Array.from({ length: synchronousExportRowLimit + 1 }, (_, index) => ({
      ...firstBaseLedgerRow,
      assertionId: `assertion_${index}`,
      publicId: `public_${index}`,
      recipientIdentity: `learner.${index}@example.edu`,
      issuedAt: `2026-03-10T15:${String(index % 60).padStart(2, "0")}:00.000Z`,
    }));

    const result = await listTenantAssertionLedgerExportRows?.(
      createFakeLedgerExportDb(overCapRows),
      {
        tenantId: "tenant_export",
      },
    );

    expect(result).toEqual({
      status: "too_large",
      rowLimit: synchronousExportRowLimit,
    });
  });
});

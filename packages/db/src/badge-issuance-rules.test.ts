/* eslint-disable no-unused-vars */
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

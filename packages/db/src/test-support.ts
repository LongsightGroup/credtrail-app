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

interface FakeLearnerProfileRow {
  id: string;
  tenant_id: string;
  subject_id: string;
  display_name: string | null;
  created_at: string;
  updated_at: string;
}

interface FakeLearnerIdentityRow {
  id: string;
  tenant_id: string;
  learner_profile_id: string;
  identity_type: LearnerIdentityType;
  identity_value: string;
  is_primary: number;
  is_verified: number;
  created_at: string;
  updated_at: string;
}

interface FakeLearnerRecordEntryRow {
  id: string;
  tenant_id: string;
  learner_profile_id: string;
  trust_level: dbModule.LearnerRecordTrustLevel;
  record_type: dbModule.LearnerRecordEntryType;
  status: dbModule.LearnerRecordStatus;
  title: string;
  description: string | null;
  issuer_name: string;
  issuer_user_id: string | null;
  source_system: dbModule.LearnerRecordSourceSystem;
  source_record_id: string | null;
  issued_at: string;
  revised_at: string | null;
  revoked_at: string | null;
  evidence_links_json: string;
  details_json: string | null;
  created_at: string;
  updated_at: string;
}

interface FakeLearnerRecordImportContextRow {
  entry_id: string;
  tenant_id: string;
  org_unit_id: string | null;
  badge_template_id: string | null;
  pathway_label: string | null;
  inferred_from_json: string;
  created_at: string;
  updated_at: string;
}

interface FakeUserRow {
  id: string;
  email: string;
}

interface FakeAuthIdentityLinkRow {
  id: string;
  auth_system: string;
  auth_user_id: string;
  auth_account_id: string | null;
  credtrail_user_id: string;
  email_snapshot: string | null;
  created_at: string;
  updated_at: string;
}

interface FakeTenantAuthPolicyRow {
  tenant_id: string;
  login_mode: "local" | "hybrid" | "sso_required";
  break_glass_enabled: number;
  local_mfa_required: number;
  default_provider_id: string | null;
  enforce_for_roles: "all_users" | "admins_only";
  created_at: string;
  updated_at: string;
}

interface FakeTenantAuthProviderRow {
  id: string;
  tenant_id: string;
  protocol: "oidc" | "saml";
  label: string;
  enabled: number;
  is_default: number;
  config_json: string;
  created_at: string;
  updated_at: string;
}

interface FakeLegacySamlConfigurationRow {
  tenant_id: string;
  idp_entity_id: string;
  sso_login_url: string;
  idp_certificate_pem: string;
  idp_metadata_url: string | null;
  sp_entity_id: string;
  assertion_consumer_service_url: string;
  name_id_format: string | null;
  enforced: number;
  created_at: string;
  updated_at: string;
}

interface FakeTenantBreakGlassAccountRow {
  tenant_id: string;
  user_id: string;
  created_by_user_id: string | null;
  last_used_at: string | null;
  last_enrollment_email_sent_at: string | null;
  revoked_at: string | null;
  created_at: string;
  updated_at: string;
}

interface FakeTenantRow {
  id: string;
  slug: string;
  display_name: string;
  plan_tier: "free" | "team" | "institution" | "enterprise";
  is_active: number;
}

interface FakeBadgeTemplateRow {
  id: string;
  tenant_id: string;
  title: string;
  description: string | null;
  criteria_uri: string | null;
  image_uri: string | null;
}

interface FakeAssertionRow {
  id: string;
  tenant_id: string;
  public_id: string | null;
  learner_profile_id: string | null;
  badge_template_id: string;
  recipient_identity: string;
  recipient_identity_type: "email" | "email_sha256" | "did" | "url";
  vc_r2_key: string;
  status_list_index: number | null;
  idempotency_key: string;
  issued_at: string;
  issued_by_user_id: string | null;
  revoked_at: string | null;
  created_at: string;
  updated_at: string;
}

interface FakeMembershipRow {
  tenant_id: string;
  user_id: string;
  role: "owner" | "admin" | "issuer" | "viewer";
  created_at?: string;
  updated_at?: string;
}

interface FakeJobQueueMessageRow {
  id: string;
  tenant_id: string;
  job_type: dbModule.JobQueueMessageType;
  payload_json: string;
  idempotency_key: string;
  attempt_count: number;
  max_attempts: number;
  available_at: string;
  leased_until: string | null;
  lease_token: string | null;
  last_error: string | null;
  completed_at: string | null;
  failed_at: string | null;
  status: dbModule.JobQueueMessageStatus;
  created_at: string;
  updated_at: string;
}

interface FakeLearnerRecordImportPreviewRow {
  tenant_id: string;
  batch_id: string;
  file_name: string;
  format: "csv";
  defaults_json: string;
  reports_json: string;
  queue_payloads_json: string;
  created_by_user_id: string | null;
  created_at: string;
  expires_at: string;
  queued_at: string | null;
}

class FakeStatement {
  private readonly sql: string;
  private readonly db: FakeSqlDatabase;
  private boundParams: unknown[] = [];

  constructor(db: FakeSqlDatabase, sql: string) {
    this.db = db;
    this.sql = sql;
  }

  bind(...params: unknown[]): this {
    this.boundParams = params;
    return this;
  }

  run(): Promise<SqlRunResult> {
    const normalizedSql = this.normalizedSql();

    if (normalizedSql.includes("INSERT INTO learner_profiles")) {
      this.insertLearnerProfile();
      return Promise.resolve(this.successResult());
    }

    if (normalizedSql.includes("UPDATE learner_identities SET is_primary = 0")) {
      this.clearPrimaryIdentity();
      return Promise.resolve(this.successResult());
    }

    if (normalizedSql.includes("INSERT INTO learner_identities")) {
      this.insertLearnerIdentity();
      return Promise.resolve(this.successResult());
    }

    if (normalizedSql.includes("INSERT INTO learner_record_entries")) {
      this.insertLearnerRecordEntry();
      return Promise.resolve(this.successResult());
    }

    if (normalizedSql.includes("INSERT INTO learner_record_import_context")) {
      this.upsertLearnerRecordImportContext();
      return Promise.resolve(this.successResult());
    }

    if (normalizedSql.includes("UPDATE learner_record_entries SET")) {
      this.updateLearnerRecordEntry();
      return Promise.resolve(this.successResult());
    }

    if (
      normalizedSql.includes("UPDATE job_queue_messages") &&
      normalizedSql.includes("job_type = 'import_learner_record_batch'")
    ) {
      this.retryLearnerRecordImportQueueMessages();
      return Promise.resolve(this.successResult());
    }

    throw new Error(`Unsupported run SQL in fake DB: ${normalizedSql}`);
  }

  first<T>(): Promise<T | null> {
    const normalizedSql = this.normalizedSql();

    if (normalizedSql.includes("FROM learner_profiles WHERE tenant_id = ? AND id = ?")) {
      return Promise.resolve(this.selectLearnerProfileById() as T | null);
    }

    if (normalizedSql.includes("FROM learner_identities WHERE tenant_id = ? AND id = ?")) {
      return Promise.resolve(this.selectLearnerIdentityById() as T | null);
    }

    if (
      normalizedSql.includes("FROM learner_profiles INNER JOIN learner_identities") &&
      normalizedSql.includes("learner_identities.identity_type = ?") &&
      normalizedSql.includes("learner_identities.is_verified = 1")
    ) {
      return Promise.resolve(this.selectLearnerProfileByVerifiedIdentity() as T | null);
    }

    if (
      normalizedSql.includes("FROM learner_profiles INNER JOIN learner_identities") &&
      normalizedSql.includes("learner_identities.identity_type = ?")
    ) {
      return Promise.resolve(this.selectLearnerProfileByIdentity() as T | null);
    }

    if (
      normalizedSql.includes("FROM learner_record_entries WHERE tenant_id = ?") &&
      normalizedSql.includes("AND id = ?")
    ) {
      return Promise.resolve(this.selectLearnerRecordEntryById() as T | null);
    }

    if (
      normalizedSql.includes("FROM learner_record_import_context") &&
      normalizedSql.includes("AND entry_id = ?")
    ) {
      return Promise.resolve(this.selectLearnerRecordImportContextByEntryId() as T | null);
    }

    if (
      normalizedSql.includes("INSERT INTO job_queue_messages") &&
      normalizedSql.includes("ON CONFLICT(tenant_id, job_type, idempotency_key) DO NOTHING")
    ) {
      return Promise.resolve(this.insertJobQueueMessageOnce() as T | null);
    }

    if (
      normalizedSql.includes("UPDATE learner_record_import_previews") &&
      normalizedSql.includes("RETURNING batch_id AS batchId")
    ) {
      return Promise.resolve(this.markLearnerRecordImportPreviewQueued() as T | null);
    }

    throw new Error(`Unsupported first SQL in fake DB: ${normalizedSql}`);
  }

  all<T>(): Promise<SqlQueryResult<T>> {
    const normalizedSql = this.normalizedSql();

    if (
      normalizedSql.includes("FROM learner_identities") &&
      normalizedSql.includes("learner_profile_id = ?")
    ) {
      const rows = this.selectLearnerIdentitiesByProfile();
      return Promise.resolve({
        ...this.successResult(),
        results: rows as T[],
      });
    }

    if (
      normalizedSql.includes("FROM assertions") &&
      normalizedSql.includes("badge_templates.criteria_uri AS badgeCriteriaUri") &&
      normalizedSql.includes("tenants.display_name AS issuerName")
    ) {
      const rows = this.selectLearnerRecordAssertionExports();
      return Promise.resolve({
        ...this.successResult(),
        results: rows as T[],
      });
    }

    if (
      normalizedSql.includes("FROM learner_record_entries") &&
      normalizedSql.includes("learner_profile_id = ?") &&
      normalizedSql.includes("ORDER BY issued_at DESC, created_at DESC")
    ) {
      const rows = this.selectLearnerRecordEntries();
      return Promise.resolve({
        ...this.successResult(),
        results: rows as T[],
      });
    }

    if (
      normalizedSql.includes("FROM job_queue_messages") &&
      normalizedSql.includes("job_type = 'import_learner_record_batch'")
    ) {
      const rows = this.selectLearnerRecordImportQueueMessages();
      return Promise.resolve({
        ...this.successResult(),
        results: rows as T[],
      });
    }

    throw new Error(`Unsupported all SQL in fake DB: ${normalizedSql}`);
  }

  private normalizedSql(): string {
    return this.sql.replace(/\s+/g, " ").trim();
  }

  private insertLearnerProfile(): void {
    const [id, tenantId, subjectId, displayName, createdAt, updatedAt] = this.boundParams;

    if (
      typeof id !== "string" ||
      typeof tenantId !== "string" ||
      typeof subjectId !== "string" ||
      typeof createdAt !== "string" ||
      typeof updatedAt !== "string" ||
      (displayName !== null && typeof displayName !== "string")
    ) {
      throw new Error("Invalid bound parameters for learner profile insert");
    }

    const duplicateSubject = this.db.learnerProfiles.find((row) => {
      return row.tenant_id === tenantId && row.subject_id === subjectId;
    });

    if (duplicateSubject !== undefined) {
      throw new Error(
        "UNIQUE constraint failed: learner_profiles.tenant_id, learner_profiles.subject_id",
      );
    }

    this.db.learnerProfiles.push({
      id,
      tenant_id: tenantId,
      subject_id: subjectId,
      display_name: displayName,
      created_at: createdAt,
      updated_at: updatedAt,
    });
  }

  private clearPrimaryIdentity(): void {
    const [updatedAt, tenantId, learnerProfileId] = this.boundParams;

    if (
      typeof updatedAt !== "string" ||
      typeof tenantId !== "string" ||
      typeof learnerProfileId !== "string"
    ) {
      throw new Error("Invalid bound parameters for clearing primary identities");
    }

    for (const row of this.db.learnerIdentities) {
      if (
        row.tenant_id === tenantId &&
        row.learner_profile_id === learnerProfileId &&
        row.is_primary === 1
      ) {
        row.is_primary = 0;
        row.updated_at = updatedAt;
      }
    }
  }

  private insertLearnerIdentity(): void {
    const [
      id,
      tenantId,
      learnerProfileId,
      identityType,
      identityValue,
      isPrimary,
      isVerified,
      createdAt,
      updatedAt,
    ] = this.boundParams;

    if (
      typeof id !== "string" ||
      typeof tenantId !== "string" ||
      typeof learnerProfileId !== "string" ||
      !this.isLearnerIdentityType(identityType) ||
      typeof identityValue !== "string" ||
      typeof isPrimary !== "number" ||
      typeof isVerified !== "number" ||
      typeof createdAt !== "string" ||
      typeof updatedAt !== "string"
    ) {
      throw new Error("Invalid bound parameters for learner identity insert");
    }

    const profileExists = this.db.learnerProfiles.some((row) => {
      return row.tenant_id === tenantId && row.id === learnerProfileId;
    });

    if (!profileExists) {
      throw new Error("FOREIGN KEY constraint failed");
    }

    const duplicateIdentity = this.db.learnerIdentities.find((row) => {
      return (
        row.tenant_id === tenantId &&
        row.identity_type === identityType &&
        row.identity_value === identityValue
      );
    });

    if (duplicateIdentity !== undefined) {
      throw new Error(
        "UNIQUE constraint failed: learner_identities.tenant_id, learner_identities.identity_type, learner_identities.identity_value",
      );
    }

    const duplicatePrimary = this.db.learnerIdentities.find((row) => {
      return (
        row.tenant_id === tenantId &&
        row.learner_profile_id === learnerProfileId &&
        row.is_primary === 1
      );
    });

    if (isPrimary === 1 && duplicatePrimary !== undefined) {
      throw new Error("UNIQUE constraint failed: idx_learner_identities_primary_per_profile");
    }

    this.db.learnerIdentities.push({
      id,
      tenant_id: tenantId,
      learner_profile_id: learnerProfileId,
      identity_type: identityType,
      identity_value: identityValue,
      is_primary: isPrimary,
      is_verified: isVerified,
      created_at: createdAt,
      updated_at: updatedAt,
    });
  }

  private insertLearnerRecordEntry(): void {
    const [
      id,
      tenantId,
      learnerProfileId,
      trustLevel,
      recordType,
      status,
      title,
      description,
      issuerName,
      issuerUserId,
      sourceSystem,
      sourceRecordId,
      issuedAt,
      revisedAt,
      revokedAt,
      evidenceLinksJson,
      detailsJson,
      createdAt,
      updatedAt,
    ] = this.boundParams;

    if (
      typeof id !== "string" ||
      typeof tenantId !== "string" ||
      typeof learnerProfileId !== "string" ||
      !this.isLearnerRecordTrustLevel(trustLevel) ||
      !this.isLearnerRecordType(recordType) ||
      !this.isLearnerRecordStatus(status) ||
      typeof title !== "string" ||
      (description !== null && typeof description !== "string") ||
      typeof issuerName !== "string" ||
      (issuerUserId !== null && typeof issuerUserId !== "string") ||
      !this.isLearnerRecordSourceSystem(sourceSystem) ||
      (sourceRecordId !== null && typeof sourceRecordId !== "string") ||
      typeof issuedAt !== "string" ||
      (revisedAt !== null && typeof revisedAt !== "string") ||
      (revokedAt !== null && typeof revokedAt !== "string") ||
      typeof evidenceLinksJson !== "string" ||
      (detailsJson !== null && typeof detailsJson !== "string") ||
      typeof createdAt !== "string" ||
      typeof updatedAt !== "string"
    ) {
      throw new Error("Invalid bound parameters for learner-record entry insert");
    }

    const profileExists = this.db.learnerProfiles.some((row) => {
      return row.tenant_id === tenantId && row.id === learnerProfileId;
    });

    if (!profileExists) {
      throw new Error("FOREIGN KEY constraint failed");
    }

    this.db.learnerRecordEntries.push({
      id,
      tenant_id: tenantId,
      learner_profile_id: learnerProfileId,
      trust_level: trustLevel,
      record_type: recordType,
      status,
      title,
      description,
      issuer_name: issuerName,
      issuer_user_id: issuerUserId,
      source_system: sourceSystem,
      source_record_id: sourceRecordId,
      issued_at: issuedAt,
      revised_at: revisedAt,
      revoked_at: revokedAt,
      evidence_links_json: evidenceLinksJson,
      details_json: detailsJson,
      created_at: createdAt,
      updated_at: updatedAt,
    });
  }

  private updateLearnerRecordEntry(): void {
    const [
      trustLevel,
      recordType,
      status,
      title,
      description,
      issuerName,
      issuerUserId,
      sourceSystem,
      sourceRecordId,
      issuedAt,
      revisedAt,
      revokedAt,
      evidenceLinksJson,
      detailsJson,
      updatedAt,
      tenantId,
      entryId,
    ] = this.boundParams;

    if (
      !this.isLearnerRecordTrustLevel(trustLevel) ||
      !this.isLearnerRecordType(recordType) ||
      !this.isLearnerRecordStatus(status) ||
      typeof title !== "string" ||
      (description !== null && typeof description !== "string") ||
      typeof issuerName !== "string" ||
      (issuerUserId !== null && typeof issuerUserId !== "string") ||
      !this.isLearnerRecordSourceSystem(sourceSystem) ||
      (sourceRecordId !== null && typeof sourceRecordId !== "string") ||
      typeof issuedAt !== "string" ||
      (revisedAt !== null && typeof revisedAt !== "string") ||
      (revokedAt !== null && typeof revokedAt !== "string") ||
      typeof evidenceLinksJson !== "string" ||
      (detailsJson !== null && typeof detailsJson !== "string") ||
      typeof updatedAt !== "string" ||
      typeof tenantId !== "string" ||
      typeof entryId !== "string"
    ) {
      throw new Error("Invalid bound parameters for learner-record entry update");
    }

    const entry = this.db.learnerRecordEntries.find((candidate) => {
      return candidate.tenant_id === tenantId && candidate.id === entryId;
    });

    if (entry === undefined) {
      return;
    }

    entry.trust_level = trustLevel;
    entry.record_type = recordType;
    entry.status = status;
    entry.title = title;
    entry.description = description;
    entry.issuer_name = issuerName;
    entry.issuer_user_id = issuerUserId;
    entry.source_system = sourceSystem;
    entry.source_record_id = sourceRecordId;
    entry.issued_at = issuedAt;
    entry.revised_at = revisedAt;
    entry.revoked_at = revokedAt;
    entry.evidence_links_json = evidenceLinksJson;
    entry.details_json = detailsJson;
    entry.updated_at = updatedAt;
  }

  private upsertLearnerRecordImportContext(): void {
    const [
      entryId,
      tenantId,
      orgUnitId,
      badgeTemplateId,
      pathwayLabel,
      inferredFromJson,
      createdAt,
      updatedAt,
    ] = this.boundParams;

    if (
      typeof entryId !== "string" ||
      typeof tenantId !== "string" ||
      (orgUnitId !== null && typeof orgUnitId !== "string") ||
      (badgeTemplateId !== null && typeof badgeTemplateId !== "string") ||
      (pathwayLabel !== null && typeof pathwayLabel !== "string") ||
      typeof inferredFromJson !== "string" ||
      typeof createdAt !== "string" ||
      typeof updatedAt !== "string"
    ) {
      throw new Error("Invalid bound parameters for learner-record import context upsert");
    }

    const existing = this.db.learnerRecordImportContexts.find((candidate) => {
      return candidate.tenant_id === tenantId && candidate.entry_id === entryId;
    });

    if (existing !== undefined) {
      existing.org_unit_id = orgUnitId;
      existing.badge_template_id = badgeTemplateId;
      existing.pathway_label = pathwayLabel;
      existing.inferred_from_json = inferredFromJson;
      existing.updated_at = updatedAt;
      return;
    }

    this.db.learnerRecordImportContexts.push({
      entry_id: entryId,
      tenant_id: tenantId,
      org_unit_id: orgUnitId,
      badge_template_id: badgeTemplateId,
      pathway_label: pathwayLabel,
      inferred_from_json: inferredFromJson,
      created_at: createdAt,
      updated_at: updatedAt,
    });
  }

  private retryLearnerRecordImportQueueMessages(): void {
    const [availableAt, updatedAt, messageId, tenantId] = this.boundParams;

    if (
      typeof availableAt !== "string" ||
      typeof updatedAt !== "string" ||
      typeof messageId !== "string" ||
      typeof tenantId !== "string"
    ) {
      throw new Error("Invalid bound parameters for learner-record import queue retry");
    }

    const row = this.db.jobQueueMessages.find((candidate) => {
      return (
        candidate.id === messageId &&
        candidate.tenant_id === tenantId &&
        candidate.job_type === "import_learner_record_batch"
      );
    });

    if (row === undefined) {
      return;
    }

    row.status = "pending";
    row.attempt_count = 0;
    row.available_at = availableAt;
    row.leased_until = null;
    row.lease_token = null;
    row.last_error = null;
    row.failed_at = null;
    row.updated_at = updatedAt;
  }

  private insertJobQueueMessageOnce(): Record<string, unknown> | null {
    const [
      id,
      tenantId,
      jobType,
      payloadJson,
      idempotencyKey,
      maxAttempts,
      availableAt,
      createdAt,
      updatedAt,
    ] = this.boundParams;

    if (
      typeof id !== "string" ||
      typeof tenantId !== "string" ||
      typeof jobType !== "string" ||
      typeof payloadJson !== "string" ||
      typeof idempotencyKey !== "string" ||
      typeof maxAttempts !== "number" ||
      typeof availableAt !== "string" ||
      typeof createdAt !== "string" ||
      typeof updatedAt !== "string"
    ) {
      throw new Error("Invalid bound parameters for idempotent job queue insert");
    }

    const duplicate = this.db.jobQueueMessages.some((row) => {
      return (
        row.tenant_id === tenantId &&
        row.job_type === jobType &&
        row.idempotency_key === idempotencyKey
      );
    });

    if (duplicate) {
      return null;
    }

    this.db.jobQueueMessages.push({
      id,
      tenant_id: tenantId,
      job_type: jobType as dbModule.JobQueueMessageType,
      payload_json: payloadJson,
      idempotency_key: idempotencyKey,
      attempt_count: 0,
      max_attempts: maxAttempts,
      available_at: availableAt,
      leased_until: null,
      lease_token: null,
      last_error: null,
      completed_at: null,
      failed_at: null,
      status: "pending",
      created_at: createdAt,
      updated_at: updatedAt,
    });

    return { id };
  }

  private markLearnerRecordImportPreviewQueued(): Record<string, unknown> | null {
    const [queuedAt, tenantId, batchId, expiresAtCutoff] = this.boundParams;

    if (
      typeof queuedAt !== "string" ||
      typeof tenantId !== "string" ||
      typeof batchId !== "string" ||
      typeof expiresAtCutoff !== "string"
    ) {
      throw new Error("Invalid bound parameters for learner-record import preview queue mark");
    }

    const preview = this.db.learnerRecordImportPreviews.find((row) => {
      return (
        row.tenant_id === tenantId &&
        row.batch_id === batchId &&
        row.queued_at === null &&
        row.expires_at > expiresAtCutoff
      );
    });

    if (preview === undefined) {
      return null;
    }

    preview.queued_at = queuedAt;
    return { batchId };
  }

  private selectLearnerProfileById(): Record<string, unknown> | null {
    const [tenantId, learnerProfileId] = this.boundParams;

    if (typeof tenantId !== "string" || typeof learnerProfileId !== "string") {
      throw new Error("Invalid bound parameters for learner profile select by id");
    }

    const row = this.db.learnerProfiles.find((candidate) => {
      return candidate.tenant_id === tenantId && candidate.id === learnerProfileId;
    });

    if (row === undefined) {
      return null;
    }

    return {
      id: row.id,
      tenantId: row.tenant_id,
      subjectId: row.subject_id,
      displayName: row.display_name,
      createdAt: row.created_at,
      updatedAt: row.updated_at,
    };
  }

  private selectLearnerIdentityById(): Record<string, unknown> | null {
    const [tenantId, identityId] = this.boundParams;

    if (typeof tenantId !== "string" || typeof identityId !== "string") {
      throw new Error("Invalid bound parameters for learner identity select by id");
    }

    const row = this.db.learnerIdentities.find((candidate) => {
      return candidate.tenant_id === tenantId && candidate.id === identityId;
    });

    if (row === undefined) {
      return null;
    }

    return {
      id: row.id,
      tenantId: row.tenant_id,
      learnerProfileId: row.learner_profile_id,
      identityType: row.identity_type,
      identityValue: row.identity_value,
      isPrimary: row.is_primary,
      isVerified: row.is_verified,
      createdAt: row.created_at,
      updatedAt: row.updated_at,
    };
  }

  private selectLearnerProfileByIdentity(): Record<string, unknown> | null {
    const [tenantId, identityType, identityValue] = this.boundParams;

    if (
      typeof tenantId !== "string" ||
      !this.isLearnerIdentityType(identityType) ||
      typeof identityValue !== "string"
    ) {
      throw new Error("Invalid bound parameters for learner profile select by identity");
    }

    const identity = this.db.learnerIdentities.find((candidate) => {
      return (
        candidate.tenant_id === tenantId &&
        candidate.identity_type === identityType &&
        candidate.identity_value === identityValue
      );
    });

    if (identity === undefined) {
      return null;
    }

    const profile = this.db.learnerProfiles.find((candidate) => {
      return candidate.tenant_id === tenantId && candidate.id === identity.learner_profile_id;
    });

    if (profile === undefined) {
      return null;
    }

    return {
      id: profile.id,
      tenantId: profile.tenant_id,
      subjectId: profile.subject_id,
      displayName: profile.display_name,
      createdAt: profile.created_at,
      updatedAt: profile.updated_at,
    };
  }

  private selectLearnerProfileByVerifiedIdentity(): Record<string, unknown> | null {
    const [tenantId, identityType, identityValue] = this.boundParams;

    if (
      typeof tenantId !== "string" ||
      !this.isLearnerIdentityType(identityType) ||
      typeof identityValue !== "string"
    ) {
      throw new Error("Invalid bound parameters for verified learner profile select by identity");
    }

    const identity = this.db.learnerIdentities.find((candidate) => {
      return (
        candidate.tenant_id === tenantId &&
        candidate.identity_type === identityType &&
        candidate.identity_value === identityValue &&
        candidate.is_verified === 1
      );
    });

    if (identity === undefined) {
      return null;
    }

    const profile = this.db.learnerProfiles.find((candidate) => {
      return candidate.tenant_id === tenantId && candidate.id === identity.learner_profile_id;
    });

    if (profile === undefined) {
      return null;
    }

    return {
      id: profile.id,
      tenantId: profile.tenant_id,
      subjectId: profile.subject_id,
      displayName: profile.display_name,
      createdAt: profile.created_at,
      updatedAt: profile.updated_at,
    };
  }

  private selectLearnerRecordEntryById(): Record<string, unknown> | null {
    const [tenantId, entryId] = this.boundParams;

    if (typeof tenantId !== "string" || typeof entryId !== "string") {
      throw new Error("Invalid bound parameters for learner-record entry select by id");
    }

    const row = this.db.learnerRecordEntries.find((candidate) => {
      return candidate.tenant_id === tenantId && candidate.id === entryId;
    });

    return row === undefined ? null : this.mapLearnerRecordEntryRow(row);
  }

  private selectLearnerRecordImportContextByEntryId(): Record<string, unknown> | null {
    const [tenantId, entryId] = this.boundParams;

    if (typeof tenantId !== "string" || typeof entryId !== "string") {
      throw new Error("Invalid bound parameters for learner-record import context select");
    }

    const row = this.db.learnerRecordImportContexts.find((candidate) => {
      return candidate.tenant_id === tenantId && candidate.entry_id === entryId;
    });

    if (row === undefined) {
      return null;
    }

    return {
      entryId: row.entry_id,
      tenantId: row.tenant_id,
      orgUnitId: row.org_unit_id,
      badgeTemplateId: row.badge_template_id,
      pathwayLabel: row.pathway_label,
      inferredFromJson: row.inferred_from_json,
      createdAt: row.created_at,
      updatedAt: row.updated_at,
    };
  }

  private selectLearnerIdentitiesByProfile(): Record<string, unknown>[] {
    const [tenantId, learnerProfileId] = this.boundParams;

    if (typeof tenantId !== "string" || typeof learnerProfileId !== "string") {
      throw new Error("Invalid bound parameters for learner identity list by profile");
    }

    return this.db.learnerIdentities
      .filter((candidate) => {
        return (
          candidate.tenant_id === tenantId && candidate.learner_profile_id === learnerProfileId
        );
      })
      .sort((left, right) => {
        if (left.is_primary !== right.is_primary) {
          return right.is_primary - left.is_primary;
        }

        return left.created_at.localeCompare(right.created_at);
      })
      .map((row) => {
        return {
          id: row.id,
          tenantId: row.tenant_id,
          learnerProfileId: row.learner_profile_id,
          identityType: row.identity_type,
          identityValue: row.identity_value,
          isPrimary: row.is_primary,
          isVerified: row.is_verified,
          createdAt: row.created_at,
          updatedAt: row.updated_at,
        };
      });
  }

  private selectLearnerRecordEntries(): Record<string, unknown>[] {
    const [tenantId, learnerProfileId, thirdParam, fourthParam] = this.boundParams;

    if (typeof tenantId !== "string" || typeof learnerProfileId !== "string") {
      throw new Error("Invalid bound parameters for learner-record entry list");
    }

    let trustLevel: dbModule.LearnerRecordTrustLevel | undefined;
    let status: dbModule.LearnerRecordStatus | undefined;

    if (thirdParam !== undefined) {
      if (this.isLearnerRecordTrustLevel(thirdParam)) {
        trustLevel = thirdParam;
      } else if (this.isLearnerRecordStatus(thirdParam)) {
        status = thirdParam;
      } else {
        throw new Error("Invalid optional bound parameter for learner-record entry list");
      }
    }

    if (fourthParam !== undefined) {
      if (!this.isLearnerRecordStatus(fourthParam)) {
        throw new Error("Invalid status bound parameter for learner-record entry list");
      }

      status = fourthParam;
    }

    return this.db.learnerRecordEntries
      .filter((candidate) => {
        if (candidate.tenant_id !== tenantId || candidate.learner_profile_id !== learnerProfileId) {
          return false;
        }

        if (trustLevel !== undefined && candidate.trust_level !== trustLevel) {
          return false;
        }

        if (status !== undefined && candidate.status !== status) {
          return false;
        }

        return true;
      })
      .sort((left, right) => {
        const issuedComparison = right.issued_at.localeCompare(left.issued_at);

        if (issuedComparison !== 0) {
          return issuedComparison;
        }

        return right.created_at.localeCompare(left.created_at);
      })
      .map((row) => this.mapLearnerRecordEntryRow(row));
  }

  private selectLearnerRecordImportQueueMessages(): Record<string, unknown>[] {
    const [tenantId] = this.boundParams;

    if (typeof tenantId !== "string") {
      throw new Error("Invalid bound parameters for learner-record import queue list");
    }

    return this.db.jobQueueMessages
      .filter((candidate) => {
        return (
          candidate.tenant_id === tenantId && candidate.job_type === "import_learner_record_batch"
        );
      })
      .sort((left, right) => right.created_at.localeCompare(left.created_at))
      .map((row) => {
        return {
          id: row.id,
          tenantId: row.tenant_id,
          jobType: row.job_type,
          payloadJson: row.payload_json,
          idempotencyKey: row.idempotency_key,
          attemptCount: row.attempt_count,
          maxAttempts: row.max_attempts,
          availableAt: row.available_at,
          leasedUntil: row.leased_until,
          leaseToken: row.lease_token,
          lastError: row.last_error,
          completedAt: row.completed_at,
          failedAt: row.failed_at,
          status: row.status,
          createdAt: row.created_at,
          updatedAt: row.updated_at,
        };
      });
  }

  private selectLearnerRecordAssertionExports(): Record<string, unknown>[] {
    const [tenantId, learnerProfileId, ...emailAliases] = this.boundParams;

    if (typeof tenantId !== "string" || typeof learnerProfileId !== "string") {
      throw new Error("Invalid bound parameters for learner-record assertion export list");
    }

    return this.db.assertions
      .filter((candidate) => {
        if (candidate.tenant_id !== tenantId) {
          return false;
        }

        if (candidate.learner_profile_id === learnerProfileId) {
          return true;
        }

        if (
          candidate.recipient_identity_type === "email" &&
          emailAliases.some(
            (alias) =>
              typeof alias === "string" &&
              candidate.recipient_identity.toLowerCase() === alias.toLowerCase(),
          )
        ) {
          return true;
        }

        return false;
      })
      .sort((left, right) => {
        const issuedComparison = right.issued_at.localeCompare(left.issued_at);

        if (issuedComparison !== 0) {
          return issuedComparison;
        }

        return right.id.localeCompare(left.id);
      })
      .map((row) => {
        const badgeTemplate = this.db.badgeTemplates.find((candidate) => {
          return candidate.tenant_id === row.tenant_id && candidate.id === row.badge_template_id;
        });
        const tenant = this.db.tenants.find((candidate) => candidate.id === row.tenant_id);

        if (badgeTemplate === undefined || tenant === undefined) {
          throw new Error("Missing tenant or badge template for learner-record assertion export");
        }

        return {
          assertionId: row.id,
          assertionPublicId: row.public_id,
          tenantId: row.tenant_id,
          learnerProfileId: row.learner_profile_id,
          badgeTemplateId: row.badge_template_id,
          badgeTitle: badgeTemplate.title,
          badgeDescription: badgeTemplate.description,
          badgeCriteriaUri: badgeTemplate.criteria_uri,
          badgeImageUri: badgeTemplate.image_uri,
          recipientIdentity: row.recipient_identity,
          recipientIdentityType: row.recipient_identity_type,
          vcR2Key: row.vc_r2_key,
          statusListIndex: row.status_list_index,
          idempotencyKey: row.idempotency_key,
          issuedAt: row.issued_at,
          issuedByUserId: row.issued_by_user_id,
          revokedAt: row.revoked_at,
          issuerName: tenant.display_name,
          createdAt: row.created_at,
          updatedAt: row.updated_at,
        };
      });
  }

  private isLearnerIdentityType(value: unknown): value is LearnerIdentityType {
    return (
      value === "email" ||
      value === "email_sha256" ||
      value === "did" ||
      value === "url" ||
      value === "saml_subject"
    );
  }

  private isLearnerRecordTrustLevel(value: unknown): value is dbModule.LearnerRecordTrustLevel {
    return value === "issuer_verified" || value === "learner_supplemental";
  }

  private isLearnerRecordStatus(value: unknown): value is dbModule.LearnerRecordStatus {
    return value === "active" || value === "revoked" || value === "expired";
  }

  private isLearnerRecordType(value: unknown): value is dbModule.LearnerRecordEntryType {
    return (
      value === "course" ||
      value === "certificate" ||
      value === "license" ||
      value === "competency" ||
      value === "work_based_learning" ||
      value === "experience" ||
      value === "membership" ||
      value === "supplemental_artifact" ||
      value === "custom"
    );
  }

  private isLearnerRecordSourceSystem(value: unknown): value is dbModule.LearnerRecordSourceSystem {
    return (
      value === "credtrail_admin" ||
      value === "csv_import" ||
      value === "api" ||
      value === "migration" ||
      value === "badge_assertion" ||
      value === "learner_self_reported"
    );
  }

  private mapLearnerRecordEntryRow(row: FakeLearnerRecordEntryRow): Record<string, unknown> {
    return {
      id: row.id,
      tenantId: row.tenant_id,
      learnerProfileId: row.learner_profile_id,
      trustLevel: row.trust_level,
      recordType: row.record_type,
      status: row.status,
      title: row.title,
      description: row.description,
      issuerName: row.issuer_name,
      issuerUserId: row.issuer_user_id,
      sourceSystem: row.source_system,
      sourceRecordId: row.source_record_id,
      issuedAt: row.issued_at,
      revisedAt: row.revised_at,
      revokedAt: row.revoked_at,
      evidenceLinksJson: row.evidence_links_json,
      detailsJson: row.details_json,
      createdAt: row.created_at,
      updatedAt: row.updated_at,
    };
  }

  private successResult(): SqlRunResult {
    return {
      success: true,
      meta: {} as SqlExecutionMeta,
    };
  }
}

export class FakeSqlDatabase {
  learnerProfiles: FakeLearnerProfileRow[] = [];
  learnerIdentities: FakeLearnerIdentityRow[] = [];
  learnerRecordEntries: FakeLearnerRecordEntryRow[] = [];
  learnerRecordImportContexts: FakeLearnerRecordImportContextRow[] = [];
  tenants: FakeTenantRow[] = [];
  badgeTemplates: FakeBadgeTemplateRow[] = [];
  assertions: FakeAssertionRow[] = [];
  jobQueueMessages: FakeJobQueueMessageRow[] = [];
  learnerRecordImportPreviews: FakeLearnerRecordImportPreviewRow[] = [];

  prepare(sql: string): FakeStatement {
    return new FakeStatement(this, sql);
  }
}

export const createFakeDb = (): SqlDatabase => {
  return new FakeSqlDatabase() as unknown as SqlDatabase;
};

class FakeAuthIdentityStatement {
  private readonly sql: string;
  private readonly db: FakeAuthIdentitySqlDatabase;
  private boundParams: unknown[] = [];

  constructor(db: FakeAuthIdentitySqlDatabase, sql: string) {
    this.db = db;
    this.sql = sql;
  }

  bind(...params: unknown[]): this {
    this.boundParams = params;
    return this;
  }

  run(): Promise<SqlRunResult> {
    const normalizedSql = this.normalizedSql();

    if (normalizedSql.includes("INSERT INTO users")) {
      this.insertUser();
      return Promise.resolve(this.successResult());
    }

    if (normalizedSql.includes("INSERT INTO auth_identity_links")) {
      this.insertAuthIdentityLink();
      return Promise.resolve(this.successResult());
    }

    throw new Error(`Unsupported run SQL in fake auth DB: ${normalizedSql}`);
  }

  first<T>(): Promise<T | null> {
    const normalizedSql = this.normalizedSql();

    if (normalizedSql.includes("FROM users WHERE email = ?")) {
      return Promise.resolve(this.selectUserByEmail() as T | null);
    }

    if (normalizedSql.includes("FROM users WHERE id = ?")) {
      return Promise.resolve(this.selectUserById() as T | null);
    }

    if (
      normalizedSql.includes("FROM auth_identity_links") &&
      normalizedSql.includes("auth_system = ?") &&
      normalizedSql.includes("auth_user_id = ?")
    ) {
      return Promise.resolve(this.selectAuthIdentityLinkByAuthUserId() as T | null);
    }

    if (
      normalizedSql.includes("FROM auth_identity_links") &&
      normalizedSql.includes("auth_system = ?") &&
      normalizedSql.includes("credtrail_user_id = ?")
    ) {
      return Promise.resolve(this.selectAuthIdentityLinkByCredtrailUserId() as T | null);
    }

    throw new Error(`Unsupported first SQL in fake auth DB: ${normalizedSql}`);
  }

  all<T>(): Promise<SqlQueryResult<T>> {
    throw new Error(`Unsupported all SQL in fake auth DB: ${this.normalizedSql()}`);
  }

  private normalizedSql(): string {
    return this.sql.replace(/\s+/g, " ").trim();
  }

  private insertUser(): void {
    const [id, email] = this.boundParams;

    if (typeof id !== "string" || typeof email !== "string") {
      throw new Error("Invalid bound parameters for user insert");
    }

    const existingUser = this.db.users.find((row) => row.email === email);

    if (existingUser === undefined) {
      this.db.users.push({
        id,
        email,
      });
    }
  }

  private insertAuthIdentityLink(): void {
    const [
      id,
      authSystem,
      authUserId,
      authAccountId,
      credtrailUserId,
      emailSnapshot,
      createdAt,
      updatedAt,
    ] = this.boundParams;

    if (
      typeof id !== "string" ||
      typeof authSystem !== "string" ||
      typeof authUserId !== "string" ||
      (authAccountId !== null && typeof authAccountId !== "string") ||
      typeof credtrailUserId !== "string" ||
      (emailSnapshot !== null && typeof emailSnapshot !== "string") ||
      typeof createdAt !== "string" ||
      typeof updatedAt !== "string"
    ) {
      throw new Error("Invalid bound parameters for auth identity link insert");
    }

    const existingLink = this.db.authIdentityLinks.find((row) => {
      return row.auth_system === authSystem && row.auth_user_id === authUserId;
    });

    if (existingLink !== undefined) {
      throw new Error(
        "UNIQUE constraint failed: auth_identity_links.auth_system, auth_identity_links.auth_user_id",
      );
    }

    this.db.authIdentityLinks.push({
      id,
      auth_system: authSystem,
      auth_user_id: authUserId,
      auth_account_id: authAccountId,
      credtrail_user_id: credtrailUserId,
      email_snapshot: emailSnapshot,
      created_at: createdAt,
      updated_at: updatedAt,
    });
  }

  private selectUserByEmail(): Record<string, unknown> | null {
    const [email] = this.boundParams;

    if (typeof email !== "string") {
      throw new Error("Invalid bound parameters for user select by email");
    }

    const row = this.db.users.find((candidate) => candidate.email === email);

    if (row === undefined) {
      return null;
    }

    return {
      id: row.id,
      email: row.email,
    };
  }

  private selectUserById(): Record<string, unknown> | null {
    const [userId] = this.boundParams;

    if (typeof userId !== "string") {
      throw new Error("Invalid bound parameters for user select by id");
    }

    const row = this.db.users.find((candidate) => candidate.id === userId);

    if (row === undefined) {
      return null;
    }

    return {
      id: row.id,
      email: row.email,
    };
  }

  private selectAuthIdentityLinkByAuthUserId(): Record<string, unknown> | null {
    const [authSystem, authUserId] = this.boundParams;

    if (typeof authSystem !== "string" || typeof authUserId !== "string") {
      throw new Error("Invalid bound parameters for auth identity link select by auth user id");
    }

    const row = this.db.authIdentityLinks.find((candidate) => {
      return candidate.auth_system === authSystem && candidate.auth_user_id === authUserId;
    });

    return row === undefined ? null : this.mapAuthIdentityLink(row);
  }

  private selectAuthIdentityLinkByCredtrailUserId(): Record<string, unknown> | null {
    const [authSystem, credtrailUserId] = this.boundParams;

    if (typeof authSystem !== "string" || typeof credtrailUserId !== "string") {
      throw new Error(
        "Invalid bound parameters for auth identity link select by CredTrail user id",
      );
    }

    const row = this.db.authIdentityLinks.find((candidate) => {
      return (
        candidate.auth_system === authSystem && candidate.credtrail_user_id === credtrailUserId
      );
    });

    return row === undefined ? null : this.mapAuthIdentityLink(row);
  }

  private mapAuthIdentityLink(row: FakeAuthIdentityLinkRow): Record<string, unknown> {
    return {
      id: row.id,
      authSystem: row.auth_system,
      authUserId: row.auth_user_id,
      authAccountId: row.auth_account_id,
      credtrailUserId: row.credtrail_user_id,
      emailSnapshot: row.email_snapshot,
      createdAt: row.created_at,
      updatedAt: row.updated_at,
    };
  }

  private successResult(): SqlRunResult {
    return {
      success: true,
      meta: {} as SqlExecutionMeta,
    };
  }
}

export class FakeAuthIdentitySqlDatabase {
  users: FakeUserRow[] = [];
  authIdentityLinks: FakeAuthIdentityLinkRow[] = [];

  prepare(sql: string): FakeAuthIdentityStatement {
    return new FakeAuthIdentityStatement(this, sql);
  }
}

export const createFakeAuthIdentityDb = (): SqlDatabase => {
  return new FakeAuthIdentitySqlDatabase() as unknown as SqlDatabase;
};

class FakeTenantAuthStatement {
  private readonly sql: string;
  private readonly db: FakeTenantAuthSqlDatabase;
  private boundParams: unknown[] = [];

  constructor(db: FakeTenantAuthSqlDatabase, sql: string) {
    this.db = db;
    this.sql = sql;
  }

  bind(...params: unknown[]): this {
    this.boundParams = params;
    return this;
  }

  run(): Promise<SqlRunResult> {
    const normalizedSql = this.normalizedSql();

    if (normalizedSql.includes("INSERT INTO users")) {
      this.insertUser();
      return Promise.resolve(this.successResult(1));
    }

    if (normalizedSql.includes("INSERT INTO memberships")) {
      return Promise.resolve(this.upsertTenantMembership());
    }

    if (normalizedSql.includes("DELETE FROM memberships")) {
      return Promise.resolve(this.deleteTenantMembership());
    }

    if (normalizedSql.includes("INSERT INTO tenant_auth_policies")) {
      return Promise.resolve(this.upsertTenantAuthPolicy());
    }

    if (
      normalizedSql.includes("UPDATE tenant_auth_providers") &&
      normalizedSql.includes("SET is_default = 0") &&
      normalizedSql.includes("AND id <> ?")
    ) {
      return Promise.resolve(this.clearOtherDefaultProviders());
    }

    if (
      normalizedSql.includes("UPDATE tenant_auth_providers") &&
      normalizedSql.includes("SET is_default = 0")
    ) {
      return Promise.resolve(this.clearTenantDefaultProviders());
    }

    if (normalizedSql.includes("INSERT INTO tenant_auth_providers")) {
      return Promise.resolve(this.insertTenantAuthProvider());
    }

    if (
      normalizedSql.includes("UPDATE tenant_auth_providers") &&
      normalizedSql.includes("SET protocol = ?")
    ) {
      return Promise.resolve(this.updateTenantAuthProvider());
    }

    if (normalizedSql.includes("DELETE FROM tenant_auth_providers")) {
      return Promise.resolve(this.deleteTenantAuthProvider());
    }

    if (
      normalizedSql.includes("UPDATE tenant_auth_policies") &&
      normalizedSql.includes("SET default_provider_id = NULL")
    ) {
      return Promise.resolve(this.clearPolicyDefaultProvider());
    }

    if (normalizedSql.includes("INSERT INTO tenant_break_glass_accounts")) {
      return Promise.resolve(this.upsertTenantBreakGlassAccount());
    }

    if (
      normalizedSql.includes("UPDATE tenant_break_glass_accounts") &&
      normalizedSql.includes("SET revoked_at = ?")
    ) {
      return Promise.resolve(this.revokeTenantBreakGlassAccount());
    }

    if (
      normalizedSql.includes("UPDATE tenant_break_glass_accounts") &&
      normalizedSql.includes("SET last_used_at = ?")
    ) {
      return Promise.resolve(this.markTenantBreakGlassAccountUsed());
    }

    if (
      normalizedSql.includes("UPDATE tenant_break_glass_accounts") &&
      normalizedSql.includes("SET last_enrollment_email_sent_at = ?")
    ) {
      return Promise.resolve(this.markTenantBreakGlassEnrollmentEmailSent());
    }

    throw new Error(`Unsupported run SQL in fake tenant auth DB: ${normalizedSql}`);
  }

  first<T>(): Promise<T | null> {
    const normalizedSql = this.normalizedSql();

    if (normalizedSql.includes("FROM users WHERE email = ?")) {
      return Promise.resolve(this.selectUserByEmail() as T | null);
    }

    if (normalizedSql.includes("FROM users WHERE id = ?")) {
      return Promise.resolve(this.selectUserById() as T | null);
    }

    if (normalizedSql.includes("FROM memberships WHERE tenant_id = ? AND user_id = ?")) {
      return Promise.resolve(this.selectTenantMembership() as T | null);
    }

    if (normalizedSql.includes("FROM tenant_auth_policies")) {
      return Promise.resolve(this.selectTenantAuthPolicy() as T | null);
    }

    if (
      normalizedSql.includes("FROM tenant_auth_providers") &&
      normalizedSql.includes("AND id = ?")
    ) {
      return Promise.resolve(this.selectTenantAuthProviderById() as T | null);
    }

    if (normalizedSql.includes("FROM tenant_sso_saml_configurations")) {
      return Promise.resolve(this.selectLegacySamlConfiguration() as T | null);
    }

    if (
      normalizedSql.includes("FROM tenant_break_glass_accounts AS account") &&
      normalizedSql.includes("account.user_id = ?")
    ) {
      return Promise.resolve(this.selectTenantBreakGlassAccountByUserId() as T | null);
    }

    if (
      normalizedSql.includes("FROM tenant_break_glass_accounts AS account") &&
      normalizedSql.includes("users.email = ?")
    ) {
      return Promise.resolve(this.selectTenantBreakGlassAccountByEmail() as T | null);
    }

    throw new Error(`Unsupported first SQL in fake tenant auth DB: ${normalizedSql}`);
  }

  all<T>(): Promise<SqlQueryResult<T>> {
    const normalizedSql = this.normalizedSql();

    if (normalizedSql.includes("FROM tenant_auth_providers")) {
      return Promise.resolve({
        ...this.successResult(),
        results: this.selectTenantAuthProviders() as T[],
      });
    }

    if (normalizedSql.includes("FROM tenant_break_glass_accounts AS account")) {
      return Promise.resolve({
        ...this.successResult(),
        results: this.selectTenantBreakGlassAccounts() as T[],
      });
    }

    if (
      normalizedSql.includes("FROM memberships INNER JOIN users") &&
      normalizedSql.includes("users.id = memberships.user_id")
    ) {
      return Promise.resolve({
        ...this.successResult(),
        results: this.selectTenantMembers() as T[],
      });
    }

    if (
      normalizedSql.includes("SELECT role, COUNT(*) AS totalCount FROM memberships") &&
      normalizedSql.includes("GROUP BY role")
    ) {
      return Promise.resolve({
        ...this.successResult(),
        results: this.countTenantMembershipsByRole() as T[],
      });
    }

    if (
      normalizedSql.includes("FROM memberships") &&
      normalizedSql.includes("INNER JOIN tenants") &&
      normalizedSql.includes("tenants.is_active = 1")
    ) {
      return Promise.resolve({
        ...this.successResult(),
        results: this.selectAccessibleTenantContexts() as T[],
      });
    }

    throw new Error(`Unsupported all SQL in fake tenant auth DB: ${normalizedSql}`);
  }

  private normalizedSql(): string {
    return this.sql.replace(/\s+/g, " ").trim();
  }

  private insertUser(): void {
    const [id, email] = this.boundParams;

    if (typeof id !== "string" || typeof email !== "string") {
      throw new Error("Invalid bound parameters for user insert");
    }

    const existingUser = this.db.users.find((row) => row.email === email);

    if (existingUser === undefined) {
      this.db.users.push({
        id,
        email,
      });
    }
  }

  private upsertTenantMembership(): SqlRunResult {
    const [tenantId, userId, role, createdAt, updatedAt] = this.boundParams;

    if (
      typeof tenantId !== "string" ||
      typeof userId !== "string" ||
      (role !== "owner" && role !== "admin" && role !== "issuer" && role !== "viewer") ||
      typeof createdAt !== "string" ||
      typeof updatedAt !== "string"
    ) {
      throw new Error("Invalid bound parameters for tenant membership upsert");
    }

    const existing = this.db.memberships.find((row) => {
      return row.tenant_id === tenantId && row.user_id === userId;
    });

    if (existing === undefined) {
      this.db.memberships.push({
        tenant_id: tenantId,
        user_id: userId,
        role,
        created_at: createdAt,
        updated_at: updatedAt,
      });
      return this.successResult(1);
    }

    existing.role = role;
    existing.updated_at = updatedAt;
    return this.successResult(1);
  }

  private deleteTenantMembership(): SqlRunResult {
    const [tenantId, userId] = this.boundParams;

    if (typeof tenantId !== "string" || typeof userId !== "string") {
      throw new Error("Invalid bound parameters for tenant membership delete");
    }

    const beforeCount = this.db.memberships.length;
    this.db.memberships = this.db.memberships.filter((row) => {
      return !(row.tenant_id === tenantId && row.user_id === userId);
    });

    return this.successResult(beforeCount - this.db.memberships.length);
  }

  private upsertTenantAuthPolicy(): SqlRunResult {
    const [
      tenantId,
      loginMode,
      breakGlassEnabled,
      localMfaRequired,
      defaultProviderId,
      enforceForRoles,
      createdAt,
      updatedAt,
    ] = this.boundParams;

    if (
      typeof tenantId !== "string" ||
      (loginMode !== "local" && loginMode !== "hybrid" && loginMode !== "sso_required") ||
      typeof breakGlassEnabled !== "number" ||
      typeof localMfaRequired !== "number" ||
      (defaultProviderId !== null && typeof defaultProviderId !== "string") ||
      (enforceForRoles !== "all_users" && enforceForRoles !== "admins_only") ||
      typeof createdAt !== "string" ||
      typeof updatedAt !== "string"
    ) {
      throw new Error("Invalid bound parameters for tenant auth policy upsert");
    }

    const existingPolicy = this.db.tenantAuthPolicies.find((row) => row.tenant_id === tenantId);

    if (existingPolicy === undefined) {
      this.db.tenantAuthPolicies.push({
        tenant_id: tenantId,
        login_mode: loginMode,
        break_glass_enabled: breakGlassEnabled,
        local_mfa_required: localMfaRequired,
        default_provider_id: defaultProviderId,
        enforce_for_roles: enforceForRoles,
        created_at: createdAt,
        updated_at: updatedAt,
      });
      return this.successResult(1);
    }

    existingPolicy.login_mode = loginMode;
    existingPolicy.break_glass_enabled = breakGlassEnabled;
    existingPolicy.local_mfa_required = localMfaRequired;
    existingPolicy.default_provider_id = defaultProviderId;
    existingPolicy.enforce_for_roles = enforceForRoles;
    existingPolicy.updated_at = updatedAt;
    return this.successResult(1);
  }

  private clearOtherDefaultProviders(): SqlRunResult {
    const [updatedAt, tenantId, providerId] = this.boundParams;

    if (
      typeof updatedAt !== "string" ||
      typeof tenantId !== "string" ||
      typeof providerId !== "string"
    ) {
      throw new Error("Invalid bound parameters for clearing tenant auth default providers");
    }

    let rowsWritten = 0;

    for (const row of this.db.tenantAuthProviders) {
      if (row.tenant_id === tenantId && row.id !== providerId && row.is_default === 1) {
        row.is_default = 0;
        row.updated_at = updatedAt;
        rowsWritten += 1;
      }
    }

    return this.successResult(rowsWritten);
  }

  private clearTenantDefaultProviders(): SqlRunResult {
    const [updatedAt, tenantId] = this.boundParams;

    if (typeof updatedAt !== "string" || typeof tenantId !== "string") {
      throw new Error("Invalid bound parameters for clearing tenant auth defaults");
    }

    let rowsWritten = 0;

    for (const row of this.db.tenantAuthProviders) {
      if (row.tenant_id === tenantId && row.is_default === 1) {
        row.is_default = 0;
        row.updated_at = updatedAt;
        rowsWritten += 1;
      }
    }

    return this.successResult(rowsWritten);
  }

  private insertTenantAuthProvider(): SqlRunResult {
    const [id, tenantId, protocol, label, enabled, isDefault, configJson, createdAt, updatedAt] =
      this.boundParams;

    if (
      typeof id !== "string" ||
      typeof tenantId !== "string" ||
      (protocol !== "oidc" && protocol !== "saml") ||
      typeof label !== "string" ||
      typeof enabled !== "number" ||
      typeof isDefault !== "number" ||
      typeof configJson !== "string" ||
      typeof createdAt !== "string" ||
      typeof updatedAt !== "string"
    ) {
      throw new Error("Invalid bound parameters for tenant auth provider insert");
    }

    this.db.tenantAuthProviders.push({
      id,
      tenant_id: tenantId,
      protocol,
      label,
      enabled,
      is_default: isDefault,
      config_json: configJson,
      created_at: createdAt,
      updated_at: updatedAt,
    });

    return this.successResult(1);
  }

  private updateTenantAuthProvider(): SqlRunResult {
    const [protocol, label, enabled, isDefault, configJson, updatedAt, tenantId, providerId] =
      this.boundParams;

    if (
      (protocol !== "oidc" && protocol !== "saml") ||
      typeof label !== "string" ||
      typeof enabled !== "number" ||
      typeof isDefault !== "number" ||
      typeof configJson !== "string" ||
      typeof updatedAt !== "string" ||
      typeof tenantId !== "string" ||
      typeof providerId !== "string"
    ) {
      throw new Error("Invalid bound parameters for tenant auth provider update");
    }

    const row = this.db.tenantAuthProviders.find((candidate) => {
      return candidate.tenant_id === tenantId && candidate.id === providerId;
    });

    if (row === undefined) {
      return this.successResult(0);
    }

    row.protocol = protocol;
    row.label = label;
    row.enabled = enabled;
    row.is_default = isDefault;
    row.config_json = configJson;
    row.updated_at = updatedAt;

    return this.successResult(1);
  }

  private deleteTenantAuthProvider(): SqlRunResult {
    const [tenantId, providerId] = this.boundParams;

    if (typeof tenantId !== "string" || typeof providerId !== "string") {
      throw new Error("Invalid bound parameters for tenant auth provider delete");
    }

    const beforeCount = this.db.tenantAuthProviders.length;
    this.db.tenantAuthProviders = this.db.tenantAuthProviders.filter((row) => {
      return !(row.tenant_id === tenantId && row.id === providerId);
    });

    return this.successResult(beforeCount - this.db.tenantAuthProviders.length);
  }

  private clearPolicyDefaultProvider(): SqlRunResult {
    const [updatedAt, tenantId, providerId] = this.boundParams;

    if (
      typeof updatedAt !== "string" ||
      typeof tenantId !== "string" ||
      typeof providerId !== "string"
    ) {
      throw new Error("Invalid bound parameters for clearing auth policy default provider");
    }

    let rowsWritten = 0;

    for (const row of this.db.tenantAuthPolicies) {
      if (row.tenant_id === tenantId && row.default_provider_id === providerId) {
        row.default_provider_id = null;
        row.updated_at = updatedAt;
        rowsWritten += 1;
      }
    }

    return this.successResult(rowsWritten);
  }

  private upsertTenantBreakGlassAccount(): SqlRunResult {
    const [tenantId, userId, createdByUserId, lastEnrollmentEmailSentAt, createdAt, updatedAt] =
      this.boundParams;

    if (
      typeof tenantId !== "string" ||
      typeof userId !== "string" ||
      (createdByUserId !== null && typeof createdByUserId !== "string") ||
      (lastEnrollmentEmailSentAt !== null && typeof lastEnrollmentEmailSentAt !== "string") ||
      typeof createdAt !== "string" ||
      typeof updatedAt !== "string"
    ) {
      throw new Error("Invalid bound parameters for tenant break-glass account upsert");
    }

    const existing = this.db.tenantBreakGlassAccounts.find((row) => {
      return row.tenant_id === tenantId && row.user_id === userId;
    });

    if (existing === undefined) {
      this.db.tenantBreakGlassAccounts.push({
        tenant_id: tenantId,
        user_id: userId,
        created_by_user_id: createdByUserId,
        last_used_at: null,
        last_enrollment_email_sent_at: lastEnrollmentEmailSentAt,
        revoked_at: null,
        created_at: createdAt,
        updated_at: updatedAt,
      });
      return this.successResult(1);
    }

    existing.created_by_user_id = createdByUserId;
    existing.last_enrollment_email_sent_at =
      lastEnrollmentEmailSentAt ?? existing.last_enrollment_email_sent_at;
    existing.revoked_at = null;
    existing.updated_at = updatedAt;
    return this.successResult(1);
  }

  private revokeTenantBreakGlassAccount(): SqlRunResult {
    const [revokedAt, updatedAt, tenantId, userId] = this.boundParams;

    if (
      typeof revokedAt !== "string" ||
      typeof updatedAt !== "string" ||
      typeof tenantId !== "string" ||
      typeof userId !== "string"
    ) {
      throw new Error("Invalid bound parameters for tenant break-glass revoke");
    }

    const row = this.db.tenantBreakGlassAccounts.find((candidate) => {
      return (
        candidate.tenant_id === tenantId &&
        candidate.user_id === userId &&
        candidate.revoked_at === null
      );
    });

    if (row === undefined) {
      return this.successResult(0);
    }

    row.revoked_at = revokedAt;
    row.updated_at = updatedAt;
    return this.successResult(1);
  }

  private markTenantBreakGlassAccountUsed(): SqlRunResult {
    const [usedAt, updatedAt, tenantId, userId] = this.boundParams;

    if (
      typeof usedAt !== "string" ||
      typeof updatedAt !== "string" ||
      typeof tenantId !== "string" ||
      typeof userId !== "string"
    ) {
      throw new Error("Invalid bound parameters for tenant break-glass usage");
    }

    const row = this.db.tenantBreakGlassAccounts.find((candidate) => {
      return candidate.tenant_id === tenantId && candidate.user_id === userId;
    });

    if (row === undefined) {
      return this.successResult(0);
    }

    row.last_used_at = usedAt;
    row.updated_at = updatedAt;
    return this.successResult(1);
  }

  private markTenantBreakGlassEnrollmentEmailSent(): SqlRunResult {
    const [sentAt, updatedAt, tenantId, userId] = this.boundParams;

    if (
      typeof sentAt !== "string" ||
      typeof updatedAt !== "string" ||
      typeof tenantId !== "string" ||
      typeof userId !== "string"
    ) {
      throw new Error("Invalid bound parameters for break-glass enrollment email mark");
    }

    const row = this.db.tenantBreakGlassAccounts.find((candidate) => {
      return candidate.tenant_id === tenantId && candidate.user_id === userId;
    });

    if (row === undefined) {
      return this.successResult(0);
    }

    row.last_enrollment_email_sent_at = sentAt;
    row.updated_at = updatedAt;
    return this.successResult(1);
  }

  private selectUserByEmail(): Record<string, unknown> | null {
    const [email] = this.boundParams;

    if (typeof email !== "string") {
      throw new Error("Invalid bound parameters for user select by email");
    }

    const row = this.db.users.find((candidate) => candidate.email === email);

    return row === undefined
      ? null
      : {
          id: row.id,
          email: row.email,
        };
  }

  private selectUserById(): Record<string, unknown> | null {
    const [userId] = this.boundParams;

    if (typeof userId !== "string") {
      throw new Error("Invalid bound parameters for user select by id");
    }

    const row = this.db.users.find((candidate) => candidate.id === userId);

    return row === undefined
      ? null
      : {
          id: row.id,
          email: row.email,
        };
  }

  private selectTenantMembership(): Record<string, unknown> | null {
    const [tenantId, userId] = this.boundParams;

    if (typeof tenantId !== "string" || typeof userId !== "string") {
      throw new Error("Invalid bound parameters for tenant membership lookup");
    }

    const row = this.db.memberships.find((candidate) => {
      return candidate.tenant_id === tenantId && candidate.user_id === userId;
    });

    return row === undefined ? null : this.mapTenantMembership(row);
  }

  private selectTenantMembers(): Record<string, unknown>[] {
    const [tenantId] = this.boundParams;

    if (typeof tenantId !== "string") {
      throw new Error("Invalid bound parameters for tenant member list");
    }

    const roleRank = {
      owner: 0,
      admin: 1,
      issuer: 2,
      viewer: 3,
    };

    const rows: Record<string, unknown>[] = [];

    for (const membership of this.db.memberships) {
      if (membership.tenant_id !== tenantId) {
        continue;
      }

      const user = this.db.users.find((candidate) => candidate.id === membership.user_id);

      if (user === undefined) {
        continue;
      }

      rows.push({
        tenantId: membership.tenant_id,
        userId: membership.user_id,
        email: user.email,
        role: membership.role,
        createdAt: membership.created_at ?? "2026-02-10T22:00:00.000Z",
        updatedAt: membership.updated_at ?? "2026-02-10T22:00:00.000Z",
      });
    }

    return rows.sort((left, right) => {
      const leftRole = left.role as FakeMembershipRow["role"];
      const rightRole = right.role as FakeMembershipRow["role"];
      const byRole = roleRank[leftRole] - roleRank[rightRole];

      if (byRole !== 0) {
        return byRole;
      }

      const byEmail = String(left.email).localeCompare(String(right.email));

      if (byEmail !== 0) {
        return byEmail;
      }

      return String(left.userId).localeCompare(String(right.userId));
    });
  }

  private countTenantMembershipsByRole(): Record<string, unknown>[] {
    const [tenantId] = this.boundParams;

    if (typeof tenantId !== "string") {
      throw new Error("Invalid bound parameters for tenant membership counts");
    }

    const counts = new Map<FakeMembershipRow["role"], number>();

    for (const membership of this.db.memberships) {
      if (membership.tenant_id !== tenantId) {
        continue;
      }

      counts.set(membership.role, (counts.get(membership.role) ?? 0) + 1);
    }

    return Array.from(counts.entries()).map(([role, totalCount]) => ({
      role,
      totalCount,
    }));
  }

  private selectTenantAuthPolicy(): Record<string, unknown> | null {
    const [tenantId] = this.boundParams;

    if (typeof tenantId !== "string") {
      throw new Error("Invalid bound parameters for tenant auth policy select");
    }

    const row = this.db.tenantAuthPolicies.find((candidate) => candidate.tenant_id === tenantId);

    if (row === undefined) {
      return null;
    }

    return {
      tenantId: row.tenant_id,
      loginMode: row.login_mode,
      breakGlassEnabled: row.break_glass_enabled,
      localMfaRequired: row.local_mfa_required,
      defaultProviderId: row.default_provider_id,
      enforceForRoles: row.enforce_for_roles,
      createdAt: row.created_at,
      updatedAt: row.updated_at,
    };
  }

  private selectTenantAuthProviders(): Record<string, unknown>[] {
    const [tenantId] = this.boundParams;

    if (typeof tenantId !== "string") {
      throw new Error("Invalid bound parameters for tenant auth provider list");
    }

    return this.db.tenantAuthProviders
      .filter((row) => row.tenant_id === tenantId)
      .sort((left, right) => {
        if (left.is_default !== right.is_default) {
          return right.is_default - left.is_default;
        }

        return left.id.localeCompare(right.id);
      })
      .map((row) => this.mapTenantAuthProvider(row));
  }

  private selectTenantAuthProviderById(): Record<string, unknown> | null {
    const [tenantId, providerId] = this.boundParams;

    if (typeof tenantId !== "string" || typeof providerId !== "string") {
      throw new Error("Invalid bound parameters for tenant auth provider lookup");
    }

    const row = this.db.tenantAuthProviders.find((candidate) => {
      return candidate.tenant_id === tenantId && candidate.id === providerId;
    });

    return row === undefined ? null : this.mapTenantAuthProvider(row);
  }

  private selectLegacySamlConfiguration(): Record<string, unknown> | null {
    const [tenantId] = this.boundParams;

    if (typeof tenantId !== "string") {
      throw new Error("Invalid bound parameters for legacy SAML configuration lookup");
    }

    const row = this.db.legacySamlConfigurations.find(
      (candidate) => candidate.tenant_id === tenantId,
    );

    if (row === undefined) {
      return null;
    }

    return {
      tenantId: row.tenant_id,
      idpEntityId: row.idp_entity_id,
      ssoLoginUrl: row.sso_login_url,
      idpCertificatePem: row.idp_certificate_pem,
      idpMetadataUrl: row.idp_metadata_url,
      spEntityId: row.sp_entity_id,
      assertionConsumerServiceUrl: row.assertion_consumer_service_url,
      nameIdFormat: row.name_id_format,
      enforced: row.enforced,
      createdAt: row.created_at,
      updatedAt: row.updated_at,
    };
  }

  private mapTenantMembership(row: FakeMembershipRow): Record<string, unknown> {
    return {
      tenantId: row.tenant_id,
      userId: row.user_id,
      role: row.role,
      createdAt: row.created_at ?? "2026-02-10T22:00:00.000Z",
      updatedAt: row.updated_at ?? "2026-02-10T22:00:00.000Z",
    };
  }

  private selectTenantBreakGlassAccountByUserId(): Record<string, unknown> | null {
    const [tenantId, userId] = this.boundParams;

    if (typeof tenantId !== "string" || typeof userId !== "string") {
      throw new Error("Invalid bound parameters for tenant break-glass lookup by user");
    }

    const row = this.db.tenantBreakGlassAccounts.find((candidate) => {
      return (
        candidate.tenant_id === tenantId &&
        candidate.user_id === userId &&
        candidate.revoked_at === null
      );
    });

    return row === undefined ? null : this.mapTenantBreakGlassAccount(row);
  }

  private selectTenantBreakGlassAccountByEmail(): Record<string, unknown> | null {
    const [tenantId, email] = this.boundParams;

    if (typeof tenantId !== "string" || typeof email !== "string") {
      throw new Error("Invalid bound parameters for tenant break-glass lookup by email");
    }

    const user = this.db.users.find((candidate) => candidate.email === email);

    if (user === undefined) {
      return null;
    }

    const row = this.db.tenantBreakGlassAccounts.find((candidate) => {
      return (
        candidate.tenant_id === tenantId &&
        candidate.user_id === user.id &&
        candidate.revoked_at === null
      );
    });

    return row === undefined ? null : this.mapTenantBreakGlassAccount(row);
  }

  private mapTenantAuthProvider(row: FakeTenantAuthProviderRow): Record<string, unknown> {
    return {
      id: row.id,
      tenantId: row.tenant_id,
      protocol: row.protocol,
      label: row.label,
      enabled: row.enabled,
      isDefault: row.is_default,
      configJson: row.config_json,
      createdAt: row.created_at,
      updatedAt: row.updated_at,
    };
  }

  private selectTenantBreakGlassAccounts(): Record<string, unknown>[] {
    const [tenantId] = this.boundParams;

    if (typeof tenantId !== "string") {
      throw new Error("Invalid bound parameters for tenant break-glass list");
    }

    return this.db.tenantBreakGlassAccounts
      .filter((row) => row.tenant_id === tenantId)
      .map((row) => this.mapTenantBreakGlassAccount(row));
  }

  private mapTenantBreakGlassAccount(row: FakeTenantBreakGlassAccountRow): Record<string, unknown> {
    const user = this.db.users.find((candidate) => candidate.id === row.user_id);
    const betterAuthUser = user
      ? this.db.betterAuthUsers.find((candidate) => candidate.email === user.email)
      : undefined;
    const betterAuthAccount =
      betterAuthUser === undefined
        ? undefined
        : this.db.betterAuthAccounts.find((candidate) => {
            return (
              candidate.user_id === betterAuthUser.id && candidate.provider_id === "credential"
            );
          });

    return {
      tenantId: row.tenant_id,
      userId: row.user_id,
      email: user?.email ?? "",
      createdByUserId: row.created_by_user_id,
      lastUsedAt: row.last_used_at,
      lastEnrollmentEmailSentAt: row.last_enrollment_email_sent_at,
      revokedAt: row.revoked_at,
      createdAt: row.created_at,
      updatedAt: row.updated_at,
      betterAuthUserId: betterAuthUser?.id ?? null,
      localCredentialEnabled: betterAuthAccount?.password ? 1 : 0,
      twoFactorEnabled: betterAuthUser?.two_factor_enabled ?? 0,
    };
  }

  private selectAccessibleTenantContexts(): AccessibleTenantContextRecord[] {
    const [userId] = this.boundParams;

    if (typeof userId !== "string") {
      throw new Error("Invalid bound parameters for accessible tenant context list");
    }

    return this.db.memberships
      .filter((membership) => membership.user_id === userId)
      .map((membership) => {
        const tenant = this.db.tenants.find((candidate) => {
          return candidate.id === membership.tenant_id && candidate.is_active === 1;
        });

        if (tenant === undefined) {
          return null;
        }

        return {
          tenantId: tenant.id,
          tenantSlug: tenant.slug,
          tenantDisplayName: tenant.display_name,
          tenantPlanTier: tenant.plan_tier,
          membershipRole: membership.role,
        };
      })
      .filter((row): row is AccessibleTenantContextRecord => row !== null)
      .sort((left, right) => {
        const byName = left.tenantDisplayName.localeCompare(right.tenantDisplayName);

        if (byName !== 0) {
          return byName;
        }

        return left.tenantSlug.localeCompare(right.tenantSlug);
      });
  }

  private successResult(rowsWritten = 0): SqlRunResult {
    return {
      success: true,
      meta: {
        rowsWritten,
      } as SqlExecutionMeta,
    };
  }
}

export class FakeTenantAuthSqlDatabase {
  users: FakeUserRow[] = [];
  tenantAuthPolicies: FakeTenantAuthPolicyRow[] = [];
  tenantAuthProviders: FakeTenantAuthProviderRow[] = [];
  tenantBreakGlassAccounts: FakeTenantBreakGlassAccountRow[] = [];
  legacySamlConfigurations: FakeLegacySamlConfigurationRow[] = [];
  tenants: FakeTenantRow[] = [];
  memberships: FakeMembershipRow[] = [];
  betterAuthUsers: Array<{
    id: string;
    email: string;
    two_factor_enabled: number;
  }> = [];
  betterAuthAccounts: Array<{
    user_id: string;
    provider_id: string;
    password: string | null;
  }> = [];

  prepare(sql: string): FakeTenantAuthStatement {
    return new FakeTenantAuthStatement(this, sql);
  }
}

export const createFakeTenantAuthDb = (): SqlDatabase => {
  return new FakeTenantAuthSqlDatabase() as unknown as SqlDatabase;
};

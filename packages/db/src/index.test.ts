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

    if (normalizedSql.includes("FROM learner_record_entries WHERE tenant_id = ?") && normalizedSql.includes("AND id = ?")) {
      return Promise.resolve(this.selectLearnerRecordEntryById() as T | null);
    }

    if (
      normalizedSql.includes("FROM learner_record_import_context") &&
      normalizedSql.includes("AND entry_id = ?")
    ) {
      return Promise.resolve(this.selectLearnerRecordImportContextByEntryId() as T | null);
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
        if (
          candidate.tenant_id !== tenantId ||
          candidate.learner_profile_id !== learnerProfileId
        ) {
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
          candidate.tenant_id === tenantId &&
          candidate.job_type === "import_learner_record_batch"
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
          return (
            candidate.tenant_id === row.tenant_id && candidate.id === row.badge_template_id
          );
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

  private isLearnerRecordSourceSystem(
    value: unknown,
  ): value is dbModule.LearnerRecordSourceSystem {
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

class FakeSqlDatabase {
  learnerProfiles: FakeLearnerProfileRow[] = [];
  learnerIdentities: FakeLearnerIdentityRow[] = [];
  learnerRecordEntries: FakeLearnerRecordEntryRow[] = [];
  learnerRecordImportContexts: FakeLearnerRecordImportContextRow[] = [];
  tenants: FakeTenantRow[] = [];
  badgeTemplates: FakeBadgeTemplateRow[] = [];
  assertions: FakeAssertionRow[] = [];
  jobQueueMessages: FakeJobQueueMessageRow[] = [];

  prepare(sql: string): FakeStatement {
    return new FakeStatement(this, sql);
  }
}

const createFakeDb = (): SqlDatabase => {
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

class FakeAuthIdentitySqlDatabase {
  users: FakeUserRow[] = [];
  authIdentityLinks: FakeAuthIdentityLinkRow[] = [];

  prepare(sql: string): FakeAuthIdentityStatement {
    return new FakeAuthIdentityStatement(this, sql);
  }
}

const createFakeAuthIdentityDb = (): SqlDatabase => {
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

class FakeTenantAuthSqlDatabase {
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

const createFakeTenantAuthDb = (): SqlDatabase => {
  return new FakeTenantAuthSqlDatabase() as unknown as SqlDatabase;
};

describe("normalizeLearnerIdentityValue", () => {
  it("normalizes email and email_sha256 identity values", () => {
    expect(normalizeLearnerIdentityValue("email", "  Student@Umich.edu ")).toBe(
      "student@umich.edu",
    );
    expect(normalizeLearnerIdentityValue("email_sha256", " AABBCC ")).toBe("aabbcc");
  });
});

describe("learner profiles and identity aliases", () => {
  it("creates a learner profile and resolves it by normalized primary identity", async () => {
    const db = createFakeDb();
    const profile = await createLearnerProfile(db, {
      tenantId: "tenant_umich",
      displayName: "Jane Doe",
      primaryIdentityType: "email",
      primaryIdentityValue: " Jane.Doe@Umich.edu ",
      primaryIdentityVerified: true,
    });

    expect(profile.tenantId).toBe("tenant_umich");
    expect(profile.displayName).toBe("Jane Doe");
    expect(profile.subjectId.startsWith("urn:credtrail:learner:tenant_umich:")).toBe(true);

    const resolved = await findLearnerProfileByIdentity(db, {
      tenantId: "tenant_umich",
      identityType: "email",
      identityValue: "jane.doe@umich.edu",
    });

    expect(resolved?.id).toBe(profile.id);

    const identities = await listLearnerIdentitiesByProfile(db, "tenant_umich", profile.id);
    expect(identities).toHaveLength(1);
    expect(identities[0]?.isPrimary).toBe(true);
    expect(identities[0]?.isVerified).toBe(true);
    expect(identities[0]?.identityValue).toBe("jane.doe@umich.edu");
  });

  it("links new aliases to the same learner and switches primary identity when requested", async () => {
    const db = createFakeDb();
    const profile = await createLearnerProfile(db, {
      tenantId: "tenant_umich",
      primaryIdentityType: "email",
      primaryIdentityValue: "student@umich.edu",
      primaryIdentityVerified: true,
    });

    await addLearnerIdentityAlias(db, {
      tenantId: "tenant_umich",
      learnerProfileId: profile.id,
      identityType: "email",
      identityValue: "student@gmail.com",
      isPrimary: true,
      isVerified: true,
    });

    const oldIdentityResolved = await findLearnerProfileByIdentity(db, {
      tenantId: "tenant_umich",
      identityType: "email",
      identityValue: "student@umich.edu",
    });
    const newIdentityResolved = await findLearnerProfileByIdentity(db, {
      tenantId: "tenant_umich",
      identityType: "email",
      identityValue: "student@gmail.com",
    });

    expect(oldIdentityResolved?.id).toBe(profile.id);
    expect(newIdentityResolved?.id).toBe(profile.id);

    const identities = await listLearnerIdentitiesByProfile(db, "tenant_umich", profile.id);
    expect(identities).toHaveLength(2);
    expect(identities[0]?.identityValue).toBe("student@gmail.com");
    expect(identities[0]?.isPrimary).toBe(true);
    expect(identities[1]?.identityValue).toBe("student@umich.edu");
    expect(identities[1]?.isPrimary).toBe(false);
  });

  it("prevents duplicate identity aliases within a tenant", async () => {
    const db = createFakeDb();
    const firstProfile = await createLearnerProfile(db, {
      tenantId: "tenant_umich",
      primaryIdentityType: "email",
      primaryIdentityValue: "first@umich.edu",
    });
    const secondProfile = await createLearnerProfile(db, {
      tenantId: "tenant_umich",
      primaryIdentityType: "email",
      primaryIdentityValue: "second@umich.edu",
    });

    expect(firstProfile.id).not.toBe(secondProfile.id);

    await expect(
      addLearnerIdentityAlias(db, {
        tenantId: "tenant_umich",
        learnerProfileId: secondProfile.id,
        identityType: "email",
        identityValue: "first@umich.edu",
      }),
    ).rejects.toThrow("UNIQUE constraint failed");
  });

  it("resolves to existing learner profile for repeated identity values", async () => {
    const db = createFakeDb();
    const first = await resolveLearnerProfileForIdentity(db, {
      tenantId: "tenant_umich",
      identityType: "email",
      identityValue: "student@umich.edu",
    });
    const second = await resolveLearnerProfileForIdentity(db, {
      tenantId: "tenant_umich",
      identityType: "email",
      identityValue: "student@umich.edu",
    });

    expect(second.id).toBe(first.id);
    const identities = await listLearnerIdentitiesByProfile(db, "tenant_umich", first.id);
    expect(identities).toHaveLength(1);
  });
});

describe("resolveLearnerProfileFromSaml", () => {
  it("falls back to verified email and links new SAML subject when subject changes", async () => {
    const db = createFakeDb();
    const profile = await createLearnerProfile(db, {
      tenantId: "tenant_umich",
      primaryIdentityType: "email",
      primaryIdentityValue: "student@umich.edu",
      primaryIdentityVerified: true,
    });

    const resolvedFromFallback = await resolveLearnerProfileFromSaml(db, {
      tenantId: "tenant_umich",
      samlSubject: "umich-subject-123",
      email: "student@umich.edu",
    });

    expect(resolvedFromFallback.strategy).toBe("verified_email");
    expect(resolvedFromFallback.profile.id).toBe(profile.id);

    const resolvedBySaml = await resolveLearnerProfileFromSaml(db, {
      tenantId: "tenant_umich",
      samlSubject: "umich-subject-123",
      email: "another-email@umich.edu",
    });

    expect(resolvedBySaml.strategy).toBe("saml_subject");
    expect(resolvedBySaml.profile.id).toBe(profile.id);

    const identities = await listLearnerIdentitiesByProfile(db, "tenant_umich", profile.id);
    expect(identities.map((entry) => entry.identityType)).toEqual(["saml_subject", "email"]);
    expect(identities[0]?.isPrimary).toBe(true);
    expect(identities[1]?.isPrimary).toBe(false);
  });

  it("creates a new profile when no existing SAML or verified email identity exists", async () => {
    const db = createFakeDb();
    const resolved = await resolveLearnerProfileFromSaml(db, {
      tenantId: "tenant_umich",
      samlSubject: "umich-subject-999",
      email: "new.student@gmail.com",
      displayName: "New Student",
    });

    expect(resolved.strategy).toBe("created");
    expect(resolved.profile.displayName).toBe("New Student");

    const identities = await listLearnerIdentitiesByProfile(
      db,
      "tenant_umich",
      resolved.profile.id,
    );
    expect(identities).toHaveLength(2);
    expect(identities[0]?.identityType).toBe("saml_subject");
    expect(identities[1]?.identityType).toBe("email");
    expect(identities[1]?.isVerified).toBe(true);
  });

  it("fails when neither SAML subject nor email is provided", async () => {
    const db = createFakeDb();

    await expect(
      resolveLearnerProfileFromSaml(db, {
        tenantId: "tenant_umich",
      }),
    ).rejects.toThrow("Cannot resolve learner profile without SAML subject or email");
  });
});

describe("learner-record entries", () => {
  it("creates and lists non-badge learner-record entries for a learner profile", async () => {
    const db = createFakeDb();
    const profile = await createLearnerProfile(db, {
      tenantId: "tenant_umich",
      primaryIdentityType: "email",
      primaryIdentityValue: "student@umich.edu",
      primaryIdentityVerified: true,
    });

    const createdEntry = await createLearnerRecordEntry(db, {
      tenantId: "tenant_umich",
      learnerProfileId: profile.id,
      trustLevel: "issuer_verified",
      recordType: "course",
      title: "Clinical Placement Seminar",
      description: "Completed with distinction.",
      issuerName: "University of Michigan",
      issuerUserId: "usr_admin",
      sourceSystem: "credtrail_admin",
      issuedAt: "2026-03-24T15:00:00.000Z",
      evidenceLinks: ["https://credtrail.example.edu/evidence/clinical-placement-seminar"],
      detailsJson: '{"grade":"A","credits":3}',
    });

    expect(createdEntry.id.startsWith("lre_")).toBe(true);
    expect(createdEntry.title).toBe("Clinical Placement Seminar");
    expect(createdEntry.evidenceLinksJson).toBe(
      '["https://credtrail.example.edu/evidence/clinical-placement-seminar"]',
    );

    const listedEntries = await listLearnerRecordEntries(db, {
      tenantId: "tenant_umich",
      learnerProfileId: profile.id,
    });

    expect(listedEntries).toEqual([createdEntry]);
  });

  it("filters learner-record entries by trust and status", async () => {
    const db = createFakeDb();
    const profile = await createLearnerProfile(db, {
      tenantId: "tenant_umich",
      primaryIdentityType: "email",
      primaryIdentityValue: "student@umich.edu",
      primaryIdentityVerified: true,
    });

    await createLearnerRecordEntry(db, {
      tenantId: "tenant_umich",
      learnerProfileId: profile.id,
      trustLevel: "issuer_verified",
      recordType: "course",
      title: "Applied Statistics",
      issuerName: "University of Michigan",
      sourceSystem: "credtrail_admin",
      issuedAt: "2026-03-20T15:00:00.000Z",
      evidenceLinks: [],
    });
    const supplemental = await createLearnerRecordEntry(db, {
      tenantId: "tenant_umich",
      learnerProfileId: profile.id,
      trustLevel: "learner_supplemental",
      recordType: "supplemental_artifact",
      title: "Portfolio Reflection",
      issuerName: "Learner Portfolio",
      sourceSystem: "learner_self_reported",
      issuedAt: "2026-03-25T15:00:00.000Z",
      evidenceLinks: [],
      status: "expired",
    });

    const filtered = await listLearnerRecordEntries(db, {
      tenantId: "tenant_umich",
      learnerProfileId: profile.id,
      trustLevel: "learner_supplemental",
      status: "expired",
    });

    expect(filtered).toEqual([supplemental]);
  });

  it("patches learner-record provenance and revoke state without mutating badge assertions", async () => {
    const db = createFakeDb();
    const profile = await createLearnerProfile(db, {
      tenantId: "tenant_umich",
      primaryIdentityType: "email",
      primaryIdentityValue: "student@umich.edu",
      primaryIdentityVerified: true,
    });
    const createdEntry = await createLearnerRecordEntry(db, {
      tenantId: "tenant_umich",
      learnerProfileId: profile.id,
      trustLevel: "issuer_verified",
      recordType: "certificate",
      title: "Instructional Design Certificate",
      issuerName: "University of Michigan",
      sourceSystem: "csv_import",
      sourceRecordId: "legacy-cert-123",
      issuedAt: "2026-03-18T15:00:00.000Z",
      evidenceLinks: ["https://credtrail.example.edu/evidence/instructional-design"],
    });

    const updatedEntry = await patchLearnerRecordEntry(db, {
      tenantId: "tenant_umich",
      entryId: createdEntry.id,
      description: "Revoked after academic integrity review.",
      status: "revoked",
      detailsJson: '{"reviewedBy":"Academic Affairs"}',
      revisedAt: "2026-03-25T12:00:00.000Z",
      revokedAt: "2026-03-25T15:00:00.000Z",
      issuerName: "University of Michigan Academic Affairs",
      sourceSystem: "api",
      sourceRecordId: "revocation-456",
      evidenceLinks: ["https://credtrail.example.edu/reviews/instructional-design"],
    });

    expect(updatedEntry).not.toBeNull();
    expect(updatedEntry).toMatchObject({
      id: createdEntry.id,
      status: "revoked",
      description: "Revoked after academic integrity review.",
      issuerName: "University of Michigan Academic Affairs",
      sourceSystem: "api",
      sourceRecordId: "revocation-456",
      revisedAt: "2026-03-25T12:00:00.000Z",
      revokedAt: "2026-03-25T15:00:00.000Z",
      detailsJson: '{"reviewedBy":"Academic Affairs"}',
      evidenceLinksJson: '["https://credtrail.example.edu/reviews/instructional-design"]',
    });
  });
});

describe("learner-record import context", () => {
  it("persists queryable smart-default context separately from learner-record details", async () => {
    const db = createFakeDb();
    const profile = await createLearnerProfile(db, {
      tenantId: "tenant_umich",
      primaryIdentityType: "email",
      primaryIdentityValue: "student@umich.edu",
      primaryIdentityVerified: true,
    });
    const entry = await createLearnerRecordEntry(db, {
      tenantId: "tenant_umich",
      learnerProfileId: profile.id,
      trustLevel: "issuer_verified",
      recordType: "course",
      title: "Clinical Placement Seminar",
      issuerName: "University of Michigan",
      sourceSystem: "csv_import",
      issuedAt: "2026-03-26T15:00:00.000Z",
      evidenceLinks: [],
    });

    const createdContext = await createLearnerRecordImportContext(db, {
      tenantId: "tenant_umich",
      entryId: entry.id,
      orgUnitId: "tenant_umich:org:department-health",
      badgeTemplateId: "badge_template_001",
      pathwayLabel: "Clinical readiness",
      inferredFrom: ["row", "badge_template"],
    });

    expect(createdContext).toMatchObject({
      entryId: entry.id,
      tenantId: "tenant_umich",
      orgUnitId: "tenant_umich:org:department-health",
      badgeTemplateId: "badge_template_001",
      pathwayLabel: "Clinical readiness",
      inferredFromJson: '["row","badge_template"]',
    });

    const loadedContext = await findLearnerRecordImportContextByEntryId(
      db,
      "tenant_umich",
      entry.id,
    );

    expect(loadedContext).toEqual(createdContext);
  });
});

describe("learner-record import queue helpers", () => {
  it("lists and retries learner-record import queue messages by batch", async () => {
    const db = createFakeDb() as unknown as FakeSqlDatabase;

    db.jobQueueMessages.push(
      {
        id: "job_import_001",
        tenant_id: "tenant_umich",
        job_type: "import_learner_record_batch",
        payload_json: JSON.stringify({
          batchId: "batch_123",
          rowNumber: 1,
          fileName: "learner-records.csv",
          format: "csv",
          row: {
            effectiveTrustLevel: "issuer_verified",
          },
        }),
        idempotency_key: "idem_import_001",
        attempt_count: 3,
        max_attempts: 8,
        available_at: "2026-03-26T15:00:00.000Z",
        leased_until: null,
        lease_token: null,
        last_error: "Temporary downstream failure",
        completed_at: null,
        failed_at: "2026-03-26T15:05:00.000Z",
        status: "failed",
        created_at: "2026-03-26T15:00:00.000Z",
        updated_at: "2026-03-26T15:05:00.000Z",
      },
      {
        id: "job_import_002",
        tenant_id: "tenant_umich",
        job_type: "import_learner_record_batch",
        payload_json: JSON.stringify({
          batchId: "batch_123",
          rowNumber: 2,
          fileName: "learner-records.csv",
          format: "csv",
          row: {
            effectiveTrustLevel: "learner_supplemental",
          },
        }),
        idempotency_key: "idem_import_002",
        attempt_count: 1,
        max_attempts: 8,
        available_at: "2026-03-26T15:00:00.000Z",
        leased_until: null,
        lease_token: null,
        last_error: null,
        completed_at: "2026-03-26T15:04:00.000Z",
        failed_at: null,
        status: "completed",
        created_at: "2026-03-26T15:01:00.000Z",
        updated_at: "2026-03-26T15:04:00.000Z",
      },
    );

    const listed = await listImportLearnerRecordBatchQueueMessages(db, {
      tenantId: "tenant_umich",
    });

    expect(listed).toHaveLength(2);
    expect(listed[0]).toMatchObject({
      batchId: "batch_123",
      rowNumber: 2,
      defaultTrustLevel: "learner_supplemental",
    });

    const retry = await retryFailedImportLearnerRecordBatchQueueMessages(db, {
      tenantId: "tenant_umich",
      batchId: "batch_123",
      rowNumbers: [1],
      nowIso: "2026-03-26T15:10:00.000Z",
    });

    expect(retry).toEqual({
      matched: 1,
      retried: 1,
      skippedNotFailed: 0,
    });
    expect(db.jobQueueMessages[0]).toMatchObject({
      status: "pending",
      attempt_count: 0,
      last_error: null,
      failed_at: null,
      available_at: "2026-03-26T15:10:00.000Z",
    });
  });
});

describe("learner-record exports", () => {
  it("lists badge assertion exports for a learner profile with email alias fallback", async () => {
    const db = createFakeDb();
    const fakeDb = db as unknown as FakeSqlDatabase;
    const profile = await createLearnerProfile(db, {
      tenantId: "tenant_umich",
      primaryIdentityType: "email",
      primaryIdentityValue: "student@umich.edu",
      primaryIdentityVerified: true,
    });

    await addLearnerIdentityAlias(db, {
      tenantId: "tenant_umich",
      learnerProfileId: profile.id,
      identityType: "email",
      identityValue: "student.alias@umich.edu",
      isVerified: true,
    });

    fakeDb.tenants.push({
      id: "tenant_umich",
      slug: "umich",
      display_name: "University of Michigan",
      plan_tier: "institution",
      is_active: 1,
    });
    fakeDb.badgeTemplates.push({
      id: "badge_template_001",
      tenant_id: "tenant_umich",
      title: "Clinical Hours Badge",
      description: "Awarded for completing clinical hours.",
      criteria_uri: "https://credtrail.example.edu/badges/clinical-hours/criteria",
      image_uri: "https://credtrail.example.edu/badges/clinical-hours/image.png",
    });
    fakeDb.assertions.push(
      {
        id: "assertion_primary",
        tenant_id: "tenant_umich",
        public_id: "public_primary",
        learner_profile_id: profile.id,
        badge_template_id: "badge_template_001",
        recipient_identity: "student@umich.edu",
        recipient_identity_type: "email",
        vc_r2_key: "tenants/tenant_umich/assertions/assertion_primary.jsonld",
        status_list_index: 1,
        idempotency_key: "idem_primary",
        issued_at: "2026-03-24T15:00:00.000Z",
        issued_by_user_id: "usr_admin",
        revoked_at: null,
        created_at: "2026-03-24T15:00:00.000Z",
        updated_at: "2026-03-24T15:00:00.000Z",
      },
      {
        id: "assertion_alias",
        tenant_id: "tenant_umich",
        public_id: "public_alias",
        learner_profile_id: null,
        badge_template_id: "badge_template_001",
        recipient_identity: "student.alias@umich.edu",
        recipient_identity_type: "email",
        vc_r2_key: "tenants/tenant_umich/assertions/assertion_alias.jsonld",
        status_list_index: 2,
        idempotency_key: "idem_alias",
        issued_at: "2026-03-25T15:00:00.000Z",
        issued_by_user_id: "usr_admin",
        revoked_at: null,
        created_at: "2026-03-25T15:00:00.000Z",
        updated_at: "2026-03-25T15:00:00.000Z",
      },
      {
        id: "assertion_other",
        tenant_id: "tenant_umich",
        public_id: "public_other",
        learner_profile_id: null,
        badge_template_id: "badge_template_001",
        recipient_identity: "someone-else@umich.edu",
        recipient_identity_type: "email",
        vc_r2_key: "tenants/tenant_umich/assertions/assertion_other.jsonld",
        status_list_index: 3,
        idempotency_key: "idem_other",
        issued_at: "2026-03-26T15:00:00.000Z",
        issued_by_user_id: "usr_admin",
        revoked_at: null,
        created_at: "2026-03-26T15:00:00.000Z",
        updated_at: "2026-03-26T15:00:00.000Z",
      },
    );

    const exported = await listLearnerRecordAssertionExports(db, {
      tenantId: "tenant_umich",
      learnerProfileId: profile.id,
    });

    expect(exported.map((row) => row.assertionId)).toEqual([
      "assertion_alias",
      "assertion_primary",
    ]);
    expect(exported[0]).toMatchObject({
      tenantId: "tenant_umich",
      learnerProfileId: null,
      badgeTemplateId: "badge_template_001",
      badgeTitle: "Clinical Hours Badge",
      badgeCriteriaUri: "https://credtrail.example.edu/badges/clinical-hours/criteria",
      issuerName: "University of Michigan",
      recipientIdentity: "student.alias@umich.edu",
    });
  });
});

describe("learner-record foundation", () => {
  it("adds a learner-record migration with provenance and tenant/profile indexes", () => {
    const sql = readFileSync(
      new URL("../migrations/0035_learner_record_entries.sql", import.meta.url),
      "utf8",
    );

    expect(sql).toContain("CREATE TABLE IF NOT EXISTS learner_record_entries");
    expect(sql).toContain("trust_level TEXT NOT NULL CHECK");
    expect(sql).toContain("source_system TEXT NOT NULL CHECK");
    expect(sql).toContain("evidence_links_json TEXT NOT NULL DEFAULT '[]'");
    expect(sql).toContain("FOREIGN KEY (tenant_id, learner_profile_id)");
    expect(sql).toContain("idx_learner_record_entries_tenant_profile_issued");
    expect(sql).toContain("idx_learner_record_entries_tenant_trust_status");
  });

  it("adds a learner-record import-context migration with queryable org-unit and badge-template indexes", () => {
    const sql = readFileSync(
      new URL("../migrations/0036_learner_record_import_context.sql", import.meta.url),
      "utf8",
    );

    expect(sql).toContain("CREATE TABLE IF NOT EXISTS learner_record_import_context");
    expect(sql).toContain("entry_id TEXT PRIMARY KEY");
    expect(sql).toContain("inferred_from_json TEXT NOT NULL DEFAULT '[\"none\"]'");
    expect(sql).toContain("idx_learner_record_import_context_tenant_org_unit");
    expect(sql).toContain("idx_learner_record_import_context_tenant_badge_template");
  });
});

describe("auth identity links", () => {
  it("persists and resolves Better Auth links by auth system and auth user id", async () => {
    const db = createFakeAuthIdentityDb();
    const user = await upsertUserByEmail(db, " Student@Example.edu ");

    const link = await createAuthIdentityLink(db, {
      authSystem: "better_auth",
      authUserId: "ba_usr_123",
      authAccountId: "ba_account_123",
      credtrailUserId: user.id,
      emailSnapshot: "student@example.edu",
    });

    const resolvedByAuthUser = await findAuthIdentityLinkByAuthUserId(
      db,
      "better_auth",
      "ba_usr_123",
    );
    const resolvedByCredtrailUser = await findAuthIdentityLinkByCredtrailUserId(
      db,
      "better_auth",
      user.id,
    );
    const resolvedUser = await findUserByEmail(db, "student@example.edu");

    expect(resolvedByAuthUser).toEqual(link);
    expect(resolvedByCredtrailUser).toEqual(link);
    expect(resolvedUser).toEqual(user);
    expect(link.emailSnapshot).toBe("student@example.edu");
  });
});

describe("tenant auth policy and provider helpers", () => {
  it("resolves local auth policy defaults when no tenant auth policy exists", async () => {
    const db = createFakeTenantAuthDb();

    const policy = await resolveTenantAuthPolicy(db, "tenant_123");

    expect(policy).toEqual({
      tenantId: "tenant_123",
      loginMode: "local",
      breakGlassEnabled: false,
      localMfaRequired: false,
      defaultProviderId: null,
      enforceForRoles: "all_users",
      createdAt: expect.any(String),
      updatedAt: expect.any(String),
    });
  });

  it("persists and updates tenant auth policy state", async () => {
    const db = createFakeTenantAuthDb();

    const created = await upsertTenantAuthPolicy(db, {
      tenantId: "tenant_123",
      loginMode: "hybrid",
      breakGlassEnabled: true,
      localMfaRequired: true,
      defaultProviderId: "tap_oidc",
      enforceForRoles: "admins_only",
    });
    const resolved = await findTenantAuthPolicy(db, "tenant_123");

    expect(created.loginMode).toBe("hybrid");
    expect(created.breakGlassEnabled).toBe(true);
    expect(created.localMfaRequired).toBe(true);
    expect(created.defaultProviderId).toBe("tap_oidc");
    expect(created.enforceForRoles).toBe("all_users");
    expect(resolved).toEqual(created);
  });

  it("keeps exactly one default OIDC auth provider per tenant when providers are created or updated", async () => {
    const db = createFakeTenantAuthDb();

    await createTenantAuthProvider(db, {
      id: "tap_oidc",
      tenantId: "tenant_123",
      protocol: "oidc",
      label: "Campus OIDC",
      enabled: true,
      isDefault: true,
      configJson: '{"issuer":"https://idp.example.edu"}',
    });
    await createTenantAuthProvider(db, {
      id: "tap_oidc_backup",
      tenantId: "tenant_123",
      protocol: "oidc",
      label: "Campus OIDC Backup",
      enabled: true,
      isDefault: false,
      configJson: '{"issuer":"https://backup-idp.example.edu"}',
    });

    const updated = await updateTenantAuthProvider(db, {
      tenantId: "tenant_123",
      providerId: "tap_oidc_backup",
      protocol: "oidc",
      label: "Campus OIDC Backup",
      enabled: false,
      isDefault: true,
      configJson: '{"issuer":"https://backup-idp.example.edu"}',
    });
    const providers = await listTenantAuthProviders(db, "tenant_123");

    expect(updated?.isDefault).toBe(true);
    expect(updated?.enabled).toBe(false);
    expect(providers).toHaveLength(2);
    expect(providers.find((provider) => provider.id === "tap_oidc_backup")?.isDefault).toBe(true);
    expect(providers.find((provider) => provider.id === "tap_oidc")?.isDefault).toBe(false);

    const backupProvider = await findTenantAuthProviderById(db, "tenant_123", "tap_oidc_backup");
    expect(backupProvider?.enabled).toBe(false);
  });

  it("rejects new hosted SAML provider writes while preserving legacy compatibility reads", async () => {
    const db = createFakeTenantAuthDb();

    await expect(
      createTenantAuthProvider(db, {
        id: "tap_saml",
        tenantId: "tenant_123",
        protocol: "saml",
        label: "Campus SAML",
        enabled: true,
        isDefault: true,
        configJson: '{"ssoLoginUrl":"https://idp.example.edu/sso"}',
      }),
    ).rejects.toThrow("Hosted enterprise sign-in currently supports OIDC providers only.");

    await createTenantAuthProvider(db, {
      id: "tap_oidc",
      tenantId: "tenant_123",
      protocol: "oidc",
      label: "Campus OIDC",
      enabled: true,
      isDefault: true,
      configJson: '{"issuer":"https://idp.example.edu"}',
    });

    await expect(
      updateTenantAuthProvider(db, {
        tenantId: "tenant_123",
        providerId: "tap_oidc",
        protocol: "saml",
        label: "Campus SAML",
        enabled: true,
        isDefault: true,
        configJson: '{"ssoLoginUrl":"https://idp.example.edu/sso"}',
      }),
    ).rejects.toThrow("Hosted enterprise sign-in currently supports OIDC providers only.");
  });

  it("bridges legacy SAML configuration into the provider and policy model", async () => {
    const db = createFakeTenantAuthDb();
    const tenantAuthDb = db as unknown as FakeTenantAuthSqlDatabase;

    tenantAuthDb.legacySamlConfigurations.push({
      tenant_id: "tenant_legacy",
      idp_entity_id: "https://idp.example.edu/entity",
      sso_login_url: "https://idp.example.edu/sso/login",
      idp_certificate_pem: "-----BEGIN CERTIFICATE-----\\nabc\\n-----END CERTIFICATE-----",
      idp_metadata_url: "https://idp.example.edu/metadata",
      sp_entity_id: "https://credtrail.example.edu/saml/sp",
      assertion_consumer_service_url: "https://credtrail.example.edu/saml/acs",
      name_id_format: "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
      enforced: 1,
      created_at: "2026-03-16T10:00:00.000Z",
      updated_at: "2026-03-16T10:00:00.000Z",
    });

    const policy = await findTenantAuthPolicy(db, "tenant_legacy");
    const providers = await listTenantAuthProviders(db, "tenant_legacy");

    expect(policy?.loginMode).toBe("sso_required");
    expect(policy?.defaultProviderId).toBe("tenant_legacy:provider:saml-default");
    expect(providers).toEqual([
      expect.objectContaining({
        id: "tenant_legacy:provider:saml-default",
        protocol: "saml",
        isDefault: true,
        enabled: true,
        label: "Legacy SAML (compatibility only)",
      }),
    ]);

    const configJson = providers[0]?.configJson ?? "{}";
    expect(configJson).toContain("idpEntityId");
    expect(configJson).toContain("idpCertificatePem");
  });

  it("stores break-glass accounts with enrollment and usage status", async () => {
    const db = createFakeTenantAuthDb();
    const tenantAuthDb = db as unknown as FakeTenantAuthSqlDatabase;
    const user = await upsertUserByEmail(db, "Admin@Example.edu");

    tenantAuthDb.betterAuthUsers.push({
      id: "ba_usr_admin",
      email: "admin@example.edu",
      two_factor_enabled: 1,
    });
    tenantAuthDb.betterAuthAccounts.push({
      user_id: "ba_usr_admin",
      provider_id: "credential",
      password: "hashed-password",
    });

    await upsertTenantBreakGlassAccount(db, {
      tenantId: "tenant_123",
      userId: user.id,
      createdByUserId: "usr_owner",
    });
    await markTenantBreakGlassEnrollmentEmailSent(db, {
      tenantId: "tenant_123",
      userId: user.id,
      sentAt: "2026-03-16T12:05:00.000Z",
    });
    await markTenantBreakGlassAccountUsed(db, {
      tenantId: "tenant_123",
      userId: user.id,
      usedAt: "2026-03-16T12:10:00.000Z",
    });

    const listed = await listTenantBreakGlassAccounts(db, "tenant_123");
    const resolved = await findActiveTenantBreakGlassAccountByEmail(
      db,
      "tenant_123",
      "admin@example.edu",
    );

    expect(listed).toHaveLength(1);
    expect(listed[0]).toEqual(
      expect.objectContaining({
        tenantId: "tenant_123",
        userId: user.id,
        email: "admin@example.edu",
        betterAuthUserId: "ba_usr_admin",
        localCredentialEnabled: true,
        twoFactorEnabled: true,
      }),
    );
    expect(resolved?.lastEnrollmentEmailSentAt).toBe("2026-03-16T12:05:00.000Z");
    expect(resolved?.lastUsedAt).toBe("2026-03-16T12:10:00.000Z");

    const removed = await revokeTenantBreakGlassAccount(db, {
      tenantId: "tenant_123",
      userId: user.id,
      revokedAt: "2026-03-16T12:20:00.000Z",
    });
    const resolvedAfterRevoke = await findActiveTenantBreakGlassAccountByEmail(
      db,
      "tenant_123",
      "admin@example.edu",
    );

    expect(removed).toBe(true);
    expect(resolvedAfterRevoke).toBeNull();
  });

  it("lists tenant members, counts roles, and removes only tenant membership", async () => {
    const db = createFakeTenantAuthDb();
    const tenantAuthDb = db as unknown as FakeTenantAuthSqlDatabase;
    const owner = await upsertUserByEmail(db, "Owner@Example.edu");
    const admin = await upsertUserByEmail(db, "Admin@Example.edu");
    const otherTenantUser = await upsertUserByEmail(db, "Other@Example.edu");

    await upsertTenantMembershipRole(db, {
      tenantId: "tenant_123",
      userId: owner.id,
      role: "owner",
    });
    await upsertTenantMembershipRole(db, {
      tenantId: "tenant_123",
      userId: admin.id,
      role: "admin",
    });
    await upsertTenantMembershipRole(db, {
      tenantId: "tenant_other",
      userId: otherTenantUser.id,
      role: "owner",
    });

    const listed = await listTenantMembers(db, "tenant_123");
    const counts = await countTenantMembershipsByRole(db, "tenant_123");
    const removed = await removeTenantMembership(db, "tenant_123", admin.id);
    const listedAfterRemoval = await listTenantMembers(db, "tenant_123");

    expect(listed).toEqual([
      expect.objectContaining({
        tenantId: "tenant_123",
        userId: owner.id,
        email: "owner@example.edu",
        role: "owner",
      }),
      expect.objectContaining({
        tenantId: "tenant_123",
        userId: admin.id,
        email: "admin@example.edu",
        role: "admin",
      }),
    ]);
    expect(counts).toEqual({
      owner: 1,
      admin: 1,
      issuer: 0,
      viewer: 0,
    });
    expect(removed).toBe(true);
    expect(listedAfterRemoval.map((member) => member.userId)).toEqual([owner.id]);
    expect(tenantAuthDb.users.some((user) => user.id === admin.id)).toBe(true);
    expect(tenantAuthDb.memberships.some((row) => row.user_id === otherTenantUser.id)).toBe(true);
  });

  it("lists accessible tenant contexts for a user from active memberships", async () => {
    const db = createFakeTenantAuthDb();
    const tenantAuthDb = db as unknown as FakeTenantAuthSqlDatabase;

    tenantAuthDb.tenants.push(
      {
        id: "tenant_admin",
        slug: "tenant-admin",
        display_name: "Admin Tenant",
        plan_tier: "enterprise",
        is_active: 1,
      },
      {
        id: "tenant_viewer",
        slug: "tenant-viewer",
        display_name: "Viewer Tenant",
        plan_tier: "team",
        is_active: 1,
      },
      {
        id: "tenant_inactive",
        slug: "tenant-inactive",
        display_name: "Inactive Tenant",
        plan_tier: "institution",
        is_active: 0,
      },
    );
    tenantAuthDb.memberships.push(
      {
        tenant_id: "tenant_viewer",
        user_id: "usr_123",
        role: "viewer",
      },
      {
        tenant_id: "tenant_admin",
        user_id: "usr_123",
        role: "admin",
      },
      {
        tenant_id: "tenant_inactive",
        user_id: "usr_123",
        role: "owner",
      },
    );

    const contexts = await listAccessibleTenantContextsForUser(db, "usr_123");

    expect(contexts).toEqual([
      {
        tenantId: "tenant_admin",
        tenantSlug: "tenant-admin",
        tenantDisplayName: "Admin Tenant",
        tenantPlanTier: "enterprise",
        membershipRole: "admin",
      },
      {
        tenantId: "tenant_viewer",
        tenantSlug: "tenant-viewer",
        tenantDisplayName: "Viewer Tenant",
        tenantPlanTier: "team",
        membershipRole: "viewer",
      },
    ]);
  });
});

describe("reporting foundation", () => {
  it("adds a reporting attribution migration with tenant and org indexes", () => {
    const sql = readFileSync(
      new URL("../migrations/0033_reporting_foundation.sql", import.meta.url),
      "utf8",
    );

    expect(sql).toContain("CREATE TABLE IF NOT EXISTS assertion_reporting_attributions");
    expect(sql).toContain("attribution_source");
    expect(sql).toContain("historical_backfill");
    expect(sql).toContain("idx_assertion_reporting_attributions_tenant_org");
    expect(sql).toContain("idx_assertion_reporting_attributions_tenant_template");
  });

  it("keeps historical reporting attribution stable when template ownership changes later", () => {
    const attribution = resolveAssertionReportingAttribution({
      issuedAt: "2026-03-05T15:00:00.000Z",
      currentOwnerOrgUnitId: "org_program",
      ownershipEvents: [
        {
          toOrgUnitId: "org_department",
          transferredAt: "2026-03-01T12:00:00.000Z",
        },
        {
          toOrgUnitId: "org_program",
          transferredAt: "2026-03-10T12:00:00.000Z",
        },
      ],
    });

    expect(attribution).toEqual({
      orgUnitId: "org_department",
      attributionSource: "historical_backfill",
      attributedAt: "2026-03-05T15:00:00.000Z",
    });
  });

  it("summarizes product-backed overview counts and marks engagement rate metrics as Phase 10-backed", () => {
    const rows = [
      {
        assertionId: "assertion_active",
        issuedAt: "2026-03-01T00:00:00.000Z",
        badgeTemplateId: "bt_1",
        orgUnitId: "org_1",
        revokedAt: null,
        latestToState: null,
        latestReasonCode: null,
      },
      {
        assertionId: "assertion_suspended_review",
        issuedAt: "2026-03-02T00:00:00.000Z",
        badgeTemplateId: "bt_1",
        orgUnitId: "org_1",
        revokedAt: null,
        latestToState: "suspended" as const,
        latestReasonCode: "appeal_pending" as const,
      },
      {
        assertionId: "assertion_revoked",
        issuedAt: "2026-03-03T00:00:00.000Z",
        badgeTemplateId: "bt_2",
        orgUnitId: "org_2",
        revokedAt: "2026-03-04T00:00:00.000Z",
        latestToState: "revoked" as const,
        latestReasonCode: "issuer_requested" as const,
      },
    ];

    expect(summarizeTenantReportingOverviewRows(rows)).toEqual({
      issued: 3,
      active: 1,
      suspended: 1,
      revoked: 1,
      pendingReview: 1,
    });

    expect(summarizeTenantReportingOverviewRows(rows, "pending_review")).toEqual({
      issued: 1,
      active: 0,
      suspended: 1,
      revoked: 0,
      pendingReview: 1,
    });

    expect(REPORTING_METRIC_DEFINITIONS).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          key: "claimRate",
          available: true,
          source: "assertion_engagement_events + assertions",
        }),
        expect.objectContaining({
          key: "shareRate",
          available: true,
          source: "assertion_engagement_events + assertions",
        }),
      ]),
    );
  });
});

describe("engagement reporting foundation", () => {
  it("adds an engagement event migration with a narrow product-owned taxonomy", () => {
    const sql = readFileSync(
      new URL("../migrations/0034_reporting_engagement_events.sql", import.meta.url),
      "utf8",
    );

    expect(ASSERTION_ENGAGEMENT_EVENT_TYPES).toEqual([
      "public_badge_view",
      "verification_view",
      "share_click",
      "learner_claim",
      "wallet_accept",
    ]);
    expect(sql).toContain("CREATE TABLE IF NOT EXISTS assertion_engagement_events");
    expect(sql).toContain("CHECK (event_type IN");
    expect(sql).toContain("'public_badge_view'");
    expect(sql).toContain("'verification_view'");
    expect(sql).toContain("'share_click'");
    expect(sql).toContain("'learner_claim'");
    expect(sql).toContain("'wallet_accept'");
    expect(sql).toContain(
      "FOREIGN KEY (assertion_id) REFERENCES assertions (id) ON DELETE CASCADE",
    );
    expect(sql).toContain("idx_assertion_engagement_events_tenant_occurred_at");
    expect(sql).toContain("idx_assertion_engagement_events_assertion_type");
  });

  it("buckets issued assertions and engagement event counts over time for selected filters", () => {
    const rows = [
      {
        assertionId: "assertion_1",
        badgeTemplateId: "bt_blue",
        orgUnitId: "org_program",
        issuedAt: "2026-03-01T08:00:00.000Z",
        revokedAt: null,
        latestToState: null,
        latestReasonCode: null,
        eventType: null,
        occurredAt: null,
      },
      {
        assertionId: "assertion_2",
        badgeTemplateId: "bt_blue",
        orgUnitId: "org_program",
        issuedAt: "2026-03-01T10:00:00.000Z",
        revokedAt: null,
        latestToState: null,
        latestReasonCode: null,
        eventType: "public_badge_view" as const,
        occurredAt: "2026-03-02T09:00:00.000Z",
      },
      {
        assertionId: "assertion_2",
        badgeTemplateId: "bt_blue",
        orgUnitId: "org_program",
        issuedAt: "2026-03-01T10:00:00.000Z",
        revokedAt: null,
        latestToState: null,
        latestReasonCode: null,
        eventType: "verification_view" as const,
        occurredAt: "2026-03-02T10:00:00.000Z",
      },
      {
        assertionId: "assertion_3",
        badgeTemplateId: "bt_blue",
        orgUnitId: "org_program",
        issuedAt: "2026-03-02T11:00:00.000Z",
        revokedAt: null,
        latestToState: null,
        latestReasonCode: null,
        eventType: "share_click" as const,
        occurredAt: "2026-03-03T12:00:00.000Z",
      },
      {
        assertionId: "assertion_4",
        badgeTemplateId: "bt_other",
        orgUnitId: "org_program",
        issuedAt: "2026-03-02T12:00:00.000Z",
        revokedAt: null,
        latestToState: null,
        latestReasonCode: null,
        eventType: "public_badge_view" as const,
        occurredAt: "2026-03-02T13:00:00.000Z",
      },
    ];

    expect(
      summarizeTenantReportingTrendRows(rows, {
        from: "2026-03-01",
        to: "2026-03-03",
        bucket: "day",
        badgeTemplateId: "bt_blue",
      }),
    ).toEqual([
      {
        bucketStart: "2026-03-01",
        issuedCount: 2,
        publicBadgeViewCount: 0,
        verificationViewCount: 0,
        shareClickCount: 0,
        learnerClaimCount: 0,
        walletAcceptCount: 0,
      },
      {
        bucketStart: "2026-03-02",
        issuedCount: 1,
        publicBadgeViewCount: 1,
        verificationViewCount: 1,
        shareClickCount: 0,
        learnerClaimCount: 0,
        walletAcceptCount: 0,
      },
      {
        bucketStart: "2026-03-03",
        issuedCount: 0,
        publicBadgeViewCount: 0,
        verificationViewCount: 0,
        shareClickCount: 1,
        learnerClaimCount: 0,
        walletAcceptCount: 0,
      },
    ]);
  });

  it("computes comparison rates from distinct engaged assertions instead of raw event totals", () => {
    const rows = [
      {
        assertionId: "assertion_1",
        badgeTemplateId: "bt_science",
        orgUnitId: "org_science",
        issuedAt: "2026-03-01T08:00:00.000Z",
        revokedAt: null,
        latestToState: null,
        latestReasonCode: null,
        eventType: null,
        occurredAt: null,
      },
      {
        assertionId: "assertion_2",
        badgeTemplateId: "bt_science",
        orgUnitId: "org_science",
        issuedAt: "2026-03-01T09:00:00.000Z",
        revokedAt: null,
        latestToState: null,
        latestReasonCode: null,
        eventType: "share_click" as const,
        occurredAt: "2026-03-02T08:00:00.000Z",
      },
      {
        assertionId: "assertion_2",
        badgeTemplateId: "bt_science",
        orgUnitId: "org_science",
        issuedAt: "2026-03-01T09:00:00.000Z",
        revokedAt: null,
        latestToState: null,
        latestReasonCode: null,
        eventType: "share_click" as const,
        occurredAt: "2026-03-02T09:00:00.000Z",
      },
      {
        assertionId: "assertion_3",
        badgeTemplateId: "bt_science",
        orgUnitId: "org_science",
        issuedAt: "2026-03-01T10:00:00.000Z",
        revokedAt: null,
        latestToState: null,
        latestReasonCode: null,
        eventType: "learner_claim" as const,
        occurredAt: "2026-03-03T08:00:00.000Z",
      },
      {
        assertionId: "assertion_3",
        badgeTemplateId: "bt_science",
        orgUnitId: "org_science",
        issuedAt: "2026-03-01T10:00:00.000Z",
        revokedAt: null,
        latestToState: null,
        latestReasonCode: null,
        eventType: "wallet_accept" as const,
        occurredAt: "2026-03-03T09:00:00.000Z",
      },
      {
        assertionId: "assertion_4",
        badgeTemplateId: "bt_arts",
        orgUnitId: "org_arts",
        issuedAt: "2026-03-02T10:00:00.000Z",
        revokedAt: null,
        latestToState: null,
        latestReasonCode: null,
        eventType: "share_click" as const,
        occurredAt: "2026-03-04T08:00:00.000Z",
      },
    ];

    expect(
      summarizeTenantReportingComparisonRows(rows, {
        groupBy: "badgeTemplate",
      }),
    ).toEqual([
      {
        groupBy: "badgeTemplate",
        groupId: "bt_science",
        issuedCount: 3,
        publicBadgeViewCount: 0,
        verificationViewCount: 0,
        shareClickCount: 2,
        learnerClaimCount: 1,
        walletAcceptCount: 1,
        shareRate: 1 / 3,
        claimRate: 1 / 3,
      },
      {
        groupBy: "badgeTemplate",
        groupId: "bt_arts",
        issuedCount: 1,
        publicBadgeViewCount: 0,
        verificationViewCount: 0,
        shareClickCount: 1,
        learnerClaimCount: 0,
        walletAcceptCount: 0,
        shareRate: 1,
        claimRate: 0,
      },
    ]);
  });
});

describe("hierarchy reporting foundation", () => {
  const summarizeTenantReportingHierarchyRows = (
    dbModule as {
      summarizeTenantReportingHierarchyRows?: (input: {
        rows: readonly {
          assertionId: string;
          badgeTemplateId: string;
          orgUnitId: string;
          issuedAt: string;
          eventType:
            | "public_badge_view"
            | "verification_view"
            | "share_click"
            | "learner_claim"
            | "wallet_accept"
            | null;
          occurredAt: string | null;
        }[];
        orgUnits: readonly {
          id: string;
          unitType: "institution" | "college" | "department" | "program";
          displayName: string;
          parentOrgUnitId: string | null;
        }[];
        query: {
          from?: string;
          to?: string;
          focusOrgUnitId?: string;
          level: "institution" | "college" | "department" | "program";
        };
        scopedRootOrgUnitIds?: readonly string[];
      }) => unknown;
    }
  ).summarizeTenantReportingHierarchyRows;

  const parseTenantReportingHierarchyQuery = (
    validationModule as {
      parseTenantReportingHierarchyQuery?: (input: unknown) => unknown;
      parseTenantReportingComparisonQuery: (input: unknown) => unknown;
    }
  ).parseTenantReportingHierarchyQuery;

  const orgUnits = [
    {
      id: "org_institution",
      unitType: "institution" as const,
      displayName: "CredTrail University",
      parentOrgUnitId: null,
    },
    {
      id: "org_college_science",
      unitType: "college" as const,
      displayName: "College of Science",
      parentOrgUnitId: "org_institution",
    },
    {
      id: "org_college_arts",
      unitType: "college" as const,
      displayName: "College of Arts",
      parentOrgUnitId: "org_institution",
    },
    {
      id: "org_department_biology",
      unitType: "department" as const,
      displayName: "Biology",
      parentOrgUnitId: "org_college_science",
    },
    {
      id: "org_department_chemistry",
      unitType: "department" as const,
      displayName: "Chemistry",
      parentOrgUnitId: "org_college_science",
    },
    {
      id: "org_department_music",
      unitType: "department" as const,
      displayName: "Music",
      parentOrgUnitId: "org_college_arts",
    },
    {
      id: "org_program_microbiology",
      unitType: "program" as const,
      displayName: "Microbiology",
      parentOrgUnitId: "org_department_biology",
    },
    {
      id: "org_program_biochemistry",
      unitType: "program" as const,
      displayName: "Biochemistry",
      parentOrgUnitId: "org_department_chemistry",
    },
    {
      id: "org_program_music_theory",
      unitType: "program" as const,
      displayName: "Music Theory",
      parentOrgUnitId: "org_department_music",
    },
  ];

  it("rolls leaf-attributed reporting rows into institution, college, department, and program groupings", () => {
    expect(summarizeTenantReportingHierarchyRows).toBeTypeOf("function");

    const rows = [
      {
        assertionId: "assertion_1",
        badgeTemplateId: "bt_science",
        orgUnitId: "org_program_microbiology",
        issuedAt: "2026-03-01T08:00:00.000Z",
        eventType: null,
        occurredAt: null,
      },
      {
        assertionId: "assertion_2",
        badgeTemplateId: "bt_science",
        orgUnitId: "org_program_microbiology",
        issuedAt: "2026-03-01T09:00:00.000Z",
        eventType: "share_click" as const,
        occurredAt: "2026-03-03T08:00:00.000Z",
      },
      {
        assertionId: "assertion_3",
        badgeTemplateId: "bt_science",
        orgUnitId: "org_program_biochemistry",
        issuedAt: "2026-03-02T09:00:00.000Z",
        eventType: "learner_claim" as const,
        occurredAt: "2026-03-04T08:00:00.000Z",
      },
      {
        assertionId: "assertion_4",
        badgeTemplateId: "bt_arts",
        orgUnitId: "org_program_music_theory",
        issuedAt: "2026-03-02T10:00:00.000Z",
        eventType: "public_badge_view" as const,
        occurredAt: "2026-03-04T09:00:00.000Z",
      },
    ];

    expect(
      summarizeTenantReportingHierarchyRows?.({
        rows,
        orgUnits,
        query: {
          level: "institution",
        },
      }),
    ).toEqual([
      expect.objectContaining({
        orgUnitId: "org_institution",
        level: "institution",
        issuedCount: 4,
      }),
    ]);

    expect(
      summarizeTenantReportingHierarchyRows?.({
        rows,
        orgUnits,
        query: {
          level: "college",
        },
      }),
    ).toEqual([
      expect.objectContaining({
        orgUnitId: "org_college_science",
        level: "college",
        issuedCount: 3,
      }),
      expect.objectContaining({
        orgUnitId: "org_college_arts",
        level: "college",
        issuedCount: 1,
      }),
    ]);

    expect(
      summarizeTenantReportingHierarchyRows?.({
        rows,
        orgUnits,
        query: {
          level: "department",
        },
      }),
    ).toEqual([
      expect.objectContaining({
        orgUnitId: "org_department_biology",
        level: "department",
        issuedCount: 2,
      }),
      expect.objectContaining({
        orgUnitId: "org_department_chemistry",
        level: "department",
        issuedCount: 1,
      }),
      expect.objectContaining({
        orgUnitId: "org_department_music",
        level: "department",
        issuedCount: 1,
      }),
    ]);

    expect(
      summarizeTenantReportingHierarchyRows?.({
        rows,
        orgUnits,
        query: {
          level: "program",
        },
      }),
    ).toEqual([
      expect.objectContaining({
        orgUnitId: "org_program_microbiology",
        level: "program",
        issuedCount: 2,
      }),
      expect.objectContaining({
        orgUnitId: "org_program_biochemistry",
        level: "program",
        issuedCount: 1,
      }),
      expect.objectContaining({
        orgUnitId: "org_program_music_theory",
        level: "program",
        issuedCount: 1,
      }),
    ]);
  });

  it("adds an explicit hierarchy query contract without redefining exact-match orgUnitId filters", () => {
    expect(parseTenantReportingHierarchyQuery).toBeTypeOf("function");

    expect(
      parseTenantReportingHierarchyQuery?.({
        from: "2026-03-01",
        to: "2026-03-31",
        focusOrgUnitId: "org_college_science",
        level: "department",
      }),
    ).toEqual({
      from: "2026-03-01",
      to: "2026-03-31",
      focusOrgUnitId: "org_college_science",
      level: "department",
    });

    expect(
      validationModule.parseTenantReportingComparisonQuery({
        from: "2026-03-01",
        to: "2026-03-31",
        orgUnitId: "org_program_microbiology",
        groupBy: "orgUnit",
      }),
    ).toEqual({
      from: "2026-03-01",
      to: "2026-03-31",
      orgUnitId: "org_program_microbiology",
      groupBy: "orgUnit",
    });
  });

  it("keeps Phase 10 raw counts and distinct-assertion rates intact after subtree filtering", () => {
    expect(summarizeTenantReportingHierarchyRows).toBeTypeOf("function");

    const rows = [
      {
        assertionId: "assertion_1",
        badgeTemplateId: "bt_science",
        orgUnitId: "org_program_microbiology",
        issuedAt: "2026-03-01T08:00:00.000Z",
        eventType: "share_click" as const,
        occurredAt: "2026-03-02T08:00:00.000Z",
      },
      {
        assertionId: "assertion_1",
        badgeTemplateId: "bt_science",
        orgUnitId: "org_program_microbiology",
        issuedAt: "2026-03-01T08:00:00.000Z",
        eventType: "share_click" as const,
        occurredAt: "2026-03-02T09:00:00.000Z",
      },
      {
        assertionId: "assertion_2",
        badgeTemplateId: "bt_science",
        orgUnitId: "org_program_biochemistry",
        issuedAt: "2026-03-01T09:00:00.000Z",
        eventType: "learner_claim" as const,
        occurredAt: "2026-03-03T08:00:00.000Z",
      },
      {
        assertionId: "assertion_2",
        badgeTemplateId: "bt_science",
        orgUnitId: "org_program_biochemistry",
        issuedAt: "2026-03-01T09:00:00.000Z",
        eventType: "wallet_accept" as const,
        occurredAt: "2026-03-03T09:00:00.000Z",
      },
      {
        assertionId: "assertion_3",
        badgeTemplateId: "bt_arts",
        orgUnitId: "org_program_music_theory",
        issuedAt: "2026-03-01T10:00:00.000Z",
        eventType: "share_click" as const,
        occurredAt: "2026-03-03T10:00:00.000Z",
      },
    ];

    expect(
      summarizeTenantReportingHierarchyRows?.({
        rows,
        orgUnits,
        query: {
          focusOrgUnitId: "org_college_science",
          level: "department",
        },
        scopedRootOrgUnitIds: ["org_college_science"],
      }),
    ).toEqual([
      expect.objectContaining({
        orgUnitId: "org_department_biology",
        level: "department",
        issuedCount: 1,
        shareClickCount: 2,
        shareRate: 1,
        claimRate: 0,
      }),
      expect.objectContaining({
        orgUnitId: "org_department_chemistry",
        level: "department",
        issuedCount: 1,
        learnerClaimCount: 1,
        walletAcceptCount: 1,
        shareRate: 0,
        claimRate: 1,
      }),
    ]);
  });
});

describe("executive rollup foundation", () => {
  const orgUnits = [
    {
      id: "org_institution",
      unitType: "institution" as const,
      displayName: "CredTrail University",
      parentOrgUnitId: null,
    },
    {
      id: "org_college_science",
      unitType: "college" as const,
      displayName: "College of Science",
      parentOrgUnitId: "org_institution",
    },
    {
      id: "org_college_arts",
      unitType: "college" as const,
      displayName: "College of Arts",
      parentOrgUnitId: "org_institution",
    },
    {
      id: "org_department_biology",
      unitType: "department" as const,
      displayName: "Biology",
      parentOrgUnitId: "org_college_science",
    },
    {
      id: "org_department_chemistry",
      unitType: "department" as const,
      displayName: "Chemistry",
      parentOrgUnitId: "org_college_science",
    },
    {
      id: "org_department_music",
      unitType: "department" as const,
      displayName: "Music",
      parentOrgUnitId: "org_college_arts",
    },
    {
      id: "org_program_microbiology",
      unitType: "program" as const,
      displayName: "Microbiology",
      parentOrgUnitId: "org_department_biology",
    },
    {
      id: "org_program_biochemistry",
      unitType: "program" as const,
      displayName: "Biochemistry",
      parentOrgUnitId: "org_department_chemistry",
    },
    {
      id: "org_program_music_theory",
      unitType: "program" as const,
      displayName: "Music Theory",
      parentOrgUnitId: "org_department_music",
    },
  ];

  const rows = [
    {
      assertionId: "assertion_1",
      badgeTemplateId: "bt_science",
      orgUnitId: "org_program_microbiology",
      issuedAt: "2026-03-01T08:00:00.000Z",
      eventType: null,
      occurredAt: null,
    },
    {
      assertionId: "assertion_2",
      badgeTemplateId: "bt_science",
      orgUnitId: "org_program_microbiology",
      issuedAt: "2026-03-01T09:00:00.000Z",
      eventType: "share_click" as const,
      occurredAt: "2026-03-03T08:00:00.000Z",
    },
    {
      assertionId: "assertion_3",
      badgeTemplateId: "bt_science",
      orgUnitId: "org_program_biochemistry",
      issuedAt: "2026-03-02T09:00:00.000Z",
      eventType: "learner_claim" as const,
      occurredAt: "2026-03-04T08:00:00.000Z",
    },
    {
      assertionId: "assertion_4",
      badgeTemplateId: "bt_arts",
      orgUnitId: "org_program_music_theory",
      issuedAt: "2026-03-02T10:00:00.000Z",
      eventType: "public_badge_view" as const,
      occurredAt: "2026-03-04T09:00:00.000Z",
    },
  ];

  it("rolls institution-focused executive views into top-level child rows", () => {
    expect(
      summarizeTenantExecutiveRollup({
        rows,
        orgUnits,
        query: {
          focusOrgUnitId: "org_institution",
          comparisonLevel: "college",
        },
      }),
    ).toEqual({
      focusOrgUnitId: "org_institution",
      focusDisplayName: "CredTrail University",
      focusParentOrgUnitId: null,
      focusUnitType: "institution",
      comparisonLevel: "college",
      focusLineageOrgUnitIds: ["org_institution"],
      filters: {
        from: null,
        to: null,
        badgeTemplateId: null,
        orgUnitId: null,
        state: null,
      },
      rows: [
        expect.objectContaining({
          orgUnitId: "org_college_science",
          displayName: "College of Science",
          level: "college",
          issuedCount: 3,
          shareRate: 1 / 3,
          claimRate: 1 / 3,
        }),
        expect.objectContaining({
          orgUnitId: "org_college_arts",
          displayName: "College of Arts",
          level: "college",
          issuedCount: 1,
          publicBadgeViewCount: 1,
          shareRate: 0,
          claimRate: 0,
        }),
      ],
    });
  });

  it("keeps scoped college executive views at the direct-child level", () => {
    expect(
      summarizeTenantExecutiveRollup({
        rows,
        orgUnits,
        query: {
          focusOrgUnitId: "org_college_science",
          comparisonLevel: "department",
        },
        scopedRootOrgUnitIds: ["org_college_science"],
      }),
    ).toEqual(
      expect.objectContaining({
        focusOrgUnitId: "org_college_science",
        focusDisplayName: "College of Science",
        focusUnitType: "college",
        comparisonLevel: "department",
        focusLineageOrgUnitIds: ["org_institution", "org_college_science"],
        rows: [
          expect.objectContaining({
            orgUnitId: "org_department_biology",
            level: "department",
            issuedCount: 2,
          }),
          expect.objectContaining({
            orgUnitId: "org_department_chemistry",
            level: "department",
            issuedCount: 1,
          }),
        ],
      }),
    );
  });

  it("falls back honestly to the focused program when no deeper comparison level exists", () => {
    expect(
      summarizeTenantExecutiveRollup({
        rows,
        orgUnits,
        query: {
          focusOrgUnitId: "org_program_microbiology",
          comparisonLevel: "program",
        },
        scopedRootOrgUnitIds: ["org_program_microbiology"],
      }),
    ).toEqual(
      expect.objectContaining({
        focusOrgUnitId: "org_program_microbiology",
        focusDisplayName: "Microbiology",
        focusUnitType: "program",
        comparisonLevel: "program",
        focusLineageOrgUnitIds: [
          "org_institution",
          "org_college_science",
          "org_department_biology",
          "org_program_microbiology",
        ],
        rows: [
          expect.objectContaining({
            orgUnitId: "org_program_microbiology",
            level: "program",
            issuedCount: 2,
            shareRate: 1 / 2,
            claimRate: 0,
          }),
        ],
      }),
    );
  });
});

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

describe("better auth core migration", () => {
  it("keeps Better Auth tables in an auth schema and preserves CredTrail-owned tables", () => {
    const sql = readFileSync(
      new URL("../migrations/0025_better_auth_core.sql", import.meta.url),
      "utf8",
    );

    expect(sql).toContain("CREATE SCHEMA IF NOT EXISTS auth");
    expect(sql).toContain("CREATE TABLE IF NOT EXISTS auth.user");
    expect(sql).toContain("CREATE TABLE IF NOT EXISTS auth.session");
    expect(sql).toContain("CREATE TABLE IF NOT EXISTS auth.account");
    expect(sql).toContain("CREATE TABLE IF NOT EXISTS auth.verification");
    expect(sql).toContain("CREATE TABLE IF NOT EXISTS auth_identity_links");
    expect(sql).not.toContain("CREATE TABLE IF NOT EXISTS users");
    expect(sql).not.toContain("CREATE TABLE IF NOT EXISTS sessions");
  });

  it("adds tenant auth policy and provider migrations with legacy SAML backfill", () => {
    const policySql = readFileSync(
      new URL("../migrations/0026_tenant_auth_policies.sql", import.meta.url),
      "utf8",
    );
    const providerSql = readFileSync(
      new URL("../migrations/0027_tenant_auth_providers.sql", import.meta.url),
      "utf8",
    );
    const backfillSql = readFileSync(
      new URL("../migrations/0028_backfill_legacy_saml_auth_providers.sql", import.meta.url),
      "utf8",
    );

    expect(policySql).toContain("CREATE TABLE IF NOT EXISTS tenant_auth_policies");
    expect(policySql).toContain("CHECK (login_mode IN ('local', 'hybrid', 'sso_required'))");
    expect(providerSql).toContain("CREATE TABLE IF NOT EXISTS tenant_auth_providers");
    expect(providerSql).toContain("CHECK (protocol IN ('oidc', 'saml'))");
    expect(providerSql).toContain("idx_tenant_auth_providers_default_per_tenant");
    expect(backfillSql).toContain("INSERT INTO tenant_auth_providers");
    expect(backfillSql).toContain("tenant_sso_saml_configurations");
    expect(backfillSql).toContain("tenant_auth_policies");
  });

  it("adds Better Auth enterprise SSO indexes without changing CredTrail-owned tables", () => {
    const ssoSql = readFileSync(
      new URL("../migrations/0029_better_auth_enterprise_sso.sql", import.meta.url),
      "utf8",
    );

    expect(ssoSql).toContain("idx_auth_user_email");
    expect(ssoSql).toContain("idx_auth_account_provider_user");
    expect(ssoSql).not.toContain("CREATE TABLE IF NOT EXISTS tenant_auth_providers");
  });

  it("removes legacy auth table helpers from the public DB package", async () => {
    const dbModule = await import("./index");

    expect(dbModule).not.toHaveProperty("createMagicLinkToken");
    expect(dbModule).not.toHaveProperty("findMagicLinkTokenByHash");
    expect(dbModule).not.toHaveProperty("markMagicLinkTokenUsed");
    expect(dbModule).not.toHaveProperty("createSession");
    expect(dbModule).not.toHaveProperty("findActiveSessionByHash");
    expect(dbModule).not.toHaveProperty("touchSession");
    expect(dbModule).not.toHaveProperty("revokeSessionByHash");
  });

  it("adds a forward migration that drops obsolete legacy auth tables and indexes", () => {
    const sql = readFileSync(
      new URL("../migrations/0032_drop_legacy_auth_tables.sql", import.meta.url),
      "utf8",
    );

    expect(sql).toContain("DROP INDEX IF EXISTS idx_magic_link_tokens_tenant_user");
    expect(sql).toContain("DROP INDEX IF EXISTS idx_magic_link_tokens_expires_at");
    expect(sql).toContain("DROP INDEX IF EXISTS idx_sessions_tenant_user");
    expect(sql).toContain("DROP INDEX IF EXISTS idx_sessions_expires_at");
    expect(sql).toContain("DROP TABLE IF EXISTS magic_link_tokens");
    expect(sql).toContain("DROP TABLE IF EXISTS sessions");
  });

  it("adds Better Auth two-factor and tenant break-glass migrations", () => {
    const twoFactorSql = readFileSync(
      new URL("../migrations/0030_better_auth_two_factor.sql", import.meta.url),
      "utf8",
    );
    const breakGlassSql = readFileSync(
      new URL("../migrations/0031_tenant_break_glass_accounts.sql", import.meta.url),
      "utf8",
    );

    expect(twoFactorSql).toContain("ALTER TABLE auth.user");
    expect(twoFactorSql).toContain("two_factor_enabled");
    expect(twoFactorSql).toContain("CREATE TABLE IF NOT EXISTS auth.two_factor");
    expect(breakGlassSql).toContain("CREATE TABLE IF NOT EXISTS tenant_break_glass_accounts");
    expect(breakGlassSql).toContain("last_enrollment_email_sent_at");
    expect(breakGlassSql).toContain("idx_tenant_break_glass_accounts_tenant_active");
  });

  it("adds LTI issuer NRPS credential columns through a forward migration", () => {
    const sql = readFileSync(
      new URL("../migrations/0039_lti_issuer_registration_nrps_credentials.sql", import.meta.url),
      "utf8",
    );

    expect(sql).toContain("ALTER TABLE lti_issuer_registrations");
    expect(sql).toContain("ADD COLUMN IF NOT EXISTS token_endpoint TEXT");
    expect(sql).toContain("ADD COLUMN IF NOT EXISTS client_secret TEXT");
  });
});

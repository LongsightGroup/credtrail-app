import { assertValidIsoTimestamp, createPrefixedId } from "./shared-helpers";
import { reevaluateLearnerPathwaysForLearner } from "./learner-pathways";
import type { SqlDatabase } from "./tenant-scope";

export type LearnerRecordTrustLevel = "issuer_verified" | "learner_supplemental";

export type LearnerRecordStatus = "active" | "revoked" | "expired";

export type LearnerRecordEntryType =
  | "course"
  | "certificate"
  | "license"
  | "competency"
  | "work_based_learning"
  | "experience"
  | "membership"
  | "supplemental_artifact"
  | "custom";

export type LearnerRecordSourceSystem =
  | "credtrail_admin"
  | "csv_import"
  | "api"
  | "migration"
  | "badge_assertion"
  | "learner_self_reported";

export interface LearnerRecordEntryRecord {
  id: string;
  tenantId: string;
  learnerProfileId: string;
  trustLevel: LearnerRecordTrustLevel;
  recordType: LearnerRecordEntryType;
  status: LearnerRecordStatus;
  title: string;
  description: string | null;
  issuerName: string;
  issuerUserId: string | null;
  sourceSystem: LearnerRecordSourceSystem;
  sourceRecordId: string | null;
  issuedAt: string;
  revisedAt: string | null;
  revokedAt: string | null;
  evidenceLinksJson: string;
  detailsJson: string | null;
  createdAt: string;
  updatedAt: string;
}

export interface CreateLearnerRecordEntryInput {
  tenantId: string;
  learnerProfileId: string;
  trustLevel: LearnerRecordTrustLevel;
  recordType: LearnerRecordEntryType;
  status?: LearnerRecordStatus | undefined;
  title: string;
  description?: string | undefined;
  issuerName: string;
  issuerUserId?: string | null | undefined;
  sourceSystem: LearnerRecordSourceSystem;
  sourceRecordId?: string | null | undefined;
  issuedAt: string;
  revisedAt?: string | null | undefined;
  revokedAt?: string | null | undefined;
  evidenceLinks: readonly string[];
  detailsJson?: string | null | undefined;
}

export interface ListLearnerRecordEntriesInput {
  tenantId: string;
  learnerProfileId: string;
  trustLevel?: LearnerRecordTrustLevel | undefined;
  status?: LearnerRecordStatus | undefined;
}

export interface PatchLearnerRecordEntryInput {
  tenantId: string;
  entryId: string;
  trustLevel?: LearnerRecordTrustLevel | undefined;
  recordType?: LearnerRecordEntryType | undefined;
  status?: LearnerRecordStatus | undefined;
  title?: string | undefined;
  description?: string | null | undefined;
  issuerName?: string | undefined;
  issuerUserId?: string | null | undefined;
  sourceSystem?: LearnerRecordSourceSystem | undefined;
  sourceRecordId?: string | null | undefined;
  issuedAt?: string | undefined;
  revisedAt?: string | null | undefined;
  revokedAt?: string | null | undefined;
  evidenceLinks?: readonly string[] | undefined;
  detailsJson?: string | null | undefined;
}
interface LearnerRecordEntryRow {
  id: string;
  tenantId: string;
  learnerProfileId: string;
  trustLevel: LearnerRecordTrustLevel;
  recordType: LearnerRecordEntryType;
  status: LearnerRecordStatus;
  title: string;
  description: string | null;
  issuerName: string;
  issuerUserId: string | null;
  sourceSystem: LearnerRecordSourceSystem;
  sourceRecordId: string | null;
  issuedAt: string;
  revisedAt: string | null;
  revokedAt: string | null;
  evidenceLinksJson: string;
  detailsJson: string | null;
  createdAt: string;
  updatedAt: string;
}
const normalizeRequiredLearnerRecordText = (value: string, fieldName: string): string => {
  const normalized = value.trim();

  if (normalized.length === 0) {
    throw new Error(`${fieldName} is required`);
  }

  return normalized;
};

const normalizeOptionalLearnerRecordText = (value: string | null | undefined): string | null => {
  if (value === undefined || value === null) {
    return null;
  }

  const normalized = value.trim();
  return normalized.length === 0 ? null : normalized;
};

const normalizeLearnerRecordEvidenceLinksJson = (evidenceLinks: readonly string[]): string => {
  return JSON.stringify(Array.from(new Set(evidenceLinks)));
};

const normalizeLearnerRecordDetailsJson = (
  detailsJson: string | null | undefined,
): string | null => {
  if (detailsJson === undefined || detailsJson === null) {
    return null;
  }

  let parsed: unknown;

  try {
    parsed = JSON.parse(detailsJson) as unknown;
  } catch {
    throw new Error("detailsJson must be valid JSON");
  }

  if (parsed === null || Array.isArray(parsed) || typeof parsed !== "object") {
    throw new Error("detailsJson must encode a JSON object");
  }

  return JSON.stringify(parsed);
};
const assertLearnerRecordEntrySemantics = (input: {
  trustLevel: LearnerRecordTrustLevel;
  recordType: LearnerRecordEntryType;
  status: LearnerRecordStatus;
  sourceSystem: LearnerRecordSourceSystem;
  revokedAt: string | null;
}): void => {
  if (input.trustLevel === "issuer_verified" && input.sourceSystem === "learner_self_reported") {
    throw new Error("issuer-verified learner-record entries cannot be learner_self_reported");
  }

  if (input.recordType === "supplemental_artifact" && input.trustLevel !== "learner_supplemental") {
    throw new Error(
      "supplemental_artifact learner-record entries must use learner_supplemental trust",
    );
  }

  if (input.status === "revoked" && input.revokedAt === null) {
    throw new Error("revoked learner-record entries must include revokedAt");
  }
};
const mapLearnerRecordEntryRow = (row: LearnerRecordEntryRow): LearnerRecordEntryRecord => {
  return {
    id: row.id,
    tenantId: row.tenantId,
    learnerProfileId: row.learnerProfileId,
    trustLevel: row.trustLevel,
    recordType: row.recordType,
    status: row.status,
    title: row.title,
    description: row.description,
    issuerName: row.issuerName,
    issuerUserId: row.issuerUserId,
    sourceSystem: row.sourceSystem,
    sourceRecordId: row.sourceRecordId,
    issuedAt: row.issuedAt,
    revisedAt: row.revisedAt,
    revokedAt: row.revokedAt,
    evidenceLinksJson: row.evidenceLinksJson,
    detailsJson: row.detailsJson,
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
  };
};
const findLearnerRecordEntryById = async (
  db: SqlDatabase,
  tenantId: string,
  entryId: string,
): Promise<LearnerRecordEntryRecord | null> => {
  const row = await db
    .prepare(
      `
      SELECT
        id,
        tenant_id AS tenantId,
        learner_profile_id AS learnerProfileId,
        trust_level AS trustLevel,
        record_type AS recordType,
        status,
        title,
        description,
        issuer_name AS issuerName,
        issuer_user_id AS issuerUserId,
        source_system AS sourceSystem,
        source_record_id AS sourceRecordId,
        issued_at AS issuedAt,
        revised_at AS revisedAt,
        revoked_at AS revokedAt,
        evidence_links_json AS evidenceLinksJson,
        details_json AS detailsJson,
        created_at AS createdAt,
        updated_at AS updatedAt
      FROM learner_record_entries
      WHERE tenant_id = ?
        AND id = ?
      LIMIT 1
    `,
    )
    .bind(tenantId, entryId)
    .first<LearnerRecordEntryRow>();

  return row === null ? null : mapLearnerRecordEntryRow(row);
};

export const createLearnerRecordEntry = async (
  db: SqlDatabase,
  input: CreateLearnerRecordEntryInput,
): Promise<LearnerRecordEntryRecord> => {
  const id = createPrefixedId("lre");
  const nowIso = new Date().toISOString();
  const status = input.status ?? "active";
  const title = normalizeRequiredLearnerRecordText(input.title, "title");
  const description = normalizeOptionalLearnerRecordText(input.description);
  const issuerName = normalizeRequiredLearnerRecordText(input.issuerName, "issuerName");
  const sourceRecordId = normalizeOptionalLearnerRecordText(input.sourceRecordId);
  const revisedAt = input.revisedAt ?? null;
  const revokedAt = input.revokedAt ?? null;
  const evidenceLinksJson = normalizeLearnerRecordEvidenceLinksJson(input.evidenceLinks);
  const detailsJson = normalizeLearnerRecordDetailsJson(input.detailsJson);

  assertValidIsoTimestamp(input.issuedAt, "issuedAt");

  if (revisedAt !== null) {
    assertValidIsoTimestamp(revisedAt, "revisedAt");
  }

  if (revokedAt !== null) {
    assertValidIsoTimestamp(revokedAt, "revokedAt");
  }

  assertLearnerRecordEntrySemantics({
    trustLevel: input.trustLevel,
    recordType: input.recordType,
    status,
    sourceSystem: input.sourceSystem,
    revokedAt,
  });

  await db
    .prepare(
      `
      INSERT INTO learner_record_entries (
        id,
        tenant_id,
        learner_profile_id,
        trust_level,
        record_type,
        status,
        title,
        description,
        issuer_name,
        issuer_user_id,
        source_system,
        source_record_id,
        issued_at,
        revised_at,
        revoked_at,
        evidence_links_json,
        details_json,
        created_at,
        updated_at
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `,
    )
    .bind(
      id,
      input.tenantId,
      input.learnerProfileId,
      input.trustLevel,
      input.recordType,
      status,
      title,
      description,
      issuerName,
      input.issuerUserId ?? null,
      input.sourceSystem,
      sourceRecordId,
      input.issuedAt,
      revisedAt,
      revokedAt,
      evidenceLinksJson,
      detailsJson,
      nowIso,
      nowIso,
    )
    .run();

  const entry = await findLearnerRecordEntryById(db, input.tenantId, id);

  if (entry === null) {
    throw new Error(`Failed to create learner-record entry "${id}"`);
  }

  await reevaluateLearnerPathwaysForLearner(db, {
    tenantId: input.tenantId,
    learnerProfileId: input.learnerProfileId,
    trigger: "learner_record_created",
  });

  return entry;
};

export const listLearnerRecordEntries = async (
  db: SqlDatabase,
  input: ListLearnerRecordEntriesInput,
): Promise<LearnerRecordEntryRecord[]> => {
  const params: unknown[] = [input.tenantId, input.learnerProfileId];
  const conditions = ["tenant_id = ?", "learner_profile_id = ?"];

  if (input.trustLevel !== undefined) {
    conditions.push("trust_level = ?");
    params.push(input.trustLevel);
  }

  if (input.status !== undefined) {
    conditions.push("status = ?");
    params.push(input.status);
  }

  const result = await db
    .prepare(
      `
      SELECT
        id,
        tenant_id AS tenantId,
        learner_profile_id AS learnerProfileId,
        trust_level AS trustLevel,
        record_type AS recordType,
        status,
        title,
        description,
        issuer_name AS issuerName,
        issuer_user_id AS issuerUserId,
        source_system AS sourceSystem,
        source_record_id AS sourceRecordId,
        issued_at AS issuedAt,
        revised_at AS revisedAt,
        revoked_at AS revokedAt,
        evidence_links_json AS evidenceLinksJson,
        details_json AS detailsJson,
        created_at AS createdAt,
        updated_at AS updatedAt
      FROM learner_record_entries
      WHERE ${conditions.join(" AND ")}
      ORDER BY issued_at DESC, created_at DESC
    `,
    )
    .bind(...params)
    .all<LearnerRecordEntryRow>();

  return result.results.map((row) => mapLearnerRecordEntryRow(row));
};

export const patchLearnerRecordEntry = async (
  db: SqlDatabase,
  input: PatchLearnerRecordEntryInput,
): Promise<LearnerRecordEntryRecord | null> => {
  const existing = await findLearnerRecordEntryById(db, input.tenantId, input.entryId);

  if (existing === null) {
    return null;
  }

  const nowIso = new Date().toISOString();
  const trustLevel = input.trustLevel ?? existing.trustLevel;
  const recordType = input.recordType ?? existing.recordType;
  const status = input.status ?? existing.status;
  const title =
    input.title === undefined
      ? existing.title
      : normalizeRequiredLearnerRecordText(input.title, "title");
  const description =
    input.description === undefined
      ? existing.description
      : normalizeOptionalLearnerRecordText(input.description);
  const issuerName =
    input.issuerName === undefined
      ? existing.issuerName
      : normalizeRequiredLearnerRecordText(input.issuerName, "issuerName");
  const issuerUserId =
    input.issuerUserId === undefined ? existing.issuerUserId : (input.issuerUserId ?? null);
  const sourceSystem =
    input.sourceSystem === undefined ? existing.sourceSystem : input.sourceSystem;
  const sourceRecordId =
    input.sourceRecordId === undefined
      ? existing.sourceRecordId
      : normalizeOptionalLearnerRecordText(input.sourceRecordId);
  const issuedAt = input.issuedAt === undefined ? existing.issuedAt : input.issuedAt;
  const revisedAt = input.revisedAt === undefined ? existing.revisedAt : input.revisedAt;
  const revokedAt = input.revokedAt === undefined ? existing.revokedAt : input.revokedAt;
  const evidenceLinksJson =
    input.evidenceLinks === undefined
      ? existing.evidenceLinksJson
      : normalizeLearnerRecordEvidenceLinksJson(input.evidenceLinks);
  const detailsJson =
    input.detailsJson === undefined
      ? existing.detailsJson
      : normalizeLearnerRecordDetailsJson(input.detailsJson);

  assertValidIsoTimestamp(issuedAt, "issuedAt");

  if (revisedAt !== null) {
    assertValidIsoTimestamp(revisedAt, "revisedAt");
  }

  if (revokedAt !== null) {
    assertValidIsoTimestamp(revokedAt, "revokedAt");
  }

  assertLearnerRecordEntrySemantics({
    trustLevel,
    recordType,
    status,
    sourceSystem,
    revokedAt,
  });

  await db
    .prepare(
      `
      UPDATE learner_record_entries
      SET
        trust_level = ?,
        record_type = ?,
        status = ?,
        title = ?,
        description = ?,
        issuer_name = ?,
        issuer_user_id = ?,
        source_system = ?,
        source_record_id = ?,
        issued_at = ?,
        revised_at = ?,
        revoked_at = ?,
        evidence_links_json = ?,
        details_json = ?,
        updated_at = ?
      WHERE tenant_id = ?
        AND id = ?
    `,
    )
    .bind(
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
      nowIso,
      input.tenantId,
      input.entryId,
    )
    .run();

  const updated = await findLearnerRecordEntryById(db, input.tenantId, input.entryId);

  if (updated !== null) {
    await reevaluateLearnerPathwaysForLearner(db, {
      tenantId: input.tenantId,
      learnerProfileId: updated.learnerProfileId,
      trigger: "learner_record_revised",
    });
  }

  return updated;
};

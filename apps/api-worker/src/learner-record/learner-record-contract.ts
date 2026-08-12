import type { AssertionRecord, LearnerRecordEntryRecord } from "@credtrail/db";

export type LearnerRecordKind = "badge_assertion" | "record_entry";
export type LearnerRecordTrustLevel = "issuer_verified" | "learner_supplemental";
export type LearnerRecordStatus = "active" | "revoked" | "expired";
export type LearnerRecordType =
  | "badge"
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

export interface LearnerRecordProvenance {
  issuerName: string;
  issuerUserId: string | null;
  sourceSystem: LearnerRecordSourceSystem;
  sourceRecordId: string | null;
  issuedAt: string;
  revisedAt: string | null;
  revokedAt: string | null;
  evidenceLinks: readonly string[];
}

export interface CanonicalLearnerRecordItem {
  id: string;
  kind: LearnerRecordKind;
  tenantId: string;
  learnerProfileId: string | null;
  trustLevel: LearnerRecordTrustLevel;
  status: LearnerRecordStatus;
  recordType: LearnerRecordType;
  title: string;
  description: string | null;
  sourceEntryId: string | null;
  badgeTemplateId: string | null;
  publicBadgeId: string | null;
  editable: boolean;
  details: Record<string, unknown> | null;
  provenance: LearnerRecordProvenance;
}

type LearnerRecordAssertionProjection = Pick<
  AssertionRecord,
  | "id"
  | "tenantId"
  | "learnerProfileId"
  | "badgeTemplateId"
  | "publicId"
  | "issuedByUserId"
  | "issuedAt"
  | "revokedAt"
>;

interface MapAssertionToCanonicalLearnerRecordItemInput {
  assertion: LearnerRecordAssertionProjection;
  badgeTitle: string;
  badgeDescription?: string | null;
  issuerName: string;
  evidenceLinks: readonly string[];
}

const displayTypeLabelByType: Record<LearnerRecordType, string> = {
  badge: "Badge",
  course: "Course",
  certificate: "Certificate",
  license: "License",
  competency: "Competency",
  work_based_learning: "Work-based learning",
  experience: "Experience",
  membership: "Membership",
  supplemental_artifact: "Supplemental artifact",
  custom: "Custom record",
};

export const learnerRecordDisplayTypeLabel = (recordType: LearnerRecordType): string => {
  return displayTypeLabelByType[recordType];
};

const parseLearnerRecordDetailsJson = (
  detailsJson: string | null,
): Record<string, unknown> | null => {
  if (detailsJson === null) {
    return null;
  }

  let parsed: unknown;

  try {
    parsed = JSON.parse(detailsJson) as unknown;
  } catch {
    throw new Error("Learner-record details JSON must be a valid object");
  }

  if (parsed === null || Array.isArray(parsed) || typeof parsed !== "object") {
    throw new Error("Learner-record details JSON must decode to an object");
  }

  return parsed as Record<string, unknown>;
};

const parseEvidenceLinksJson = (evidenceLinksJson: string): readonly string[] => {
  let parsed: unknown;

  try {
    parsed = JSON.parse(evidenceLinksJson) as unknown;
  } catch {
    throw new Error("Learner-record evidenceLinks JSON must be a valid string array");
  }

  if (!Array.isArray(parsed) || parsed.some((value) => typeof value !== "string")) {
    throw new Error("Learner-record evidenceLinks JSON must decode to a string array");
  }

  return parsed;
};

const learnerRecordStatusFromAssertion = (
  assertion: LearnerRecordAssertionProjection,
): LearnerRecordStatus => {
  if (assertion.revokedAt !== null) {
    return "revoked";
  }

  return "active";
};

export const mapAssertionToCanonicalLearnerRecordItem = (
  input: MapAssertionToCanonicalLearnerRecordItemInput,
): CanonicalLearnerRecordItem => {
  const { assertion, badgeTitle, badgeDescription, issuerName, evidenceLinks } = input;

  return {
    id: assertion.id,
    kind: "badge_assertion",
    tenantId: assertion.tenantId,
    learnerProfileId: assertion.learnerProfileId,
    trustLevel: "issuer_verified",
    status: learnerRecordStatusFromAssertion(assertion),
    recordType: "badge",
    title: badgeTitle,
    description: badgeDescription ?? null,
    sourceEntryId: null,
    badgeTemplateId: assertion.badgeTemplateId,
    publicBadgeId: assertion.publicId,
    editable: false,
    details: null,
    provenance: {
      issuerName,
      issuerUserId: assertion.issuedByUserId,
      sourceSystem: "badge_assertion",
      sourceRecordId: assertion.id,
      issuedAt: assertion.issuedAt,
      revisedAt: null,
      revokedAt: assertion.revokedAt,
      evidenceLinks: [...evidenceLinks],
    },
  };
};

export const mapLearnerRecordEntryToCanonicalLearnerRecordItem = (
  entry: LearnerRecordEntryRecord,
): CanonicalLearnerRecordItem => {
  return {
    id: entry.id,
    kind: "record_entry",
    tenantId: entry.tenantId,
    learnerProfileId: entry.learnerProfileId,
    trustLevel: entry.trustLevel,
    status: entry.status,
    recordType: entry.recordType,
    title: entry.title,
    description: entry.description,
    sourceEntryId: entry.id,
    badgeTemplateId: null,
    publicBadgeId: null,
    editable: true,
    details: parseLearnerRecordDetailsJson(entry.detailsJson),
    provenance: {
      issuerName: entry.issuerName,
      issuerUserId: entry.issuerUserId,
      sourceSystem: entry.sourceSystem,
      sourceRecordId: entry.sourceRecordId,
      issuedAt: entry.issuedAt,
      revisedAt: entry.revisedAt,
      revokedAt: entry.revokedAt,
      evidenceLinks: [...parseEvidenceLinksJson(entry.evidenceLinksJson)],
    },
  };
};

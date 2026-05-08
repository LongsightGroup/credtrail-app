import { learnerRecordDisplayTypeLabel } from "./learner-record-contract";
import type {
  CanonicalLearnerRecordItem,
  LearnerRecordSourceSystem,
  LearnerRecordStatus,
  LearnerRecordTrustLevel,
} from "./learner-record-contract";
import type { LearnerRecordExportBundle } from "./learner-record-export";

export type LearnerRecordPresentationSectionKey =
  | "issuerVerifiedActive"
  | "supplementalActive"
  | "historical";

export interface LearnerRecordPresentationSummary {
  total: number;
  issuerVerified: number;
  supplemental: number;
  active: number;
  historical: number;
  badgeAssertions: number;
  recordEntries: number;
}

export interface LearnerRecordPresentationDetailRow {
  label: string;
  value: string;
}

export interface LearnerRecordPresentationItem {
  id: string;
  kind: CanonicalLearnerRecordItem["kind"];
  recordType: CanonicalLearnerRecordItem["recordType"];
  recordTypeLabel: string;
  title: string;
  description: string | null;
  trustLevel: LearnerRecordTrustLevel;
  trustLabel: string;
  status: LearnerRecordStatus;
  statusLabel: string;
  editable: boolean;
  publicBadgePath: string | null;
  evidenceLinks: readonly string[];
  details: readonly LearnerRecordPresentationDetailRow[];
  provenanceSummary: string;
  provenanceDetails: readonly LearnerRecordPresentationDetailRow[];
}

export interface LearnerRecordPresentationSection {
  key: LearnerRecordPresentationSectionKey;
  title: string;
  description: string;
  itemCountLabel: string;
  items: readonly LearnerRecordPresentationItem[];
}

export interface LearnerRecordPresentationModel {
  tenantId: string;
  learnerProfileId: string;
  learnerDisplayName: string | null;
  learnerSubjectId: string;
  generatedAt: string;
  summary: LearnerRecordPresentationSummary;
  sections: readonly LearnerRecordPresentationSection[];
}

const trustLabelByLevel: Record<LearnerRecordTrustLevel, string> = {
  issuer_verified: "Issuer verified",
  learner_supplemental: "Learner supplemental",
};

const statusLabelByStatus: Record<LearnerRecordStatus, string> = {
  active: "Active",
  revoked: "Revoked",
  expired: "Expired",
};

const sourceSystemLabelByType: Record<LearnerRecordSourceSystem, string> = {
  credtrail_admin: "CredTrail admin",
  csv_import: "CSV import",
  api: "API",
  migration: "Migration",
  badge_assertion: "Badge assertion",
  learner_self_reported: "Learner self-reported",
};

const buildCountLabel = (count: number): string => {
  return count === 1 ? "1 item" : `${count} items`;
};

const formatPresentationValue = (value: unknown): string => {
  if (typeof value === "string") {
    return value;
  }

  if (typeof value === "number" || typeof value === "boolean") {
    return String(value);
  }

  return JSON.stringify(value);
};

const buildItemDetails = (
  item: CanonicalLearnerRecordItem,
): readonly LearnerRecordPresentationDetailRow[] => {
  const detailRows: LearnerRecordPresentationDetailRow[] = [];

  if (item.details !== null) {
    for (const [key, value] of Object.entries(item.details).sort(([left], [right]) =>
      left.localeCompare(right),
    )) {
      detailRows.push({
        label: key,
        value: formatPresentationValue(value),
      });
    }
  }

  return detailRows;
};

const buildProvenanceDetails = (
  item: CanonicalLearnerRecordItem,
): readonly LearnerRecordPresentationDetailRow[] => {
  const provenanceDetails: LearnerRecordPresentationDetailRow[] = [
    {
      label: "Issued",
      value: item.provenance.issuedAt,
    },
    {
      label: "Issuer",
      value: item.provenance.issuerName,
    },
    {
      label: "Source",
      value: sourceSystemLabelByType[item.provenance.sourceSystem],
    },
  ];

  if (item.provenance.revisedAt !== null) {
    provenanceDetails.push({
      label: "Revised",
      value: item.provenance.revisedAt,
    });
  }

  if (item.provenance.revokedAt !== null) {
    provenanceDetails.push({
      label: "Revoked",
      value: item.provenance.revokedAt,
    });
  }

  if (item.provenance.sourceRecordId !== null) {
    provenanceDetails.push({
      label: "Source record",
      value: item.provenance.sourceRecordId,
    });
  }

  return provenanceDetails;
};

const buildProvenanceSummary = (item: CanonicalLearnerRecordItem): string => {
  return `${item.provenance.issuerName} · ${sourceSystemLabelByType[item.provenance.sourceSystem]}`;
};

const isHistoricalItem = (item: CanonicalLearnerRecordItem): boolean => {
  return item.status !== "active";
};

const mapPresentationItem = (item: CanonicalLearnerRecordItem): LearnerRecordPresentationItem => {
  return {
    id: item.id,
    kind: item.kind,
    recordType: item.recordType,
    recordTypeLabel: learnerRecordDisplayTypeLabel(item.recordType),
    title: item.title,
    description: item.description,
    trustLevel: item.trustLevel,
    trustLabel: trustLabelByLevel[item.trustLevel],
    status: item.status,
    statusLabel: statusLabelByStatus[item.status],
    editable: item.editable,
    publicBadgePath:
      item.publicBadgeId === null ? null : `/badges/${encodeURIComponent(item.publicBadgeId)}`,
    evidenceLinks: [...item.provenance.evidenceLinks],
    details: buildItemDetails(item),
    provenanceSummary: buildProvenanceSummary(item),
    provenanceDetails: buildProvenanceDetails(item),
  };
};

const buildPresentationSection = (input: {
  key: LearnerRecordPresentationSectionKey;
  title: string;
  description: string;
  items: readonly CanonicalLearnerRecordItem[];
}): LearnerRecordPresentationSection | null => {
  if (input.items.length === 0) {
    return null;
  }

  return {
    key: input.key,
    title: input.title,
    description: input.description,
    itemCountLabel: buildCountLabel(input.items.length),
    items: input.items.map((item) => mapPresentationItem(item)),
  };
};

export const createLearnerRecordPresentation = (
  bundle: LearnerRecordExportBundle,
): LearnerRecordPresentationModel => {
  const issuerVerifiedActive = bundle.items.filter(
    (item) => item.trustLevel === "issuer_verified" && !isHistoricalItem(item),
  );
  const supplementalActive = bundle.items.filter(
    (item) => item.trustLevel === "learner_supplemental" && !isHistoricalItem(item),
  );
  const historical = bundle.items.filter((item) => isHistoricalItem(item));

  const sections = [
    buildPresentationSection({
      key: "issuerVerifiedActive",
      title: "Institution-verified record",
      description:
        "Active badges and institution-managed record entries that the tenant stands behind.",
      items: issuerVerifiedActive,
    }),
    buildPresentationSection({
      key: "supplementalActive",
      title: "Learner-supplemental record",
      description:
        "Active learner-supplied items that remain visible without being presented as institution-verified credentials.",
      items: supplementalActive,
    }),
    buildPresentationSection({
      key: "historical",
      title: "Historical record",
      description:
        "Revoked or expired record items stay visible here so the learner record does not hide prior credential history.",
      items: historical,
    }),
  ].filter((section): section is LearnerRecordPresentationSection => section !== null);

  return {
    tenantId: bundle.tenantId,
    learnerProfileId: bundle.learnerProfile.id,
    learnerDisplayName: bundle.learnerProfile.displayName,
    learnerSubjectId: bundle.learnerProfile.subjectId,
    generatedAt: bundle.generatedAt,
    summary: {
      total: bundle.items.length,
      issuerVerified: bundle.items.filter((item) => item.trustLevel === "issuer_verified").length,
      supplemental: bundle.items.filter((item) => item.trustLevel === "learner_supplemental")
        .length,
      active: bundle.items.filter((item) => item.status === "active").length,
      historical: bundle.items.filter((item) => isHistoricalItem(item)).length,
      badgeAssertions: bundle.items.filter((item) => item.kind === "badge_assertion").length,
      recordEntries: bundle.items.filter((item) => item.kind === "record_entry").length,
    },
    sections,
  };
};

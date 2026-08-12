import type { LearnerProfileRecord, SqlDatabase } from "@credtrail/db";
import {
  findLearnerProfileById,
  listLearnerRecordAssertionExports,
  listLearnerRecordEntries,
} from "@credtrail/db";
import type { LearnerRecordExportProfile } from "@credtrail/validation";

import {
  type CanonicalLearnerRecordItem,
  mapAssertionToCanonicalLearnerRecordItem,
  mapLearnerRecordEntryToCanonicalLearnerRecordItem,
} from "./learner-record-contract";

export type LearnerRecordStandardsFramework = "ob3" | "vc_did" | "clr" | "pesc" | "ctdl" | "ceds";
export type LearnerRecordStandardsSupportStatus = "native" | "mapped" | "unavailable";

export interface LearnerRecordStandardsFieldSupport {
  nativeFieldPath: string;
  standardsFieldPath: string;
  status: LearnerRecordStandardsSupportStatus;
  appliesToKinds: readonly CanonicalLearnerRecordItem["kind"][];
  notes: string | null;
}

export interface LearnerRecordStandardsFrameworkSupport {
  framework: LearnerRecordStandardsFramework;
  label: string;
  summary: string;
  fields: readonly LearnerRecordStandardsFieldSupport[];
}

export interface LearnerRecordStandardsMappingCatalog {
  catalogVersion: "credtrail-learner-record-standards/v1";
  frameworks: readonly LearnerRecordStandardsFrameworkSupport[];
}

export interface LearnerRecordPortableExport {
  schemaVersion: "credtrail-learner-record-export/v1";
  profile: "native_portable_json";
  tenantId: string;
  learnerProfileId: string;
  learner: {
    subjectId: string;
    displayName: string | null;
  };
  generatedAt: string;
  counts: {
    totalItems: number;
    badgeAssertions: number;
    recordEntries: number;
    issuerVerified: number;
    learnerSupplemental: number;
  };
  items: readonly CanonicalLearnerRecordItem[];
}

export interface LearnerRecordClrAlignedExport {
  schemaVersion: "credtrail-learner-record-export/v1";
  profile: "clr_alignment_json";
  tenantId: string;
  learnerProfileId: string;
  learner: {
    subjectId: string;
    displayName: string | null;
  };
  generatedAt: string;
  records: readonly {
    itemId: string;
    itemKind: CanonicalLearnerRecordItem["kind"];
    nativeRecordType: CanonicalLearnerRecordItem["recordType"];
    trustLevel: CanonicalLearnerRecordItem["trustLevel"];
    status: CanonicalLearnerRecordItem["status"];
    title: string;
    description: string | null;
    issuedAt: string;
    revisedAt: string | null;
    revokedAt: string | null;
    evidenceLinks: readonly string[];
    alignment: {
      clr: LearnerRecordStandardsSupportStatus;
      pesc: LearnerRecordStandardsSupportStatus;
      ctdl: LearnerRecordStandardsSupportStatus;
      ceds: LearnerRecordStandardsSupportStatus;
    };
  }[];
  standardsMapping: LearnerRecordStandardsMappingCatalog;
}

export type LearnerRecordSerializedExport =
  | LearnerRecordPortableExport
  | LearnerRecordClrAlignedExport;

export interface LearnerRecordExportBundle {
  tenantId: string;
  learnerProfile: LearnerProfileRecord;
  generatedAt: string;
  items: readonly CanonicalLearnerRecordItem[];
  standardsMapping: LearnerRecordStandardsMappingCatalog;
}

const createFieldSupport = (
  nativeFieldPath: string,
  standardsFieldPath: string,
  status: LearnerRecordStandardsSupportStatus,
  appliesToKinds: readonly CanonicalLearnerRecordItem["kind"][],
  notes?: string,
): LearnerRecordStandardsFieldSupport => {
  return {
    nativeFieldPath,
    standardsFieldPath,
    status,
    appliesToKinds,
    notes: notes ?? null,
  };
};

export const LEARNER_RECORD_STANDARDS_MAPPING_CATALOG: LearnerRecordStandardsMappingCatalog = {
  catalogVersion: "credtrail-learner-record-standards/v1",
  frameworks: [
    {
      framework: "ob3",
      label: "Open Badges 3.0",
      summary:
        "Badge assertions are native where CredTrail already issues and verifies OB3 credentials.",
      fields: [
        createFieldSupport("id", "credential.id", "native", ["badge_assertion"]),
        createFieldSupport("title", "credential.credentialSubject.achievement.name", "native", [
          "badge_assertion",
        ]),
        createFieldSupport(
          "description",
          "credential.credentialSubject.achievement.description",
          "native",
          ["badge_assertion"],
        ),
        createFieldSupport("publicBadgeId", "credential.credentialSubject.id", "native", [
          "badge_assertion",
        ]),
        createFieldSupport(
          "recordType",
          "credential.type",
          "unavailable",
          ["record_entry"],
          "Non-badge learner-record entries are not emitted as native OB3 credentials in Phase 27.",
        ),
      ],
    },
    {
      framework: "vc_did",
      label: "VC / DID",
      summary:
        "Badge assertions already sit on VC-style and DID-backed product seams; non-badge entries remain mapped or unavailable.",
      fields: [
        createFieldSupport("id", "verifiableCredential.id", "native", ["badge_assertion"]),
        createFieldSupport("provenance.issuedAt", "issuanceDate", "native", ["badge_assertion"]),
        createFieldSupport("trustLevel", "credentialStatus", "mapped", ["record_entry"]),
        createFieldSupport(
          "details",
          "credentialSubject.additionalProperties",
          "mapped",
          ["record_entry"],
          "Non-badge details can be carried as aligned supplemental properties.",
        ),
      ],
    },
    {
      framework: "clr",
      label: "CLR-aligned",
      summary:
        "CredTrail can emit a structured CLR-aligned preview without claiming full CLR conformance.",
      fields: [
        createFieldSupport("learnerProfileId", "learner.identifier", "mapped", [
          "badge_assertion",
          "record_entry",
        ]),
        createFieldSupport("title", "records.title", "mapped", ["badge_assertion", "record_entry"]),
        createFieldSupport("provenance.issuedAt", "records.awardedOn", "mapped", [
          "badge_assertion",
          "record_entry",
        ]),
        createFieldSupport("provenance.evidenceLinks", "records.evidence", "mapped", [
          "badge_assertion",
          "record_entry",
        ]),
      ],
    },
    {
      framework: "pesc",
      label: "PESC-aligned",
      summary:
        "Initial field-level mapping only; no registrar-grade PESC exchange claim is made in Phase 27.",
      fields: [
        createFieldSupport("title", "academicRecord.recordTitle", "mapped", [
          "badge_assertion",
          "record_entry",
        ]),
        createFieldSupport("status", "academicRecord.recordStatus", "mapped", [
          "badge_assertion",
          "record_entry",
        ]),
      ],
    },
    {
      framework: "ctdl",
      label: "CTDL-aligned",
      summary: "CTDL-aligned fields are exposed as mappings from native learner-record truth.",
      fields: [
        createFieldSupport("recordType", "credentialType", "mapped", [
          "badge_assertion",
          "record_entry",
        ]),
        createFieldSupport("description", "description", "mapped", [
          "badge_assertion",
          "record_entry",
        ]),
      ],
    },
    {
      framework: "ceds",
      label: "CEDS-aligned",
      summary: "CEDS alignment is limited to basic learner-record descriptors in this phase.",
      fields: [
        createFieldSupport("learnerProfileId", "LearnerIdentifier", "mapped", [
          "badge_assertion",
          "record_entry",
        ]),
        createFieldSupport("provenance.issuedAt", "RecordStartDate", "mapped", [
          "badge_assertion",
          "record_entry",
        ]),
        createFieldSupport("provenance.revokedAt", "RecordEndDate", "mapped", [
          "badge_assertion",
          "record_entry",
        ]),
      ],
    },
  ],
};

const sortLearnerRecordItems = (
  items: readonly CanonicalLearnerRecordItem[],
): CanonicalLearnerRecordItem[] => {
  return [...items].sort((left, right) => {
    const issuedCompare = right.provenance.issuedAt.localeCompare(left.provenance.issuedAt);

    if (issuedCompare !== 0) {
      return issuedCompare;
    }

    return right.id.localeCompare(left.id);
  });
};

const itemWithBadgeMetadata = (
  item: CanonicalLearnerRecordItem,
  metadata: {
    badgeCriteriaUri: string | null;
    badgeImageUri: string | null;
  },
): CanonicalLearnerRecordItem => {
  if (metadata.badgeCriteriaUri === null && metadata.badgeImageUri === null) {
    return item;
  }

  return {
    ...item,
    details: {
      ...item.details,
      ...(metadata.badgeCriteriaUri === null ? {} : { criteriaUri: metadata.badgeCriteriaUri }),
      ...(metadata.badgeImageUri === null ? {} : { imageUri: metadata.badgeImageUri }),
    },
  };
};

export const createLearnerRecordStandardsMappingCatalog =
  (): LearnerRecordStandardsMappingCatalog => {
    return LEARNER_RECORD_STANDARDS_MAPPING_CATALOG;
  };

const buildPortableCounts = (items: readonly CanonicalLearnerRecordItem[]) => {
  return {
    totalItems: items.length,
    badgeAssertions: items.filter((item) => item.kind === "badge_assertion").length,
    recordEntries: items.filter((item) => item.kind === "record_entry").length,
    issuerVerified: items.filter((item) => item.trustLevel === "issuer_verified").length,
    learnerSupplemental: items.filter((item) => item.trustLevel === "learner_supplemental").length,
  };
};

export const serializeLearnerRecordExport = (
  bundle: LearnerRecordExportBundle,
  profile: LearnerRecordExportProfile,
): LearnerRecordSerializedExport => {
  const learner = {
    subjectId: bundle.learnerProfile.subjectId,
    displayName: bundle.learnerProfile.displayName,
  };

  if (profile === "native_portable_json") {
    return {
      schemaVersion: "credtrail-learner-record-export/v1",
      profile,
      tenantId: bundle.tenantId,
      learnerProfileId: bundle.learnerProfile.id,
      learner,
      generatedAt: bundle.generatedAt,
      counts: buildPortableCounts(bundle.items),
      items: bundle.items,
    };
  }

  return {
    schemaVersion: "credtrail-learner-record-export/v1",
    profile,
    tenantId: bundle.tenantId,
    learnerProfileId: bundle.learnerProfile.id,
    learner,
    generatedAt: bundle.generatedAt,
    records: bundle.items.map((item) => {
      return {
        itemId: item.id,
        itemKind: item.kind,
        nativeRecordType: item.recordType,
        trustLevel: item.trustLevel,
        status: item.status,
        title: item.title,
        description: item.description,
        issuedAt: item.provenance.issuedAt,
        revisedAt: item.provenance.revisedAt,
        revokedAt: item.provenance.revokedAt,
        evidenceLinks: item.provenance.evidenceLinks,
        alignment: {
          clr: "mapped",
          pesc: "mapped",
          ctdl: "mapped",
          ceds: "mapped",
        },
      };
    }),
    standardsMapping: bundle.standardsMapping,
  };
};

export const buildLearnerRecordStandardsMappingResponse = (
  bundle: LearnerRecordExportBundle,
  profile: LearnerRecordExportProfile = "clr_alignment_json",
) => {
  return {
    tenantId: bundle.tenantId,
    learnerProfileId: bundle.learnerProfile.id,
    profile,
    generatedAt: bundle.generatedAt,
    itemCounts: buildPortableCounts(bundle.items),
    standardsMapping: bundle.standardsMapping,
  };
};

export const loadLearnerRecordExportBundle = async (
  db: SqlDatabase,
  input: {
    tenantId: string;
    learnerProfileId: string;
  },
): Promise<LearnerRecordExportBundle | null> => {
  const learnerProfile = await findLearnerProfileById(db, input.tenantId, input.learnerProfileId);

  if (learnerProfile === null) {
    return null;
  }

  const [assertions, entries] = await Promise.all([
    listLearnerRecordAssertionExports(db, {
      tenantId: input.tenantId,
      learnerProfileId: input.learnerProfileId,
    }),
    listLearnerRecordEntries(db, {
      tenantId: input.tenantId,
      learnerProfileId: input.learnerProfileId,
    }),
  ]);

  const assertionItems = assertions.map((record) => {
    return itemWithBadgeMetadata(
      mapAssertionToCanonicalLearnerRecordItem({
        assertion: {
          id: record.assertionId,
          tenantId: record.tenantId,
          publicId: record.assertionPublicId,
          learnerProfileId: record.learnerProfileId,
          badgeTemplateId: record.badgeTemplateId,
          issuedAt: record.issuedAt,
          issuedByUserId: record.issuedByUserId,
          revokedAt: record.revokedAt,
        },
        badgeTitle: record.badgeTitle,
        badgeDescription: record.badgeDescription,
        issuerName: record.issuerName,
        evidenceLinks: [],
      }),
      {
        badgeCriteriaUri: record.badgeCriteriaUri,
        badgeImageUri: record.badgeImageUri,
      },
    );
  });
  const entryItems = entries.map((entry) =>
    mapLearnerRecordEntryToCanonicalLearnerRecordItem(entry),
  );

  return {
    tenantId: input.tenantId,
    learnerProfile,
    generatedAt: new Date().toISOString(),
    items: sortLearnerRecordItems([...assertionItems, ...entryItems]),
    standardsMapping: createLearnerRecordStandardsMappingCatalog(),
  };
};

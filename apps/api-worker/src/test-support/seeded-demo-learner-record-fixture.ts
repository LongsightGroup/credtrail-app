import type {
  LearnerProfileRecord,
  LearnerRecordAssertionExportRecord,
  LearnerRecordEntryRecord,
} from "@credtrail/db";

import {
  mapAssertionToCanonicalLearnerRecordItem,
  mapLearnerRecordEntryToCanonicalLearnerRecordItem,
} from "../learner-record/learner-record-contract";
import {
  buildLearnerRecordStandardsMappingResponse,
  createLearnerRecordStandardsMappingCatalog,
  serializeLearnerRecordExport,
  type LearnerRecordClrAlignedExport,
  type LearnerRecordExportBundle,
  type LearnerRecordPortableExport,
} from "../learner-record/learner-record-export";
import {
  createLearnerRecordPresentation,
  type LearnerRecordPresentationModel,
} from "../learner-record/learner-record-presentation";

const GENERATED_AT = "2026-03-26T12:00:00.000Z";
const TENANT_ID = "tenant_123";
const LEARNER_PROFILE_ID = "lpr_123";
const LEARNER_EMAIL = "learner@example.edu";
const NATIVE_EXPORT_PROFILE = "native_portable_json";
const STANDARDS_MAPPING_PROFILE = "clr_alignment_json";

interface SeededDemoLearnerRecordRouteFamily {
  learnerRecord: string;
  adminReview: string;
  nativeExport: string;
  standardsMapping: string;
}

interface SeededDemoLearnerRecordFixture {
  tenantId: string;
  learnerProfileId: string;
  learnerEmail: string;
  routeFamily: SeededDemoLearnerRecordRouteFamily;
  learnerProfile: LearnerProfileRecord;
  assertionExports: readonly LearnerRecordAssertionExportRecord[];
  recordEntries: readonly LearnerRecordEntryRecord[];
  exportBundle: LearnerRecordExportBundle;
  presentation: LearnerRecordPresentationModel;
  nativePortableExport: LearnerRecordPortableExport;
  clrAlignedExport: LearnerRecordClrAlignedExport;
  standardsMappingResponse: ReturnType<typeof buildLearnerRecordStandardsMappingResponse>;
}

const createLearnerProfile = (overrides?: Partial<LearnerProfileRecord>): LearnerProfileRecord => {
  return {
    id: LEARNER_PROFILE_ID,
    tenantId: TENANT_ID,
    subjectId: `urn:credtrail:learner:${TENANT_ID}:${LEARNER_PROFILE_ID}`,
    displayName: "Learner One",
    createdAt: "2026-03-25T12:00:00.000Z",
    updatedAt: "2026-03-25T12:00:00.000Z",
    ...overrides,
  };
};

const createAssertionExport = (
  overrides?: Partial<LearnerRecordAssertionExportRecord>,
): LearnerRecordAssertionExportRecord => {
  return {
    assertionId: `${TENANT_ID}:assertion_456`,
    assertionPublicId: "public_assertion_456",
    tenantId: TENANT_ID,
    learnerProfileId: LEARNER_PROFILE_ID,
    badgeTemplateId: "badge_template_analytics",
    badgeTitle: "Applied Analytics Badge",
    badgeDescription: "Awarded for applied analytics work.",
    badgeCriteriaUri: "https://credtrail.example.edu/badges/applied-analytics/criteria",
    badgeImageUri: "https://credtrail.example.edu/badges/applied-analytics/image.png",
    recipientIdentity: LEARNER_EMAIL,
    recipientIdentityType: "email",
    vcR2Key: `tenants/${TENANT_ID}/assertions/assertion_456.jsonld`,
    statusListIndex: 12,
    idempotencyKey: "idem_123",
    issuedAt: "2026-03-24T15:00:00.000Z",
    issuedByUserId: "usr_admin",
    revokedAt: null,
    issuerName: "CredTrail University",
    createdAt: "2026-03-24T15:00:00.000Z",
    updatedAt: "2026-03-24T15:00:00.000Z",
    ...overrides,
  };
};

const createRecordEntry = (
  overrides?: Partial<LearnerRecordEntryRecord>,
): LearnerRecordEntryRecord => {
  return {
    id: "lre_123",
    tenantId: TENANT_ID,
    learnerProfileId: LEARNER_PROFILE_ID,
    trustLevel: "issuer_verified",
    recordType: "course",
    status: "active",
    title: "Clinical Placement Seminar",
    description: "Completed with distinction.",
    issuerName: "CredTrail University",
    issuerUserId: "usr_admin",
    sourceSystem: "credtrail_admin",
    sourceRecordId: null,
    issuedAt: "2026-03-23T15:00:00.000Z",
    revisedAt: null,
    revokedAt: null,
    evidenceLinksJson: '["https://credtrail.example.edu/evidence/clinical-placement-seminar"]',
    detailsJson: '{"grade":"A","term":"Spring 2026"}',
    createdAt: "2026-03-23T15:00:00.000Z",
    updatedAt: "2026-03-23T15:00:00.000Z",
    ...overrides,
  };
};

const learnerProfile = createLearnerProfile();

const assertionExports = [
  createAssertionExport(),
] as const satisfies readonly LearnerRecordAssertionExportRecord[];

const recordEntries = [
  createRecordEntry(),
  createRecordEntry({
    id: "lre_supp_001",
    trustLevel: "learner_supplemental",
    recordType: "supplemental_artifact",
    title: "Portfolio Reflection",
    description: "Learner-supplied capstone reflection.",
    issuerName: "Learner self report",
    issuerUserId: null,
    sourceSystem: "learner_self_reported",
    sourceRecordId: null,
    issuedAt: "2026-03-22T15:00:00.000Z",
    evidenceLinksJson: '["https://portfolio.example.edu/learner-one"]',
    detailsJson: '{"portfolioUrl":"https://portfolio.example.edu/learner-one"}',
  }),
  createRecordEntry({
    id: "lre_hist_001",
    recordType: "membership",
    status: "revoked",
    title: "Leadership Society Membership",
    description: "Imported prior standing from a historical departmental record.",
    issuerName: "CredTrail University",
    issuerUserId: "usr_admin",
    sourceSystem: "csv_import",
    sourceRecordId: "legacy:membership:001",
    issuedAt: "2026-03-20T15:00:00.000Z",
    revisedAt: "2026-03-21T15:00:00.000Z",
    revokedAt: "2026-03-22T15:00:00.000Z",
    evidenceLinksJson: "[]",
    detailsJson: '{"importBatch":"batch_legacy_001"}',
  }),
] as const satisfies readonly LearnerRecordEntryRecord[];

const exportBundle: LearnerRecordExportBundle = {
  tenantId: TENANT_ID,
  learnerProfile,
  generatedAt: GENERATED_AT,
  items: [
    {
      ...mapAssertionToCanonicalLearnerRecordItem({
        assertion: {
          id: assertionExports[0].assertionId,
          tenantId: assertionExports[0].tenantId,
          publicId: assertionExports[0].assertionPublicId,
          learnerProfileId: assertionExports[0].learnerProfileId,
          badgeTemplateId: assertionExports[0].badgeTemplateId,
          issuedAt: assertionExports[0].issuedAt,
          issuedByUserId: assertionExports[0].issuedByUserId,
          revokedAt: assertionExports[0].revokedAt,
        },
        badgeTitle: assertionExports[0].badgeTitle,
        badgeDescription: assertionExports[0].badgeDescription,
        issuerName: assertionExports[0].issuerName,
        evidenceLinks: [],
      }),
      details: {
        criteriaUri: assertionExports[0].badgeCriteriaUri,
        imageUri: assertionExports[0].badgeImageUri,
      },
    },
    ...recordEntries.map((entry) => mapLearnerRecordEntryToCanonicalLearnerRecordItem(entry)),
  ],
  standardsMapping: createLearnerRecordStandardsMappingCatalog(),
};

const routeFamily: SeededDemoLearnerRecordRouteFamily = {
  learnerRecord: `/tenants/${TENANT_ID}/learner/record`,
  adminReview: `/tenants/${TENANT_ID}/admin/operations/learner-records?learner=${encodeURIComponent(LEARNER_EMAIL)}`,
  nativeExport: `/v1/tenants/${TENANT_ID}/learner-records/${LEARNER_PROFILE_ID}/export?profile=${NATIVE_EXPORT_PROFILE}`,
  standardsMapping: `/v1/tenants/${TENANT_ID}/learner-records/${LEARNER_PROFILE_ID}/standards-mapping?profile=${STANDARDS_MAPPING_PROFILE}`,
};

export const seededDemoLearnerRecordFixture: SeededDemoLearnerRecordFixture = {
  tenantId: TENANT_ID,
  learnerProfileId: LEARNER_PROFILE_ID,
  learnerEmail: LEARNER_EMAIL,
  routeFamily,
  learnerProfile,
  assertionExports,
  recordEntries,
  exportBundle,
  presentation: createLearnerRecordPresentation(exportBundle),
  nativePortableExport: serializeLearnerRecordExport(
    exportBundle,
    NATIVE_EXPORT_PROFILE,
  ) as LearnerRecordPortableExport,
  clrAlignedExport: serializeLearnerRecordExport(
    exportBundle,
    STANDARDS_MAPPING_PROFILE,
  ) as LearnerRecordClrAlignedExport,
  standardsMappingResponse: buildLearnerRecordStandardsMappingResponse(
    exportBundle,
    STANDARDS_MAPPING_PROFILE,
  ),
};

import {
  findTenantById,
  listBadgeTemplates,
  listTenantOrgUnits,
  type BadgeTemplateRecord,
  type LearnerRecordImportContextInferenceSource,
  type SqlDatabase,
  type TenantOrgUnitRecord,
} from "@credtrail/db";
import {
  learnerRecordImportBatchDefaultsSchema,
  learnerRecordImportRowSchema,
  type LearnerRecordImportBatchDefaults,
  type LearnerRecordImportQueuePayload,
  type LearnerRecordImportRow,
  type LearnerRecordImportRowReport,
  type LearnerRecordImportSmartContext,
} from "@credtrail/validation";
import {
  parseLearnerRecordImportFile,
  type LearnerRecordImportCandidateRow,
  type LearnerRecordImportFileFormat,
} from "./learner-record-import-file";

/** Prepared reports and queue payloads for one validated import batch. */
export interface LearnerRecordImportBatchResult {
  readonly reports: readonly LearnerRecordImportRowReport[];
  readonly queuePayloads: readonly LearnerRecordImportQueuePayload[];
}

/** Complete preview state produced before an import is queued. */
export interface PreparedLearnerRecordImportSubmission {
  readonly batchId: string;
  readonly fileName: string;
  readonly format: LearnerRecordImportFileFormat;
  readonly defaults: LearnerRecordImportBatchDefaults;
  readonly reports: readonly LearnerRecordImportRowReport[];
  readonly queuePayloads: readonly LearnerRecordImportQueuePayload[];
}

const learnerRecordImportFieldLabel = (field: string): string => {
  switch (field) {
    case "orgUnitUrlKey":
      return "org unit URL key";
    case "badgeTemplateUrlKey":
      return "badge template URL key";
    default:
      return field;
  }
};

const zodIssuePathLabel = (path: readonly PropertyKey[]): string => {
  if (path.length === 0) {
    return "row";
  }

  const pathSegments = path.map(String);
  const firstSegment = pathSegments[0] ?? "row";
  const label = learnerRecordImportFieldLabel(firstSegment);
  const remainingSegments = pathSegments.slice(1);

  return remainingSegments.length === 0 ? label : `${label}.${remainingSegments.join(".")}`;
};

const zodIssueMessages = (
  issues: readonly {
    path: readonly PropertyKey[];
    message: string;
  }[],
): string[] => {
  return issues.map((issue) => {
    const path = zodIssuePathLabel(issue.path);
    return `${path}: ${issue.message}`;
  });
};

const distinctInferenceSources = (
  sources: readonly LearnerRecordImportContextInferenceSource[],
): LearnerRecordImportContextInferenceSource[] => {
  return Array.from(new Set(sources));
};

const normalizeOptionalText = (value: string | undefined): string | null => {
  if (value === undefined) {
    return null;
  }

  const trimmed = value.trim();
  return trimmed.length === 0 ? null : trimmed;
};

const resolveExplicitOrgUnit = (
  row: LearnerRecordImportRow,
  orgUnits: readonly TenantOrgUnitRecord[],
): {
  orgUnit: TenantOrgUnitRecord | null;
  errors: string[];
  warnings: string[];
  usedRowValue: boolean;
} => {
  const warnings: string[] = [];
  const orgUnitById =
    row.orgUnitId === undefined
      ? null
      : (orgUnits.find((orgUnit) => orgUnit.id === row.orgUnitId) ?? null);
  const orgUnitByUrlKey =
    row.orgUnitUrlKey === undefined
      ? null
      : (orgUnits.find((orgUnit) => orgUnit.slug === row.orgUnitUrlKey) ?? null);

  if (orgUnitById !== null && orgUnitByUrlKey !== null && orgUnitById.id !== orgUnitByUrlKey.id) {
    return {
      orgUnit: null,
      errors: ["Org unit ID and org unit URL key refer to different org units"],
      warnings: [],
      usedRowValue: true,
    };
  }

  const orgUnit = orgUnitById ?? orgUnitByUrlKey;

  if (orgUnit === null && (row.orgUnitId !== undefined || row.orgUnitUrlKey !== undefined)) {
    warnings.push(
      "Row org-unit reference did not match the current tenant structure. The record will import without explicit org-unit grouping metadata.",
    );
  }

  return {
    orgUnit,
    errors: [],
    warnings,
    usedRowValue: row.orgUnitId !== undefined || row.orgUnitUrlKey !== undefined,
  };
};

const resolveBadgeTemplate = (
  row: LearnerRecordImportRow,
  badgeTemplates: readonly BadgeTemplateRecord[],
): {
  badgeTemplate: BadgeTemplateRecord | null;
  errors: string[];
  warnings: string[];
  usedRowValue: boolean;
} => {
  const warnings: string[] = [];
  const templateById =
    row.badgeTemplateId === undefined
      ? null
      : (badgeTemplates.find((badgeTemplate) => badgeTemplate.id === row.badgeTemplateId) ?? null);
  const templateByUrlKey =
    row.badgeTemplateUrlKey === undefined
      ? null
      : (badgeTemplates.find((badgeTemplate) => badgeTemplate.slug === row.badgeTemplateUrlKey) ??
        null);

  if (
    templateById !== null &&
    templateByUrlKey !== null &&
    templateById.id !== templateByUrlKey.id
  ) {
    return {
      badgeTemplate: null,
      errors: ["Badge template ID and badge template URL key refer to different badge templates"],
      warnings: [],
      usedRowValue: true,
    };
  }

  const badgeTemplate = templateById ?? templateByUrlKey;

  if (
    badgeTemplate === null &&
    (row.badgeTemplateId !== undefined || row.badgeTemplateUrlKey !== undefined)
  ) {
    warnings.push(
      "Row badge-template reference did not match the current tenant catalog. The record will import without badge-template grouping metadata.",
    );
  }

  return {
    badgeTemplate,
    errors: [],
    warnings,
    usedRowValue: row.badgeTemplateId !== undefined || row.badgeTemplateUrlKey !== undefined,
  };
};

const prepareLearnerRecordImportRow = (input: {
  readonly rowNumber: number;
  readonly candidate: Record<string, unknown>;
  readonly defaults: LearnerRecordImportBatchDefaults;
  readonly tenantDisplayName: string;
  readonly orgUnits: readonly TenantOrgUnitRecord[];
  readonly badgeTemplates: readonly BadgeTemplateRecord[];
  readonly fileName: string;
  readonly requestedAt: string;
  readonly requestedByUserId?: string;
  readonly batchId: string;
}): {
  report: LearnerRecordImportRowReport;
  queuePayload: LearnerRecordImportQueuePayload | null;
} => {
  const parsedRow = learnerRecordImportRowSchema.safeParse(input.candidate);

  if (!parsedRow.success) {
    return {
      report: {
        rowNumber: input.rowNumber,
        status: "invalid",
        errors: zodIssueMessages(parsedRow.error.issues),
        warnings: [],
        preview: null,
      },
      queuePayload: null,
    };
  }

  const row = parsedRow.data;
  const errors: string[] = [];
  const warnings: string[] = [];
  const effectiveTrustLevel = row.trustLevel ?? input.defaults.defaultTrustLevel;

  if (
    row.recordType === "supplemental_artifact" &&
    effectiveTrustLevel !== "learner_supplemental"
  ) {
    errors.push("supplemental_artifact rows must import as learner_supplemental");
  }

  const explicitOrgUnit = resolveExplicitOrgUnit(row, input.orgUnits);
  const explicitBadgeTemplate = resolveBadgeTemplate(row, input.badgeTemplates);
  errors.push(...explicitOrgUnit.errors, ...explicitBadgeTemplate.errors);
  warnings.push(...explicitOrgUnit.warnings, ...explicitBadgeTemplate.warnings);

  const inferredSources: LearnerRecordImportContextInferenceSource[] = [];
  let resolvedOrgUnit = explicitOrgUnit.orgUnit;

  if (explicitOrgUnit.usedRowValue) {
    inferredSources.push("row", "org_unit");
  }

  if (explicitBadgeTemplate.usedRowValue) {
    inferredSources.push("row", "badge_template");
  }

  if (resolvedOrgUnit === null && explicitBadgeTemplate.badgeTemplate?.ownerOrgUnitId !== null) {
    const ownerOrgUnit = input.orgUnits.find(
      (orgUnit) => orgUnit.id === explicitBadgeTemplate.badgeTemplate?.ownerOrgUnitId,
    );

    if (ownerOrgUnit !== undefined) {
      resolvedOrgUnit = ownerOrgUnit;
      inferredSources.push("badge_template");
    }
  }

  if (row.pathwayLabel !== undefined) {
    warnings.push(
      "Pathway is preserved as imported metadata only. CredTrail does not yet treat pathway as a native learner-record relation.",
    );
  }

  if (resolvedOrgUnit === null && explicitBadgeTemplate.badgeTemplate === null) {
    warnings.push(
      "No org-unit or badge-template context matched this row. The record will import without smart-default grouping metadata.",
    );
  }

  const effectiveIssuerName =
    normalizeOptionalText(row.issuerName) ??
    normalizeOptionalText(input.defaults.defaultIssuerName) ??
    input.tenantDisplayName;
  const inference = distinctInferenceSources(
    inferredSources.length === 0 ? ["none"] : inferredSources,
  );

  if (errors.length > 0) {
    return {
      report: {
        rowNumber: input.rowNumber,
        status: "invalid",
        errors,
        warnings,
        preview: null,
      },
      queuePayload: null,
    };
  }

  const smartContext: LearnerRecordImportSmartContext = {
    orgUnitId: resolvedOrgUnit?.id ?? null,
    orgUnitLabel: resolvedOrgUnit?.displayName ?? null,
    badgeTemplateId: explicitBadgeTemplate.badgeTemplate?.id ?? null,
    badgeTemplateLabel: explicitBadgeTemplate.badgeTemplate?.title ?? null,
    pathwayLabel: normalizeOptionalText(row.pathwayLabel),
    inferredFrom: inference,
  };
  const queuePayload: LearnerRecordImportQueuePayload = {
    batchId: input.batchId,
    rowNumber: input.rowNumber,
    fileName: input.fileName,
    format: "csv",
    requestedAt: input.requestedAt,
    ...(input.requestedByUserId === undefined
      ? {}
      : { requestedByUserId: input.requestedByUserId }),
    row: {
      learnerEmail: row.learnerEmail,
      learnerDisplayName: normalizeOptionalText(row.learnerDisplayName),
      title: row.title,
      recordType: row.recordType,
      issuedAt: row.issuedAt,
      description: normalizeOptionalText(row.description),
      sourceRecordId: normalizeOptionalText(row.sourceRecordId),
      evidenceLinks: row.evidenceLinks ?? [],
      effectiveTrustLevel,
      effectiveIssuerName,
      smartContext: {
        orgUnitId: smartContext.orgUnitId,
        badgeTemplateId: smartContext.badgeTemplateId,
        pathwayLabel: smartContext.pathwayLabel,
        inferredFrom: smartContext.inferredFrom,
      },
    },
  };

  return {
    report: {
      rowNumber: input.rowNumber,
      status: "valid",
      errors: [],
      warnings,
      preview: {
        learner: {
          email: row.learnerEmail,
          displayName: normalizeOptionalText(row.learnerDisplayName),
        },
        record: {
          title: row.title,
          recordType: row.recordType,
          issuedAt: row.issuedAt,
          description: normalizeOptionalText(row.description),
          sourceRecordId: normalizeOptionalText(row.sourceRecordId),
          evidenceLinks: row.evidenceLinks ?? [],
        },
        trustLevel: effectiveTrustLevel,
        issuerName: effectiveIssuerName,
        sourceSystem: "csv_import",
        smartContext,
      },
    },
    queuePayload,
  };
};

/** Validates candidate rows and builds their preview reports and queue payloads. */
export const prepareLearnerRecordImportBatch = (input: {
  readonly rows: readonly LearnerRecordImportCandidateRow[];
  readonly defaults: LearnerRecordImportBatchDefaults;
  readonly tenantDisplayName: string;
  readonly orgUnits: readonly TenantOrgUnitRecord[];
  readonly badgeTemplates: readonly BadgeTemplateRecord[];
  readonly fileName: string;
  readonly batchId: string;
  readonly requestedAt: string;
  readonly requestedByUserId?: string;
}): LearnerRecordImportBatchResult => {
  const defaults = learnerRecordImportBatchDefaultsSchema.parse(input.defaults);
  const reports: LearnerRecordImportRowReport[] = [];
  const queuePayloads: LearnerRecordImportQueuePayload[] = [];

  for (const row of input.rows) {
    const prepared = prepareLearnerRecordImportRow({
      rowNumber: row.rowNumber,
      candidate: row.candidate,
      defaults,
      tenantDisplayName: input.tenantDisplayName,
      orgUnits: input.orgUnits,
      badgeTemplates: input.badgeTemplates,
      fileName: input.fileName,
      batchId: input.batchId,
      requestedAt: input.requestedAt,
      ...(input.requestedByUserId === undefined
        ? {}
        : { requestedByUserId: input.requestedByUserId }),
    });

    reports.push(prepared.report);

    if (prepared.queuePayload !== null) {
      queuePayloads.push(prepared.queuePayload);
    }
  }

  return {
    reports,
    queuePayloads,
  };
};

/** Loads tenant context and prepares one learner-record import submission. */
export const prepareLearnerRecordImportSubmission = async (
  db: SqlDatabase,
  input: {
    readonly tenantId: string;
    readonly fileName: string;
    readonly content: string;
    readonly defaults: LearnerRecordImportBatchDefaults;
    readonly requestedAt: string;
    readonly requestedByUserId?: string;
    readonly batchId?: string;
  },
): Promise<PreparedLearnerRecordImportSubmission> => {
  const tenant = await findTenantById(db, input.tenantId);

  if (tenant === null) {
    throw new Error(`Tenant "${input.tenantId}" not found`);
  }

  const [orgUnits, badgeTemplates] = await Promise.all([
    listTenantOrgUnits(db, {
      tenantId: input.tenantId,
      includeInactive: true,
    }),
    listBadgeTemplates(db, {
      tenantId: input.tenantId,
      includeArchived: false,
    }),
  ]);
  const parsedFile = parseLearnerRecordImportFile({
    content: input.content,
  });
  const batchId = input.batchId ?? crypto.randomUUID();
  const prepared = prepareLearnerRecordImportBatch({
    rows: parsedFile.rows,
    defaults: input.defaults,
    tenantDisplayName: tenant.displayName,
    orgUnits,
    badgeTemplates,
    fileName: input.fileName,
    batchId,
    requestedAt: input.requestedAt,
    ...(input.requestedByUserId === undefined
      ? {}
      : { requestedByUserId: input.requestedByUserId }),
  });

  return {
    batchId,
    fileName: input.fileName,
    format: parsedFile.format,
    defaults: input.defaults,
    reports: prepared.reports,
    queuePayloads: prepared.queuePayloads,
  };
};

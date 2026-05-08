import {
  enqueueJobQueueMessage,
  findTenantById,
  createLearnerRecordEntry,
  createLearnerRecordImportContext,
  listBadgeTemplates,
  listTenantOrgUnits,
  resolveLearnerProfileForIdentity,
  type BadgeTemplateRecord,
  type ImportLearnerRecordBatchQueueMessageRecord,
  type LearnerRecordEntryType,
  type LearnerRecordImportContextInferenceSource,
  type LearnerRecordTrustLevel,
  type SqlDatabase,
  type TenantOrgUnitRecord,
} from "@credtrail/db";
import {
  learnerRecordImportBatchDefaultsSchema,
  learnerRecordImportRowSchema,
  type LearnerRecordImportBatchDefaults,
  type LearnerRecordImportRow,
} from "@credtrail/validation";

export type LearnerRecordImportFileFormat = "csv";

export interface LearnerRecordImportCandidateRow {
  rowNumber: number;
  candidate: Record<string, unknown>;
}

export interface ParseLearnerRecordImportFileResult {
  format: LearnerRecordImportFileFormat;
  rows: LearnerRecordImportCandidateRow[];
}

export class LearnerRecordImportFileParseError extends Error {
  public constructor(message: string) {
    super(message);
    this.name = "LearnerRecordImportFileParseError";
  }
}

export interface LearnerRecordImportSmartContext {
  orgUnitId: string | null;
  orgUnitLabel: string | null;
  badgeTemplateId: string | null;
  badgeTemplateLabel: string | null;
  pathwayLabel: string | null;
  inferredFrom: readonly LearnerRecordImportContextInferenceSource[];
}

export interface LearnerRecordImportPreview {
  learner: {
    email: string;
    displayName: string | null;
  };
  record: {
    title: string;
    recordType: LearnerRecordEntryType;
    issuedAt: string;
    description: string | null;
    sourceRecordId: string | null;
    evidenceLinks: readonly string[];
  };
  trustLevel: LearnerRecordTrustLevel;
  issuerName: string;
  sourceSystem: "csv_import";
  smartContext: LearnerRecordImportSmartContext;
}

export interface LearnerRecordImportRowReport {
  rowNumber: number;
  status: "valid" | "invalid";
  errors: string[];
  warnings: string[];
  preview: LearnerRecordImportPreview | null;
}

export interface LearnerRecordImportPreparedRow {
  learnerEmail: string;
  learnerDisplayName: string | null;
  title: string;
  recordType: LearnerRecordEntryType;
  issuedAt: string;
  description: string | null;
  sourceRecordId: string | null;
  evidenceLinks: readonly string[];
  effectiveTrustLevel: LearnerRecordTrustLevel;
  effectiveIssuerName: string;
  smartContext: {
    orgUnitId: string | null;
    badgeTemplateId: string | null;
    pathwayLabel: string | null;
    inferredFrom: readonly LearnerRecordImportContextInferenceSource[];
  };
}

export interface LearnerRecordImportQueuePayload {
  batchId: string;
  rowNumber: number;
  fileName: string;
  format: LearnerRecordImportFileFormat;
  requestedAt: string;
  requestedByUserId?: string;
  row: LearnerRecordImportPreparedRow;
}

export interface LearnerRecordImportBatchResult {
  reports: LearnerRecordImportRowReport[];
  queuePayloads: LearnerRecordImportQueuePayload[];
}

export interface PreparedLearnerRecordImportSubmission {
  batchId: string;
  fileName: string;
  format: LearnerRecordImportFileFormat;
  defaults: LearnerRecordImportBatchDefaults;
  reports: LearnerRecordImportRowReport[];
  queuePayloads: LearnerRecordImportQueuePayload[];
}

export interface LearnerRecordImportBatchProgressSummary {
  batchId: string;
  fileName: string | null;
  format: string | null;
  totalRows: number;
  pendingRows: number;
  processingRows: number;
  completedRows: number;
  failedRows: number;
  retryableRows: number;
  failedRowNumbers: number[];
  latestError: string | null;
  defaultTrustLevel: LearnerRecordTrustLevel | null;
  firstQueuedAt: string;
  lastUpdatedAt: string;
}

const MAX_IMPORT_ROWS = 500;

export const LEARNER_RECORD_IMPORT_TEMPLATE_HEADERS = [
  "learnerEmail",
  "learnerDisplayName",
  "title",
  "recordType",
  "issuedAt",
  "trustLevel",
  "description",
  "issuerName",
  "orgUnitId",
  "orgUnitSlug",
  "badgeTemplateId",
  "badgeTemplateSlug",
  "pathwayLabel",
  "sourceRecordId",
  "evidenceLinks",
] as const;

const normalizeHeader = (value: string): string => {
  return value
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]/g, "");
};

const canonicalFieldForHeader = (
  header: string,
): (typeof LEARNER_RECORD_IMPORT_TEMPLATE_HEADERS)[number] | null => {
  switch (header) {
    case "learneremail":
    case "email":
      return "learnerEmail";
    case "learnerdisplayname":
    case "displayname":
    case "learnername":
      return "learnerDisplayName";
    case "title":
      return "title";
    case "recordtype":
    case "type":
      return "recordType";
    case "issuedat":
    case "issued":
    case "issuedon":
      return "issuedAt";
    case "trustlevel":
    case "trust":
      return "trustLevel";
    case "description":
      return "description";
    case "issuername":
    case "issuer":
      return "issuerName";
    case "orgunitid":
      return "orgUnitId";
    case "orgunitslug":
      return "orgUnitSlug";
    case "badgetemplateid":
    case "templateid":
      return "badgeTemplateId";
    case "badgetemplateslug":
    case "templateslug":
      return "badgeTemplateSlug";
    case "pathwaylabel":
    case "pathway":
      return "pathwayLabel";
    case "sourcerecordid":
    case "sourceid":
      return "sourceRecordId";
    case "evidencelinks":
    case "evidence":
      return "evidenceLinks";
    default:
      return null;
  }
};

const parseCsvMatrix = (input: string): string[][] => {
  const rows: string[][] = [];
  let currentRow: string[] = [];
  let currentField = "";
  let insideQuotes = false;

  for (let index = 0; index < input.length; index += 1) {
    const character = input[index] ?? "";

    if (insideQuotes) {
      if (character === '"') {
        const nextCharacter = input[index + 1];

        if (nextCharacter === '"') {
          currentField += '"';
          index += 1;
        } else {
          insideQuotes = false;
        }
      } else {
        currentField += character;
      }

      continue;
    }

    if (character === '"') {
      insideQuotes = true;
      continue;
    }

    if (character === ",") {
      currentRow.push(currentField);
      currentField = "";
      continue;
    }

    if (character === "\n") {
      currentRow.push(currentField);
      rows.push(currentRow);
      currentRow = [];
      currentField = "";
      continue;
    }

    if (character === "\r") {
      continue;
    }

    currentField += character;
  }

  if (insideQuotes) {
    throw new LearnerRecordImportFileParseError("Invalid CSV: unclosed quoted value");
  }

  currentRow.push(currentField);

  if (currentRow.some((value) => value.trim().length > 0)) {
    rows.push(currentRow);
  }

  return rows;
};

const parseEvidenceLinksCell = (value: string): string[] | string => {
  const trimmed = value.trim();

  if (trimmed.length === 0) {
    return [];
  }

  if (trimmed.startsWith("[")) {
    try {
      const parsed = JSON.parse(trimmed) as unknown;

      if (Array.isArray(parsed) && parsed.every((entry) => typeof entry === "string")) {
        return parsed.map((entry) => entry.trim()).filter((entry) => entry.length > 0);
      }
    } catch {
      // fall back to raw string and let validation surface the error.
    }
  }

  const segments = trimmed
    .split("|")
    .map((entry) => entry.trim())
    .filter((entry) => entry.length > 0);

  return segments.length > 0 ? segments : trimmed;
};

const normalizeCandidateValue = (
  field: (typeof LEARNER_RECORD_IMPORT_TEMPLATE_HEADERS)[number],
  value: string,
): unknown => {
  if (field === "evidenceLinks") {
    return parseEvidenceLinksCell(value);
  }

  return value.trim();
};

export const parseLearnerRecordImportFile = (input: {
  fileName: string;
  mimeType: string;
  content: string;
}): ParseLearnerRecordImportFileResult => {
  const rows = parseCsvMatrix(input.content);

  if (rows.length === 0) {
    throw new LearnerRecordImportFileParseError("CSV upload is empty");
  }

  const headerRow = rows[0] ?? [];
  const mappedHeaders = headerRow.map((value) => canonicalFieldForHeader(normalizeHeader(value)));

  if (!mappedHeaders.some((header) => header !== null)) {
    throw new LearnerRecordImportFileParseError(
      "CSV header must include learnerEmail, title, recordType, and issuedAt columns",
    );
  }

  const parsedRows: LearnerRecordImportCandidateRow[] = [];

  for (let rowIndex = 1; rowIndex < rows.length; rowIndex += 1) {
    const row = rows[rowIndex] ?? [];
    const candidate: Record<string, unknown> = {};
    let hasData = false;

    for (let columnIndex = 0; columnIndex < mappedHeaders.length; columnIndex += 1) {
      const header = mappedHeaders[columnIndex];

      if (header === null || header === undefined) {
        continue;
      }

      const rawValue = row[columnIndex] ?? "";

      if (rawValue.trim().length === 0) {
        continue;
      }

      hasData = true;
      candidate[header] = normalizeCandidateValue(header, rawValue);
    }

    if (!hasData) {
      continue;
    }

    parsedRows.push({
      rowNumber: rowIndex,
      candidate,
    });
  }

  if (parsedRows.length === 0) {
    throw new LearnerRecordImportFileParseError("CSV upload does not contain any data rows");
  }

  if (parsedRows.length > MAX_IMPORT_ROWS) {
    throw new LearnerRecordImportFileParseError(
      `CSV upload exceeds the ${String(MAX_IMPORT_ROWS)} row limit`,
    );
  }

  return {
    format: "csv",
    rows: parsedRows,
  };
};

const zodIssueMessages = (
  issues: readonly {
    path: readonly PropertyKey[];
    message: string;
  }[],
): string[] => {
  return issues.map((issue) => {
    const path = issue.path.length > 0 ? issue.path.map(String).join(".") : "row";
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
  const orgUnitBySlug =
    row.orgUnitSlug === undefined
      ? null
      : (orgUnits.find((orgUnit) => orgUnit.slug === row.orgUnitSlug) ?? null);

  if (orgUnitById !== null && orgUnitBySlug !== null && orgUnitById.id !== orgUnitBySlug.id) {
    return {
      orgUnit: null,
      errors: ["orgUnitId and orgUnitSlug refer to different org units"],
      warnings: [],
      usedRowValue: true,
    };
  }

  const orgUnit = orgUnitById ?? orgUnitBySlug;

  if (orgUnit === null && (row.orgUnitId !== undefined || row.orgUnitSlug !== undefined)) {
    warnings.push(
      "Row org-unit reference did not match the current tenant structure. The record will import without explicit org-unit grouping metadata.",
    );
  }

  return {
    orgUnit,
    errors: [],
    warnings,
    usedRowValue: row.orgUnitId !== undefined || row.orgUnitSlug !== undefined,
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
  const templateBySlug =
    row.badgeTemplateSlug === undefined
      ? null
      : (badgeTemplates.find((badgeTemplate) => badgeTemplate.slug === row.badgeTemplateSlug) ??
        null);

  if (templateById !== null && templateBySlug !== null && templateById.id !== templateBySlug.id) {
    return {
      badgeTemplate: null,
      errors: ["badgeTemplateId and badgeTemplateSlug refer to different badge templates"],
      warnings: [],
      usedRowValue: true,
    };
  }

  const badgeTemplate = templateById ?? templateBySlug;

  if (
    badgeTemplate === null &&
    (row.badgeTemplateId !== undefined || row.badgeTemplateSlug !== undefined)
  ) {
    warnings.push(
      "Row badge-template reference did not match the current tenant catalog. The record will import without badge-template grouping metadata.",
    );
  }

  return {
    badgeTemplate,
    errors: [],
    warnings,
    usedRowValue: row.badgeTemplateId !== undefined || row.badgeTemplateSlug !== undefined,
  };
};

const prepareLearnerRecordImportRow = (input: {
  rowNumber: number;
  candidate: Record<string, unknown>;
  defaults: LearnerRecordImportBatchDefaults;
  tenantDisplayName: string;
  orgUnits: readonly TenantOrgUnitRecord[];
  badgeTemplates: readonly BadgeTemplateRecord[];
  fileName: string;
  requestedAt: string;
  requestedByUserId?: string;
  batchId: string;
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

export const prepareLearnerRecordImportBatch = (input: {
  rows: readonly LearnerRecordImportCandidateRow[];
  defaults: LearnerRecordImportBatchDefaults;
  tenantDisplayName: string;
  orgUnits: readonly TenantOrgUnitRecord[];
  badgeTemplates: readonly BadgeTemplateRecord[];
  fileName: string;
  batchId: string;
  requestedAt: string;
  requestedByUserId?: string;
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

export const prepareLearnerRecordImportSubmission = async (
  db: SqlDatabase,
  input: {
    tenantId: string;
    fileName: string;
    mimeType: string;
    content: string;
    defaults: LearnerRecordImportBatchDefaults;
    requestedAt: string;
    requestedByUserId?: string;
    batchId?: string;
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
    fileName: input.fileName,
    mimeType: input.mimeType,
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

export const enqueueLearnerRecordImportBatch = async (
  db: SqlDatabase,
  tenantId: string,
  queuePayloads: readonly LearnerRecordImportQueuePayload[],
): Promise<number> => {
  let queuedRows = 0;

  for (const payload of queuePayloads) {
    await enqueueJobQueueMessage(db, {
      tenantId,
      jobType: "import_learner_record_batch",
      payload,
      idempotencyKey: `learner-record-import:${payload.batchId}:${String(payload.rowNumber)}`,
    });
    queuedRows += 1;
  }

  return queuedRows;
};

const buildImportDetailsJson = (payload: LearnerRecordImportQueuePayload): string | undefined => {
  const details: Record<string, unknown> = {};

  if (payload.row.smartContext.pathwayLabel !== null) {
    details.pathwayHint = payload.row.smartContext.pathwayLabel;
  }

  if (
    payload.row.smartContext.orgUnitId !== null ||
    payload.row.smartContext.badgeTemplateId !== null
  ) {
    details.importContext = {
      ...(payload.row.smartContext.orgUnitId === null
        ? {}
        : { orgUnitId: payload.row.smartContext.orgUnitId }),
      ...(payload.row.smartContext.badgeTemplateId === null
        ? {}
        : { badgeTemplateId: payload.row.smartContext.badgeTemplateId }),
      inferredFrom: payload.row.smartContext.inferredFrom,
    };
  }

  return Object.keys(details).length === 0 ? undefined : JSON.stringify(details);
};

export const applyLearnerRecordImportQueuePayload = async (
  db: SqlDatabase,
  tenantId: string,
  payload: LearnerRecordImportQueuePayload,
): Promise<{
  learnerProfileId: string;
  learnerRecordEntryId: string;
}> => {
  const learnerProfile = await resolveLearnerProfileForIdentity(db, {
    tenantId,
    identityType: "email",
    identityValue: payload.row.learnerEmail,
    ...(payload.row.learnerDisplayName === null
      ? {}
      : { displayName: payload.row.learnerDisplayName }),
  });

  const entry = await createLearnerRecordEntry(db, {
    tenantId,
    learnerProfileId: learnerProfile.id,
    trustLevel: payload.row.effectiveTrustLevel,
    recordType: payload.row.recordType,
    title: payload.row.title,
    ...(payload.row.description === null ? {} : { description: payload.row.description }),
    issuerName: payload.row.effectiveIssuerName,
    ...(payload.requestedByUserId === undefined ? {} : { issuerUserId: payload.requestedByUserId }),
    sourceSystem: "csv_import",
    ...(payload.row.sourceRecordId === null ? {} : { sourceRecordId: payload.row.sourceRecordId }),
    issuedAt: payload.row.issuedAt,
    evidenceLinks: payload.row.evidenceLinks,
    ...(buildImportDetailsJson(payload) === undefined
      ? {}
      : { detailsJson: buildImportDetailsJson(payload) }),
  });

  await createLearnerRecordImportContext(db, {
    tenantId,
    entryId: entry.id,
    ...(payload.row.smartContext.orgUnitId === null
      ? {}
      : { orgUnitId: payload.row.smartContext.orgUnitId }),
    ...(payload.row.smartContext.badgeTemplateId === null
      ? {}
      : { badgeTemplateId: payload.row.smartContext.badgeTemplateId }),
    ...(payload.row.smartContext.pathwayLabel === null
      ? {}
      : { pathwayLabel: payload.row.smartContext.pathwayLabel }),
    inferredFrom: payload.row.smartContext.inferredFrom,
  });

  return {
    learnerProfileId: learnerProfile.id,
    learnerRecordEntryId: entry.id,
  };
};

export const summarizeLearnerRecordImportProgress = (
  messages: readonly ImportLearnerRecordBatchQueueMessageRecord[],
): {
  totals: {
    messages: number;
    batches: number;
    pendingRows: number;
    processingRows: number;
    completedRows: number;
    failedRows: number;
  };
  batches: LearnerRecordImportBatchProgressSummary[];
} => {
  const summaries = new Map<string, LearnerRecordImportBatchProgressSummary>();

  for (const message of messages) {
    const existing = summaries.get(message.batchId);
    const summary = existing ?? {
      batchId: message.batchId,
      fileName: message.fileName,
      format: message.format,
      totalRows: 0,
      pendingRows: 0,
      processingRows: 0,
      completedRows: 0,
      failedRows: 0,
      retryableRows: 0,
      failedRowNumbers: [],
      latestError: null,
      defaultTrustLevel: message.defaultTrustLevel,
      firstQueuedAt: message.createdAt,
      lastUpdatedAt: message.updatedAt,
    };

    summary.totalRows += 1;

    if (message.createdAt < summary.firstQueuedAt) {
      summary.firstQueuedAt = message.createdAt;
    }

    if (message.updatedAt > summary.lastUpdatedAt) {
      summary.lastUpdatedAt = message.updatedAt;
    }

    if (summary.fileName === null && message.fileName !== null) {
      summary.fileName = message.fileName;
    }

    if (summary.format === null && message.format !== null) {
      summary.format = message.format;
    }

    if (summary.defaultTrustLevel === null && message.defaultTrustLevel !== null) {
      summary.defaultTrustLevel = message.defaultTrustLevel;
    }

    if (message.lastError !== null && message.lastError.trim().length > 0) {
      summary.latestError = message.lastError;
    }

    if (message.status === "pending") {
      summary.pendingRows += 1;
    } else if (message.status === "processing") {
      summary.processingRows += 1;
    } else if (message.status === "completed") {
      summary.completedRows += 1;
    } else {
      summary.failedRows += 1;
      summary.retryableRows += 1;

      if (message.rowNumber !== null) {
        summary.failedRowNumbers.push(message.rowNumber);
      }
    }

    if (existing === undefined) {
      summaries.set(message.batchId, summary);
    }
  }

  const batches = Array.from(summaries.values())
    .map((summary) => {
      summary.failedRowNumbers.sort((left, right) => left - right);
      return {
        ...summary,
        failedRowNumbers: summary.failedRowNumbers.slice(0, 50),
      };
    })
    .sort((left, right) => right.lastUpdatedAt.localeCompare(left.lastUpdatedAt));

  return {
    totals: batches.reduce(
      (accumulator, batch) => {
        accumulator.messages += batch.totalRows;
        accumulator.pendingRows += batch.pendingRows;
        accumulator.processingRows += batch.processingRows;
        accumulator.completedRows += batch.completedRows;
        accumulator.failedRows += batch.failedRows;
        return accumulator;
      },
      {
        messages: 0,
        batches: batches.length,
        pendingRows: 0,
        processingRows: 0,
        completedRows: 0,
        failedRows: 0,
      },
    ),
    batches,
  };
};

export const buildLearnerRecordImportTemplateCsv = (): string => {
  const sampleRow = [
    "learner@example.edu",
    "Learner Example",
    "Clinical Placement Seminar",
    "course",
    "2026-03-26T12:00:00.000Z",
    "",
    "Completed with distinction.",
    "",
    "",
    "department-health",
    "",
    "clinical-placement-badge",
    "Clinical readiness",
    "legacy-course-123",
    '["https://credtrail.example.edu/evidence/clinical-placement"]',
  ];

  return `${LEARNER_RECORD_IMPORT_TEMPLATE_HEADERS.join(",")}\n${sampleRow
    .map((value) => `"${value.replaceAll('"', '""')}"`)
    .join(",")}\n`;
};

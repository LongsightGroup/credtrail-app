/** File formats accepted by the learner-record import boundary. */
export type LearnerRecordImportFileFormat = "csv";

/** One non-empty CSV row normalized to learner-import field names. */
export interface LearnerRecordImportCandidateRow {
  readonly rowNumber: number;
  readonly candidate: Record<string, unknown>;
}

/** Parsed rows and detected format for one import upload. */
export interface ParseLearnerRecordImportFileResult {
  readonly format: LearnerRecordImportFileFormat;
  readonly rows: readonly LearnerRecordImportCandidateRow[];
}

class LearnerRecordImportFileParseError extends Error {
  public constructor(message: string) {
    super(message);
    this.name = "LearnerRecordImportFileParseError";
  }
}

const MAX_IMPORT_ROWS = 500;

const LEARNER_RECORD_IMPORT_FIELDS = [
  "learnerEmail",
  "learnerDisplayName",
  "title",
  "recordType",
  "issuedAt",
  "trustLevel",
  "description",
  "issuerName",
  "orgUnitId",
  "orgUnitUrlKey",
  "badgeTemplateId",
  "badgeTemplateUrlKey",
  "pathwayLabel",
  "sourceRecordId",
  "evidenceLinks",
] as const;

type LearnerRecordImportField = (typeof LEARNER_RECORD_IMPORT_FIELDS)[number];

const REQUIRED_LEARNER_RECORD_IMPORT_FIELDS = [
  "learnerEmail",
  "title",
  "recordType",
  "issuedAt",
] as const satisfies readonly LearnerRecordImportField[];

const LEARNER_RECORD_IMPORT_TEMPLATE_HEADERS = [
  "learnerEmail",
  "learnerDisplayName",
  "title",
  "recordType",
  "issuedAt",
  "trustLevel",
  "description",
  "issuerName",
  "orgUnitId",
  "orgUnitUrlKey",
  "badgeTemplateId",
  "badgeTemplateUrlKey",
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

const canonicalFieldForHeader = (header: string): LearnerRecordImportField | null => {
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
    case "orguniturlkey":
      return "orgUnitUrlKey";
    case "badgetemplateid":
    case "templateid":
      return "badgeTemplateId";
    case "badgetemplateurlkey":
      return "badgeTemplateUrlKey";
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
      // Fall back to raw text so row validation can report the invalid value.
    }
  }

  const segments = trimmed
    .split("|")
    .map((entry) => entry.trim())
    .filter((entry) => entry.length > 0);

  return segments.length > 0 ? segments : trimmed;
};

const normalizeCandidateValue = (field: LearnerRecordImportField, value: string): unknown => {
  if (field === "evidenceLinks") {
    return parseEvidenceLinksCell(value);
  }

  return value.trim();
};

/** Parses and normalizes one learner-record CSV upload. */
export const parseLearnerRecordImportFile = (input: {
  readonly content: string;
}): ParseLearnerRecordImportFileResult => {
  const rows = parseCsvMatrix(input.content);

  if (rows.length === 0) {
    throw new LearnerRecordImportFileParseError("CSV upload is empty");
  }

  const headerRow = rows[0] ?? [];
  const mappedHeaders = headerRow.map((value) => canonicalFieldForHeader(normalizeHeader(value)));
  const unsupportedHeaders = headerRow.filter((value, index) => {
    return value.trim().length > 0 && mappedHeaders[index] === null;
  });

  if (unsupportedHeaders.length > 0) {
    throw new LearnerRecordImportFileParseError(
      `CSV header contains unsupported columns: ${unsupportedHeaders.join(", ")}. Download the current template and use its column names.`,
    );
  }

  const missingRequiredHeaders = REQUIRED_LEARNER_RECORD_IMPORT_FIELDS.filter(
    (requiredHeader) => !mappedHeaders.includes(requiredHeader),
  );

  if (missingRequiredHeaders.length > 0) {
    throw new LearnerRecordImportFileParseError(
      `CSV header is missing required columns: ${missingRequiredHeaders.join(", ")}`,
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

/** Builds the current learner-record CSV template. */
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
    "course-123",
    '["https://credtrail.example.edu/evidence/clinical-placement"]',
  ];

  return `${LEARNER_RECORD_IMPORT_TEMPLATE_HEADERS.join(",")}\n${sampleRow
    .map((value) => `"${value.replaceAll('"', '""')}"`)
    .join(",")}\n`;
};

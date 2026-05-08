import { asJsonObject, asNonEmptyString } from "../utils/value-parsers";

export type CredlyExportFileFormat = "csv" | "json";

export interface CredlyExportUploadRow {
  rowNumber: number;
  candidate: Record<string, unknown>;
}

export interface ParseCredlyExportFileResult {
  format: CredlyExportFileFormat;
  rows: CredlyExportUploadRow[];
}

export class CredlyExportFileParseError extends Error {
  public constructor(message: string) {
    super(message);
    this.name = "CredlyExportFileParseError";
  }
}

const MAX_CREDLY_EXPORT_ROWS = 500;

interface CanonicalCredlyRow {
  firstName?: string;
  lastName?: string;
  email?: string;
  issuedAt?: string;
  badgeTemplateId?: string;
  badgeTemplateName?: string;
  badgeTemplateDescription?: string;
  badgeTemplateImageUrl?: string;
  badgeTemplateCriteriaUrl?: string;
  issuerId?: string;
  issuerName?: string;
  issuerUrl?: string;
  assertionId?: string;
  evidenceUrl?: string;
}

const normalizeHeader = (value: string): string => {
  return value
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]/g, "");
};

const canonicalFieldForCsvHeader = (header: string): keyof CanonicalCredlyRow | null => {
  switch (header) {
    case "firstname":
    case "issuedtofirstname":
    case "recipientfirstname":
      return "firstName";
    case "lastname":
    case "issuedtolastname":
    case "recipientlastname":
      return "lastName";
    case "email":
    case "recipientemail":
    case "issuedtoemail":
      return "email";
    case "issuedat":
    case "issueddate":
    case "awardedat":
    case "dateissued":
    case "issuedon":
      return "issuedAt";
    case "badgetemplateid":
    case "templateid":
      return "badgeTemplateId";
    case "badgetemplatename":
    case "badgename":
    case "title":
      return "badgeTemplateName";
    case "badgetemplatedescription":
    case "badgedescription":
      return "badgeTemplateDescription";
    case "badgetemplateimageurl":
    case "badgeimageurl":
    case "imageurl":
      return "badgeTemplateImageUrl";
    case "badgetemplateglobalactivityurl":
    case "globalactivityurl":
    case "badgecriteriaurl":
    case "criteriaurl":
      return "badgeTemplateCriteriaUrl";
    case "issuerid":
    case "organizationid":
      return "issuerId";
    case "issuername":
    case "organizationname":
      return "issuerName";
    case "issuerurl":
    case "organizationurl":
      return "issuerUrl";
    case "id":
    case "assertionid":
    case "credentialid":
    case "issuedbadgeid":
      return "assertionId";
    case "evidence":
    case "evidenceurl":
    case "artifacturl":
      return "evidenceUrl";
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
    throw new CredlyExportFileParseError("Invalid CSV: unclosed quoted value");
  }

  currentRow.push(currentField);

  if (currentRow.some((value) => value.trim().length > 0)) {
    rows.push(currentRow);
  }

  return rows;
};

const getPathValue = (value: unknown, path: readonly string[]): unknown => {
  const rootObject = asJsonObject(value);

  if (rootObject === null) {
    return undefined;
  }

  const joinedPath = path.join(".");

  if (Object.prototype.hasOwnProperty.call(rootObject, joinedPath)) {
    return rootObject[joinedPath];
  }

  let current: unknown = value;

  for (const segment of path) {
    if (Array.isArray(current)) {
      const index = Number.parseInt(segment, 10);

      if (!Number.isFinite(index) || index < 0) {
        return undefined;
      }

      current = current[index];
      continue;
    }

    const objectValue = asJsonObject(current);

    if (objectValue === null) {
      return undefined;
    }

    current = objectValue[segment];
  }

  return current;
};

const pickString = (value: unknown, paths: readonly (readonly string[])[]): string | undefined => {
  for (const path of paths) {
    const candidate = asNonEmptyString(getPathValue(value, path));

    if (candidate !== null) {
      return candidate;
    }
  }

  return undefined;
};

const pickObject = (
  value: unknown,
  paths: readonly (readonly string[])[],
): Record<string, unknown> | undefined => {
  for (const path of paths) {
    const objectCandidate = asJsonObject(getPathValue(value, path));

    if (objectCandidate !== null) {
      return objectCandidate;
    }
  }

  return undefined;
};

const pickIssuerFromEntities = (value: unknown): Record<string, unknown> | undefined => {
  const issuerObject = pickObject(value, [["issuer"]]);

  if (issuerObject === undefined) {
    return undefined;
  }

  const entities = issuerObject.entities;

  if (!Array.isArray(entities) || entities.length === 0) {
    return undefined;
  }

  const firstEntity = asJsonObject(entities[0]);
  return firstEntity ?? undefined;
};

const rowToOb2Candidate = (row: CanonicalCredlyRow, rowNumber: number): Record<string, unknown> => {
  const recipientName = [row.firstName, row.lastName]
    .filter((segment): segment is string => segment !== undefined)
    .join(" ")
    .trim();
  const badgeTemplateName =
    row.badgeTemplateName ?? row.badgeTemplateId ?? `Credly imported badge ${String(rowNumber)}`;
  const issuerReference = row.issuerId ?? row.issuerUrl;
  const issuerObject =
    row.issuerName === undefined && issuerReference === undefined
      ? undefined
      : {
          type: "Issuer",
          ...(issuerReference === undefined ? {} : { id: issuerReference }),
          ...(row.issuerName === undefined ? {} : { name: row.issuerName }),
          ...(row.issuerUrl === undefined ? {} : { url: row.issuerUrl }),
        };
  const badgeClass: Record<string, unknown> = {
    type: "BadgeClass",
    ...(row.badgeTemplateId === undefined ? {} : { id: row.badgeTemplateId }),
    name: badgeTemplateName,
    ...(row.badgeTemplateDescription === undefined
      ? {}
      : { description: row.badgeTemplateDescription }),
    ...(row.badgeTemplateImageUrl === undefined
      ? {}
      : {
          image: {
            id: row.badgeTemplateImageUrl,
            type: "Image",
          },
        }),
    ...(row.badgeTemplateCriteriaUrl === undefined
      ? {}
      : {
          criteria: {
            id: row.badgeTemplateCriteriaUrl,
            type: "Criteria",
          },
        }),
    ...(issuerReference === undefined
      ? issuerObject === undefined
        ? {}
        : { issuer: issuerObject }
      : { issuer: issuerReference }),
  };
  const assertion: Record<string, unknown> = {
    type: "Assertion",
    ...(row.assertionId === undefined ? {} : { id: row.assertionId }),
    recipient: {
      type: "email",
      ...(row.email === undefined ? {} : { identity: row.email }),
      ...(recipientName.length === 0 ? {} : { name: recipientName }),
    },
    badge: row.badgeTemplateId ?? badgeClass,
    ...(row.issuedAt === undefined ? {} : { issuedOn: row.issuedAt }),
    ...(row.evidenceUrl === undefined
      ? {}
      : {
          evidence: [
            {
              id: row.evidenceUrl,
            },
          ],
        }),
  };

  return {
    ob2Assertion: assertion,
    ob2BadgeClass: badgeClass,
    ...(issuerReference === undefined || issuerObject === undefined
      ? {}
      : { ob2Issuer: issuerObject }),
  };
};

const canonicalCredlyRowFromJson = (row: Record<string, unknown>): CanonicalCredlyRow => {
  const badgeTemplate = pickObject(row, [["badge_template"], ["badgeTemplate"], ["badge"]]);
  const issuerEntity = pickIssuerFromEntities(row);
  const canonicalRow: CanonicalCredlyRow = {};
  const firstName = pickString(row, [
    ["issued_to_first_name"],
    ["recipient_first_name"],
    ["first_name"],
  ]);
  const lastName = pickString(row, [
    ["issued_to_last_name"],
    ["recipient_last_name"],
    ["last_name"],
  ]);
  const email = pickString(row, [
    ["issued_to_email"],
    ["recipient_email"],
    ["email"],
    ["recipient", "email"],
  ]);
  const issuedAt = pickString(row, [["issued_at"], ["issued_on"], ["awarded_at"], ["issuedOn"]]);
  const badgeTemplateId =
    (badgeTemplate === undefined ? undefined : asNonEmptyString(badgeTemplate.id)) ??
    pickString(row, [["badge_template_id"], ["badgeTemplateId"]]);
  const badgeTemplateName =
    (badgeTemplate === undefined ? undefined : asNonEmptyString(badgeTemplate.name)) ??
    pickString(row, [["badge_name"], ["badgeTemplateName"]]);
  const badgeTemplateDescription =
    (badgeTemplate === undefined ? undefined : asNonEmptyString(badgeTemplate.description)) ??
    pickString(row, [["badge_description"], ["badgeTemplateDescription"]]);
  const badgeTemplateImageUrl =
    (badgeTemplate === undefined ? undefined : asNonEmptyString(badgeTemplate.image_url)) ??
    pickString(row, [["badge_image_url"], ["badgeTemplateImageUrl"]]);
  const badgeTemplateCriteriaUrl =
    (badgeTemplate === undefined
      ? undefined
      : asNonEmptyString(badgeTemplate.global_activity_url)) ??
    pickString(row, [["badge_criteria_url"], ["badgeTemplateCriteriaUrl"]]);
  const issuerId =
    (issuerEntity === undefined ? undefined : asNonEmptyString(issuerEntity.id)) ??
    pickString(row, [["issuer_id"], ["issuerId"]]);
  const issuerName =
    (issuerEntity === undefined ? undefined : asNonEmptyString(issuerEntity.name)) ??
    pickString(row, [["issuer_name"], ["issuerName"]]);
  const issuerUrl =
    (issuerEntity === undefined ? undefined : asNonEmptyString(issuerEntity.url)) ??
    pickString(row, [["issuer_url"], ["issuerUrl"]]);
  const assertionId = pickString(row, [["id"], ["assertion_id"], ["credential_id"]]);
  const evidenceUrl = pickString(row, [["evidence_url"], ["artifact_url"]]);

  if (firstName !== undefined) {
    canonicalRow.firstName = firstName;
  }

  if (lastName !== undefined) {
    canonicalRow.lastName = lastName;
  }

  if (email !== undefined) {
    canonicalRow.email = email;
  }

  if (issuedAt !== undefined) {
    canonicalRow.issuedAt = issuedAt;
  }

  if (badgeTemplateId !== undefined) {
    canonicalRow.badgeTemplateId = badgeTemplateId;
  }

  if (badgeTemplateName !== undefined) {
    canonicalRow.badgeTemplateName = badgeTemplateName;
  }

  if (badgeTemplateDescription !== undefined) {
    canonicalRow.badgeTemplateDescription = badgeTemplateDescription;
  }

  if (badgeTemplateImageUrl !== undefined) {
    canonicalRow.badgeTemplateImageUrl = badgeTemplateImageUrl;
  }

  if (badgeTemplateCriteriaUrl !== undefined) {
    canonicalRow.badgeTemplateCriteriaUrl = badgeTemplateCriteriaUrl;
  }

  if (issuerId !== undefined) {
    canonicalRow.issuerId = issuerId;
  }

  if (issuerName !== undefined) {
    canonicalRow.issuerName = issuerName;
  }

  if (issuerUrl !== undefined) {
    canonicalRow.issuerUrl = issuerUrl;
  }

  if (assertionId !== undefined) {
    canonicalRow.assertionId = assertionId;
  }

  if (evidenceUrl !== undefined) {
    canonicalRow.evidenceUrl = evidenceUrl;
  }

  return canonicalRow;
};

const parseCsvRows = (input: string): CredlyExportUploadRow[] => {
  const rows = parseCsvMatrix(input);

  if (rows.length === 0) {
    throw new CredlyExportFileParseError("CSV upload is empty");
  }

  const headerRow = rows[0] ?? [];
  const mappedHeaders = headerRow.map((headerCell) => {
    return canonicalFieldForCsvHeader(normalizeHeader(headerCell));
  });
  const hasRecognizedHeader = mappedHeaders.some((header) => header !== null);

  if (!hasRecognizedHeader) {
    throw new CredlyExportFileParseError("CSV header does not contain recognized Credly columns");
  }

  const parsedRows: CredlyExportUploadRow[] = [];

  for (let rowIndex = 1; rowIndex < rows.length; rowIndex += 1) {
    const row = rows[rowIndex] ?? [];
    const canonicalRow: CanonicalCredlyRow = {};
    let hasData = false;

    for (let columnIndex = 0; columnIndex < mappedHeaders.length; columnIndex += 1) {
      const header = mappedHeaders[columnIndex] ?? null;

      if (header === null) {
        continue;
      }

      const cellValue = row[columnIndex] ?? "";

      if (cellValue.trim().length > 0) {
        hasData = true;
        canonicalRow[header] = cellValue.trim();
      }
    }

    if (!hasData) {
      continue;
    }

    parsedRows.push({
      rowNumber: rowIndex,
      candidate: rowToOb2Candidate(canonicalRow, rowIndex),
    });
  }

  return parsedRows;
};

const parseJsonRows = (input: string): CredlyExportUploadRow[] => {
  let parsed: unknown;

  try {
    parsed = JSON.parse(input) as unknown;
  } catch {
    throw new CredlyExportFileParseError("JSON upload is not valid JSON");
  }

  let rowsValue: unknown;

  if (Array.isArray(parsed)) {
    rowsValue = parsed;
  } else {
    const objectValue = asJsonObject(parsed);

    if (objectValue === null) {
      throw new CredlyExportFileParseError("JSON upload must be an array or object");
    }

    rowsValue = objectValue.data ?? objectValue.rows;
  }

  if (!Array.isArray(rowsValue)) {
    throw new CredlyExportFileParseError("JSON upload must include an array in data or rows");
  }

  const rows = rowsValue as unknown[];
  const parsedRows: CredlyExportUploadRow[] = [];

  for (let index = 0; index < rows.length; index += 1) {
    const rowValue = rows[index];
    const rowObject = asJsonObject(rowValue);

    if (rowObject === null) {
      parsedRows.push({
        rowNumber: index + 1,
        candidate: {},
      });
      continue;
    }

    parsedRows.push({
      rowNumber: index + 1,
      candidate: rowToOb2Candidate(canonicalCredlyRowFromJson(rowObject), index + 1),
    });
  }

  return parsedRows;
};

const detectFormat = (input: {
  fileName: string;
  mimeType: string;
  content: string;
}): CredlyExportFileFormat => {
  const fileName = input.fileName.trim().toLowerCase();
  const mimeType = input.mimeType.trim().toLowerCase();

  if (fileName.endsWith(".json") || mimeType.includes("application/json")) {
    return "json";
  }

  if (fileName.endsWith(".csv") || mimeType.includes("text/csv")) {
    return "csv";
  }

  try {
    JSON.parse(input.content);
    return "json";
  } catch {
    return "csv";
  }
};

export const parseCredlyExportFile = (input: {
  fileName: string;
  mimeType: string;
  content: string;
}): ParseCredlyExportFileResult => {
  const format = detectFormat(input);
  const rows = format === "json" ? parseJsonRows(input.content) : parseCsvRows(input.content);

  if (rows.length === 0) {
    throw new CredlyExportFileParseError("Credly export does not contain any data rows");
  }

  if (rows.length > MAX_CREDLY_EXPORT_ROWS) {
    throw new CredlyExportFileParseError(
      `Credly export exceeds max supported rows (${String(MAX_CREDLY_EXPORT_ROWS)})`,
    );
  }

  return {
    format,
    rows,
  };
};

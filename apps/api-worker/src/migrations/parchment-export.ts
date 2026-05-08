import { asJsonObject, asNonEmptyString } from "../utils/value-parsers";

export type ParchmentExportFileFormat = "csv" | "json";

export interface ParchmentExportUploadRow {
  rowNumber: number;
  candidate: Record<string, unknown>;
}

export interface ParseParchmentExportFileResult {
  format: ParchmentExportFileFormat;
  rows: ParchmentExportUploadRow[];
}

export class ParchmentExportFileParseError extends Error {
  public constructor(message: string) {
    super(message);
    this.name = "ParchmentExportFileParseError";
  }
}

const MAX_PARCHMENT_EXPORT_ROWS = 1000;

interface CanonicalParchmentRow {
  recipientIdentity?: string;
  recipientType?: string;
  recipientHashed?: boolean;
  recipientSalt?: string;
  firstName?: string;
  lastName?: string;
  recipientName?: string;
  issuedAt?: string;
  badgeClassId?: string;
  badgeClassName?: string;
  badgeClassDescription?: string;
  badgeClassImageUrl?: string;
  badgeClassCriteriaUrl?: string;
  issuerId?: string;
  issuerName?: string;
  issuerUrl?: string;
  assertionId?: string;
  evidenceUrl?: string;
  evidenceNarrative?: string;
  narrative?: string;
}

type CanonicalParchmentCsvField = Exclude<keyof CanonicalParchmentRow, "recipientHashed">;

const normalizeHeader = (value: string): string => {
  return value
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]/g, "");
};

const canonicalFieldForCsvHeader = (header: string): CanonicalParchmentCsvField | null => {
  switch (header) {
    case "identifier":
    case "recipientemail":
    case "email":
    case "issuedtoemail":
      return "recipientIdentity";
    case "recipienttype":
      return "recipientType";
    case "firstname":
    case "issuedtofirstname":
    case "recipientfirstname":
      return "firstName";
    case "lastname":
    case "issuedtolastname":
    case "recipientlastname":
      return "lastName";
    case "recipientname":
    case "issuedtoname":
    case "name":
      return "recipientName";
    case "issuedat":
    case "issueddate":
    case "issuedon":
    case "awardedat":
    case "issuedate":
      return "issuedAt";
    case "badgeclassid":
    case "badgeid":
    case "badge":
    case "badgetemplateid":
      return "badgeClassId";
    case "badgeclassname":
    case "badgename":
    case "title":
    case "badgetemplatename":
      return "badgeClassName";
    case "badgeclassdescription":
    case "badgedescription":
    case "badgetemplatedescription":
      return "badgeClassDescription";
    case "badgeclassimageurl":
    case "badgeimageurl":
    case "imageurl":
      return "badgeClassImageUrl";
    case "badgeclasscriteriaurl":
    case "badgecriteriaurl":
    case "criteriaurl":
      return "badgeClassCriteriaUrl";
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
    case "evidencenarrative":
    case "artifactnarrative":
    case "artifactdescription":
      return "evidenceNarrative";
    case "narrative":
      return "narrative";
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
    throw new ParchmentExportFileParseError("Invalid CSV: unclosed quoted value");
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
    const candidate = asJsonObject(getPathValue(value, path));

    if (candidate !== null) {
      return candidate;
    }
  }

  return undefined;
};

const pickBoolean = (
  value: unknown,
  paths: readonly (readonly string[])[],
): boolean | undefined => {
  for (const path of paths) {
    const candidate = getPathValue(value, path);

    if (typeof candidate === "boolean") {
      return candidate;
    }

    if (candidate === "true") {
      return true;
    }

    if (candidate === "false") {
      return false;
    }
  }

  return undefined;
};

const extractEvidenceObject = (value: unknown): Record<string, unknown> | undefined => {
  const evidenceValue = getPathValue(value, ["evidence"]);
  const evidenceArray = Array.isArray(evidenceValue) ? (evidenceValue as unknown[]) : null;

  if (evidenceArray !== null) {
    const firstEvidence = evidenceArray[0];
    const evidenceObject = asJsonObject(firstEvidence);

    if (evidenceObject !== null) {
      return evidenceObject;
    }

    const firstEvidenceText = asNonEmptyString(firstEvidence);

    if (firstEvidenceText !== null) {
      return {
        id: firstEvidenceText,
      };
    }
  }

  const directEvidenceObject = asJsonObject(evidenceValue);
  return directEvidenceObject ?? undefined;
};

const rowToOb2Candidate = (
  row: CanonicalParchmentRow,
  rowNumber: number,
): Record<string, unknown> => {
  const recipientName =
    row.recipientName ??
    [row.firstName, row.lastName]
      .filter((segment): segment is string => segment !== undefined)
      .join(" ")
      .trim();
  const badgeClassName =
    row.badgeClassName ?? row.badgeClassId ?? `Parchment imported badge ${String(rowNumber)}`;
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
    ...(row.badgeClassId === undefined ? {} : { id: row.badgeClassId }),
    name: badgeClassName,
    ...(row.badgeClassDescription === undefined ? {} : { description: row.badgeClassDescription }),
    ...(row.badgeClassImageUrl === undefined
      ? {}
      : {
          image: {
            id: row.badgeClassImageUrl,
            type: "Image",
          },
        }),
    ...(row.badgeClassCriteriaUrl === undefined
      ? {}
      : {
          criteria: {
            id: row.badgeClassCriteriaUrl,
            type: "Criteria",
          },
        }),
    ...(issuerReference === undefined
      ? issuerObject === undefined
        ? {}
        : { issuer: issuerObject }
      : { issuer: issuerReference }),
  };
  const evidenceObject =
    row.evidenceUrl === undefined && row.evidenceNarrative === undefined
      ? undefined
      : {
          ...(row.evidenceUrl === undefined ? {} : { id: row.evidenceUrl }),
          ...(row.evidenceNarrative === undefined ? {} : { narrative: row.evidenceNarrative }),
        };
  const assertion: Record<string, unknown> = {
    type: "Assertion",
    ...(row.assertionId === undefined ? {} : { id: row.assertionId }),
    recipient: {
      type: row.recipientType ?? "email",
      ...(row.recipientIdentity === undefined ? {} : { identity: row.recipientIdentity }),
      ...(recipientName.length === 0 ? {} : { name: recipientName }),
      ...(row.recipientHashed === undefined ? {} : { hashed: row.recipientHashed }),
      ...(row.recipientSalt === undefined ? {} : { salt: row.recipientSalt }),
    },
    badge: row.badgeClassId ?? badgeClass,
    ...(row.issuedAt === undefined ? {} : { issuedOn: row.issuedAt }),
    ...(row.narrative === undefined ? {} : { narrative: row.narrative }),
    ...(evidenceObject === undefined ? {} : { evidence: [evidenceObject] }),
  };

  return {
    ob2Assertion: assertion,
    ob2BadgeClass: badgeClass,
    ...(issuerReference === undefined || issuerObject === undefined
      ? {}
      : { ob2Issuer: issuerObject }),
  };
};

const canonicalParchmentRowFromJson = (row: Record<string, unknown>): CanonicalParchmentRow => {
  const badgeClass = pickObject(row, [["badgeclass"], ["badgeClass"], ["badge_class"], ["badge"]]);
  const issuerObject =
    pickObject(row, [["issuer"]]) ??
    (badgeClass === undefined ? undefined : pickObject(badgeClass, [["issuer"]]));
  const evidenceObject = extractEvidenceObject(row);
  const canonicalRow: CanonicalParchmentRow = {};
  const recipientIdentity = pickString(row, [
    ["identifier"],
    ["recipient_email"],
    ["recipientEmail"],
    ["email"],
    ["recipient", "identity"],
  ]);
  const recipientType = pickString(row, [["recipient_type"], ["recipient", "type"]]);
  const recipientHashed = pickBoolean(row, [["recipient_hashed"], ["recipient", "hashed"]]);
  const recipientSalt = pickString(row, [["recipient_salt"], ["recipient", "salt"]]);
  const firstName = pickString(row, [
    ["first_name"],
    ["recipient_first_name"],
    ["issued_to_first_name"],
    ["recipient", "firstName"],
  ]);
  const lastName = pickString(row, [
    ["last_name"],
    ["recipient_last_name"],
    ["issued_to_last_name"],
    ["recipient", "lastName"],
  ]);
  const recipientName = pickString(row, [
    ["recipient_name"],
    ["issued_to_name"],
    ["recipient", "name"],
  ]);
  const issuedAt = pickString(row, [["issued_on"], ["issued_at"], ["awarded_at"], ["issue_date"]]);
  const badgeClassId =
    (badgeClass === undefined ? undefined : asNonEmptyString(badgeClass.id)) ??
    pickString(row, [["badge_class_id"], ["badgeClassId"], ["badge_template_id"]]);
  const badgeClassName =
    (badgeClass === undefined ? undefined : asNonEmptyString(badgeClass.name)) ??
    pickString(row, [["badge_class_name"], ["badgeClassName"], ["badge_name"]]);
  const badgeClassDescription =
    (badgeClass === undefined ? undefined : asNonEmptyString(badgeClass.description)) ??
    pickString(row, [
      ["badge_class_description"],
      ["badgeClassDescription"],
      ["badge_description"],
    ]);
  const badgeClassImageUrl =
    (badgeClass === undefined
      ? undefined
      : pickString(badgeClass, [["image", "id"], ["image_url"], ["image"]])) ??
    pickString(row, [["badge_class_image_url"], ["badgeClassImageUrl"], ["badge_image_url"]]);
  const badgeClassCriteriaUrl =
    (badgeClass === undefined
      ? undefined
      : pickString(badgeClass, [["criteria", "id"], ["criteria_url"], ["criteria"]])) ??
    pickString(row, [
      ["badge_class_criteria_url"],
      ["badgeClassCriteriaUrl"],
      ["badge_criteria_url"],
    ]);
  const issuerId =
    (issuerObject === undefined ? undefined : asNonEmptyString(issuerObject.id)) ??
    pickString(row, [["issuer_id"], ["issuerId"]]);
  const issuerName =
    (issuerObject === undefined ? undefined : asNonEmptyString(issuerObject.name)) ??
    pickString(row, [["issuer_name"], ["issuerName"]]);
  const issuerUrl =
    (issuerObject === undefined ? undefined : asNonEmptyString(issuerObject.url)) ??
    pickString(row, [["issuer_url"], ["issuerUrl"]]);
  const assertionId = pickString(row, [["id"], ["assertion_id"], ["credential_id"]]);
  const evidenceUrl =
    (evidenceObject === undefined
      ? undefined
      : pickString(evidenceObject, [["id"], ["url"], ["artifact_url"]])) ??
    pickString(row, [["evidence_url"], ["artifact_url"]]);
  const evidenceNarrative =
    (evidenceObject === undefined
      ? undefined
      : pickString(evidenceObject, [["narrative"], ["description"]])) ??
    pickString(row, [["evidence_narrative"], ["artifact_narrative"]]);
  const narrative = pickString(row, [["narrative"]]);

  if (recipientIdentity !== undefined) {
    canonicalRow.recipientIdentity = recipientIdentity;
  }

  if (recipientType !== undefined) {
    canonicalRow.recipientType = recipientType;
  }

  if (recipientHashed !== undefined) {
    canonicalRow.recipientHashed = recipientHashed;
  }

  if (recipientSalt !== undefined) {
    canonicalRow.recipientSalt = recipientSalt;
  }

  if (firstName !== undefined) {
    canonicalRow.firstName = firstName;
  }

  if (lastName !== undefined) {
    canonicalRow.lastName = lastName;
  }

  if (recipientName !== undefined) {
    canonicalRow.recipientName = recipientName;
  }

  if (issuedAt !== undefined) {
    canonicalRow.issuedAt = issuedAt;
  }

  if (badgeClassId !== undefined) {
    canonicalRow.badgeClassId = badgeClassId;
  }

  if (badgeClassName !== undefined) {
    canonicalRow.badgeClassName = badgeClassName;
  }

  if (badgeClassDescription !== undefined) {
    canonicalRow.badgeClassDescription = badgeClassDescription;
  }

  if (badgeClassImageUrl !== undefined) {
    canonicalRow.badgeClassImageUrl = badgeClassImageUrl;
  }

  if (badgeClassCriteriaUrl !== undefined) {
    canonicalRow.badgeClassCriteriaUrl = badgeClassCriteriaUrl;
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

  if (evidenceNarrative !== undefined) {
    canonicalRow.evidenceNarrative = evidenceNarrative;
  }

  if (narrative !== undefined) {
    canonicalRow.narrative = narrative;
  }

  return canonicalRow;
};

const parseCsvRows = (input: string): ParchmentExportUploadRow[] => {
  const rows = parseCsvMatrix(input);

  if (rows.length === 0) {
    throw new ParchmentExportFileParseError("CSV upload is empty");
  }

  const headerRow = rows[0] ?? [];
  const mappedHeaders = headerRow.map((headerCell) => {
    return canonicalFieldForCsvHeader(normalizeHeader(headerCell));
  });
  const hasRecognizedHeader = mappedHeaders.some((header) => header !== null);

  if (!hasRecognizedHeader) {
    throw new ParchmentExportFileParseError(
      "CSV header does not contain recognized Parchment/Canvas Credentials columns",
    );
  }

  const parsedRows: ParchmentExportUploadRow[] = [];

  for (let rowIndex = 1; rowIndex < rows.length; rowIndex += 1) {
    const row = rows[rowIndex] ?? [];
    const canonicalRow: CanonicalParchmentRow = {};
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

const flattenJsonRows = (parsed: unknown): unknown[] => {
  if (Array.isArray(parsed)) {
    return parsed;
  }

  const objectValue = asJsonObject(parsed);

  if (objectValue === null) {
    throw new ParchmentExportFileParseError("JSON upload must be an array or object");
  }

  const listCandidates = [
    objectValue.data,
    objectValue.rows,
    objectValue.result,
    objectValue.assertions,
  ];

  for (const candidate of listCandidates) {
    if (Array.isArray(candidate)) {
      return candidate;
    }
  }

  const badgeClassesValue = objectValue.badge_classes ?? objectValue.badgeClasses;

  if (Array.isArray(badgeClassesValue)) {
    const flattenedRows: Record<string, unknown>[] = [];
    const topLevelIssuer = asJsonObject(objectValue.issuer);

    for (const badgeClassValue of badgeClassesValue) {
      const badgeClass = asJsonObject(badgeClassValue);

      if (badgeClass === null) {
        continue;
      }

      const assertionsValue = badgeClass.assertions;

      if (!Array.isArray(assertionsValue)) {
        continue;
      }

      for (const assertionValue of assertionsValue) {
        const assertion = asJsonObject(assertionValue);

        if (assertion === null) {
          continue;
        }

        flattenedRows.push({
          ...assertion,
          ...(assertion.badgeclass === undefined && assertion.badgeClass === undefined
            ? { badgeclass: badgeClass }
            : {}),
          ...(assertion.issuer === undefined && topLevelIssuer !== null
            ? { issuer: topLevelIssuer }
            : {}),
        });
      }
    }

    if (flattenedRows.length > 0) {
      return flattenedRows;
    }
  }

  throw new ParchmentExportFileParseError(
    "JSON upload must include rows in an array, data, rows, result, assertions, or badge_classes assertions",
  );
};

const parseJsonRows = (input: string): ParchmentExportUploadRow[] => {
  let parsed: unknown;

  try {
    parsed = JSON.parse(input) as unknown;
  } catch {
    throw new ParchmentExportFileParseError("JSON upload is not valid JSON");
  }

  const rows = flattenJsonRows(parsed);
  const parsedRows: ParchmentExportUploadRow[] = [];

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
      candidate: rowToOb2Candidate(canonicalParchmentRowFromJson(rowObject), index + 1),
    });
  }

  return parsedRows;
};

const detectFormat = (input: {
  fileName: string;
  mimeType: string;
  content: string;
}): ParchmentExportFileFormat => {
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

export const parseParchmentExportFile = (input: {
  fileName: string;
  mimeType: string;
  content: string;
}): ParseParchmentExportFileResult => {
  const format = detectFormat(input);
  const rows = format === "json" ? parseJsonRows(input.content) : parseCsvRows(input.content);

  if (rows.length === 0) {
    throw new ParchmentExportFileParseError("Parchment export does not contain any data rows");
  }

  if (rows.length > MAX_PARCHMENT_EXPORT_ROWS) {
    throw new ParchmentExportFileParseError(
      `Parchment export exceeds max supported rows (${String(MAX_PARCHMENT_EXPORT_ROWS)})`,
    );
  }

  return {
    format,
    rows,
  };
};

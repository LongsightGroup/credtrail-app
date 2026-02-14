import type { JsonObject } from '@credtrail/core-domain';
import { asJsonObject, asNonEmptyString } from '../utils/value-parsers';

export type MigrationBatchFileFormat = 'csv' | 'json';

export interface MigrationBatchUploadRow {
  rowNumber: number;
  candidate: Record<string, unknown>;
}

export interface ParseMigrationBatchUploadFileResult {
  format: MigrationBatchFileFormat;
  rows: MigrationBatchUploadRow[];
}

export class MigrationBatchFileParseError extends Error {
  public constructor(message: string) {
    super(message);
    this.name = 'MigrationBatchFileParseError';
  }
}

const MAX_BATCH_ROWS = 500;

const normalizeHeader = (value: string): string => {
  return value.trim().toLowerCase().replace(/[^a-z0-9]/g, '');
};

const canonicalFieldForHeader = (header: string): string | null => {
  switch (header) {
    case 'ob2assertion':
    case 'assertion':
      return 'ob2Assertion';
    case 'ob2badgeclass':
    case 'badgeclass':
    case 'badge':
      return 'ob2BadgeClass';
    case 'ob2issuer':
    case 'issuer':
      return 'ob2Issuer';
    case 'bakedbadgeimage':
    case 'bakedbadge':
    case 'baked':
      return 'bakedBadgeImage';
    default:
      return null;
  }
};

const parseJsonCellValue = (value: string): JsonObject | string => {
  const trimmed = value.trim();

  if (trimmed.length === 0) {
    return '';
  }

  try {
    const parsed = JSON.parse(trimmed) as unknown;
    const jsonObject = asJsonObject(parsed);

    if (jsonObject !== null) {
      return jsonObject;
    }
  } catch {
    // keep as raw string to let request-level validation surface field errors.
  }

  return trimmed;
};

const normalizeRowCandidate = (rawRow: Record<string, unknown>): Record<string, unknown> => {
  const candidate: Record<string, unknown> = {};

  for (const [rawKey, rawValue] of Object.entries(rawRow)) {
    const canonicalField = canonicalFieldForHeader(normalizeHeader(rawKey));

    if (canonicalField === null) {
      continue;
    }

    if (rawValue === null || rawValue === undefined) {
      continue;
    }

    const textValue = asNonEmptyString(rawValue);

    if (textValue === null) {
      if (canonicalField !== 'bakedBadgeImage') {
        const jsonValue = asJsonObject(rawValue);

        if (jsonValue !== null) {
          candidate[canonicalField] = jsonValue;
        }
      }

      continue;
    }

    if (canonicalField === 'bakedBadgeImage') {
      candidate[canonicalField] = textValue;
      continue;
    }

    candidate[canonicalField] = parseJsonCellValue(textValue);
  }

  return candidate;
};

const detectFormat = (input: {
  fileName: string;
  mimeType: string;
  content: string;
}): MigrationBatchFileFormat => {
  const fileName = input.fileName.trim().toLowerCase();
  const mimeType = input.mimeType.trim().toLowerCase();

  if (fileName.endsWith('.json') || mimeType.includes('application/json')) {
    return 'json';
  }

  if (fileName.endsWith('.csv') || mimeType.includes('text/csv')) {
    return 'csv';
  }

  try {
    JSON.parse(input.content);
    return 'json';
  } catch {
    return 'csv';
  }
};

const parseCsvMatrix = (input: string): string[][] => {
  const rows: string[][] = [];
  let currentRow: string[] = [];
  let currentField = '';
  let insideQuotes = false;

  for (let index = 0; index < input.length; index += 1) {
    const character = input[index] ?? '';

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

    if (character === ',') {
      currentRow.push(currentField);
      currentField = '';
      continue;
    }

    if (character === '\n') {
      currentRow.push(currentField);
      rows.push(currentRow);
      currentRow = [];
      currentField = '';
      continue;
    }

    if (character === '\r') {
      continue;
    }

    currentField += character;
  }

  if (insideQuotes) {
    throw new MigrationBatchFileParseError('Invalid CSV: unclosed quoted value');
  }

  currentRow.push(currentField);

  const hasAnyValue = currentRow.some((value) => {
    return value.trim().length > 0;
  });

  if (hasAnyValue) {
    rows.push(currentRow);
  }

  return rows;
};

const parseCsvRows = (input: string): MigrationBatchUploadRow[] => {
  const rows = parseCsvMatrix(input);

  if (rows.length === 0) {
    throw new MigrationBatchFileParseError('CSV upload is empty');
  }

  const headerRow = rows[0] ?? [];
  const mappedHeaders = headerRow.map((headerCell) => {
    return canonicalFieldForHeader(normalizeHeader(headerCell));
  });
  const hasRecognizedHeader = mappedHeaders.some((header) => header !== null);

  if (!hasRecognizedHeader) {
    throw new MigrationBatchFileParseError(
      'CSV header must include at least one supported column: ob2Assertion, ob2BadgeClass, ob2Issuer, bakedBadgeImage',
    );
  }

  const parsedRows: MigrationBatchUploadRow[] = [];

  for (let rowIndex = 1; rowIndex < rows.length; rowIndex += 1) {
    const row = rows[rowIndex] ?? [];
    const rawRow: Record<string, unknown> = {};
    let hasData = false;

    for (let columnIndex = 0; columnIndex < mappedHeaders.length; columnIndex += 1) {
      const header = mappedHeaders[columnIndex] ?? null;

      if (header === null) {
        continue;
      }

      const cellValue = row[columnIndex] ?? '';

      if (cellValue.trim().length > 0) {
        hasData = true;
      }

      rawRow[header] = cellValue;
    }

    if (!hasData) {
      continue;
    }

    parsedRows.push({
      rowNumber: rowIndex,
      candidate: normalizeRowCandidate(rawRow),
    });
  }

  return parsedRows;
};

const parseJsonRows = (input: string): MigrationBatchUploadRow[] => {
  let parsed: unknown;

  try {
    parsed = JSON.parse(input) as unknown;
  } catch {
    throw new MigrationBatchFileParseError('JSON upload is not valid JSON');
  }

  let rowsValue: unknown;

  if (Array.isArray(parsed)) {
    rowsValue = parsed;
  } else {
    const objectValue = asJsonObject(parsed);

    if (objectValue === null) {
      throw new MigrationBatchFileParseError('JSON upload must be an array of row objects');
    }

    rowsValue = objectValue.rows;
  }

  if (!Array.isArray(rowsValue)) {
    throw new MigrationBatchFileParseError('JSON upload must provide rows as an array');
  }

  const rows = rowsValue as unknown[];
  const parsedRows: MigrationBatchUploadRow[] = [];

  for (let index = 0; index < rows.length; index += 1) {
    const rowValue = rows[index];

    if (rowValue === null || rowValue === undefined) {
      continue;
    }

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
      candidate: normalizeRowCandidate(rowObject),
    });
  }

  return parsedRows;
};

export const parseMigrationBatchUploadFile = (input: {
  fileName: string;
  mimeType: string;
  content: string;
}): ParseMigrationBatchUploadFileResult => {
  const format = detectFormat(input);
  const rows = format === 'json' ? parseJsonRows(input.content) : parseCsvRows(input.content);

  if (rows.length === 0) {
    throw new MigrationBatchFileParseError('Batch upload does not contain any data rows');
  }

  if (rows.length > MAX_BATCH_ROWS) {
    throw new MigrationBatchFileParseError(
      `Batch upload exceeds max supported rows (${String(MAX_BATCH_ROWS)})`,
    );
  }

  return {
    format,
    rows,
  };
};

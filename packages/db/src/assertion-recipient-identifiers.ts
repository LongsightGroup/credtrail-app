import type {
  RecipientIdentifierInput,
  RecipientIdentifierRecord,
  RecipientIdentifierType,
} from "./learner-profiles";
import type { SqlDatabase, SqlQueryResult } from "./tenant-scope";
import { normalizeEmail } from "./users";

interface RecipientIdentifierRow {
  assertionId: string;
  identifierType: RecipientIdentifierType;
  identifierValue: string;
  createdAt: string;
}

const mapRecipientIdentifierRow = (row: RecipientIdentifierRow): RecipientIdentifierRecord => {
  return {
    assertionId: row.assertionId,
    identifierType: row.identifierType,
    identifierValue: row.identifierValue,
    createdAt: row.createdAt,
  };
};

const normalizeRecipientIdentifierValue = (
  identifierType: RecipientIdentifierType,
  identifierValue: string,
): string => {
  const trimmedValue = identifierValue.trim();

  if (identifierType === "emailAddress") {
    return normalizeEmail(trimmedValue);
  }

  return trimmedValue;
};

export const uniqueRecipientIdentifiers = (
  input: readonly RecipientIdentifierInput[],
): RecipientIdentifierInput[] => {
  const seen = new Set<string>();
  const unique: RecipientIdentifierInput[] = [];

  for (const entry of input) {
    const normalizedValue = normalizeRecipientIdentifierValue(
      entry.identifierType,
      entry.identifierValue,
    );

    if (normalizedValue.length === 0) {
      continue;
    }

    const dedupeKey = `${entry.identifierType}::${normalizedValue}`;

    if (seen.has(dedupeKey)) {
      continue;
    }

    seen.add(dedupeKey);
    unique.push({
      identifierType: entry.identifierType,
      identifierValue: normalizedValue,
    });
  }

  return unique;
};

export const insertAssertionRecipientIdentifiers = async (
  db: SqlDatabase,
  assertionId: string,
  recipientIdentifiers: readonly RecipientIdentifierInput[],
): Promise<void> => {
  if (recipientIdentifiers.length === 0) {
    return;
  }

  const insertStatement = async (): Promise<void> => {
    for (const entry of recipientIdentifiers) {
      await db
        .prepare(
          `
          INSERT INTO recipient_identifiers (
            assertion_id,
            identifier_type,
            identifier_value,
            created_at
          )
          VALUES (?, ?, ?, ?)
          ON CONFLICT DO NOTHING
        `,
        )
        .bind(assertionId, entry.identifierType, entry.identifierValue, new Date().toISOString())
        .run();
    }
  };

  await insertStatement();
};

export const listRecipientIdentifiersForAssertion = async (
  db: SqlDatabase,
  assertionId: string,
): Promise<RecipientIdentifierRecord[]> => {
  const listStatement = (): Promise<SqlQueryResult<RecipientIdentifierRow>> =>
    db
      .prepare(
        `
        SELECT
          assertion_id AS assertionId,
          identifier_type AS identifierType,
          identifier_value AS identifierValue,
          created_at AS createdAt
        FROM recipient_identifiers
        WHERE assertion_id = ?
        ORDER BY created_at ASC
      `,
      )
      .bind(assertionId)
      .all<RecipientIdentifierRow>();

  const result = await listStatement();

  return result.results.map((row) => mapRecipientIdentifierRow(row));
};

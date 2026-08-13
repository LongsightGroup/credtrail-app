import { normalizeEmail } from "./users";
import { assertionRecordSelectSql } from "./assertion-achievement-snapshot-sql.js";
import type { SqlDatabase } from "./tenant-scope";
import type {
  AssertionRecord,
  ListAssertionsByBadgeTemplatesAndRecipientEmailsInput,
  ListAssertionsByIdempotencyKeysInput,
} from "./assertion-types.js";
import { chunkValues, mapAssertionRow, uniqueNonEmptyStrings } from "./assertion-internal.js";
import type { AssertionRow } from "./assertion-internal.js";

export const findAssertionById = async (
  db: SqlDatabase,
  tenantId: string,
  assertionId: string,
): Promise<AssertionRecord | null> => {
  const row = await db
    .prepare(
      `
      SELECT
        ${assertionRecordSelectSql}
      FROM assertions
      WHERE assertions.tenant_id = ?
        AND assertions.id = ?
      LIMIT 1
    `,
    )
    .bind(tenantId, assertionId)
    .first<AssertionRow>();

  if (row === null) {
    return null;
  }

  return mapAssertionRow(row);
};

export const findAssertionByIdempotencyKey = async (
  db: SqlDatabase,
  tenantId: string,
  idempotencyKey: string,
): Promise<AssertionRecord | null> => {
  const row = await db
    .prepare(
      `
      SELECT
        ${assertionRecordSelectSql}
      FROM assertions
      WHERE assertions.tenant_id = ?
        AND assertions.idempotency_key = ?
      LIMIT 1
    `,
    )
    .bind(tenantId, idempotencyKey)
    .first<AssertionRow>();

  if (row === null) {
    return null;
  }

  return mapAssertionRow(row);
};

export const listAssertionsByIdempotencyKeys = async (
  db: SqlDatabase,
  input: ListAssertionsByIdempotencyKeysInput,
): Promise<AssertionRecord[]> => {
  const idempotencyKeys = uniqueNonEmptyStrings(input.idempotencyKeys);

  if (idempotencyKeys.length === 0) {
    return [];
  }

  const assertions: AssertionRecord[] = [];

  for (const keyChunk of chunkValues(idempotencyKeys, 400)) {
    const keyPlaceholders = keyChunk.map(() => "?").join(", ");
    const result = await db
      .prepare(
        `
        SELECT
          ${assertionRecordSelectSql}
        FROM assertions
        WHERE assertions.tenant_id = ?
          AND assertions.idempotency_key IN (${keyPlaceholders})
      `,
      )
      .bind(input.tenantId, ...keyChunk)
      .all<AssertionRow>();

    assertions.push(...result.results.map((row) => mapAssertionRow(row)));
  }

  return assertions;
};

export const listAssertionsByBadgeTemplatesAndRecipientEmails = async (
  db: SqlDatabase,
  input: ListAssertionsByBadgeTemplatesAndRecipientEmailsInput,
): Promise<AssertionRecord[]> => {
  const badgeTemplateIds = uniqueNonEmptyStrings(input.badgeTemplateIds);
  const recipientEmails = Array.from(
    new Set(uniqueNonEmptyStrings(input.recipientEmails).map((email) => normalizeEmail(email))),
  );

  if (badgeTemplateIds.length === 0 || recipientEmails.length === 0) {
    return [];
  }

  const assertions: AssertionRecord[] = [];

  for (const badgeTemplateIdChunk of chunkValues(badgeTemplateIds, 100)) {
    for (const recipientEmailChunk of chunkValues(recipientEmails, 100)) {
      const badgeTemplateIdPlaceholders = badgeTemplateIdChunk.map(() => "?").join(", ");
      const recipientEmailPlaceholders = recipientEmailChunk.map(() => "?").join(", ");
      const result = await db
        .prepare(
          `
          SELECT
            ${assertionRecordSelectSql}
          FROM assertions
          WHERE assertions.tenant_id = ?
            AND assertions.badge_template_id IN (${badgeTemplateIdPlaceholders})
            AND assertions.recipient_identity_type = 'email'
            AND LOWER(assertions.recipient_identity) IN (${recipientEmailPlaceholders})
          ORDER BY assertions.issued_at DESC, assertions.id DESC
        `,
        )
        .bind(input.tenantId, ...badgeTemplateIdChunk, ...recipientEmailChunk)
        .all<AssertionRow>();

      assertions.push(...result.results.map((row) => mapAssertionRow(row)));
    }
  }

  return assertions;
};

export const findAssertionByPublicId = async (
  db: SqlDatabase,
  publicId: string,
): Promise<AssertionRecord | null> => {
  const row = await db
    .prepare(
      `
      SELECT
        ${assertionRecordSelectSql}
      FROM assertions
      WHERE assertions.public_id = ?
      LIMIT 1
    `,
    )
    .bind(publicId)
    .first<AssertionRow>();

  if (row === null) {
    return null;
  }

  return mapAssertionRow(row);
};

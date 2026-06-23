import { normalizeEmail } from "./users";
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
        id,
        tenant_id AS tenantId,
        public_id AS publicId,
        learner_profile_id AS learnerProfileId,
        badge_template_id AS badgeTemplateId,
        recipient_identity AS recipientIdentity,
        recipient_identity_type AS recipientIdentityType,
        vc_r2_key AS vcR2Key,
        status_list_index AS statusListIndex,
        idempotency_key AS idempotencyKey,
        issued_at AS issuedAt,
        issued_by_user_id AS issuedByUserId,
        revoked_at AS revokedAt,
        created_at AS createdAt,
        updated_at AS updatedAt
      FROM assertions
      WHERE tenant_id = ?
        AND id = ?
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
        id,
        tenant_id AS tenantId,
        public_id AS publicId,
        learner_profile_id AS learnerProfileId,
        badge_template_id AS badgeTemplateId,
        recipient_identity AS recipientIdentity,
        recipient_identity_type AS recipientIdentityType,
        vc_r2_key AS vcR2Key,
        status_list_index AS statusListIndex,
        idempotency_key AS idempotencyKey,
        issued_at AS issuedAt,
        issued_by_user_id AS issuedByUserId,
        revoked_at AS revokedAt,
        created_at AS createdAt,
        updated_at AS updatedAt
      FROM assertions
      WHERE tenant_id = ?
        AND idempotency_key = ?
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
          id,
          tenant_id AS tenantId,
          public_id AS publicId,
          learner_profile_id AS learnerProfileId,
          badge_template_id AS badgeTemplateId,
          recipient_identity AS recipientIdentity,
          recipient_identity_type AS recipientIdentityType,
          vc_r2_key AS vcR2Key,
          status_list_index AS statusListIndex,
          idempotency_key AS idempotencyKey,
          issued_at AS issuedAt,
          issued_by_user_id AS issuedByUserId,
          revoked_at AS revokedAt,
          created_at AS createdAt,
          updated_at AS updatedAt
        FROM assertions
        WHERE tenant_id = ?
          AND idempotency_key IN (${keyPlaceholders})
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
            id,
            tenant_id AS tenantId,
            public_id AS publicId,
            learner_profile_id AS learnerProfileId,
            badge_template_id AS badgeTemplateId,
            recipient_identity AS recipientIdentity,
            recipient_identity_type AS recipientIdentityType,
            vc_r2_key AS vcR2Key,
            status_list_index AS statusListIndex,
            idempotency_key AS idempotencyKey,
            issued_at AS issuedAt,
            issued_by_user_id AS issuedByUserId,
            revoked_at AS revokedAt,
            created_at AS createdAt,
            updated_at AS updatedAt
          FROM assertions
          WHERE tenant_id = ?
            AND badge_template_id IN (${badgeTemplateIdPlaceholders})
            AND recipient_identity_type = 'email'
            AND LOWER(recipient_identity) IN (${recipientEmailPlaceholders})
          ORDER BY issued_at DESC, id DESC
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
        id,
        tenant_id AS tenantId,
        public_id AS publicId,
        learner_profile_id AS learnerProfileId,
        badge_template_id AS badgeTemplateId,
        recipient_identity AS recipientIdentity,
        recipient_identity_type AS recipientIdentityType,
        vc_r2_key AS vcR2Key,
        status_list_index AS statusListIndex,
        idempotency_key AS idempotencyKey,
        issued_at AS issuedAt,
        issued_by_user_id AS issuedByUserId,
        revoked_at AS revokedAt,
        created_at AS createdAt,
        updated_at AS updatedAt
      FROM assertions
      WHERE public_id = ?
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

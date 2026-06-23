import type { SqlDatabase } from "./tenant-scope";
import type {
  ListPublicBadgeWallEntriesInput,
  PublicBadgeWallEntryRecord,
} from "./assertion-types.js";
import { mapPublicBadgeWallEntryRow } from "./assertion-internal.js";
import type { PublicBadgeWallEntryRow } from "./assertion-internal.js";

export const listPublicBadgeWallEntries = async (
  db: SqlDatabase,
  input: ListPublicBadgeWallEntriesInput,
): Promise<PublicBadgeWallEntryRecord[]> => {
  const queryLimit = Math.max(1, Math.min(input.limit ?? 300, 1000));
  const result =
    input.badgeTemplateId === undefined
      ? await db
          .prepare(
            `
            SELECT
              assertions.id AS assertionId,
              assertions.public_id AS assertionPublicId,
              assertions.tenant_id AS tenantId,
              assertions.badge_template_id AS badgeTemplateId,
              badge_templates.title AS badgeTitle,
              badge_templates.description AS badgeDescription,
              badge_templates.image_uri AS badgeImageUri,
              assertions.recipient_identity AS recipientIdentity,
              assertions.recipient_identity_type AS recipientIdentityType,
              assertions.issued_at AS issuedAt,
              assertions.revoked_at AS revokedAt
            FROM assertions
            INNER JOIN badge_templates
              ON badge_templates.tenant_id = assertions.tenant_id
              AND badge_templates.id = assertions.badge_template_id
            WHERE assertions.tenant_id = ?
              AND assertions.public_id IS NOT NULL
            ORDER BY assertions.issued_at DESC
            LIMIT ?
          `,
          )
          .bind(input.tenantId, queryLimit)
          .all<PublicBadgeWallEntryRow>()
      : await db
          .prepare(
            `
            SELECT
              assertions.id AS assertionId,
              assertions.public_id AS assertionPublicId,
              assertions.tenant_id AS tenantId,
              assertions.badge_template_id AS badgeTemplateId,
              badge_templates.title AS badgeTitle,
              badge_templates.description AS badgeDescription,
              badge_templates.image_uri AS badgeImageUri,
              assertions.recipient_identity AS recipientIdentity,
              assertions.recipient_identity_type AS recipientIdentityType,
              assertions.issued_at AS issuedAt,
              assertions.revoked_at AS revokedAt
            FROM assertions
            INNER JOIN badge_templates
              ON badge_templates.tenant_id = assertions.tenant_id
              AND badge_templates.id = assertions.badge_template_id
            WHERE assertions.tenant_id = ?
              AND assertions.badge_template_id = ?
              AND assertions.public_id IS NOT NULL
            ORDER BY assertions.issued_at DESC
            LIMIT ?
          `,
          )
          .bind(input.tenantId, input.badgeTemplateId, queryLimit)
          .all<PublicBadgeWallEntryRow>();

  return result.results.map((row) => mapPublicBadgeWallEntryRow(row));
};

import { findBadgeTemplateById, type BadgeTemplateRecord } from "./badge-templates.js";
import { createBadgeTemplateOwnershipEvent } from "./badge-template-ownership-event-writes.js";
import { createPrefixedId } from "./shared-helpers.js";
import { ensureInstitutionOrgUnitForTenant } from "./tenant-org-units.js";
import { runSqlTransaction, type SqlDatabase } from "./tenant-scope.js";

export interface UpsertBadgeTemplateBySlugInput {
  tenantId: string;
  slug: string;
  title: string;
  description?: string | undefined;
  criteriaUri?: string | undefined;
  createdByUserId?: string | undefined;
}

export interface UpsertBadgeTemplateBySlugResult {
  status: "created" | "updated" | "unchanged";
  template: BadgeTemplateRecord;
}

/** Creates or updates an active template by its tenant-scoped slug under one transaction. */
export const upsertBadgeTemplateBySlug = async (
  db: SqlDatabase,
  input: UpsertBadgeTemplateBySlugInput,
): Promise<UpsertBadgeTemplateBySlugResult> => {
  return runSqlTransaction(db, async (transaction) => {
    const nowIso = new Date().toISOString();
    const id = createPrefixedId("bt");
    const ownerOrgUnitId = await ensureInstitutionOrgUnitForTenant(transaction, input.tenantId);
    const governanceMetadataJson = '{"stability":"institution_registry"}';
    const inserted = await transaction
      .prepare(
        `
        INSERT INTO badge_templates (
          id,
          tenant_id,
          slug,
          title,
          description,
          criteria_uri,
          image_uri,
          trusted_credential_metadata_json,
          created_by_user_id,
          owner_org_unit_id,
          governance_metadata_json,
          is_archived,
          created_at,
          updated_at
        )
        VALUES (?, ?, ?, ?, ?, ?, NULL, NULL, ?, ?, ?, 0, ?, ?)
        ON CONFLICT (tenant_id, slug) DO NOTHING
      `,
      )
      .bind(
        id,
        input.tenantId,
        input.slug,
        input.title,
        input.description ?? null,
        input.criteriaUri ?? null,
        input.createdByUserId ?? null,
        ownerOrgUnitId,
        governanceMetadataJson,
        nowIso,
        nowIso,
      )
      .run();

    if ((inserted.meta.rowsWritten ?? 0) > 0) {
      const template = await findBadgeTemplateById(transaction, input.tenantId, id);

      if (template === null) {
        throw new Error(`Unable to load created badge template "${id}"`);
      }

      await createBadgeTemplateOwnershipEvent(transaction, {
        tenantId: input.tenantId,
        badgeTemplateId: template.id,
        fromOrgUnitId: null,
        toOrgUnitId: template.ownerOrgUnitId,
        reasonCode: "initial_assignment",
        reason: "Badge template ownership assigned at creation",
        governanceMetadataJson: template.governanceMetadataJson,
        transferredByUserId: template.createdByUserId,
        transferredAt: template.createdAt,
      });

      return { status: "created", template };
    }

    const existing = await transaction
      .prepare(
        `
        SELECT id
        FROM badge_templates
        WHERE tenant_id = ?
          AND slug = ?
        LIMIT 1
        FOR UPDATE
      `,
      )
      .bind(input.tenantId, input.slug)
      .first<{ id: string }>();

    if (existing === null) {
      throw new Error(`Unable to load badge template with slug "${input.slug}"`);
    }

    const template = await findBadgeTemplateById(transaction, input.tenantId, existing.id);

    if (template === null) {
      throw new Error(`Unable to load badge template "${existing.id}"`);
    }

    if (template.isArchived) {
      throw new Error(`Badge template with slug "${input.slug}" is archived`);
    }

    if (
      template.title === input.title &&
      template.description === (input.description ?? null) &&
      template.criteriaUri === (input.criteriaUri ?? null)
    ) {
      return { status: "unchanged", template };
    }

    await transaction
      .prepare(
        `
        UPDATE badge_templates
        SET title = ?,
            description = ?,
            criteria_uri = ?,
            updated_at = ?
        WHERE tenant_id = ?
          AND id = ?
      `,
      )
      .bind(
        input.title,
        input.description ?? null,
        input.criteriaUri ?? null,
        nowIso,
        input.tenantId,
        template.id,
      )
      .run();

    const updated = await findBadgeTemplateById(transaction, input.tenantId, template.id);

    if (updated === null) {
      throw new Error(`Unable to load updated badge template "${template.id}"`);
    }

    return { status: "updated", template: updated };
  });
};

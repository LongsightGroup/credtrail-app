import type {
  BadgeTemplateOwnershipEventRecord,
  BadgeTemplateOwnershipReasonCode,
} from "./badge-templates.js";
import { createPrefixedId } from "./shared-helpers.js";
import type { SqlDatabase } from "./tenant-scope.js";

interface CreateBadgeTemplateOwnershipEventInput {
  tenantId: string;
  badgeTemplateId: string;
  fromOrgUnitId: string | null;
  toOrgUnitId: string;
  reasonCode: BadgeTemplateOwnershipReasonCode;
  reason: string | null;
  governanceMetadataJson: string | null;
  transferredByUserId: string | null;
  transferredAt: string;
}

/** Records one immutable ownership event inside its caller-owned write boundary. */
export const createBadgeTemplateOwnershipEvent = async (
  db: SqlDatabase,
  input: CreateBadgeTemplateOwnershipEventInput,
): Promise<BadgeTemplateOwnershipEventRecord> => {
  const id = createPrefixedId("btoe");
  await db
    .prepare(
      `
      INSERT INTO badge_template_ownership_events (
        id,
        tenant_id,
        badge_template_id,
        from_org_unit_id,
        to_org_unit_id,
        reason_code,
        reason,
        governance_metadata_json,
        transferred_by_user_id,
        transferred_at,
        created_at
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `,
    )
    .bind(
      id,
      input.tenantId,
      input.badgeTemplateId,
      input.fromOrgUnitId,
      input.toOrgUnitId,
      input.reasonCode,
      input.reason,
      input.governanceMetadataJson,
      input.transferredByUserId,
      input.transferredAt,
      input.transferredAt,
    )
    .run();

  return {
    id,
    tenantId: input.tenantId,
    badgeTemplateId: input.badgeTemplateId,
    fromOrgUnitId: input.fromOrgUnitId,
    toOrgUnitId: input.toOrgUnitId,
    reasonCode: input.reasonCode,
    reason: input.reason,
    governanceMetadataJson: input.governanceMetadataJson,
    transferredByUserId: input.transferredByUserId,
    transferredAt: input.transferredAt,
    createdAt: input.transferredAt,
  };
};

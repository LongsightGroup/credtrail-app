import {
  createAuditLog,
  findBadgeTemplateById,
  findBadgeTemplateImageRevisionById,
  updateBadgeTemplate,
  type BadgeTemplateRecord,
  type BadgeTemplateImageRevisionRecord,
  type SqlDatabase,
  type TenantMembershipRole,
} from "@credtrail/db";
import { buildBadgeTemplateImageUriChange } from "./badge-template-audit-metadata";
import { recordBadgeTemplateImageRevisionIfChanged } from "./badge-template-image-revision-recording";

export type BadgeTemplateImageRevisionRestoreError = {
  status: 404;
  message: string;
};

export type BadgeTemplateImageRevisionRestoreSuccess = {
  updatedTemplate: BadgeTemplateRecord;
  restoredRevision: BadgeTemplateImageRevisionRecord;
};

export const restoreBadgeTemplateImageRevision = async (input: {
  db: SqlDatabase;
  tenantId: string;
  badgeTemplateId: string;
  revisionId: string;
  actorUserId: string;
  membershipRole: TenantMembershipRole;
}): Promise<BadgeTemplateImageRevisionRestoreSuccess | BadgeTemplateImageRevisionRestoreError> => {
  const template = await findBadgeTemplateById(input.db, input.tenantId, input.badgeTemplateId);

  if (template === null) {
    return { status: 404, message: "Badge template not found" };
  }

  const revision = await findBadgeTemplateImageRevisionById(
    input.db,
    input.tenantId,
    input.badgeTemplateId,
    input.revisionId,
  );

  if (revision === null) {
    return { status: 404, message: "Badge template image revision not found" };
  }

  const updatedTemplate = await updateBadgeTemplate(input.db, {
    tenantId: input.tenantId,
    id: input.badgeTemplateId,
    imageUri: revision.previousImageUri,
  });

  if (updatedTemplate === null) {
    return { status: 404, message: "Badge template not found" };
  }

  await recordBadgeTemplateImageRevisionIfChanged(input.db, {
    tenantId: input.tenantId,
    badgeTemplateId: input.badgeTemplateId,
    previousImageUri: template.imageUri,
    newImageUri: updatedTemplate.imageUri,
    sourceType: "restore",
    createdByUserId: input.actorUserId,
    metadataJson: JSON.stringify({
      restoredRevisionId: revision.id,
    }),
  });

  const restoredImageUriChange = buildBadgeTemplateImageUriChange(
    template.imageUri,
    updatedTemplate.imageUri,
  );

  await createAuditLog(input.db, {
    tenantId: input.tenantId,
    actorUserId: input.actorUserId,
    action: "badge_template.image_restored",
    targetType: "badge_template",
    targetId: updatedTemplate.id,
    metadata: {
      role: input.membershipRole,
      restoredRevisionId: revision.id,
      ...(restoredImageUriChange === null ? {} : { changes: [restoredImageUriChange] }),
    },
  });

  return { updatedTemplate, restoredRevision: revision };
};

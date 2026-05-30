import {
  createAuditLog,
  createBadgeTemplate,
  updateBadgeTemplate,
  type BadgeTemplateRecord,
  type SqlDatabase,
  type TenantMembershipRole,
} from "@credtrail/db";
import type { CreateBadgeTemplateRequest, UpdateBadgeTemplateRequest } from "@credtrail/validation";
import { isUniqueConstraintError } from "../http/database-errors";
import { buildBadgeTemplateFieldChanges } from "./badge-template-audit-metadata";
import { recordBadgeTemplateImageRevisionIfChanged } from "./badge-template-image-revision-recording";

export const isBadgeTemplateSlugConflict = (error: unknown): boolean => {
  return isUniqueConstraintError(error) && error.message.includes("badge_templates");
};

export const createBadgeTemplateWithAudit = async (
  db: SqlDatabase,
  input: {
    tenantId: string;
    request: CreateBadgeTemplateRequest;
    actorUserId: string;
    membershipRole: TenantMembershipRole;
  },
): Promise<BadgeTemplateRecord> => {
  const template = await createBadgeTemplate(db, {
    tenantId: input.tenantId,
    slug: input.request.slug,
    title: input.request.title,
    description: input.request.description,
    criteriaUri: input.request.criteriaUri,
    imageUri: input.request.imageUri,
    ownerOrgUnitId: input.request.ownerOrgUnitId,
    createdByUserId: input.actorUserId,
  });

  await createAuditLog(db, {
    tenantId: input.tenantId,
    actorUserId: input.actorUserId,
    action: "badge_template.created",
    targetType: "badge_template",
    targetId: template.id,
    metadata: {
      role: input.membershipRole,
      slug: template.slug,
      title: template.title,
      ownerOrgUnitId: template.ownerOrgUnitId,
    },
  });

  return template;
};

export const updateBadgeTemplateWithAudit = async (
  db: SqlDatabase,
  input: {
    tenantId: string;
    badgeTemplateId: string;
    existingTemplate: BadgeTemplateRecord;
    request: UpdateBadgeTemplateRequest;
    actorUserId: string;
    membershipRole: TenantMembershipRole;
  },
): Promise<BadgeTemplateRecord | null> => {
  const template = await updateBadgeTemplate(db, {
    tenantId: input.tenantId,
    id: input.badgeTemplateId,
    slug: input.request.slug,
    title: input.request.title,
    description: input.request.description,
    criteriaUri: input.request.criteriaUri,
    imageUri: input.request.imageUri,
  });

  if (template === null) {
    return null;
  }

  if (input.request.imageUri !== undefined) {
    await recordBadgeTemplateImageRevisionIfChanged(db, {
      tenantId: input.tenantId,
      badgeTemplateId: input.badgeTemplateId,
      previousImageUri: input.existingTemplate.imageUri,
      newImageUri: template.imageUri,
      sourceType: "manual_update",
      createdByUserId: input.actorUserId,
    });
  }

  const changes = buildBadgeTemplateFieldChanges(input.existingTemplate, template, input.request);

  if (changes.length > 0) {
    await createAuditLog(db, {
      tenantId: input.tenantId,
      actorUserId: input.actorUserId,
      action: "badge_template.updated",
      targetType: "badge_template",
      targetId: template.id,
      metadata: {
        role: input.membershipRole,
        changes,
      },
    });
  }

  return template;
};

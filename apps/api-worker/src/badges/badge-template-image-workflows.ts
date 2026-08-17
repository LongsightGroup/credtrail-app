import {
  createAuditLog,
  findBadgeTemplateById,
  findBadgeTemplateImageGenerationById,
  updateBadgeTemplate,
  type BadgeTemplateRecord,
  type SqlDatabase,
  type TenantMembershipRole,
} from "@credtrail/db";
import type { AppBindings, AppContext } from "../app/types";
import { canonicalAppUrl } from "../http/canonical-app-url";
import { buildBadgeTemplateImageUriChange } from "./badge-template-audit-metadata";
import { recordBadgeTemplateImageRevisionIfChanged } from "./badge-template-image-revision-recording";
import {
  BADGE_TEMPLATE_IMAGE_MAX_BYTES,
  badgeTemplateImageMimeTypeFromBytes,
  badgeTemplateImageMimeTypeFromValue,
  badgeTemplateImagePublicPath,
  storeBadgeTemplateImage,
} from "./template-image-storage";

export type BadgeTemplateImageUploadWorkflowError = {
  status: 400 | 404 | 413 | 422 | 500;
  message: string;
};

export type BadgeTemplateImageApplyWorkflowError = {
  status: 404 | 409;
  message: string;
};

export type BadgeTemplateImageUploadSuccess = {
  updatedTemplate: BadgeTemplateRecord;
};

export type BadgeTemplateImageApplySuccess = {
  updatedTemplate: BadgeTemplateRecord;
};

export const uploadBadgeTemplateImage = async (input: {
  c: AppContext;
  db: SqlDatabase;
  bindings: AppBindings;
  tenantId: string;
  badgeTemplateId: string;
  actorUserId: string;
  membershipRole: TenantMembershipRole;
  file: File;
}): Promise<BadgeTemplateImageUploadSuccess | BadgeTemplateImageUploadWorkflowError> => {
  const template = await findBadgeTemplateById(input.db, input.tenantId, input.badgeTemplateId);

  if (template === null) {
    return { status: 404, message: "Badge template not found" };
  }

  if (input.file.size < 1) {
    return { status: 422, message: "Badge template image file must not be empty" };
  }

  if (input.file.size > BADGE_TEMPLATE_IMAGE_MAX_BYTES) {
    return {
      status: 413,
      message: `Badge template image exceeds ${String(BADGE_TEMPLATE_IMAGE_MAX_BYTES)} byte limit`,
    };
  }

  const declaredMimeType = badgeTemplateImageMimeTypeFromValue(input.file.type);

  if (declaredMimeType === null) {
    return {
      status: 422,
      message: "Unsupported image type. Allowed types: image/png, image/jpeg, image/webp",
    };
  }

  const bytes = new Uint8Array(await input.file.arrayBuffer());
  const detectedMimeType = badgeTemplateImageMimeTypeFromBytes(bytes);

  if (detectedMimeType === null || detectedMimeType !== declaredMimeType) {
    return {
      status: 422,
      message: "Uploaded file content does not match declared image type",
    };
  }

  const assetId = crypto.randomUUID();
  const fileName = input.file.name.trim();
  await storeBadgeTemplateImage(input.bindings.BADGE_OBJECTS, {
    tenantId: input.tenantId,
    badgeTemplateId: input.badgeTemplateId,
    assetId,
    mimeType: declaredMimeType,
    bytes,
    originalFilename: fileName.length === 0 ? null : fileName,
  });

  const imagePath = badgeTemplateImagePublicPath({
    tenantId: input.tenantId,
    badgeTemplateId: input.badgeTemplateId,
    assetId,
  });
  const imageUrl = canonicalAppUrl(input.bindings.PUBLIC_APP_ORIGIN, imagePath);
  const updatedTemplate = await updateBadgeTemplate(input.db, {
    tenantId: input.tenantId,
    id: input.badgeTemplateId,
    imageUri: imageUrl,
  });

  if (updatedTemplate === null) {
    return { status: 404, message: "Badge template not found" };
  }

  await recordBadgeTemplateImageRevisionIfChanged(input.db, {
    tenantId: input.tenantId,
    badgeTemplateId: input.badgeTemplateId,
    previousImageUri: template.imageUri,
    newImageUri: updatedTemplate.imageUri,
    sourceType: "upload",
    createdByUserId: input.actorUserId,
    metadata: {
      imagePath,
      imageMimeType: declaredMimeType,
      imageSizeBytes: bytes.byteLength,
      fileName: fileName.length === 0 ? null : fileName,
    },
  });

  const imageUriChange = buildBadgeTemplateImageUriChange(
    template.imageUri,
    updatedTemplate.imageUri,
  );

  await createAuditLog(input.db, {
    tenantId: input.tenantId,
    actorUserId: input.actorUserId,
    action: "badge_template.image_uploaded",
    targetType: "badge_template",
    targetId: updatedTemplate.id,
    metadata: {
      role: input.membershipRole,
      imagePath,
      imageMimeType: declaredMimeType,
      imageSizeBytes: bytes.byteLength,
      ...(fileName.length === 0 ? {} : { fileName }),
      ...(imageUriChange === null ? {} : { changes: [imageUriChange] }),
    },
  });

  return { updatedTemplate };
};

export const applyBadgeTemplateGeneratedImage = async (input: {
  db: SqlDatabase;
  tenantId: string;
  badgeTemplateId: string;
  generationId: string;
  actorUserId: string;
  membershipRole: TenantMembershipRole;
}): Promise<BadgeTemplateImageApplySuccess | BadgeTemplateImageApplyWorkflowError> => {
  const template = await findBadgeTemplateById(input.db, input.tenantId, input.badgeTemplateId);

  if (template === null) {
    return { status: 404, message: "Badge template not found" };
  }

  const generation = await findBadgeTemplateImageGenerationById(
    input.db,
    input.tenantId,
    input.generationId,
  );

  if (generation === null || generation.badgeTemplateId !== input.badgeTemplateId) {
    return { status: 404, message: "Badge template image generation not found" };
  }

  if (generation.status !== "succeeded" || generation.resultImageUri === null) {
    return { status: 409, message: "Badge template image generation is not ready to apply" };
  }

  const updatedTemplate = await updateBadgeTemplate(input.db, {
    tenantId: input.tenantId,
    id: input.badgeTemplateId,
    imageUri: generation.resultImageUri,
  });

  if (updatedTemplate === null) {
    return { status: 404, message: "Badge template not found" };
  }

  await recordBadgeTemplateImageRevisionIfChanged(input.db, {
    tenantId: input.tenantId,
    badgeTemplateId: input.badgeTemplateId,
    previousImageUri: template.imageUri,
    newImageUri: updatedTemplate.imageUri,
    sourceType: "ai_generated",
    createdByUserId: input.actorUserId,
    promptText: generation.promptText,
    metadata: {
      generationId: generation.id,
      stylePreset: generation.stylePreset,
    },
  });

  const appliedImageUriChange = buildBadgeTemplateImageUriChange(
    template.imageUri,
    updatedTemplate.imageUri,
  );

  await createAuditLog(input.db, {
    tenantId: input.tenantId,
    actorUserId: input.actorUserId,
    action: "badge_template.image_generation_applied",
    targetType: "badge_template",
    targetId: updatedTemplate.id,
    metadata: {
      role: input.membershipRole,
      generationId: generation.id,
      ...(appliedImageUriChange === null ? {} : { changes: [appliedImageUriChange] }),
    },
  });

  return { updatedTemplate };
};

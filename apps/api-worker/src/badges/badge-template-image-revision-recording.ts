import {
  createBadgeTemplateImageRevision,
  type BadgeTemplateImageRevisionSource,
  type SqlDatabase,
} from "@credtrail/db";

export type RecordBadgeTemplateImageRevisionInput = {
  tenantId: string;
  badgeTemplateId: string;
  previousImageUri: string | null;
  newImageUri: string | null;
  sourceType: BadgeTemplateImageRevisionSource;
  createdByUserId: string;
  promptText?: string | undefined;
  provider?: string | undefined;
  model?: string | undefined;
  metadata?: Record<string, string | number | boolean | null> | undefined;
  metadataJson?: string | null;
};

export const recordBadgeTemplateImageRevisionIfChanged = async (
  db: SqlDatabase,
  input: RecordBadgeTemplateImageRevisionInput,
): Promise<void> => {
  if (input.previousImageUri === input.newImageUri) {
    return;
  }

  await createBadgeTemplateImageRevision(db, {
    tenantId: input.tenantId,
    badgeTemplateId: input.badgeTemplateId,
    previousImageUri: input.previousImageUri,
    newImageUri: input.newImageUri,
    sourceType: input.sourceType,
    promptText: input.promptText,
    provider: input.provider,
    model: input.model,
    metadataJson:
      input.metadataJson ?? (input.metadata === undefined ? null : JSON.stringify(input.metadata)),
    createdByUserId: input.createdByUserId,
  });
};

import type { SqlDatabase } from "@credtrail/db";
import { listBadgeTemplateImageRevisionCountsByTenant } from "@credtrail/db";

type BadgeTemplateImageRevisionCounts = Awaited<
  ReturnType<typeof listBadgeTemplateImageRevisionCountsByTenant>
>;

const isMissingImageRevisionStorageError = (error: unknown): boolean => {
  if (!(error instanceof Error)) {
    return false;
  }

  const message = error.message.toLowerCase();

  return (
    message.includes("badge_template_image_revisions") &&
    (message.includes("does not exist") ||
      message.includes("no such table") ||
      message.includes("undefined_table"))
  );
};

export const listOptionalBadgeTemplateImageRevisionCountsByTenant = async (
  db: SqlDatabase,
  tenantId: string,
): Promise<BadgeTemplateImageRevisionCounts> => {
  try {
    return await listBadgeTemplateImageRevisionCountsByTenant(db, tenantId);
  } catch (error) {
    if (isMissingImageRevisionStorageError(error)) {
      return [];
    }

    throw error;
  }
};

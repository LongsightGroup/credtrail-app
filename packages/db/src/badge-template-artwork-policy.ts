import { usesManagedBadgeTemplateImageReference } from "@credtrail/validation";

import type { BadgeTemplateRecord } from "./badge-templates.js";

/** Returns whether a template references artwork in its own managed asset namespace. */
export const badgeTemplateArtworkUsesManagedReference = (
  template: BadgeTemplateRecord,
): boolean => {
  return usesManagedBadgeTemplateImageReference({
    imageUri: template.imageUri,
    tenantId: template.tenantId,
    badgeTemplateId: template.id,
  });
};

/** Rejects a template that cannot safely be captured in immutable rule and assertion history. */
export const assertBadgeTemplateArtworkUsesManagedReference = (
  template: BadgeTemplateRecord,
): void => {
  if (badgeTemplateArtworkUsesManagedReference(template)) {
    return;
  }

  throw new Error(
    `Badge template "${template.id}" must use managed immutable artwork before rule authoring`,
  );
};

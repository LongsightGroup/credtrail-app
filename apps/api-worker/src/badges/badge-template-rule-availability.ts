import type { BadgeTemplateRecord } from "@credtrail/db";
import { resolveManagedBadgeTemplateImageReference } from "@credtrail/validation";
import { canonicalAppUrl } from "../http/canonical-app-url";

/** Persisted artwork state used to decide whether a template belongs in the rule-builder list. */
export type RuleBuilderBadgeTemplateAvailability =
  | "available"
  | "missing_artwork"
  | "unmanaged_artwork";

/** One template paired with its rule-builder availability. */
export interface RuleBuilderBadgeTemplateAvailabilityEntry {
  readonly template: BadgeTemplateRecord;
  readonly artworkAvailability: RuleBuilderBadgeTemplateAvailability;
}

/**
 * Classifies templates from their persisted immutable-artwork reference without reading object data.
 * Rule submission verifies the selected object's existence and contents before it writes a version.
 */
export const classifyRuleBuilderBadgeTemplateAvailability = (input: {
  readonly publicAppOrigin: string;
  readonly badgeTemplates: readonly BadgeTemplateRecord[];
}): readonly RuleBuilderBadgeTemplateAvailabilityEntry[] => {
  return input.badgeTemplates.map((template) => {
    if (template.imageUri === null) {
      return { template, artworkAvailability: "missing_artwork" };
    }

    const reference = resolveManagedBadgeTemplateImageReference({
      imageUri: template.imageUri,
      tenantId: template.tenantId,
      badgeTemplateId: template.id,
    });
    const artworkAvailability =
      reference !== null &&
      canonicalAppUrl(input.publicAppOrigin, reference.path) === template.imageUri
        ? "available"
        : "unmanaged_artwork";

    return { template, artworkAvailability };
  });
};

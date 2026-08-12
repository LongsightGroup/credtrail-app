import type { BadgeAchievementSnapshot } from "@credtrail/validation";
import type { BadgeIssuanceRuleVersionSnapshot } from "./badge-issuance-rule-types.js";
import type { BadgeTemplateRecord } from "./badge-templates.js";

/** Projects the credential-bearing fields of a badge template. */
export const badgeAchievementSnapshotFromTemplate = (
  template: BadgeTemplateRecord,
): BadgeAchievementSnapshot => ({
  badgeTemplateId: template.id,
  title: template.title,
  description: template.description,
  criteriaUri: template.criteriaUri,
  imageUri: template.imageUri,
  trustedCredentialMetadataJson: template.trustedCredentialMetadataJson ?? null,
});

/** Compares every credential-bearing field in two achievement snapshots. */
export const badgeAchievementSnapshotsEqual = (
  left: BadgeAchievementSnapshot,
  right: BadgeAchievementSnapshot,
): boolean => {
  return (
    left.badgeTemplateId === right.badgeTemplateId &&
    left.title === right.title &&
    left.description === right.description &&
    left.criteriaUri === right.criteriaUri &&
    left.imageUri === right.imageUri &&
    left.trustedCredentialMetadataJson === right.trustedCredentialMetadataJson
  );
};

/** Projects credential-bearing achievement content from one immutable governed version. */
export const badgeAchievementSnapshotFromRuleVersion = (
  snapshot: BadgeIssuanceRuleVersionSnapshot,
): BadgeAchievementSnapshot => ({
  badgeTemplateId: snapshot.badgeTemplateId,
  title: snapshot.badgeTemplateTitle,
  description: snapshot.badgeTemplateDescription,
  criteriaUri: snapshot.badgeTemplateCriteriaUri,
  imageUri: snapshot.badgeTemplateImageUri,
  trustedCredentialMetadataJson: snapshot.badgeTemplateTrustedCredentialMetadataJson,
});

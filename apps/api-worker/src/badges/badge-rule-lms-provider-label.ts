import type { BadgeIssuanceRuleLmsProviderKind } from "@credtrail/db";

/** Returns the product-facing name for a badge rule's LMS provider. */
export const badgeRuleLmsProviderLabel = (
  providerKind: BadgeIssuanceRuleLmsProviderKind,
): string => {
  switch (providerKind) {
    case "canvas":
      return "Canvas";
    case "moodle":
      return "Moodle";
    case "blackboard_ultra":
      return "Blackboard Ultra";
    case "d2l_brightspace":
      return "D2L Brightspace";
    case "sakai":
      return "Sakai";
  }
};

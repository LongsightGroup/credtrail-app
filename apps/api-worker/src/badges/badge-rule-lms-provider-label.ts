import type { BadgeIssuanceRuleLmsProviderKind } from "@credtrail/db";

/** Returns the product-facing name for a badge rule's LMS provider. */
export const badgeRuleLmsProviderLabel = (
  providerKind: BadgeIssuanceRuleLmsProviderKind,
): string => {
  switch (providerKind) {
    case "canvas":
      return "Canvas";
    case "sakai":
      return "Sakai";
  }
};

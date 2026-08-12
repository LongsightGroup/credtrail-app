import type { IssuableBadgeArtworkFailure } from "./badge-achievement-snapshot";

/** HTTP response details for artwork that cannot safely be used for issuance. */
export interface BadgeArtworkIssuanceHttpFailure {
  readonly statusCode: 409 | 503;
  readonly error: string;
}

/** Maps every artwork-resolution failure into the canonical issuance HTTP response. */
export const badgeArtworkIssuanceHttpFailure = (
  failure: IssuableBadgeArtworkFailure,
): BadgeArtworkIssuanceHttpFailure => {
  switch (failure.status) {
    case "unmanaged_artwork":
      return {
        statusCode: 409,
        error: "Upload this badge's artwork in CredTrail before issuing it.",
      };
    case "missing_artwork":
      return {
        statusCode: 409,
        error: "Upload this badge's approved artwork in CredTrail before issuing it.",
      };
    case "invalid_artwork":
      return {
        statusCode: 409,
        error: "This badge's managed artwork is invalid. Replace it before issuing.",
      };
    case "storage_unavailable":
      return {
        statusCode: 503,
        error: "CredTrail could not check this badge's artwork right now. Try again shortly.",
      };
  }
};

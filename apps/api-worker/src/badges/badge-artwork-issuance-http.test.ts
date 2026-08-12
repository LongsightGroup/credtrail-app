import { describe, expect, it } from "vitest";
import { badgeArtworkIssuanceHttpFailure } from "./badge-artwork-issuance-http";

describe("badgeArtworkIssuanceHttpFailure", () => {
  it("preserves dependency outages as retryable service failures", () => {
    expect(
      badgeArtworkIssuanceHttpFailure({
        status: "storage_unavailable",
        cause: new Error("R2 unavailable"),
      }),
    ).toEqual({
      statusCode: 503,
      error: "CredTrail could not check this badge's artwork right now. Try again shortly.",
    });
  });

  it.each([
    ["unmanaged_artwork", "Upload this badge's artwork in CredTrail before issuing it."],
    [
      "missing_artwork",
      "Upload this badge's approved artwork in CredTrail before issuing it.",
    ],
    ["invalid_artwork", "This badge's managed artwork is invalid. Replace it before issuing."],
  ] as const)("maps %s to a fixable conflict", (status, error) => {
    expect(badgeArtworkIssuanceHttpFailure({ status })).toEqual({ statusCode: 409, error });
  });
});

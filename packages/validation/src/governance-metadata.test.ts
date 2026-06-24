import { describe, expect, it } from "vitest";
import {
  isLtiInstructorPlacementEnabled,
  parseGovernanceMetadataJson,
} from "./governance-metadata.js";

describe("governance metadata", () => {
  it("parses instructor placement flags from stored JSON", () => {
    expect(
      isLtiInstructorPlacementEnabled(
        JSON.stringify({ ltiInstructorPlacement: { enabled: true } }),
      ),
    ).toBe(true);
    expect(isLtiInstructorPlacementEnabled(null)).toBe(false);
    expect(isLtiInstructorPlacementEnabled("{not-json")).toBe(false);
    expect(
      parseGovernanceMetadataJson(
        JSON.stringify({
          stability: "institution_registry",
          ltiInstructorPlacement: { enabled: true },
        }),
      ),
    ).toEqual({
      stability: "institution_registry",
      ltiInstructorPlacement: { enabled: true },
    });
  });

  it("rejects malformed instructor placement metadata", () => {
    expect(
      parseGovernanceMetadataJson(JSON.stringify({ ltiInstructorPlacement: { enabled: "yes" } })),
    ).toBeNull();
  });
});

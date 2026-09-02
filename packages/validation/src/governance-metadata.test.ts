import { describe, expect, it } from "vitest";
import {
  isLtiInstructorPlacementEnabled,
  parseLtiInstructorPlacementPolicyRequest,
  parseGovernanceMetadataJson,
  setLtiInstructorPlacementPolicy,
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

  it("parses only an explicit boolean placement policy", () => {
    expect(parseLtiInstructorPlacementPolicyRequest({ enabled: true })).toEqual({
      enabled: true,
    });
    expect(() => parseLtiInstructorPlacementPolicyRequest({ enabled: "true" })).toThrow(
      /expected boolean/i,
    );
    expect(() =>
      parseLtiInstructorPlacementPolicyRequest({ enabled: true, unexpected: true }),
    ).toThrow(/unrecognized key/i);
  });

  it("sets instructor placement while preserving other governance metadata", () => {
    const enabled = setLtiInstructorPlacementPolicy(
      JSON.stringify({ stability: "institution_registry", approval: "registrar" }),
      true,
    );

    expect(enabled.status).toBe("updated");
    if (enabled.status !== "updated") {
      throw new Error("Expected valid governance metadata to be updated");
    }
    expect(parseGovernanceMetadataJson(enabled.governanceMetadataJson)).toEqual({
      stability: "institution_registry",
      approval: "registrar",
      ltiInstructorPlacement: { enabled: true },
    });

    const disabled = setLtiInstructorPlacementPolicy(enabled.governanceMetadataJson, false);
    expect(disabled.status).toBe("updated");
    if (disabled.status !== "updated") {
      throw new Error("Expected valid governance metadata to be updated");
    }
    expect(parseGovernanceMetadataJson(disabled.governanceMetadataJson)).toEqual({
      stability: "institution_registry",
      approval: "registrar",
      ltiInstructorPlacement: { enabled: false },
    });
  });

  it("creates metadata from an empty value but never overwrites invalid stored metadata", () => {
    expect(setLtiInstructorPlacementPolicy(null, true)).toEqual({
      status: "updated",
      governanceMetadataJson: '{"ltiInstructorPlacement":{"enabled":true}}',
    });
    expect(setLtiInstructorPlacementPolicy("{not-json", true)).toEqual({
      status: "invalid_existing_metadata",
    });
    expect(
      setLtiInstructorPlacementPolicy(
        JSON.stringify({ ltiInstructorPlacement: { enabled: "yes" } }),
        true,
      ),
    ).toEqual({ status: "invalid_existing_metadata" });
  });
});

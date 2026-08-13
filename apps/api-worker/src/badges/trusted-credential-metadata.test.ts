import { completeTrustEdCredentialMetadataInput } from "@credtrail/validation/testing";
import { describe, expect, it } from "vitest";
import {
  emptyTrustEdCredentialMetadata,
  parseTrustEdCredentialMetadataJsonResult,
} from "./trusted-credential-metadata";

describe("parseTrustEdCredentialMetadataJsonResult", () => {
  it("parses valid stored metadata", () => {
    const result = parseTrustEdCredentialMetadataJsonResult(
      JSON.stringify(completeTrustEdCredentialMetadataInput),
    );

    expect(result.status).toBe("valid");
    expect(result.metadata?.skills[0]?.name).toBe("Applied data analysis");
    expect(result.metadata?.results[0]?.resultDate).toBe("2026-05-18");
  });

  it("distinguishes invalid stored metadata from missing metadata", () => {
    expect(parseTrustEdCredentialMetadataJsonResult(null)).toEqual({
      status: "empty",
      metadata: null,
      error: null,
    });

    const result = parseTrustEdCredentialMetadataJsonResult("{not-json");

    expect(result.status).toBe("invalid");
    expect(result.metadata).toBeNull();
    expect(result.error).toContain("JSON");
  });

  it("returns schema validation details for invalid stored metadata", () => {
    const result = parseTrustEdCredentialMetadataJsonResult(
      JSON.stringify({
        ...completeTrustEdCredentialMetadataInput,
        results: [{ value: "Pass", resultDate: "May 18, 2026" }],
      }),
    );

    expect(result.status).toBe("invalid");
    expect(result.metadata).toBeNull();
    expect(result.error).toContain("resultDate");
  });
});

describe("emptyTrustEdCredentialMetadata", () => {
  it("returns an empty metadata shape for authoring defaults", () => {
    expect(emptyTrustEdCredentialMetadata()).toEqual({
      skills: [],
      frameworkAlignments: [],
      issuerAuthority: null,
      evidence: [],
      results: [],
      criteria: null,
      assessments: [],
      achievementType: null,
      rubrics: [],
      duration: null,
      credits: null,
      endorsements: [],
    });
  });
});

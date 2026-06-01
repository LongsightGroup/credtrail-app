import { completeTrustEdCredentialMetadataInput } from "@credtrail/validation/testing";
import { describe, expect, it } from "vitest";
import {
  emptyTrustEdCredentialMetadata,
  parseTrustEdCredentialMetadataJson,
  parseTrustEdCredentialMetadataJsonResult,
} from "./trusted-credential-metadata";

describe("parseTrustEdCredentialMetadataJson", () => {
  it("returns null when stored metadata is missing", () => {
    expect(parseTrustEdCredentialMetadataJson(null)).toBeNull();
    expect(parseTrustEdCredentialMetadataJson(undefined)).toBeNull();
  });

  it("parses valid stored metadata", () => {
    const metadata = parseTrustEdCredentialMetadataJson(
      JSON.stringify(completeTrustEdCredentialMetadataInput),
    );

    expect(metadata?.skills[0]?.name).toBe("Applied data analysis");
    expect(metadata?.results[0]?.resultDate).toBe("2026-05-18");
  });

  it("returns null for invalid JSON", () => {
    expect(parseTrustEdCredentialMetadataJson("{not-json")).toBeNull();
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

  it("returns null when stored metadata fails schema validation", () => {
    expect(
      parseTrustEdCredentialMetadataJson(
        JSON.stringify({
          ...completeTrustEdCredentialMetadataInput,
          results: [{ value: "Pass", resultDate: "May 18, 2026" }],
        }),
      ),
    ).toBeNull();
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

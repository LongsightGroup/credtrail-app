import { describe, expect, it } from "vitest";

import { parseTrustEdCredentialMetadata } from "./trusted-credential";
import { completeTrustEdCredentialMetadataInput } from "./testing";

describe("parseTrustEdCredentialMetadata", () => {
  it("parses TrustEd credential metadata", () => {
    const payload = parseTrustEdCredentialMetadata(completeTrustEdCredentialMetadataInput);

    expect(payload.skills[0]?.name).toBe("Applied data analysis");
    expect(payload.results[0]?.resultDate).toBe("2026-05-18");
  });

  it("rejects invalid TrustEd credential metadata URLs and dates", () => {
    expect(() => {
      parseTrustEdCredentialMetadata({
        skills: [{ name: "Applied data analysis", identifierUri: "not a url", source: null }],
        frameworkAlignments: [],
        issuerAuthority: null,
        evidence: [],
        results: [],
        criteria: null,
        assessments: [],
        achievementType: "Project",
        rubrics: [],
        duration: null,
        credits: null,
        endorsements: [],
      });
    }).toThrow(/url/i);

    expect(() => {
      parseTrustEdCredentialMetadata({
        skills: [],
        frameworkAlignments: [],
        issuerAuthority: null,
        evidence: [],
        results: [{ value: "Pass", resultDate: "2026-99-99" }],
        criteria: null,
        assessments: [],
        achievementType: "Project",
        rubrics: [],
        duration: null,
        credits: null,
        endorsements: [],
      });
    }).toThrow(/invalid iso date/i);
  });
});

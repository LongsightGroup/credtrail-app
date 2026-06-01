import { buildCompleteTrustEdCredentialMetadata } from "@credtrail/validation/testing";
import { describe, expect, it } from "vitest";
import {
  evaluateTrustEdCredentialReadiness,
  type TrustEdCredentialMetadata,
  type TrustEdCredentialReadinessCheckId,
} from "./trusted-credential-readiness";

const checkStatus = (
  metadata: TrustEdCredentialMetadata,
  checkId: TrustEdCredentialReadinessCheckId,
): "satisfied" | "missing" => {
  const result = evaluateTrustEdCredentialReadiness(metadata);
  const readinessCheck = result.checks.find((check) => check.id === checkId);

  if (readinessCheck === undefined) {
    throw new Error(`Missing readiness check ${checkId}`);
  }

  return readinessCheck.status;
};

describe("TrustEd credential readiness", () => {
  it("returns not_evaluated when no metadata exists", () => {
    expect(evaluateTrustEdCredentialReadiness(null)).toEqual({
      status: "not_evaluated",
      checks: [],
    });
    expect(evaluateTrustEdCredentialReadiness(undefined)).toEqual({
      status: "not_evaluated",
      checks: [],
    });
  });

  it("marks complete metadata as ready", () => {
    const result = evaluateTrustEdCredentialReadiness(buildCompleteTrustEdCredentialMetadata());

    expect(result.status).toBe("ready");
    expect(result.checks.every((check) => check.status === "satisfied")).toBe(true);
  });

  it("marks missing required metadata as incomplete with field-specific checks", () => {
    const metadata = buildCompleteTrustEdCredentialMetadata({
      skills: [],
      frameworkAlignments: [],
      issuerAuthority: null,
      evidence: [],
      results: [],
      criteria: null,
      assessments: [],
      achievementType: null,
    });
    const result = evaluateTrustEdCredentialReadiness(metadata);

    expect(result.status).toBe("incomplete");
    expect(checkStatus(metadata, "skills")).toBe("missing");
    expect(checkStatus(metadata, "framework_alignment")).toBe("missing");
    expect(checkStatus(metadata, "issuer_authority")).toBe("missing");
    expect(checkStatus(metadata, "evidence")).toBe("missing");
    expect(checkStatus(metadata, "result")).toBe("missing");
    expect(checkStatus(metadata, "criteria")).toBe("missing");
    expect(checkStatus(metadata, "assessment")).toBe("missing");
    expect(checkStatus(metadata, "achievement_type")).toBe("missing");
  });

  it("requires a linked framework alignment", () => {
    const metadata = buildCompleteTrustEdCredentialMetadata({
      frameworkAlignments: [
        {
          targetName: "Analyze civic datasets",
          targetUri: " ",
          frameworkName: "Example CASE Framework",
          frameworkUri: "https://case.example.edu/frameworks/data-analysis",
        },
      ],
    });

    expect(evaluateTrustEdCredentialReadiness(metadata).status).toBe("incomplete");
    expect(checkStatus(metadata, "framework_alignment")).toBe("missing");
  });

  it("requires a result date", () => {
    const metadata = buildCompleteTrustEdCredentialMetadata({
      results: [
        {
          value: "Pass",
          resultDate: "",
        },
      ],
    });

    expect(evaluateTrustEdCredentialReadiness(metadata).status).toBe("incomplete");
    expect(checkStatus(metadata, "result")).toBe("missing");
  });

  it("requires assessment description and date", () => {
    const metadata = buildCompleteTrustEdCredentialMetadata({
      assessments: [
        {
          description: "Faculty-scored applied analytics capstone.",
          assessmentDate: "",
        },
      ],
    });

    expect(evaluateTrustEdCredentialReadiness(metadata).status).toBe("incomplete");
    expect(checkStatus(metadata, "assessment")).toBe("missing");
  });

  it("rejects non-specific achievement types", () => {
    const abbreviated = buildCompleteTrustEdCredentialMetadata({ achievementType: "N/A" });
    const written = buildCompleteTrustEdCredentialMetadata({ achievementType: "Not Applicable" });

    expect(evaluateTrustEdCredentialReadiness(abbreviated).status).toBe("incomplete");
    expect(checkStatus(abbreviated, "achievement_type")).toBe("missing");
    expect(evaluateTrustEdCredentialReadiness(written).status).toBe("incomplete");
    expect(checkStatus(written, "achievement_type")).toBe("missing");
  });

  it("reports missing recommended metadata without blocking readiness", () => {
    const metadata = buildCompleteTrustEdCredentialMetadata({
      rubrics: [],
      duration: null,
      credits: null,
      endorsements: [],
    });
    const result = evaluateTrustEdCredentialReadiness(metadata);

    expect(result.status).toBe("ready");
    expect(checkStatus(metadata, "rubric")).toBe("missing");
    expect(checkStatus(metadata, "duration_credit")).toBe("missing");
    expect(checkStatus(metadata, "endorsement")).toBe("missing");
  });
});

import { describe, expect, it } from "vitest";
import {
  evaluateTrustEdCredentialReadiness,
  type TrustEdCredentialMetadata,
  type TrustEdCredentialReadinessCheckId,
} from "./trusted-credential-readiness";

const completeMetadata = (
  overrides?: Partial<TrustEdCredentialMetadata>,
): TrustEdCredentialMetadata => {
  return {
    skills: [
      {
        name: "Applied data analysis",
        identifierUri: "https://skills.example.edu/skills/applied-data-analysis",
        source: "Example Skills Framework",
      },
    ],
    frameworkAlignments: [
      {
        targetName: "Analyze civic datasets",
        targetUri: "https://case.example.edu/frameworks/data-analysis/items/analyze-civic-data",
        frameworkName: "Example CASE Framework",
        frameworkUri: "https://case.example.edu/frameworks/data-analysis",
      },
    ],
    issuerAuthority: {
      name: "Middle States Commission on Higher Education",
      uri: "https://www.msche.org/institution/0000/",
      authorityType: "accreditor",
    },
    evidence: [
      {
        name: "Capstone analysis portfolio",
        uri: "https://evidence.example.edu/learners/123/capstone",
        description: "Portfolio evidence reviewed by the program faculty.",
      },
    ],
    results: [
      {
        value: "Pass",
        resultDate: "2026-05-18",
      },
    ],
    criteria: {
      text: "Complete the applied analytics project and faculty review.",
      uri: "https://credentials.example.edu/badges/applied-analytics/criteria",
    },
    assessments: [
      {
        description: "Faculty-scored applied analytics capstone.",
        assessmentDate: "2026-05-18",
      },
    ],
    achievementType: "Project",
    rubrics: [
      {
        name: "Applied analytics rubric",
        uri: "https://credentials.example.edu/rubrics/applied-analytics",
      },
    ],
    duration: {
      value: "6 weeks",
    },
    credits: {
      available: "3 credits",
      earned: "3 credits",
    },
    endorsements: [
      {
        endorserName: "Regional Workforce Council",
        endorserUri: "https://workforce.example.edu/endorsements/applied-analytics",
      },
    ],
    ...overrides,
  };
};

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
    const result = evaluateTrustEdCredentialReadiness(completeMetadata());

    expect(result.status).toBe("ready");
    expect(result.checks.every((check) => check.status === "satisfied")).toBe(true);
  });

  it("marks missing required metadata as incomplete with field-specific checks", () => {
    const metadata = completeMetadata({
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
    const metadata = completeMetadata({
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
    const metadata = completeMetadata({
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
    const metadata = completeMetadata({
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
    const abbreviated = completeMetadata({ achievementType: "N/A" });
    const written = completeMetadata({ achievementType: "Not Applicable" });

    expect(evaluateTrustEdCredentialReadiness(abbreviated).status).toBe("incomplete");
    expect(checkStatus(abbreviated, "achievement_type")).toBe("missing");
    expect(evaluateTrustEdCredentialReadiness(written).status).toBe("incomplete");
    expect(checkStatus(written, "achievement_type")).toBe("missing");
  });

  it("reports missing recommended metadata without blocking readiness", () => {
    const metadata = completeMetadata({
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

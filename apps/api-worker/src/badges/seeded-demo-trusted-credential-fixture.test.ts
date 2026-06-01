import { describe, expect, it } from "vitest";

import {
  getSeededDemoTrustEdCredentialFixture,
  SEEDED_DEMO_TRUSTED_CREDENTIAL_VERIFY_COMMAND,
} from "./seeded-demo-trusted-credential-fixture";
import {
  evidenceDetailsFromCredential,
  trustEdCredentialDetailsFromCredential,
} from "./public-badge-helpers";

describe("seeded demo TrustEd credential fixture", () => {
  it("exports a canonical public credential slice with TrustEd-aligned metadata", () => {
    const fixture = getSeededDemoTrustEdCredentialFixture();
    const trustDetails = trustEdCredentialDetailsFromCredential(fixture.credential);
    const evidenceDetails = evidenceDetailsFromCredential(fixture.credential);

    expect(fixture.tenantId).toBe("tenant_123");
    expect(fixture.routeFamily.publicCredential).toBe("/badges/trusted-demo-credential");
    expect(fixture.routeFamily.ob3Json).toBe("/badges/trusted-demo-credential/jsonld");
    expect(fixture.routeFamily.walletOffer).toBe("/credentials/v1/offers/trusted-demo-credential");
    expect(fixture.readiness.status).toBe("ready");
    expect(fixture.readiness.checks.every((check) => check.status === "satisfied")).toBe(true);
    expect(fixture.badgeTemplate.trustedCredentialMetadataJson).toContain("Applied data analysis");
    expect(trustDetails.achievementType).toBe("Project");
    expect(trustDetails.criteriaNarrative).toBe(
      "Complete the applied analytics project and faculty review.",
    );
    expect(trustDetails.alignments).toEqual([
      {
        targetName: "Analyze civic datasets",
        targetUrl: "https://case.example.edu/frameworks/data-analysis/items/analyze-civic-data",
        targetFramework: "Example CASE Framework",
        frameworkUri: "https://case.example.edu/frameworks/data-analysis",
      },
    ]);
    expect(trustDetails.results).toEqual([{ value: "Pass", resultDate: "2026-05-18" }]);
    expect(trustDetails.skills).toEqual([
      {
        name: "Applied data analysis",
        identifierUri: "https://skills.example.edu/skills/applied-data-analysis",
        source: "Example Skills Framework",
      },
    ]);
    expect(trustDetails.issuerAuthority).toEqual({
      name: "Middle States Commission on Higher Education",
      uri: "https://www.msche.org/institution/0000/",
      authorityType: "accreditor",
    });
    expect(trustDetails.assessments).toEqual([
      {
        description: "Faculty-scored applied analytics capstone.",
        assessmentDate: "2026-05-18",
      },
    ]);
    expect(trustDetails.rubrics).toEqual([
      {
        name: "Applied analytics rubric",
        uri: "https://credentials.example.edu/rubrics/applied-analytics",
      },
    ]);
    expect(trustDetails.duration).toBe("6 weeks");
    expect(trustDetails.credits).toEqual({ available: "3 credits", earned: "3 credits" });
    expect(trustDetails.endorsements).toEqual([
      {
        endorserName: "Regional Workforce Council",
        endorserUri: "https://workforce.example.edu/endorsements/applied-analytics",
      },
    ]);
    expect(evidenceDetails).toEqual([
      {
        uri: "https://evidence.example.edu/learners/123/capstone",
        name: "Capstone analysis portfolio",
        description: "Portfolio evidence reviewed by the program faculty.",
      },
    ]);
    expect(SEEDED_DEMO_TRUSTED_CREDENTIAL_VERIFY_COMMAND).toContain(
      "seeded-demo-trusted-credential-fixture.test.ts",
    );
  });
});

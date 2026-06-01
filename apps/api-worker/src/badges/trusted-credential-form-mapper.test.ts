import { describe, expect, it } from "vitest";
import {
  formHasTrustEdMetadataFields,
  trustEdMetadataFromForm,
} from "./trusted-credential-form-mapper";

describe("trusted credential form mapper", () => {
  it("detects TrustEd metadata fields independently from HTTP routes", () => {
    const emptyForm = new FormData();
    const trustedForm = new FormData();
    const legacyForm = new FormData();
    trustedForm.set("trustedSkills[0].name", "Applied data analysis");
    legacyForm.set("trustedSkillName", "Applied data analysis");

    expect(formHasTrustEdMetadataFields(emptyForm)).toBe(false);
    expect(formHasTrustEdMetadataFields(trustedForm)).toBe(true);
    expect(formHasTrustEdMetadataFields(legacyForm)).toBe(false);
  });

  it("maps admin form fields into normalized TrustEd metadata", () => {
    const formData = new FormData();
    formData.set("trustedSkills[0].name", " Applied data analysis ");
    formData.set("trustedSkills[0].identifierUri", "https://skills.example.edu/applied-data");
    formData.set("trustedSkills[0].source", "Example Skills Framework");
    formData.set("trustedSkills[1].name", "Stakeholder communication");
    formData.set("trustedSkills[1].identifierUri", "https://skills.example.edu/communication");
    formData.set("trustedSkills[1].source", "Example Skills Framework");
    formData.set("trustedFrameworkAlignments[0].targetName", "Analyze civic datasets");
    formData.set(
      "trustedFrameworkAlignments[0].targetUri",
      "https://case.example.edu/items/analyze",
    );
    formData.set("trustedFrameworkAlignments[0].frameworkName", "Example CASE Framework");
    formData.set(
      "trustedFrameworkAlignments[0].frameworkUri",
      "https://case.example.edu/frameworks/data-analysis",
    );
    formData.set("trustedIssuerAuthorityName", "Middle States Commission");
    formData.set("trustedIssuerAuthorityUri", "https://www.msche.org/institution/0000/");
    formData.set("trustedIssuerAuthorityType", "accreditor");
    formData.set("trustedEvidence[0].name", "Capstone analysis portfolio");
    formData.set("trustedEvidence[0].uri", "https://evidence.example.edu/123");
    formData.set("trustedEvidence[0].description", "Reviewed by faculty.");
    formData.set("trustedResults[0].value", "Pass");
    formData.set("trustedResults[0].resultDate", "2026-05-18");
    formData.set("trustedCriteriaText", "Complete the project.");
    formData.set("criteriaUri", "https://credentials.example.edu/criteria");
    formData.set("trustedAssessments[0].description", "Faculty-scored capstone.");
    formData.set("trustedAssessments[0].assessmentDate", "2026-05-18");
    formData.set("trustedAchievementType", "Project");
    formData.set("trustedRubrics[0].name", "Applied analytics rubric");
    formData.set("trustedRubrics[0].uri", "https://credentials.example.edu/rubrics/applied");
    formData.set("trustedDurationValue", "6 weeks");
    formData.set("trustedCreditsAvailable", "3 credits");
    formData.set("trustedCreditsEarned", "3 credits");
    formData.set("trustedEndorsements[0].endorserName", "Regional Workforce Council");
    formData.set(
      "trustedEndorsements[0].endorserUri",
      "https://workforce.example.edu/endorsements/applied",
    );

    const metadata = trustEdMetadataFromForm(formData);

    expect(metadata.skills).toEqual([
      {
        name: "Applied data analysis",
        identifierUri: "https://skills.example.edu/applied-data",
        source: "Example Skills Framework",
      },
      {
        name: "Stakeholder communication",
        identifierUri: "https://skills.example.edu/communication",
        source: "Example Skills Framework",
      },
    ]);
    expect(metadata.frameworkAlignments[0]?.targetUri).toBe(
      "https://case.example.edu/items/analyze",
    );
    expect(metadata.issuerAuthority?.authorityType).toBe("accreditor");
    expect(metadata.evidence[0]?.description).toBe("Reviewed by faculty.");
    expect(metadata.results).toEqual([{ value: "Pass", resultDate: "2026-05-18" }]);
    expect(metadata.criteria?.text).toBe("Complete the project.");
    expect(metadata.criteria?.uri).toBe("https://credentials.example.edu/criteria");
    expect(metadata.assessments[0]?.description).toBe("Faculty-scored capstone.");
    expect(metadata.achievementType).toBe("Project");
    expect(metadata.rubrics[0]?.name).toBe("Applied analytics rubric");
    expect(metadata.duration?.value).toBe("6 weeks");
    expect(metadata.credits).toEqual({ available: "3 credits", earned: "3 credits" });
    expect(metadata.endorsements[0]?.endorserName).toBe("Regional Workforce Council");
  });

  it("omits empty optional objects and repeatable rows", () => {
    const formData = new FormData();
    formData.set("trustedSkills[0].name", "");
    formData.set("trustedCriteriaText", " ");

    const metadata = trustEdMetadataFromForm(formData);

    expect(metadata.skills).toEqual([]);
    expect(metadata.criteria).toBeNull();
    expect(metadata.issuerAuthority).toBeNull();
    expect(metadata.duration).toBeNull();
    expect(metadata.credits).toBeNull();
  });

  it("keeps sparse indexed rows in submitted order and omits removed rows", () => {
    const formData = new FormData();
    formData.set("trustedSkills[1].name", "Second visible skill");
    formData.set("trustedSkills[1].identifierUri", "");
    formData.set("trustedSkills[3].name", "Fourth visible skill");
    formData.set("trustedSkills[3].source", "Imported framework");
    formData.set("trustedEvidence[2].uri", "https://evidence.example.edu/kept");
    formData.set("trustedEvidence[2].description", "The first two rows were removed in the UI.");

    const metadata = trustEdMetadataFromForm(formData);

    expect(metadata.skills).toEqual([
      {
        name: "Second visible skill",
        identifierUri: null,
        source: null,
      },
      {
        name: "Fourth visible skill",
        identifierUri: null,
        source: "Imported framework",
      },
    ]);
    expect(metadata.evidence).toEqual([
      {
        name: null,
        uri: "https://evidence.example.edu/kept",
        description: "The first two rows were removed in the UI.",
      },
    ]);
  });
});

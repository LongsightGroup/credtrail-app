import { describe, expect, it } from "vitest";
import {
  formHasTrustEdMetadataFields,
  trustedCredentialFieldNames,
  trustEdMetadataFromForm,
} from "./trusted-credential-form-mapper";

describe("trusted credential form mapper", () => {
  it("detects TrustEd metadata fields independently from HTTP routes", () => {
    const emptyForm = new FormData();
    const trustedForm = new FormData();
    trustedForm.set("trustedSkillName", "Applied data analysis");

    expect(formHasTrustEdMetadataFields(emptyForm)).toBe(false);
    expect(formHasTrustEdMetadataFields(trustedForm)).toBe(true);
    expect(trustedCredentialFieldNames).toContain("trustedAssessmentDescription");
  });

  it("maps admin form fields into normalized TrustEd metadata", () => {
    const formData = new FormData();
    formData.set("trustedSkillName", " Applied data analysis ");
    formData.set("trustedSkillIdentifierUri", "https://skills.example.edu/applied-data");
    formData.set("trustedSkillSource", "Example Skills Framework");
    formData.set("trustedFrameworkTargetName", "Analyze civic datasets");
    formData.set("trustedFrameworkTargetUri", "https://case.example.edu/items/analyze");
    formData.set("trustedFrameworkName", "Example CASE Framework");
    formData.set("trustedFrameworkUri", "https://case.example.edu/frameworks/data-analysis");
    formData.set("trustedIssuerAuthorityName", "Middle States Commission");
    formData.set("trustedIssuerAuthorityUri", "https://www.msche.org/institution/0000/");
    formData.set("trustedIssuerAuthorityType", "accreditor");
    formData.set("trustedEvidenceName", "Capstone analysis portfolio");
    formData.set("trustedEvidenceUri", "https://evidence.example.edu/123");
    formData.set("trustedEvidenceDescription", "Reviewed by faculty.");
    formData.set("trustedResultValue", "Pass");
    formData.set("trustedResultDate", "2026-05-18");
    formData.set("trustedCriteriaText", "Complete the project.");
    formData.set("trustedCriteriaUri", "https://credentials.example.edu/criteria");
    formData.set("trustedAssessmentDescription", "Faculty-scored capstone.");
    formData.set("trustedAssessmentDate", "2026-05-18");
    formData.set("trustedAchievementType", "Project");
    formData.set("trustedRubricName", "Applied analytics rubric");
    formData.set("trustedRubricUri", "https://credentials.example.edu/rubrics/applied");
    formData.set("trustedDurationValue", "6 weeks");
    formData.set("trustedCreditsAvailable", "3 credits");
    formData.set("trustedCreditsEarned", "3 credits");
    formData.set("trustedEndorserName", "Regional Workforce Council");
    formData.set("trustedEndorserUri", "https://workforce.example.edu/endorsements/applied");

    const metadata = trustEdMetadataFromForm(formData);

    expect(metadata.skills).toEqual([
      {
        name: "Applied data analysis",
        identifierUri: "https://skills.example.edu/applied-data",
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
    expect(metadata.assessments[0]?.description).toBe("Faculty-scored capstone.");
    expect(metadata.achievementType).toBe("Project");
    expect(metadata.rubrics[0]?.name).toBe("Applied analytics rubric");
    expect(metadata.duration?.value).toBe("6 weeks");
    expect(metadata.credits).toEqual({ available: "3 credits", earned: "3 credits" });
    expect(metadata.endorsements[0]?.endorserName).toBe("Regional Workforce Council");
  });

  it("omits empty optional objects and repeatable rows", () => {
    const formData = new FormData();
    formData.set("trustedSkillName", "");
    formData.set("trustedCriteriaText", " ");

    const metadata = trustEdMetadataFromForm(formData);

    expect(metadata.skills).toEqual([]);
    expect(metadata.criteria).toBeNull();
    expect(metadata.issuerAuthority).toBeNull();
    expect(metadata.duration).toBeNull();
    expect(metadata.credits).toBeNull();
  });
});

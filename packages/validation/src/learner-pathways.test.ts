import { describe, expect, it } from "vitest";
import { parseCreateLearnerPathwayRequest } from "./learner-pathways";

describe("learner pathway validation", () => {
  it("requires a final credential only for credential-producing completion behaviors", () => {
    expect(() =>
      parseCreateLearnerPathwayRequest({
        ownerOrgUnitId: "org_123",
        title: "Clinical Leadership",
        learnerDescription: "Build verified clinical leadership practice.",
        completionBehavior: "review_required",
        requirements: [
          {
            requirementKind: "learner_record",
            learnerRecordType: "course",
            title: "Verified course completion",
          },
        ],
      }),
    ).toThrow("Choose the final credential");

    expect(
      parseCreateLearnerPathwayRequest({
        ownerOrgUnitId: "org_123",
        title: "Clinical Leadership",
        learnerDescription: "Build verified clinical leadership practice.",
        completionBehavior: "mark_complete",
        requirements: [
          {
            requirementKind: "learner_record",
            learnerRecordType: "course",
            title: "Verified course completion",
          },
        ],
      }).completionBehavior,
    ).toBe("mark_complete");
  });

  it("rejects learner-supplemental artifacts as official requirements", () => {
    expect(() =>
      parseCreateLearnerPathwayRequest({
        ownerOrgUnitId: "org_123",
        title: "Clinical Leadership",
        learnerDescription: "Build verified clinical leadership practice.",
        completionBehavior: "mark_complete",
        requirements: [
          {
            requirementKind: "learner_record",
            learnerRecordType: "supplemental_artifact",
            title: "Learner portfolio",
          },
        ],
      }),
    ).toThrow("Invalid option");
  });

  it("rejects a final credential that would depend on itself", () => {
    expect(() =>
      parseCreateLearnerPathwayRequest({
        ownerOrgUnitId: "org_123",
        title: "Clinical Leadership",
        learnerDescription: "Build verified clinical leadership practice.",
        completionBehavior: "credential_eligible",
        finalBadgeTemplateId: "badge_123",
        requirements: [
          {
            requirementKind: "badge_template",
            badgeTemplateId: "badge_123",
            title: "Clinical Leadership",
          },
        ],
      }),
    ).toThrow("cannot also be a pathway requirement");
  });
});

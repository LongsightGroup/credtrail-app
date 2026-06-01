import {
  completeTrustEdCredentialMetadata,
  completeTrustEdCredentialMetadataInput,
} from "@credtrail/validation/testing";
import { describe, expect, it } from "vitest";

import {
  projectTrustEdMetadataToOb3,
  trustEdCredentialDetailsFromOb3Credential,
} from "./trusted-credential-ob3-projection";

describe("projectTrustEdMetadataToOb3", () => {
  it("projects every readiness category into issued credential fields", () => {
    const projection = projectTrustEdMetadataToOb3(completeTrustEdCredentialMetadata());
    const credential = {
      credentialSubject: {
        achievement: projection.achievement,
        ...projection.subject,
      },
    };
    const details = trustEdCredentialDetailsFromOb3Credential(credential);

    expect(projection.achievement).toEqual(
      expect.objectContaining({
        achievementType: completeTrustEdCredentialMetadataInput.achievementType,
        skill: expect.any(Array),
        issuerAuthority: expect.any(Object),
        assessment: expect.any(Array),
        rubric: expect.any(Array),
        duration: expect.any(Object),
        creditValue: expect.any(Object),
        endorsement: expect.any(Array),
      }),
    );
    expect(projection.subject).toEqual(
      expect.objectContaining({
        evidence: expect.any(Array),
        result: expect.any(Array),
      }),
    );
    expect(details.skills).toHaveLength(1);
    expect(details.issuerAuthority?.name).toBe("Middle States Commission on Higher Education");
    expect(details.assessments).toHaveLength(1);
    expect(details.results).toHaveLength(1);
    expect(details.rubrics).toHaveLength(1);
    expect(details.duration).toBe("6 weeks");
    expect(details.credits).toEqual({ available: "3 credits", earned: "3 credits" });
    expect(details.endorsements).toHaveLength(1);
  });
});

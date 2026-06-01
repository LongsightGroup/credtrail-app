import {
  parseTrustEdCredentialMetadata,
  type TrustEdCredentialMetadata,
} from "@credtrail/validation";

export const emptyTrustEdCredentialMetadata = (): TrustEdCredentialMetadata => {
  return {
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
  };
};

export const parseTrustEdCredentialMetadataJson = (
  metadataJson: string | null | undefined,
): TrustEdCredentialMetadata | null => {
  if (metadataJson === null || metadataJson === undefined) {
    return null;
  }

  return parseTrustEdCredentialMetadata(JSON.parse(metadataJson) as unknown);
};

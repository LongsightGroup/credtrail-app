import {
  parseTrustEdCredentialMetadata,
  type TrustEdCredentialMetadata,
} from "@credtrail/validation";

export type TrustEdCredentialMetadataParseResult =
  | {
      status: "empty";
      metadata: null;
      error: null;
    }
  | {
      status: "valid";
      metadata: TrustEdCredentialMetadata;
      error: null;
    }
  | {
      status: "invalid";
      metadata: null;
      error: string;
    };

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

const errorMessageFromUnknown = (error: unknown): string => {
  if (error instanceof Error && error.message.trim().length > 0) {
    return error.message.trim();
  }

  return "Stored TrustEd metadata could not be parsed.";
};

export const parseTrustEdCredentialMetadataJsonResult = (
  metadataJson: string | null | undefined,
): TrustEdCredentialMetadataParseResult => {
  if (metadataJson === null || metadataJson === undefined) {
    return {
      status: "empty",
      metadata: null,
      error: null,
    };
  }

  try {
    const parsed: unknown = JSON.parse(metadataJson);
    return {
      status: "valid",
      metadata: parseTrustEdCredentialMetadata(parsed),
      error: null,
    };
  } catch (error: unknown) {
    return {
      status: "invalid",
      metadata: null,
      error: errorMessageFromUnknown(error),
    };
  }
};

export const parseTrustEdCredentialMetadataJson = (
  metadataJson: string | null | undefined,
): TrustEdCredentialMetadata | null => {
  const result = parseTrustEdCredentialMetadataJsonResult(metadataJson);

  return result.status === "valid" ? result.metadata : null;
};

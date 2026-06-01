import type { JsonObject } from "@credtrail/core-domain";
import type { AssertionRecord } from "@credtrail/db";
import { asJsonObject, asNonEmptyString } from "../utils/value-parsers";

const IMS_GLOBAL_OB3_VALIDATOR_BASE_URL = "https://vc.1ed.tech/upload";

export interface AchievementDetails {
  badgeClassUri: string | null;
  description: string | null;
  criteriaUri: string | null;
  imageUri: string | null;
}

export interface EvidenceDetails {
  uri: string;
  name: string | null;
  description: string | null;
}

export interface TrustEdAlignmentDetails {
  targetUrl: string;
  targetName: string | null;
  targetFramework: string | null;
  frameworkUri: string | null;
}

export interface TrustEdResultDetails {
  value: string;
  resultDate: string;
}

export interface TrustEdCredentialDetails {
  achievementType: string | null;
  criteriaUri: string | null;
  criteriaNarrative: string | null;
  alignments: TrustEdAlignmentDetails[];
  results: TrustEdResultDetails[];
}

export const githubUsernameFromUrl = (value: string): string | null => {
  try {
    const parsedUrl = new URL(value);

    if (parsedUrl.hostname !== "github.com" && parsedUrl.hostname !== "www.github.com") {
      return null;
    }

    const firstPath = parsedUrl.pathname
      .split("/")
      .map((segment) => segment.trim())
      .find((segment) => segment.length > 0);

    if (firstPath === undefined) {
      return null;
    }

    return firstPath;
  } catch {
    return null;
  }
};

export const recipientDisplayNameFromAssertion = (assertion: AssertionRecord): string | null => {
  if (assertion.recipientIdentityType === "email") {
    const email = assertion.recipientIdentity.trim();
    return email.length === 0 ? null : email;
  }

  if (assertion.recipientIdentityType === "url") {
    const username = githubUsernameFromUrl(assertion.recipientIdentity);

    if (username !== null) {
      return `@${username}`;
    }

    try {
      const parsedUrl = new URL(assertion.recipientIdentity);
      return parsedUrl.hostname.replace(/^www\./, "");
    } catch {
      return null;
    }
  }

  return null;
};

export const githubAvatarUrlForUsername = (username: string): string => {
  return `https://github.com/${encodeURIComponent(username)}.png?size=256`;
};

export const recipientAvatarUrlFromAssertion = (assertion: AssertionRecord): string | null => {
  if (assertion.recipientIdentityType !== "url") {
    return null;
  }

  const username = githubUsernameFromUrl(assertion.recipientIdentity);
  return username === null ? null : githubAvatarUrlForUsername(username);
};

export const linkedDataReferenceId = (value: unknown): string | null => {
  const stringValue = asNonEmptyString(value);

  if (stringValue !== null) {
    return stringValue;
  }

  const linkedDataObject = asJsonObject(value);
  return asNonEmptyString(linkedDataObject?.id);
};

export const achievementDetailsFromCredential = (credential: JsonObject): AchievementDetails => {
  const credentialSubject = asJsonObject(credential.credentialSubject);
  const achievement = asJsonObject(credentialSubject?.achievement);

  return {
    badgeClassUri: linkedDataReferenceId(achievement?.id),
    description: asNonEmptyString(achievement?.description),
    criteriaUri: linkedDataReferenceId(achievement?.criteria),
    imageUri: linkedDataReferenceId(achievement?.image),
  };
};

export const imsOb3ValidatorUrl = (targetUrl: string): string => {
  const validatorUrl = new URL(IMS_GLOBAL_OB3_VALIDATOR_BASE_URL);
  validatorUrl.searchParams.set("validatorId", "OB30Inspector");
  validatorUrl.searchParams.set("uri", targetUrl);
  return validatorUrl.toString();
};

const evidenceDetailsFromValue = (value: unknown): EvidenceDetails | null => {
  const uri = linkedDataReferenceId(value);

  if (uri === null) {
    return null;
  }

  const evidenceObject = asJsonObject(value);

  return {
    uri,
    name: asNonEmptyString(evidenceObject?.name),
    description: asNonEmptyString(evidenceObject?.description),
  };
};

export const evidenceDetailsFromCredential = (credential: JsonObject): EvidenceDetails[] => {
  const credentialSubject = asJsonObject(credential.credentialSubject);
  const evidence = credentialSubject?.evidence;

  if (Array.isArray(evidence)) {
    const mappedEvidence = evidence.map((entry) => evidenceDetailsFromValue(entry));
    return mappedEvidence.filter((entry): entry is EvidenceDetails => entry !== null);
  }

  const singularEvidence = evidenceDetailsFromValue(evidence);
  return singularEvidence === null ? [] : [singularEvidence];
};

const trustEdAlignmentDetailsFromValue = (value: unknown): TrustEdAlignmentDetails | null => {
  const alignment = asJsonObject(value);
  const targetUrl = asNonEmptyString(alignment?.targetUrl);

  if (targetUrl === null) {
    return null;
  }

  return {
    targetUrl,
    targetName: asNonEmptyString(alignment?.targetName),
    targetFramework: asNonEmptyString(alignment?.targetFramework),
    frameworkUri: asNonEmptyString(alignment?.frameworkUri),
  };
};

const trustEdResultDetailsFromValue = (value: unknown): TrustEdResultDetails | null => {
  const result = asJsonObject(value);
  const resultValue = asNonEmptyString(result?.value);
  const resultDate = asNonEmptyString(result?.resultDate);

  if (resultValue === null || resultDate === null) {
    return null;
  }

  return {
    value: resultValue,
    resultDate,
  };
};

const arrayFromLinkedDataValue = (value: unknown): unknown[] => {
  if (Array.isArray(value)) {
    return value;
  }

  return value === undefined || value === null ? [] : [value];
};

export const trustEdCredentialDetailsFromCredential = (
  credential: JsonObject,
): TrustEdCredentialDetails => {
  const credentialSubject = asJsonObject(credential.credentialSubject);
  const achievement = asJsonObject(credentialSubject?.achievement);
  const criteria = asJsonObject(achievement?.criteria);
  const alignments = arrayFromLinkedDataValue(achievement?.alignment)
    .map((entry) => trustEdAlignmentDetailsFromValue(entry))
    .filter((entry): entry is TrustEdAlignmentDetails => entry !== null);
  const results = arrayFromLinkedDataValue(credentialSubject?.result)
    .map((entry) => trustEdResultDetailsFromValue(entry))
    .filter((entry): entry is TrustEdResultDetails => entry !== null);

  return {
    achievementType: asNonEmptyString(achievement?.achievementType),
    criteriaUri: linkedDataReferenceId(achievement?.criteria),
    criteriaNarrative: asNonEmptyString(criteria?.narrative),
    alignments,
    results,
  };
};

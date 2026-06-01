import {
  parseTrustEdCredentialMetadata,
  type TrustEdCredentialMetadata,
} from "@credtrail/validation";

export const trustedCredentialFieldNames = [
  "trustedSkillName",
  "trustedSkillIdentifierUri",
  "trustedSkillSource",
  "trustedFrameworkTargetName",
  "trustedFrameworkTargetUri",
  "trustedFrameworkName",
  "trustedFrameworkUri",
  "trustedIssuerAuthorityName",
  "trustedIssuerAuthorityUri",
  "trustedIssuerAuthorityType",
  "trustedEvidenceName",
  "trustedEvidenceUri",
  "trustedEvidenceDescription",
  "trustedResultValue",
  "trustedResultDate",
  "trustedCriteriaText",
  "trustedCriteriaUri",
  "trustedAssessmentDescription",
  "trustedAssessmentDate",
  "trustedAchievementType",
  "trustedRubricName",
  "trustedRubricUri",
  "trustedDurationValue",
  "trustedCreditsAvailable",
  "trustedCreditsEarned",
  "trustedEndorserName",
  "trustedEndorserUri",
] as const;

const optionalFormText = (formData: FormData, name: string): string | undefined => {
  const value = formData.get(name);

  if (typeof value !== "string") {
    return undefined;
  }

  const trimmed = value.trim();

  return trimmed.length === 0 ? undefined : trimmed;
};

const nullableFormText = (formData: FormData, name: string): string | null => {
  return optionalFormText(formData, name) ?? null;
};

// Admin forms expose one row per repeatable field; keep arrays at length 0 or 1 until multi-entry UI exists.
const oneWhenAny = <ValueType extends Record<string, string | null>>(
  entry: ValueType,
): ValueType[] => {
  return Object.values(entry).some((value) => value !== null) ? [entry] : [];
};

export const formHasTrustEdMetadataFields = (formData: FormData): boolean => {
  return trustedCredentialFieldNames.some((fieldName) => formData.has(fieldName));
};

export const trustEdMetadataFromForm = (formData: FormData): TrustEdCredentialMetadata => {
  const metadata = {
    skills: oneWhenAny({
      name: nullableFormText(formData, "trustedSkillName"),
      identifierUri: nullableFormText(formData, "trustedSkillIdentifierUri"),
      source: nullableFormText(formData, "trustedSkillSource"),
    }),
    frameworkAlignments: oneWhenAny({
      targetName: nullableFormText(formData, "trustedFrameworkTargetName"),
      targetUri: nullableFormText(formData, "trustedFrameworkTargetUri"),
      frameworkName: nullableFormText(formData, "trustedFrameworkName"),
      frameworkUri: nullableFormText(formData, "trustedFrameworkUri"),
    }),
    issuerAuthority: {
      name: nullableFormText(formData, "trustedIssuerAuthorityName"),
      uri: nullableFormText(formData, "trustedIssuerAuthorityUri"),
      authorityType: nullableFormText(formData, "trustedIssuerAuthorityType"),
    },
    evidence: oneWhenAny({
      name: nullableFormText(formData, "trustedEvidenceName"),
      uri: nullableFormText(formData, "trustedEvidenceUri"),
      description: nullableFormText(formData, "trustedEvidenceDescription"),
    }),
    results: oneWhenAny({
      value: nullableFormText(formData, "trustedResultValue"),
      resultDate: nullableFormText(formData, "trustedResultDate"),
    }),
    criteria: {
      text: nullableFormText(formData, "trustedCriteriaText"),
      uri: nullableFormText(formData, "trustedCriteriaUri"),
    },
    assessments: oneWhenAny({
      description: nullableFormText(formData, "trustedAssessmentDescription"),
      assessmentDate: nullableFormText(formData, "trustedAssessmentDate"),
    }),
    achievementType: nullableFormText(formData, "trustedAchievementType"),
    rubrics: oneWhenAny({
      name: nullableFormText(formData, "trustedRubricName"),
      uri: nullableFormText(formData, "trustedRubricUri"),
    }),
    duration: {
      value: nullableFormText(formData, "trustedDurationValue"),
    },
    credits: {
      available: nullableFormText(formData, "trustedCreditsAvailable"),
      earned: nullableFormText(formData, "trustedCreditsEarned"),
    },
    endorsements: oneWhenAny({
      endorserName: nullableFormText(formData, "trustedEndorserName"),
      endorserUri: nullableFormText(formData, "trustedEndorserUri"),
    }),
  };

  const issuerAuthority =
    metadata.issuerAuthority.name === null &&
    metadata.issuerAuthority.uri === null &&
    metadata.issuerAuthority.authorityType === null
      ? null
      : metadata.issuerAuthority;
  const criteria =
    metadata.criteria.text === null && metadata.criteria.uri === null ? null : metadata.criteria;
  const duration = metadata.duration.value === null ? null : metadata.duration;
  const credits =
    metadata.credits.available === null && metadata.credits.earned === null
      ? null
      : metadata.credits;

  return parseTrustEdCredentialMetadata({
    ...metadata,
    issuerAuthority,
    criteria,
    duration,
    credits,
  });
};

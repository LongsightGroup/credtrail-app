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

const oneWhenAny = <ValueType extends Record<string, string | null | undefined>>(
  entry: ValueType,
): ValueType[] => {
  return Object.values(entry).some((value) => value !== null) ? [entry] : [];
};

const mergeEditableFirstRow = <ValueType extends Record<string, string | null | undefined>>(
  entry: ValueType,
  existingRows: readonly ValueType[] | undefined,
): ValueType[] => {
  // v1 renders and edits row 0 only. Preserve any stored tail rows until the UI supports multi-row editing.
  return [...oneWhenAny(entry), ...(existingRows?.slice(1) ?? [])];
};

export const formHasTrustEdMetadataFields = (formData: FormData): boolean => {
  return trustedCredentialFieldNames.some((fieldName) => formData.has(fieldName));
};

export const trustEdMetadataFromForm = (
  formData: FormData,
  existingMetadata?: TrustEdCredentialMetadata | null,
): TrustEdCredentialMetadata => {
  const metadata = {
    skills: mergeEditableFirstRow(
      {
        name: nullableFormText(formData, "trustedSkillName"),
        identifierUri: nullableFormText(formData, "trustedSkillIdentifierUri"),
        source: nullableFormText(formData, "trustedSkillSource"),
      },
      existingMetadata?.skills,
    ),
    frameworkAlignments: mergeEditableFirstRow(
      {
        targetName: nullableFormText(formData, "trustedFrameworkTargetName"),
        targetUri: nullableFormText(formData, "trustedFrameworkTargetUri"),
        frameworkName: nullableFormText(formData, "trustedFrameworkName"),
        frameworkUri: nullableFormText(formData, "trustedFrameworkUri"),
      },
      existingMetadata?.frameworkAlignments,
    ),
    issuerAuthority: {
      name: nullableFormText(formData, "trustedIssuerAuthorityName"),
      uri: nullableFormText(formData, "trustedIssuerAuthorityUri"),
      authorityType: nullableFormText(formData, "trustedIssuerAuthorityType"),
    },
    evidence: mergeEditableFirstRow(
      {
        name: nullableFormText(formData, "trustedEvidenceName"),
        uri: nullableFormText(formData, "trustedEvidenceUri"),
        description: nullableFormText(formData, "trustedEvidenceDescription"),
      },
      existingMetadata?.evidence,
    ),
    results: mergeEditableFirstRow(
      {
        value: nullableFormText(formData, "trustedResultValue"),
        resultDate: nullableFormText(formData, "trustedResultDate"),
      },
      existingMetadata?.results,
    ),
    criteria: {
      text: nullableFormText(formData, "trustedCriteriaText"),
      uri: nullableFormText(formData, "trustedCriteriaUri"),
    },
    assessments: mergeEditableFirstRow(
      {
        description: nullableFormText(formData, "trustedAssessmentDescription"),
        assessmentDate: nullableFormText(formData, "trustedAssessmentDate"),
      },
      existingMetadata?.assessments,
    ),
    achievementType: nullableFormText(formData, "trustedAchievementType"),
    rubrics: mergeEditableFirstRow(
      {
        name: nullableFormText(formData, "trustedRubricName"),
        uri: nullableFormText(formData, "trustedRubricUri"),
      },
      existingMetadata?.rubrics,
    ),
    duration: {
      value: nullableFormText(formData, "trustedDurationValue"),
    },
    credits: {
      available: nullableFormText(formData, "trustedCreditsAvailable"),
      earned: nullableFormText(formData, "trustedCreditsEarned"),
    },
    endorsements: mergeEditableFirstRow(
      {
        endorserName: nullableFormText(formData, "trustedEndorserName"),
        endorserUri: nullableFormText(formData, "trustedEndorserUri"),
      },
      existingMetadata?.endorsements,
    ),
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

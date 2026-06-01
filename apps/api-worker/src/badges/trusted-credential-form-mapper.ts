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

const trustedCredentialRepeatableGroupNames = [
  "trustedSkills",
  "trustedFrameworkAlignments",
  "trustedEvidence",
  "trustedResults",
  "trustedAssessments",
  "trustedRubrics",
  "trustedEndorsements",
] as const;

const formHasIndexedTrustEdMetadataFields = (formData: FormData): boolean => {
  const indexedFieldPattern = new RegExp(
    `^(${trustedCredentialRepeatableGroupNames.join("|")})\\[\\d+\\]\\.`,
  );

  for (const key of formData.keys()) {
    if (indexedFieldPattern.test(key)) {
      return true;
    }
  }

  return false;
};

const escapeRegExp = (value: string): string => {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
};

const indexedRowsFromForm = <FieldName extends string>(
  formData: FormData,
  groupName: string,
  fieldNames: readonly FieldName[],
): Array<Record<FieldName, string | null>> => {
  const fieldNamePattern = fieldNames.map(escapeRegExp).join("|");
  const keyPattern = new RegExp(`^${escapeRegExp(groupName)}\\[(\\d+)\\]\\.(${fieldNamePattern})$`);
  const rows = new Map<number, Partial<Record<FieldName, string | null>>>();

  for (const key of formData.keys()) {
    const match = keyPattern.exec(key);

    if (match === null) {
      continue;
    }

    const rowIndex = Number.parseInt(match[1] ?? "", 10);
    const fieldName = match[2] as FieldName | undefined;

    if (!Number.isInteger(rowIndex) || fieldName === undefined) {
      continue;
    }

    const row: Partial<Record<FieldName, string | null>> = rows.get(rowIndex) ?? {};
    row[fieldName] = nullableFormText(formData, key);
    rows.set(rowIndex, row);
  }

  return [...rows.entries()]
    .sort(([leftIndex], [rightIndex]) => leftIndex - rightIndex)
    .map(([, row]) => {
      const completeRow = {} as Record<FieldName, string | null>;

      for (const fieldName of fieldNames) {
        completeRow[fieldName] = row[fieldName] ?? null;
      }

      return completeRow;
    })
    .filter((row) => Object.values(row).some((value) => value !== null));
};

export const formHasTrustEdMetadataFields = (formData: FormData): boolean => {
  return (
    trustedCredentialFieldNames.some((fieldName) => formData.has(fieldName)) ||
    formHasIndexedTrustEdMetadataFields(formData)
  );
};

const repeatableRowsFromForm = <ValueType extends Record<string, string | null>>(
  formData: FormData,
  groupName: string,
  fieldNames: readonly (keyof ValueType & string)[],
  legacyEntry: ValueType,
): ValueType[] => {
  const indexedRows = indexedRowsFromForm(formData, groupName, fieldNames) as ValueType[];

  return indexedRows.length > 0 ? indexedRows : oneWhenAny(legacyEntry);
};

export const trustEdMetadataFromForm = (formData: FormData): TrustEdCredentialMetadata => {
  const metadata = {
    skills: repeatableRowsFromForm(formData, "trustedSkills", ["name", "identifierUri", "source"], {
      name: nullableFormText(formData, "trustedSkillName"),
      identifierUri: nullableFormText(formData, "trustedSkillIdentifierUri"),
      source: nullableFormText(formData, "trustedSkillSource"),
    }),
    frameworkAlignments: repeatableRowsFromForm(
      formData,
      "trustedFrameworkAlignments",
      ["targetName", "targetUri", "frameworkName", "frameworkUri"],
      {
        targetName: nullableFormText(formData, "trustedFrameworkTargetName"),
        targetUri: nullableFormText(formData, "trustedFrameworkTargetUri"),
        frameworkName: nullableFormText(formData, "trustedFrameworkName"),
        frameworkUri: nullableFormText(formData, "trustedFrameworkUri"),
      },
    ),
    issuerAuthority: {
      name: nullableFormText(formData, "trustedIssuerAuthorityName"),
      uri: nullableFormText(formData, "trustedIssuerAuthorityUri"),
      authorityType: nullableFormText(formData, "trustedIssuerAuthorityType"),
    },
    evidence: repeatableRowsFromForm(formData, "trustedEvidence", ["name", "uri", "description"], {
      name: nullableFormText(formData, "trustedEvidenceName"),
      uri: nullableFormText(formData, "trustedEvidenceUri"),
      description: nullableFormText(formData, "trustedEvidenceDescription"),
    }),
    results: repeatableRowsFromForm(formData, "trustedResults", ["value", "resultDate"], {
      value: nullableFormText(formData, "trustedResultValue"),
      resultDate: nullableFormText(formData, "trustedResultDate"),
    }),
    criteria: {
      text: nullableFormText(formData, "trustedCriteriaText"),
      uri: nullableFormText(formData, "trustedCriteriaUri"),
    },
    assessments: repeatableRowsFromForm(
      formData,
      "trustedAssessments",
      ["description", "assessmentDate"],
      {
        description: nullableFormText(formData, "trustedAssessmentDescription"),
        assessmentDate: nullableFormText(formData, "trustedAssessmentDate"),
      },
    ),
    achievementType: nullableFormText(formData, "trustedAchievementType"),
    rubrics: repeatableRowsFromForm(formData, "trustedRubrics", ["name", "uri"], {
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
    endorsements: repeatableRowsFromForm(
      formData,
      "trustedEndorsements",
      ["endorserName", "endorserUri"],
      {
        endorserName: nullableFormText(formData, "trustedEndorserName"),
        endorserUri: nullableFormText(formData, "trustedEndorserUri"),
      },
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

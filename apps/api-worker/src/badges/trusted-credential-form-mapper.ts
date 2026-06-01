import {
  parseTrustEdCredentialMetadata,
  type TrustEdCredentialMetadata,
} from "@credtrail/validation";

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

const trustedCredentialRepeatableGroupNames = [
  "trustedSkills",
  "trustedFrameworkAlignments",
  "trustedEvidence",
  "trustedResults",
  "trustedAssessments",
  "trustedRubrics",
  "trustedEndorsements",
] as const;

const trustedCredentialScalarFieldNames = new Set<string>([
  "trustedIssuerAuthorityName",
  "trustedIssuerAuthorityUri",
  "trustedIssuerAuthorityType",
  "trustedCriteriaText",
  "trustedAchievementType",
  "trustedDurationValue",
  "trustedCreditsAvailable",
  "trustedCreditsEarned",
]);

const escapeRegExp = (value: string): string => {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
};

const indexedFieldPattern = new RegExp(
  `^(${trustedCredentialRepeatableGroupNames.join("|")})\\[\\d+\\]\\.`,
);

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
  for (const key of formData.keys()) {
    if (trustedCredentialScalarFieldNames.has(key) || indexedFieldPattern.test(key)) {
      return true;
    }
  }

  return false;
};

const repeatableRowsFromForm = <ValueType extends Record<string, string | null>>(
  formData: FormData,
  groupName: string,
  fieldNames: readonly (keyof ValueType & string)[],
): ValueType[] => {
  return indexedRowsFromForm(formData, groupName, fieldNames) as ValueType[];
};

export const trustEdMetadataFromForm = (formData: FormData): TrustEdCredentialMetadata => {
  const metadata = {
    skills: repeatableRowsFromForm(formData, "trustedSkills", ["name", "identifierUri", "source"]),
    frameworkAlignments: repeatableRowsFromForm(formData, "trustedFrameworkAlignments", [
      "targetName",
      "targetUri",
      "frameworkName",
      "frameworkUri",
    ]),
    issuerAuthority: {
      name: nullableFormText(formData, "trustedIssuerAuthorityName"),
      uri: nullableFormText(formData, "trustedIssuerAuthorityUri"),
      authorityType: nullableFormText(formData, "trustedIssuerAuthorityType"),
    },
    evidence: repeatableRowsFromForm(formData, "trustedEvidence", ["name", "uri", "description"]),
    results: repeatableRowsFromForm(formData, "trustedResults", ["value", "resultDate"]),
    criteria: {
      text: nullableFormText(formData, "trustedCriteriaText"),
      uri: nullableFormText(formData, "criteriaUri"),
    },
    assessments: repeatableRowsFromForm(formData, "trustedAssessments", [
      "description",
      "assessmentDate",
    ]),
    achievementType: nullableFormText(formData, "trustedAchievementType"),
    rubrics: repeatableRowsFromForm(formData, "trustedRubrics", ["name", "uri"]),
    duration: {
      value: nullableFormText(formData, "trustedDurationValue"),
    },
    credits: {
      available: nullableFormText(formData, "trustedCreditsAvailable"),
      earned: nullableFormText(formData, "trustedCreditsEarned"),
    },
    endorsements: repeatableRowsFromForm(formData, "trustedEndorsements", [
      "endorserName",
      "endorserUri",
    ]),
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

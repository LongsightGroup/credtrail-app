import type { JsonObject } from "@credtrail/core-domain";
import type { TrustEdCredentialMetadata } from "@credtrail/validation";
import { asJsonObject, asNonEmptyString } from "../utils/value-parsers";

export interface TrustEdCredentialOb3Projection {
  achievement: JsonObject;
  subject: JsonObject;
}

export interface TrustEdNamedReferenceDetails {
  name: string | null;
  uri: string | null;
}

export interface TrustEdAlignmentDetails {
  targetUrl: string;
  targetName: string | null;
  targetFramework: string | null;
  frameworkUri: string | null;
}

export interface TrustEdSkillDetails {
  name: string | null;
  identifierUri: string | null;
  source: string | null;
}

export interface TrustEdIssuerAuthorityDetails {
  name: string | null;
  uri: string | null;
  authorityType: string | null;
}

export interface TrustEdAssessmentDetails {
  description: string | null;
  assessmentDate: string | null;
}

export interface TrustEdResultDetails {
  value: string;
  resultDate: string;
}

export interface TrustEdCreditsDetails {
  available: string | null;
  earned: string | null;
}

export interface TrustEdEndorsementDetails {
  endorserName: string | null;
  endorserUri: string | null;
}

export interface TrustEdCredentialDetails {
  achievementType: string | null;
  criteriaUri: string | null;
  criteriaNarrative: string | null;
  alignments: TrustEdAlignmentDetails[];
  skills: TrustEdSkillDetails[];
  issuerAuthority: TrustEdIssuerAuthorityDetails | null;
  assessments: TrustEdAssessmentDetails[];
  results: TrustEdResultDetails[];
  rubrics: TrustEdNamedReferenceDetails[];
  duration: string | null;
  credits: TrustEdCreditsDetails | null;
  endorsements: TrustEdEndorsementDetails[];
}

const objectArray = <ValueType>(
  values: readonly ValueType[],
  mapValue: (value: ValueType) => JsonObject | null,
): JsonObject[] => {
  return values
    .map((value) => mapValue(value))
    .filter((value): value is JsonObject => value !== null);
};

export const projectTrustEdMetadataToOb3 = (
  metadata: TrustEdCredentialMetadata,
): TrustEdCredentialOb3Projection => {
  const alignment = objectArray(metadata.frameworkAlignments, (alignmentMetadata) => {
    if (alignmentMetadata.targetUri === null) {
      return null;
    }

    return {
      type: ["Alignment"],
      targetUrl: alignmentMetadata.targetUri,
      ...(alignmentMetadata.targetName === null
        ? {}
        : { targetName: alignmentMetadata.targetName }),
      ...(alignmentMetadata.frameworkName === null
        ? {}
        : { targetFramework: alignmentMetadata.frameworkName }),
      ...(alignmentMetadata.frameworkUri === null
        ? {}
        : { frameworkUri: alignmentMetadata.frameworkUri }),
    };
  });
  const evidence = objectArray(metadata.evidence, (evidenceMetadata) => {
    if (evidenceMetadata.uri === null && evidenceMetadata.name === null) {
      return null;
    }

    return {
      type: ["Evidence"],
      ...(evidenceMetadata.uri === null ? {} : { id: evidenceMetadata.uri }),
      ...(evidenceMetadata.name === null ? {} : { name: evidenceMetadata.name }),
      ...(evidenceMetadata.description === null
        ? {}
        : { description: evidenceMetadata.description }),
    };
  });
  const result = objectArray(metadata.results, (resultMetadata) => {
    if (resultMetadata.value === null || resultMetadata.resultDate === null) {
      return null;
    }

    return {
      type: ["Result"],
      value: resultMetadata.value,
      resultDate: resultMetadata.resultDate,
    };
  });
  const skills = objectArray(metadata.skills, (skill) => {
    if (skill.name === null && skill.identifierUri === null) {
      return null;
    }

    return {
      type: ["Skill"],
      ...(skill.identifierUri === null ? {} : { id: skill.identifierUri }),
      ...(skill.name === null ? {} : { name: skill.name }),
      ...(skill.source === null ? {} : { source: skill.source }),
    };
  });
  const assessments = objectArray(metadata.assessments, (assessment) => {
    if (assessment.description === null && assessment.assessmentDate === null) {
      return null;
    }

    return {
      type: ["Assessment"],
      ...(assessment.description === null ? {} : { description: assessment.description }),
      ...(assessment.assessmentDate === null ? {} : { assessmentDate: assessment.assessmentDate }),
    };
  });
  const rubrics = objectArray(metadata.rubrics, (rubric) => {
    if (rubric.name === null && rubric.uri === null) {
      return null;
    }

    return {
      type: ["Rubric"],
      ...(rubric.uri === null ? {} : { id: rubric.uri }),
      ...(rubric.name === null ? {} : { name: rubric.name }),
    };
  });
  const endorsements = objectArray(metadata.endorsements, (endorsement) => {
    if (endorsement.endorserName === null && endorsement.endorserUri === null) {
      return null;
    }

    return {
      type: ["Endorsement"],
      ...(endorsement.endorserUri === null ? {} : { id: endorsement.endorserUri }),
      ...(endorsement.endorserName === null ? {} : { name: endorsement.endorserName }),
    };
  });
  const issuerAuthority =
    metadata.issuerAuthority === null
      ? null
      : {
          type: ["IssuerAuthority"],
          ...(metadata.issuerAuthority.uri === null ? {} : { id: metadata.issuerAuthority.uri }),
          ...(metadata.issuerAuthority.name === null
            ? {}
            : { name: metadata.issuerAuthority.name }),
          ...(metadata.issuerAuthority.authorityType === null
            ? {}
            : { authorityType: metadata.issuerAuthority.authorityType }),
        };
  const duration =
    metadata.duration === null || metadata.duration.value === null
      ? null
      : {
          type: ["Duration"],
          value: metadata.duration.value,
        };
  const credits =
    metadata.credits === null
      ? null
      : {
          type: ["CreditValue"],
          ...(metadata.credits.available === null ? {} : { available: metadata.credits.available }),
          ...(metadata.credits.earned === null ? {} : { earned: metadata.credits.earned }),
        };

  return {
    achievement: {
      ...(metadata.achievementType === null ? {} : { achievementType: metadata.achievementType }),
      ...(alignment.length === 0 ? {} : { alignment }),
      ...(metadata.criteria === null
        ? {}
        : {
            criteria: {
              type: "Criteria",
              ...(metadata.criteria.uri === null ? {} : { id: metadata.criteria.uri }),
              ...(metadata.criteria.text === null ? {} : { narrative: metadata.criteria.text }),
            },
          }),
      ...(skills.length === 0 ? {} : { skill: skills }),
      ...(issuerAuthority === null ? {} : { issuerAuthority }),
      ...(assessments.length === 0 ? {} : { assessment: assessments }),
      ...(rubrics.length === 0 ? {} : { rubric: rubrics }),
      ...(duration === null ? {} : { duration }),
      ...(credits === null ? {} : { creditValue: credits }),
      ...(endorsements.length === 0 ? {} : { endorsement: endorsements }),
    },
    subject: {
      ...(evidence.length === 0 ? {} : { evidence }),
      ...(result.length === 0 ? {} : { result }),
    },
  };
};

const arrayFromLinkedDataValue = (value: unknown): unknown[] => {
  if (Array.isArray(value)) {
    return value;
  }

  return value === undefined || value === null ? [] : [value];
};

const linkedDataReferenceId = (value: unknown): string | null => {
  const stringValue = asNonEmptyString(value);

  if (stringValue !== null) {
    return stringValue;
  }

  const linkedDataObject = asJsonObject(value);
  return asNonEmptyString(linkedDataObject?.id);
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

const trustEdSkillDetailsFromValue = (value: unknown): TrustEdSkillDetails | null => {
  const skill = asJsonObject(value);
  const name = asNonEmptyString(skill?.name);
  const identifierUri = linkedDataReferenceId(value);

  if (name === null && identifierUri === null) {
    return null;
  }

  return {
    name,
    identifierUri,
    source: asNonEmptyString(skill?.source),
  };
};

const trustEdAssessmentDetailsFromValue = (value: unknown): TrustEdAssessmentDetails | null => {
  const assessment = asJsonObject(value);
  const description = asNonEmptyString(assessment?.description);
  const assessmentDate = asNonEmptyString(assessment?.assessmentDate);

  if (description === null && assessmentDate === null) {
    return null;
  }

  return {
    description,
    assessmentDate,
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

const trustEdNamedReferenceDetailsFromValue = (
  value: unknown,
): TrustEdNamedReferenceDetails | null => {
  const reference = asJsonObject(value);
  const name = asNonEmptyString(reference?.name);
  const uri = linkedDataReferenceId(value);

  if (name === null && uri === null) {
    return null;
  }

  return {
    name,
    uri,
  };
};

const trustEdEndorsementDetailsFromValue = (value: unknown): TrustEdEndorsementDetails | null => {
  const endorsement = asJsonObject(value);
  const endorserName = asNonEmptyString(endorsement?.name);
  const endorserUri = linkedDataReferenceId(value);

  if (endorserName === null && endorserUri === null) {
    return null;
  }

  return {
    endorserName,
    endorserUri,
  };
};

export const trustEdCredentialDetailsFromOb3Credential = (
  credential: JsonObject,
): TrustEdCredentialDetails => {
  const credentialSubject = asJsonObject(credential.credentialSubject);
  const achievement = asJsonObject(credentialSubject?.achievement);
  const criteria = asJsonObject(achievement?.criteria);
  const issuerAuthority = asJsonObject(achievement?.issuerAuthority);
  const duration = asJsonObject(achievement?.duration);
  const credits = asJsonObject(achievement?.creditValue);

  return {
    achievementType: asNonEmptyString(achievement?.achievementType),
    criteriaUri: linkedDataReferenceId(achievement?.criteria),
    criteriaNarrative: asNonEmptyString(criteria?.narrative),
    alignments: arrayFromLinkedDataValue(achievement?.alignment)
      .map((entry) => trustEdAlignmentDetailsFromValue(entry))
      .filter((entry): entry is TrustEdAlignmentDetails => entry !== null),
    skills: arrayFromLinkedDataValue(achievement?.skill)
      .map((entry) => trustEdSkillDetailsFromValue(entry))
      .filter((entry): entry is TrustEdSkillDetails => entry !== null),
    issuerAuthority:
      issuerAuthority === null
        ? null
        : {
            name: asNonEmptyString(issuerAuthority.name),
            uri: linkedDataReferenceId(issuerAuthority),
            authorityType: asNonEmptyString(issuerAuthority.authorityType),
          },
    assessments: arrayFromLinkedDataValue(achievement?.assessment)
      .map((entry) => trustEdAssessmentDetailsFromValue(entry))
      .filter((entry): entry is TrustEdAssessmentDetails => entry !== null),
    results: arrayFromLinkedDataValue(credentialSubject?.result)
      .map((entry) => trustEdResultDetailsFromValue(entry))
      .filter((entry): entry is TrustEdResultDetails => entry !== null),
    rubrics: arrayFromLinkedDataValue(achievement?.rubric)
      .map((entry) => trustEdNamedReferenceDetailsFromValue(entry))
      .filter((entry): entry is TrustEdNamedReferenceDetails => entry !== null),
    duration: asNonEmptyString(duration?.value),
    credits:
      credits === null
        ? null
        : {
            available: asNonEmptyString(credits.available),
            earned: asNonEmptyString(credits.earned),
          },
    endorsements: arrayFromLinkedDataValue(achievement?.endorsement)
      .map((entry) => trustEdEndorsementDetailsFromValue(entry))
      .filter((entry): entry is TrustEdEndorsementDetails => entry !== null),
  };
};

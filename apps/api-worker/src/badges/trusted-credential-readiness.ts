export type TrustEdCredentialReadinessStatus = "not_evaluated" | "incomplete" | "ready";
export type TrustEdCredentialReadinessCheckCategory = "required" | "recommended";
export type TrustEdCredentialReadinessCheckStatus = "satisfied" | "missing";

export type TrustEdCredentialReadinessCheckId =
  | "skills"
  | "framework_alignment"
  | "issuer_authority"
  | "evidence"
  | "result"
  | "criteria"
  | "assessment"
  | "achievement_type"
  | "rubric"
  | "duration_credit"
  | "endorsement";

export interface TrustEdCredentialSkill {
  name: string | null;
  identifierUri: string | null;
  source: string | null;
}

export interface TrustEdCredentialFrameworkAlignment {
  targetName: string | null;
  targetUri: string | null;
  frameworkName: string | null;
  frameworkUri: string | null;
}

export interface TrustEdCredentialIssuerAuthority {
  name: string | null;
  uri: string | null;
  authorityType: string | null;
}

export interface TrustEdCredentialEvidenceArtifact {
  name: string | null;
  uri: string | null;
  description: string | null;
}

export interface TrustEdCredentialResult {
  value: string | null;
  resultDate: string | null;
}

export interface TrustEdCredentialCriteria {
  text: string | null;
  uri: string | null;
}

export interface TrustEdCredentialAssessment {
  description: string | null;
  assessmentDate: string | null;
}

export interface TrustEdCredentialRubric {
  name: string | null;
  uri: string | null;
}

export interface TrustEdCredentialDuration {
  value: string | null;
}

export interface TrustEdCredentialCredits {
  available: string | null;
  earned: string | null;
}

export interface TrustEdCredentialEndorsement {
  endorserName: string | null;
  endorserUri: string | null;
}

export interface TrustEdCredentialMetadata {
  skills: readonly TrustEdCredentialSkill[];
  frameworkAlignments: readonly TrustEdCredentialFrameworkAlignment[];
  issuerAuthority: TrustEdCredentialIssuerAuthority | null;
  evidence: readonly TrustEdCredentialEvidenceArtifact[];
  results: readonly TrustEdCredentialResult[];
  criteria: TrustEdCredentialCriteria | null;
  assessments: readonly TrustEdCredentialAssessment[];
  achievementType: string | null;
  rubrics: readonly TrustEdCredentialRubric[];
  duration: TrustEdCredentialDuration | null;
  credits: TrustEdCredentialCredits | null;
  endorsements: readonly TrustEdCredentialEndorsement[];
}

export interface TrustEdCredentialReadinessCheck {
  id: TrustEdCredentialReadinessCheckId;
  category: TrustEdCredentialReadinessCheckCategory;
  status: TrustEdCredentialReadinessCheckStatus;
  label: string;
  message: string;
}

export interface TrustEdCredentialReadinessResult {
  status: TrustEdCredentialReadinessStatus;
  checks: readonly TrustEdCredentialReadinessCheck[];
}

const hasText = (value: string | null): boolean => {
  return value !== null && value.trim().length > 0;
};

const isSpecificAchievementType = (value: string | null): boolean => {
  if (value === null || value.trim().length === 0) {
    return false;
  }

  const normalized = value.trim().toLowerCase();
  return normalized !== "n/a" && normalized !== "not applicable";
};

const check = (
  id: TrustEdCredentialReadinessCheckId,
  category: TrustEdCredentialReadinessCheckCategory,
  satisfied: boolean,
  label: string,
  satisfiedMessage: string,
  missingMessage: string,
): TrustEdCredentialReadinessCheck => {
  return {
    id,
    category,
    status: satisfied ? "satisfied" : "missing",
    label,
    message: satisfied ? satisfiedMessage : missingMessage,
  };
};

const hasSkill = (metadata: TrustEdCredentialMetadata): boolean => {
  return metadata.skills.some((skill) => hasText(skill.name) || hasText(skill.identifierUri));
};

const hasFrameworkAlignment = (metadata: TrustEdCredentialMetadata): boolean => {
  return metadata.frameworkAlignments.some((alignment) => hasText(alignment.targetUri));
};

const hasIssuerAuthority = (metadata: TrustEdCredentialMetadata): boolean => {
  return (
    metadata.issuerAuthority !== null &&
    (hasText(metadata.issuerAuthority.name) || hasText(metadata.issuerAuthority.uri))
  );
};

const hasEvidence = (metadata: TrustEdCredentialMetadata): boolean => {
  return metadata.evidence.some((artifact) => hasText(artifact.uri) || hasText(artifact.name));
};

const hasResult = (metadata: TrustEdCredentialMetadata): boolean => {
  return metadata.results.some((result) => hasText(result.value) && hasText(result.resultDate));
};

const hasCriteria = (metadata: TrustEdCredentialMetadata): boolean => {
  return (
    metadata.criteria !== null &&
    (hasText(metadata.criteria.text) || hasText(metadata.criteria.uri))
  );
};

const hasAssessment = (metadata: TrustEdCredentialMetadata): boolean => {
  return metadata.assessments.some(
    (assessment) => hasText(assessment.description) && hasText(assessment.assessmentDate),
  );
};

const hasRubric = (metadata: TrustEdCredentialMetadata): boolean => {
  return metadata.rubrics.some((rubric) => hasText(rubric.name) || hasText(rubric.uri));
};

const hasDurationOrCredit = (metadata: TrustEdCredentialMetadata): boolean => {
  return (
    (metadata.duration !== null && hasText(metadata.duration.value)) ||
    (metadata.credits !== null &&
      (hasText(metadata.credits.available) || hasText(metadata.credits.earned)))
  );
};

const hasEndorsement = (metadata: TrustEdCredentialMetadata): boolean => {
  return metadata.endorsements.some(
    (endorsement) => hasText(endorsement.endorserName) || hasText(endorsement.endorserUri),
  );
};

export const evaluateTrustEdCredentialReadiness = (
  metadata: TrustEdCredentialMetadata | null | undefined,
): TrustEdCredentialReadinessResult => {
  if (metadata === null || metadata === undefined) {
    return {
      status: "not_evaluated",
      checks: [],
    };
  }

  const checks: TrustEdCredentialReadinessCheck[] = [
    check(
      "skills",
      "required",
      hasSkill(metadata),
      "Skills",
      "At least one represented skill is present.",
      "Add at least one represented skill.",
    ),
    check(
      "framework_alignment",
      "required",
      hasFrameworkAlignment(metadata),
      "Framework alignment",
      "At least one linked external framework alignment is present.",
      "Add a linked external framework alignment, preferably CASE, CTDL, or RSD.",
    ),
    check(
      "issuer_authority",
      "required",
      hasIssuerAuthority(metadata),
      "Issuer accreditation or awarding authority",
      "Issuer authority metadata is present.",
      "Add issuer accreditation or awarding authority metadata.",
    ),
    check(
      "evidence",
      "required",
      hasEvidence(metadata),
      "Evidence",
      "At least one evidence artifact is present.",
      "Add at least one evidence artifact.",
    ),
    check(
      "result",
      "required",
      hasResult(metadata),
      "Result",
      "At least one result with a result date is present.",
      "Add at least one result with a result date.",
    ),
    check(
      "criteria",
      "required",
      hasCriteria(metadata),
      "Criteria",
      "Criteria are present.",
      "Add criteria that explain what the learner needed to achieve.",
    ),
    check(
      "assessment",
      "required",
      hasAssessment(metadata),
      "Assessment",
      "At least one assessment with description and date is present.",
      "Add assessment information with description and date.",
    ),
    check(
      "achievement_type",
      "required",
      isSpecificAchievementType(metadata.achievementType),
      "Achievement type",
      "A specific achievement type is present.",
      "Add a specific achievement type. Do not use N/A or Not Applicable.",
    ),
    check(
      "rubric",
      "recommended",
      hasRubric(metadata),
      "Rubric",
      "Rubric information is present.",
      "Add rubric information when applicable.",
    ),
    check(
      "duration_credit",
      "recommended",
      hasDurationOrCredit(metadata),
      "Duration and credit",
      "Duration or credit information is present.",
      "Add duration or credit information when applicable.",
    ),
    check(
      "endorsement",
      "recommended",
      hasEndorsement(metadata),
      "Endorsement",
      "Endorsement information is present.",
      "Add third-party endorsement information when applicable.",
    ),
  ];

  const missingRequired = checks.some(
    (readinessCheck) =>
      readinessCheck.category === "required" && readinessCheck.status === "missing",
  );

  return {
    status: missingRequired ? "incomplete" : "ready",
    checks,
  };
};

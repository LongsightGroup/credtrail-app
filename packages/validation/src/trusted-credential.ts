import { z } from "zod";

const trustedCredentialShortTextSchema = z.string().trim().min(1).max(300);
const trustedCredentialDescriptionSchema = z.string().trim().min(1).max(4000);
const trustedCredentialUriSchema = z.string().trim().url().max(2048);
const trustedCredentialDateSchema = z.iso.date();

export const trustedCredentialSkillSchema = z.object({
  name: trustedCredentialShortTextSchema.nullable(),
  identifierUri: trustedCredentialUriSchema.nullable(),
  source: trustedCredentialShortTextSchema.nullable(),
});

export const trustedCredentialFrameworkAlignmentSchema = z.object({
  targetName: trustedCredentialShortTextSchema.nullable(),
  targetUri: trustedCredentialUriSchema.nullable(),
  frameworkName: trustedCredentialShortTextSchema.nullable(),
  frameworkUri: trustedCredentialUriSchema.nullable(),
});

export const trustedCredentialIssuerAuthoritySchema = z.object({
  name: trustedCredentialShortTextSchema.nullable(),
  uri: trustedCredentialUriSchema.nullable(),
  authorityType: trustedCredentialShortTextSchema.nullable(),
});

export const trustedCredentialEvidenceArtifactSchema = z.object({
  name: trustedCredentialShortTextSchema.nullable(),
  uri: trustedCredentialUriSchema.nullable(),
  description: trustedCredentialDescriptionSchema.nullable(),
});

export const trustedCredentialResultSchema = z.object({
  value: trustedCredentialShortTextSchema.nullable(),
  resultDate: trustedCredentialDateSchema.nullable(),
});

export const trustedCredentialCriteriaSchema = z.object({
  text: trustedCredentialDescriptionSchema.nullable(),
  uri: trustedCredentialUriSchema.nullable(),
});

export const trustedCredentialAssessmentSchema = z.object({
  description: trustedCredentialDescriptionSchema.nullable(),
  assessmentDate: trustedCredentialDateSchema.nullable(),
});

export const trustedCredentialRubricSchema = z.object({
  name: trustedCredentialShortTextSchema.nullable(),
  uri: trustedCredentialUriSchema.nullable(),
});

export const trustedCredentialDurationSchema = z.object({
  value: trustedCredentialShortTextSchema.nullable(),
});

export const trustedCredentialCreditsSchema = z.object({
  available: trustedCredentialShortTextSchema.nullable(),
  earned: trustedCredentialShortTextSchema.nullable(),
});

export const trustedCredentialEndorsementSchema = z.object({
  endorserName: trustedCredentialShortTextSchema.nullable(),
  endorserUri: trustedCredentialUriSchema.nullable(),
});

export const trustedCredentialMetadataSchema = z.object({
  skills: z.array(trustedCredentialSkillSchema).max(100),
  frameworkAlignments: z.array(trustedCredentialFrameworkAlignmentSchema).max(100),
  issuerAuthority: trustedCredentialIssuerAuthoritySchema.nullable(),
  evidence: z.array(trustedCredentialEvidenceArtifactSchema).max(100),
  results: z.array(trustedCredentialResultSchema).max(100),
  criteria: trustedCredentialCriteriaSchema.nullable(),
  assessments: z.array(trustedCredentialAssessmentSchema).max(100),
  achievementType: trustedCredentialShortTextSchema.nullable(),
  rubrics: z.array(trustedCredentialRubricSchema).max(100),
  duration: trustedCredentialDurationSchema.nullable(),
  credits: trustedCredentialCreditsSchema.nullable(),
  endorsements: z.array(trustedCredentialEndorsementSchema).max(100),
});

export type TrustEdCredentialMetadata = z.infer<typeof trustedCredentialMetadataSchema>;

export const parseTrustEdCredentialMetadata = (input: unknown): TrustEdCredentialMetadata => {
  return trustedCredentialMetadataSchema.parse(input);
};

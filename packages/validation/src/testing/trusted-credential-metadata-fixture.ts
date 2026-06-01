import { parseTrustEdCredentialMetadata, type TrustEdCredentialMetadata } from "../index";

export const completeTrustEdCredentialMetadataInput = {
  skills: [
    {
      name: "Applied data analysis",
      identifierUri: "https://skills.example.edu/skills/applied-data-analysis",
      source: "Example Skills Framework",
    },
  ],
  frameworkAlignments: [
    {
      targetName: "Analyze civic datasets",
      targetUri: "https://case.example.edu/frameworks/data-analysis/items/analyze-civic-data",
      frameworkName: "Example CASE Framework",
      frameworkUri: "https://case.example.edu/frameworks/data-analysis",
    },
  ],
  issuerAuthority: {
    name: "Middle States Commission on Higher Education",
    uri: "https://www.msche.org/institution/0000/",
    authorityType: "accreditor",
  },
  evidence: [
    {
      name: "Capstone analysis portfolio",
      uri: "https://evidence.example.edu/learners/123/capstone",
      description: "Portfolio evidence reviewed by the program faculty.",
    },
  ],
  results: [
    {
      value: "Pass",
      resultDate: "2026-05-18",
    },
  ],
  criteria: {
    text: "Complete the applied analytics project and faculty review.",
    uri: "https://credentials.example.edu/badges/applied-analytics/criteria",
  },
  assessments: [
    {
      description: "Faculty-scored applied analytics capstone.",
      assessmentDate: "2026-05-18",
    },
  ],
  achievementType: "Project",
  rubrics: [
    {
      name: "Applied analytics rubric",
      uri: "https://credentials.example.edu/rubrics/applied-analytics",
    },
  ],
  duration: {
    value: "6 weeks",
  },
  credits: {
    available: "3 credits",
    earned: "3 credits",
  },
  endorsements: [
    {
      endorserName: "Regional Workforce Council",
      endorserUri: "https://workforce.example.edu/endorsements/applied-analytics",
    },
  ],
} as const;

export const completeTrustEdCredentialMetadata = (): TrustEdCredentialMetadata => {
  return parseTrustEdCredentialMetadata(completeTrustEdCredentialMetadataInput);
};

export const buildCompleteTrustEdCredentialMetadata = (
  overrides?: Partial<TrustEdCredentialMetadata>,
): TrustEdCredentialMetadata => {
  return {
    ...completeTrustEdCredentialMetadata(),
    ...overrides,
  };
};

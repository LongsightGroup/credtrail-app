import { completeTrustEdCredentialMetadataInput } from "@credtrail/validation/testing";

// Local dev seeding reuses the worker's public demo credential fixture so the
// database row and R2 object stay byte-for-byte aligned with the served route.
// If more scripts need this fixture, move it to a shared package.
import { getSeededDemoTrustEdCredentialFixture } from "../apps/api-worker/src/badges/seeded-demo-trusted-credential-fixture";
import {
  localDevDemoAdminEmail,
  localDevDemoLearnerEmail,
  localDevDemoRoutes,
  localDevDemoTenantId,
} from "./local-dev-demo-defaults.mjs";

export {
  localDevDemoAdminEmail,
  localDevDemoLearnerEmail,
  localDevDemoRoutes,
  localDevDemoTenantId,
};

const incompleteTrustEdCredentialMetadataInput = {
  ...completeTrustEdCredentialMetadataInput,
  skills: [],
  evidence: [],
};

export const localDevDemoTemplates = [
  {
    id: "badge_template_trusted_demo",
    slug: "trusted-applied-analytics",
    title: "Applied Analytics TrustEd Credential",
    description: "Awarded for demonstrated applied analytics skill with reviewed evidence.",
    criteriaUri: "https://credentials.example.edu/badges/applied-analytics/criteria",
    imageUri: "https://credentials.example.edu/badges/applied-analytics/image.png",
    trustedCredentialMetadataJson: JSON.stringify(completeTrustEdCredentialMetadataInput),
  },
  {
    id: "badge_template_incomplete_trusted_demo",
    slug: "incomplete-workforce-readiness",
    title: "Workforce Readiness Credential",
    description: "Seeded with intentionally incomplete TrustEd metadata for readiness QA.",
    criteriaUri: "https://credentials.example.edu/badges/workforce-readiness/criteria",
    imageUri: "https://credentials.example.edu/badges/workforce-readiness/image.png",
    trustedCredentialMetadataJson: JSON.stringify(incompleteTrustEdCredentialMetadataInput),
  },
  {
    id: "badge_template_foundations",
    slug: "foundations",
    title: "Foundations Badge",
    description: "Awarded for completing the local demo foundations workflow.",
    criteriaUri: "https://localhost/criteria/foundations",
    imageUri: "https://credentials.example.edu/badges/foundations/image.png",
    trustedCredentialMetadataJson: undefined,
  },
  {
    id: "badge_template_capstone",
    slug: "capstone",
    title: "Capstone Badge",
    description: "Awarded for demonstrating the capstone skill in the local demo environment.",
    criteriaUri: "https://localhost/criteria/capstone",
    imageUri: "https://credentials.example.edu/badges/capstone/image.png",
    trustedCredentialMetadataJson: undefined,
  },
] as const;

export const localDevDemoRule = {
  name: "Local Demo: Applied Analytics Completion",
  description: "Active seeded rule for first-day rule-builder and criteria-registry QA.",
  badgeTemplateId: "badge_template_trusted_demo",
  lmsProviderKind: "canvas" as const,
  lmsConnectionId: "local-demo-lms",
  definition: {
    conditions: {
      all: [
        {
          type: "course_completion",
          courseId: "course-applied-analytics",
          minCompletionPercent: 100,
          requireCompleted: true,
        },
        {
          type: "grade_threshold",
          courseId: "course-applied-analytics",
          scoreField: "final_score",
          minScore: 85,
        },
      ],
    },
  },
};

export const localDevDemoLmsConnection = {
  id: localDevDemoRule.lmsConnectionId,
  displayName: "Local Demo Canvas",
  providerKind: localDevDemoRule.lmsProviderKind,
  apiBaseUrl: "https://canvas.localhost.invalid",
  authorizationEndpoint: "https://canvas.localhost.invalid/login/oauth2/auth",
  tokenEndpoint: "https://canvas.localhost.invalid/login/oauth2/token",
  clientId: "local-demo-client",
  scope: "url:GET|/api/v1/courses url:GET|/api/v1/courses/:course_id/assignments",
} as const;

export const localDevDemoTrustedCredentialFixture = getSeededDemoTrustEdCredentialFixture();

export default {
  localDevDemoAdminEmail,
  localDevDemoLmsConnection,
  localDevDemoLearnerEmail,
  localDevDemoRoutes,
  localDevDemoRule,
  localDevDemoTemplates,
  localDevDemoTenantId,
  localDevDemoTrustedCredentialFixture,
};

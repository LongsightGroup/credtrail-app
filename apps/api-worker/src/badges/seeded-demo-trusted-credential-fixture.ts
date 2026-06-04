import type { JsonObject } from "@credtrail/core-domain";
import type { AssertionRecord, BadgeTemplateRecord, LearnerProfileRecord } from "@credtrail/db";
import {
  completeTrustEdCredentialMetadata,
  completeTrustEdCredentialMetadataInput,
} from "@credtrail/validation/testing";

import {
  evaluateTrustEdCredentialReadiness,
  type TrustEdCredentialReadinessResult,
} from "./trusted-credential-readiness";
import { projectTrustEdMetadataToOb3 } from "./trusted-credential-ob3-projection";

const TENANT_ID = "tenant_123";
const ASSERTION_ID = `${TENANT_ID}:assertion_trusted_demo`;
const PUBLIC_ID = "trusted-demo-credential";
const LEARNER_PROFILE_ID = "lpr_trusted_demo";
const BADGE_TEMPLATE_ID = "badge_template_trusted_demo";
const ISSUED_AT = "2026-05-18T16:00:00.000Z";
const UPDATED_AT = "2026-05-18T16:00:00.000Z";
const TRUSTED_CREDENTIAL_METADATA_JSON = JSON.stringify(completeTrustEdCredentialMetadataInput);

export const SEEDED_DEMO_TRUSTED_CREDENTIAL_VERIFY_COMMAND =
  "pnpm exec vitest run apps/api-worker/src/badges/seeded-demo-trusted-credential-fixture.test.ts apps/api-worker/src/public-badge-page.test.ts";

export interface SeededDemoTrustEdCredentialRouteFamily {
  publicCredential: string;
  ob3Json: string;
  summaryJson: string;
  walletOffer: string;
}

export interface SeededDemoTrustEdCredentialFixture {
  tenantId: string;
  assertionId: string;
  publicId: string;
  learnerProfileId: string;
  badgeTemplateId: string;
  routeFamily: SeededDemoTrustEdCredentialRouteFamily;
  assertion: AssertionRecord;
  learnerProfile: LearnerProfileRecord;
  badgeTemplate: BadgeTemplateRecord;
  credential: JsonObject;
  readiness: TrustEdCredentialReadinessResult;
}

const createAssertion = (): AssertionRecord => {
  return {
    id: ASSERTION_ID,
    tenantId: TENANT_ID,
    publicId: PUBLIC_ID,
    learnerProfileId: LEARNER_PROFILE_ID,
    badgeTemplateId: BADGE_TEMPLATE_ID,
    recipientIdentity: "learner@example.edu",
    recipientIdentityType: "email",
    vcR2Key: `tenants/${TENANT_ID}/assertions/${encodeURIComponent(ASSERTION_ID)}.jsonld`,
    statusListIndex: 7,
    idempotencyKey: "trusted-demo-credential",
    issuedAt: ISSUED_AT,
    issuedByUserId: "usr_admin",
    revokedAt: null,
    createdAt: ISSUED_AT,
    updatedAt: UPDATED_AT,
  };
};

const createLearnerProfile = (): LearnerProfileRecord => {
  return {
    id: LEARNER_PROFILE_ID,
    tenantId: TENANT_ID,
    subjectId: `did:web:credential.example.edu:learners:${LEARNER_PROFILE_ID}`,
    displayName: "Ada Lovelace",
    createdAt: ISSUED_AT,
    updatedAt: UPDATED_AT,
  };
};

const createBadgeTemplate = (): BadgeTemplateRecord => {
  return {
    id: BADGE_TEMPLATE_ID,
    tenantId: TENANT_ID,
    slug: "trusted-applied-analytics",
    title: "Applied Analytics TrustEd Credential",
    description: "Awarded for demonstrated applied analytics skill with reviewed evidence.",
    criteriaUri: "https://credentials.example.edu/badges/applied-analytics/criteria",
    imageUri: "https://credentials.example.edu/badges/applied-analytics/image.png",
    trustedCredentialMetadataJson: TRUSTED_CREDENTIAL_METADATA_JSON,
    createdByUserId: "usr_admin",
    ownerOrgUnitId: `${TENANT_ID}:org:institution`,
    governanceMetadataJson: '{"source":"seeded_demo_trusted_credential_fixture"}',
    isArchived: false,
    createdAt: "2026-05-01T12:00:00.000Z",
    updatedAt: UPDATED_AT,
  };
};

const createCredential = (): JsonObject => {
  const trustEdProjection = projectTrustEdMetadataToOb3(completeTrustEdCredentialMetadata());

  return {
    "@context": [
      "https://www.w3.org/ns/credentials/v2",
      "https://purl.imsglobal.org/spec/ob/v3p0/context-3.0.3.json",
      "https://credtrail.org/ns/trusted-credential/v1",
    ],
    id: `urn:credtrail:assertion:${encodeURIComponent(ASSERTION_ID)}`,
    type: ["VerifiableCredential", "OpenBadgeCredential"],
    name: "Applied Analytics TrustEd Credential",
    issuer: {
      id: "did:web:credential.example.edu:issuers:example-university",
      name: "Example University",
      url: "https://credential.example.edu",
    },
    validFrom: ISSUED_AT,
    credentialSubject: {
      id: `did:web:credential.example.edu:learners:${LEARNER_PROFILE_ID}`,
      type: ["AchievementSubject"],
      achievement: {
        id: `urn:credtrail:badge-template:${encodeURIComponent(BADGE_TEMPLATE_ID)}`,
        type: ["Achievement"],
        name: "Applied Analytics TrustEd Credential",
        description: "Awarded for demonstrated applied analytics skill with reviewed evidence.",
        image: {
          id: "https://credentials.example.edu/badges/applied-analytics/image.png",
          type: "Image",
        },
        ...trustEdProjection.achievement,
      },
      ...trustEdProjection.subject,
    },
  };
};

export const getSeededDemoTrustEdCredentialFixture = (): SeededDemoTrustEdCredentialFixture => {
  return {
    tenantId: TENANT_ID,
    assertionId: ASSERTION_ID,
    publicId: PUBLIC_ID,
    learnerProfileId: LEARNER_PROFILE_ID,
    badgeTemplateId: BADGE_TEMPLATE_ID,
    routeFamily: {
      publicCredential: `/badges/${encodeURIComponent(PUBLIC_ID)}`,
      ob3Json: `/badges/${encodeURIComponent(PUBLIC_ID)}/jsonld`,
      summaryJson: `/badges/${encodeURIComponent(PUBLIC_ID)}/summary`,
      walletOffer: `/credentials/v1/offers/${encodeURIComponent(PUBLIC_ID)}`,
    },
    assertion: createAssertion(),
    learnerProfile: createLearnerProfile(),
    badgeTemplate: createBadgeTemplate(),
    credential: createCredential(),
    readiness: evaluateTrustEdCredentialReadiness(completeTrustEdCredentialMetadata()),
  };
};

export const seededDemoTrustEdCredentialFixture = getSeededDemoTrustEdCredentialFixture();

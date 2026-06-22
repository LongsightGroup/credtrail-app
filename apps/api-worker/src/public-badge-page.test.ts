import { once } from "node:events";
import { createServer } from "node:http";

import { CredentialOfferClient } from "@sphereon/oid4vci-client";
import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("@credtrail/db", async () => {
  const actual = await vi.importActual<typeof import("@credtrail/db")>("@credtrail/db");

  return {
    ...actual,
    consumeOid4vciPreAuthorizedCode: vi.fn(),
    createOid4vciAccessToken: vi.fn(),
    createOid4vciPreAuthorizedCode: vi.fn(),
    findAssertionById: vi.fn(),
    findActiveOid4vciAccessTokenByHash: vi.fn(),
    findAssertionByPublicId: vi.fn(),
    findBadgeTemplateById: vi.fn(),
    findLearnerProfileById: vi.fn(),
    findUserById: vi.fn(),
    listLtiIssuerRegistrations: vi.fn(),
    recordAssertionEngagementEvent: vi.fn(),
    resolveAssertionLifecycleState: vi.fn(),
  };
});

vi.mock("@credtrail/core-domain", async () => {
  const actual =
    await vi.importActual<typeof import("@credtrail/core-domain")>("@credtrail/core-domain");

  return {
    ...actual,
    getImmutableCredentialObject: vi.fn(),
  };
});

vi.mock("@credtrail/db/postgres", () => {
  return {
    createPostgresDatabase: vi.fn(),
  };
});

import { type JsonObject, getImmutableCredentialObject } from "@credtrail/core-domain";
import {
  consumeOid4vciPreAuthorizedCode,
  createOid4vciAccessToken,
  createOid4vciPreAuthorizedCode,
  findAssertionById,
  findActiveOid4vciAccessTokenByHash,
  findAssertionByPublicId,
  findBadgeTemplateById,
  findLearnerProfileById,
  listLtiIssuerRegistrations,
  recordAssertionEngagementEvent,
  resolveAssertionLifecycleState,
  type AssertionEngagementEventRecord,
  type AssertionRecord,
  type BadgeTemplateRecord,
  type LearnerProfileRecord,
  type Oid4vciAccessTokenRecord,
  type Oid4vciPreAuthorizedCodeRecord,
  type SqlDatabase,
} from "@credtrail/db";
import { createPostgresDatabase } from "@credtrail/db/postgres";

import { app } from "./index";
import { getSeededDemoTrustEdCredentialFixture } from "./badges/seeded-demo-trusted-credential-fixture";

const mockedFindAssertionById = vi.mocked(findAssertionById);
const mockedFindAssertionByPublicId = vi.mocked(findAssertionByPublicId);
const mockedCreateOid4vciPreAuthorizedCode = vi.mocked(createOid4vciPreAuthorizedCode);
const mockedConsumeOid4vciPreAuthorizedCode = vi.mocked(consumeOid4vciPreAuthorizedCode);
const mockedCreateOid4vciAccessToken = vi.mocked(createOid4vciAccessToken);
const mockedFindActiveOid4vciAccessTokenByHash = vi.mocked(findActiveOid4vciAccessTokenByHash);
const mockedFindBadgeTemplateById = vi.mocked(findBadgeTemplateById);
const mockedFindLearnerProfileById = vi.mocked(findLearnerProfileById);
const mockedRecordAssertionEngagementEvent = vi.mocked(recordAssertionEngagementEvent);
const mockedResolveAssertionLifecycleState = vi.mocked(resolveAssertionLifecycleState);
const mockedGetImmutableCredentialObject = vi.mocked(getImmutableCredentialObject);
const mockedListLtiIssuerRegistrations = vi.mocked(listLtiIssuerRegistrations);
const mockedCreatePostgresDatabase = vi.mocked(createPostgresDatabase);
const fakeDb = {
  prepare: vi.fn(),
} as unknown as SqlDatabase;
const PRE_AUTHORIZED_CODE_GRANT = "urn:ietf:params:oauth:grant-type:pre-authorized_code";

interface ResolvedCredentialOfferForTest {
  credentialIssuer: string;
  credentialConfigurationIds: string[];
  credentials: Array<{
    format: string;
  }>;
  preAuthorizedCode: string;
}

const createEnv = (): {
  APP_ENV: string;
  DATABASE_URL: string;
  BADGE_OBJECTS: R2Bucket;
  PLATFORM_DOMAIN: string;
} => {
  return {
    APP_ENV: "test",
    DATABASE_URL: "postgres://credtrail-test.local/db",
    BADGE_OBJECTS: {} as R2Bucket,
    PLATFORM_DOMAIN: "credtrail.test",
  };
};

const sampleAssertion = (overrides?: {
  revokedAt?: string | null;
  statusListIndex?: number | null;
}): AssertionRecord => {
  return {
    id: "tenant_123:assertion_456",
    tenantId: "tenant_123",
    publicId: "40a6dc92-85ec-4cb0-8a50-afb2ae700e22",
    learnerProfileId: "lpr_123",
    badgeTemplateId: "badge_template_001",
    recipientIdentity: "learner@example.edu",
    recipientIdentityType: "email",
    vcR2Key: "tenants/tenant_123/assertions/tenant_123%3Aassertion_456.jsonld",
    statusListIndex: overrides?.statusListIndex === undefined ? 0 : overrides.statusListIndex,
    idempotencyKey: "idem_abc",
    issuedAt: "2026-02-10T22:00:00.000Z",
    issuedByUserId: "usr_123",
    revokedAt: overrides?.revokedAt ?? null,
    createdAt: "2026-02-10T22:00:00.000Z",
    updatedAt: "2026-02-10T22:00:00.000Z",
  };
};

const sampleLearnerProfile = (overrides?: Partial<LearnerProfileRecord>): LearnerProfileRecord => {
  return {
    id: "lpr_123",
    tenantId: "tenant_123",
    subjectId: "urn:credtrail:learner:tenant_123:lpr_123",
    displayName: null,
    createdAt: "2026-02-10T22:00:00.000Z",
    updatedAt: "2026-02-10T22:00:00.000Z",
    ...overrides,
  };
};

const sampleBadgeTemplate = (overrides?: Partial<BadgeTemplateRecord>): BadgeTemplateRecord => {
  return {
    id: "badge_template_001",
    tenantId: "tenant_123",
    slug: "typescript-foundations",
    title: "TypeScript Foundations",
    description: "Awarded for completing TypeScript fundamentals.",
    criteriaUri: "https://example.edu/badges/typescript-foundations/criteria",
    imageUri: null,
    createdByUserId: "usr_123",
    ownerOrgUnitId: "tenant_123:org:institution",
    governanceMetadataJson: null,
    isArchived: false,
    createdAt: "2026-02-10T22:00:00.000Z",
    updatedAt: "2026-02-10T22:00:00.000Z",
    ...overrides,
  };
};

const sampleOid4vciPreAuthorizedCodeRecord = (
  overrides?: Partial<Oid4vciPreAuthorizedCodeRecord>,
): Oid4vciPreAuthorizedCodeRecord => {
  return {
    id: "ovp_123",
    codeHash: "offer-code-hash",
    tenantId: "tenant_123",
    assertionId: "tenant_123:assertion_456",
    publicBadgeId: "40a6dc92-85ec-4cb0-8a50-afb2ae700e22",
    expiresAt: "2026-02-10T22:10:00.000Z",
    usedAt: null,
    createdAt: "2026-02-10T22:00:00.000Z",
    ...overrides,
  };
};

const sampleOid4vciAccessTokenRecord = (
  overrides?: Partial<Oid4vciAccessTokenRecord>,
): Oid4vciAccessTokenRecord => {
  return {
    id: "ova_123",
    accessTokenHash: "oid4vci-access-hash",
    tenantId: "tenant_123",
    assertionId: "tenant_123:assertion_456",
    expiresAt: "2026-02-10T22:10:00.000Z",
    revokedAt: null,
    createdAt: "2026-02-10T22:00:00.000Z",
    ...overrides,
  };
};

const sampleAssertionEngagementEvent = (
  overrides?: Partial<AssertionEngagementEventRecord>,
): AssertionEngagementEventRecord => {
  return {
    id: "aee_123",
    tenantId: "tenant_123",
    assertionId: "tenant_123:assertion_456",
    eventType: "public_badge_view",
    actorType: "anonymous",
    channel: null,
    occurredAt: "2026-02-10T22:00:00.000Z",
    createdAt: "2026-02-10T22:00:00.000Z",
    ...overrides,
  };
};

const isRecord = (value: unknown): value is Record<string, unknown> => {
  return value !== null && typeof value === "object" && !Array.isArray(value);
};

const requiredRecordValue = (value: unknown, label: string): Record<string, unknown> => {
  if (!isRecord(value)) {
    throw new Error(`${label} must be an object`);
  }

  return value;
};

const requiredRecordProperty = (
  record: Record<string, unknown>,
  propertyName: string,
): Record<string, unknown> => {
  return requiredRecordValue(record[propertyName], propertyName);
};

const requiredStringProperty = (record: Record<string, unknown>, propertyName: string): string => {
  const value = record[propertyName];

  if (typeof value !== "string" || value.length === 0) {
    throw new Error(`${propertyName} must be a non-empty string`);
  }

  return value;
};

const requiredStringArrayProperty = (
  record: Record<string, unknown>,
  propertyName: string,
): string[] => {
  const value = record[propertyName];

  if (!Array.isArray(value) || value.some((item) => typeof item !== "string")) {
    throw new Error(`${propertyName} must be an array of strings`);
  }

  return value;
};

const requiredArrayProperty = (
  record: Record<string, unknown>,
  propertyName: string,
): unknown[] => {
  const value = record[propertyName];

  if (!Array.isArray(value)) {
    throw new Error(`${propertyName} must be an array`);
  }

  return value;
};

const parseCredentialOfferForTest = (payload: unknown): ResolvedCredentialOfferForTest => {
  const offer = requiredRecordValue(payload, "credential offer");
  const credentialIssuer = requiredStringProperty(offer, "credential_issuer");
  const credentialConfigurationIds = requiredStringArrayProperty(
    offer,
    "credential_configuration_ids",
  );
  const grants = requiredRecordProperty(offer, "grants");
  const preAuthorizedCodeGrant = requiredRecordProperty(grants, PRE_AUTHORIZED_CODE_GRANT);
  const credentials = requiredArrayProperty(offer, "credentials").map((credential) => {
    const credentialRecord = requiredRecordValue(credential, "credential");

    return {
      format: requiredStringProperty(credentialRecord, "format"),
    };
  });

  new URL(credentialIssuer);

  return {
    credentialIssuer,
    credentialConfigurationIds,
    credentials,
    preAuthorizedCode: requiredStringProperty(preAuthorizedCodeGrant, "pre-authorized_code"),
  };
};

const resolveCredentialOfferUriForTest = async (
  walletOfferUri: string,
): Promise<ResolvedCredentialOfferForTest> => {
  const parsedWalletOfferUri = new URL(walletOfferUri);

  if (parsedWalletOfferUri.protocol !== "openid-credential-offer:") {
    throw new Error("wallet offer URI must use the openid-credential-offer scheme");
  }

  const credentialOfferUri = parsedWalletOfferUri.searchParams.get("credential_offer_uri");

  if (credentialOfferUri === null || credentialOfferUri.length === 0) {
    throw new Error("wallet offer URI must include credential_offer_uri");
  }

  const response = await fetch(credentialOfferUri);

  if (!response.ok) {
    throw new Error(`credential_offer_uri returned ${String(response.status)}`);
  }

  return parseCredentialOfferForTest(await response.json());
};

beforeEach(() => {
  mockedCreatePostgresDatabase.mockReset();
  mockedCreatePostgresDatabase.mockReturnValue(fakeDb);
  mockedFindAssertionByPublicId.mockReset();
  mockedFindAssertionById.mockReset();
  mockedCreateOid4vciPreAuthorizedCode.mockReset();
  mockedCreateOid4vciPreAuthorizedCode.mockResolvedValue(sampleOid4vciPreAuthorizedCodeRecord());
  mockedConsumeOid4vciPreAuthorizedCode.mockReset();
  mockedConsumeOid4vciPreAuthorizedCode.mockResolvedValue(
    sampleOid4vciPreAuthorizedCodeRecord({
      usedAt: "2026-02-10T22:01:00.000Z",
    }),
  );
  mockedCreateOid4vciAccessToken.mockReset();
  mockedCreateOid4vciAccessToken.mockResolvedValue(sampleOid4vciAccessTokenRecord());
  mockedFindActiveOid4vciAccessTokenByHash.mockReset();
  mockedFindActiveOid4vciAccessTokenByHash.mockResolvedValue(sampleOid4vciAccessTokenRecord());
  mockedFindBadgeTemplateById.mockReset();
  mockedFindBadgeTemplateById.mockResolvedValue(null);
  mockedFindLearnerProfileById.mockReset();
  mockedRecordAssertionEngagementEvent.mockReset();
  mockedRecordAssertionEngagementEvent.mockResolvedValue({
    status: "recorded",
    event: sampleAssertionEngagementEvent(),
  });
  mockedResolveAssertionLifecycleState.mockReset();
  mockedResolveAssertionLifecycleState.mockResolvedValue({
    state: "active",
    source: "default_active",
    reasonCode: null,
    reason: null,
    transitionedAt: null,
    revokedAt: null,
  });
  mockedGetImmutableCredentialObject.mockReset();
  mockedListLtiIssuerRegistrations.mockReset();
  mockedListLtiIssuerRegistrations.mockResolvedValue([]);
});

describe("GET /badges/:badgeIdentifier", () => {
  it("renders a public badge page with verified status for canonical public permalink", async () => {
    const env = createEnv();
    const credential: JsonObject = {
      "@context": ["https://www.w3.org/ns/credentials/v2"],
      id: "urn:credtrail:assertion:tenant_123%3Aassertion_456",
      type: ["VerifiableCredential", "OpenBadgeCredential"],
      issuer: {
        id: "did:web:credtrail.test:tenant_123",
        name: "Example University",
        url: "https://example.edu",
      },
      credentialSubject: {
        id: "mailto:learner@example.edu",
        achievement: {
          id: "https://example.edu/badges/typescript-foundations",
          name: "TypeScript Foundations",
          description: "Awarded for completing TypeScript fundamentals.",
          criteria: {
            id: "https://example.edu/badges/typescript-foundations/criteria",
          },
          image: {
            id: "https://example.edu/badges/typescript-foundations/image.png",
          },
        },
        evidence: [
          {
            id: "https://example.edu/evidence/123",
            name: "Capstone Submission",
            description: "Final capstone reviewed by instructor.",
          },
          "https://example.edu/evidence/gradebook/123",
        ],
      },
    };

    mockedFindAssertionByPublicId.mockResolvedValue(sampleAssertion());
    mockedFindLearnerProfileById.mockResolvedValue(
      sampleLearnerProfile({
        displayName: "Ada Lovelace",
      }),
    );
    mockedFindBadgeTemplateById.mockResolvedValue(
      sampleBadgeTemplate({
        imageUri: "https://cdn.example.edu/badges/typescript-foundations/template.png",
      }),
    );
    mockedGetImmutableCredentialObject.mockResolvedValue(credential);

    const response = await app.request(
      "/badges/40a6dc92-85ec-4cb0-8a50-afb2ae700e22",
      undefined,
      env,
    );
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(response.headers.get("content-type")).toContain("text/html");
    expect(response.headers.get("cache-control")).toBe("no-store");
    expect(body).toContain("TypeScript Foundations");
    expect(body).toContain("Verified");
    expect(body).toContain("Example University");
    expect(body).toContain("https://example.edu");
    expect(body).toContain("Ada Lovelace");
    expect(body).toContain("/badges/40a6dc92-85ec-4cb0-8a50-afb2ae700e22/verification");
    expect(body).toContain("Share this credential");
    expect(body).toContain('id="share-this-credential"');
    expect(body).not.toContain("Copy public URL");
    expect(body).not.toContain("Anyone can verify the issuer");
    expect(body).toContain("Public page URL");
    expect(body).toContain('id="copy-badge-url-technical-button"');
    expect(body).toContain("Summary JSON");
    expect(body).toContain("/badges/40a6dc92-85ec-4cb0-8a50-afb2ae700e22/summary");
    expect(body).toContain("/badges/40a6dc92-85ec-4cb0-8a50-afb2ae700e22/download");
    expect(body).toContain("/badges/40a6dc92-85ec-4cb0-8a50-afb2ae700e22/download.pdf");
    expect(body).toContain("/badges/40a6dc92-85ec-4cb0-8a50-afb2ae700e22/jsonld");
    expect(body).toContain("/credentials/v1/offers/40a6dc92-85ec-4cb0-8a50-afb2ae700e22");
    expect(body).not.toContain(">PDF</a>");
    expect(body).toContain("Open Badges 3.0 JSON");
    expect(body).toContain("OpenID4VCI offer");
    expect(body).not.toContain("Add to Browser Wallet");
    expect(body).toMatch(/id="chapi-store-row"[^>]*hidden/);
    expect(body).toContain('id="chapi-store-link"');
    expect(body).toContain("Save in this browser");
    expect(body).toContain("Open in wallet app");
    expect(body).not.toContain("Claim in Wallet");
    expect(body).not.toContain("DCC Learner Wallet");
    expect(body).toContain("Wallet &amp; downloads");
    expect(body).toContain("On your phone");
    expect(body).toContain("On this device");
    expect(body).not.toContain("Digital Credentials Consortium");
    expect(body).toContain("openid-credential-offer:");
    expect(body).toContain("credential_offer_uri=");
    expect(body).toContain("/credentials/v1/dcc/exchanges/40a6dc92-85ec-4cb0-8a50-afb2ae700e22");
    expect(body).toContain("Add to LinkedIn Profile");
    expect(body).toContain("/badges/40a6dc92-85ec-4cb0-8a50-afb2ae700e22/share/linkedin-profile");
    expect(body).toContain("Share to LinkedIn feed");
    expect(body).toContain("/badges/40a6dc92-85ec-4cb0-8a50-afb2ae700e22/share/linkedin-feed");
    expect(body).not.toContain("linkedin.com/profile/add");
    expect(body).not.toContain("linkedin.com/sharing/share-offsite");
    expect(body).not.toContain("Validate Assertion (IMS)");
    expect(body).not.toContain("Validate Badge Class (IMS)");
    expect(body).not.toContain("Validate Issuer (IMS)");
    expect(body).not.toContain("openbadgesvalidator.imsglobal.org/?url=");
    expect(body).not.toContain("vc.1ed.tech/upload?validatorId=OB30Inspector");
    expect(body).not.toContain("api.qrserver.com");
    expect(body).toContain("/badges/40a6dc92-85ec-4cb0-8a50-afb2ae700e22/wallet-qr.svg");
    expect(body).toContain("QR code to import this credential into your wallet");
    expect(body).toContain("Scan with your phone camera or wallet app.");
    expect(body).toContain("Open Badges 3.0 JSON");
    expect(body).toContain(
      '<link rel="alternate" type="application/vc+ld+json" href="http://localhost/badges/40a6dc92-85ec-4cb0-8a50-afb2ae700e22/jsonld"',
    );
    expect(body).toContain(
      '<link rel="alternate" type="application/json" href="http://localhost/badges/40a6dc92-85ec-4cb0-8a50-afb2ae700e22/summary"',
    );
    expect(body).toContain("Awarded for completing TypeScript fundamentals.");
    expect(body).toContain("https://example.edu/badges/typescript-foundations/criteria");
    expect(body).toContain("/showcase/tenant_123/criteria?badgeTemplateId=badge_template_001");
    expect(body).toContain(
      'src="https://cdn.example.edu/badges/typescript-foundations/template.png"',
    );
    expect(body).toContain(
      'data-fallback-src="https://example.edu/badges/typescript-foundations/image.png"',
    );
    expect(body).toContain("Capstone Submission");
    expect(body).toContain("https://example.edu/evidence/gradebook/123");
    expect(body).toContain("/badges/40a6dc92-85ec-4cb0-8a50-afb2ae700e22");
    expect(body).toContain(
      '<link rel="canonical" href="http://localhost/badges/40a6dc92-85ec-4cb0-8a50-afb2ae700e22"',
    );
    expect(body).toContain(
      '<meta name="description" content="Awarded for completing TypeScript fundamentals."',
    );
    expect(body).toContain(
      '<meta property="og:title" content="TypeScript Foundations | CredTrail"',
    );
    expect(body).toContain(
      '<meta property="og:url" content="http://localhost/badges/40a6dc92-85ec-4cb0-8a50-afb2ae700e22"',
    );
    expect(body).toContain(
      '<meta property="og:image" content="https://cdn.example.edu/badges/typescript-foundations/template.png"',
    );
    expect(body).toContain('<meta name="twitter:card" content="summary_large_image"');
    expect(body).toContain(
      '<meta name="twitter:image" content="https://cdn.example.edu/badges/typescript-foundations/template.png"',
    );
    expect(mockedRecordAssertionEngagementEvent).toHaveBeenCalledWith(
      fakeDb,
      expect.objectContaining({
        tenantId: "tenant_123",
        assertionId: "tenant_123:assertion_456",
        eventType: "public_badge_view",
        actorType: "anonymous",
        occurredAt: expect.stringMatching(/^20/),
      }),
    );
  });

  it("returns a self-hosted wallet QR SVG for public badge pages", async () => {
    const env = createEnv();

    mockedFindAssertionByPublicId.mockResolvedValue(sampleAssertion());
    mockedGetImmutableCredentialObject.mockResolvedValue({
      "@context": ["https://www.w3.org/ns/credentials/v2"],
      id: "urn:credtrail:assertion:tenant_123%3Aassertion_456",
      type: ["VerifiableCredential", "OpenBadgeCredential"],
      issuer: {
        id: "did:web:credtrail.test:tenant_123",
        name: "Example University",
      },
      credentialSubject: {
        achievement: {
          name: "TypeScript Foundations",
        },
      },
    } satisfies JsonObject);

    const response = await app.request(
      "/badges/40a6dc92-85ec-4cb0-8a50-afb2ae700e22/wallet-qr.svg",
      undefined,
      env,
    );
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(response.headers.get("content-type")).toContain("image/svg+xml");
    expect(body).toContain("<svg");
    expect(body).toContain("</svg>");
  });

  it("shows IMS validation links for non-VC-v2 credentials", async () => {
    const env = createEnv();
    const credential: JsonObject = {
      "@context": ["https://w3id.org/openbadges/v2"],
      id: "urn:credtrail:assertion:tenant_123%3Aassertion_456",
      issuer: {
        id: "https://issuer.example.edu",
        name: "Example University",
        url: "https://example.edu",
      },
      credentialSubject: {
        achievement: {
          id: "https://example.edu/badges/typescript-foundations",
          name: "TypeScript Foundations",
          criteria: {
            id: "https://example.edu/badges/typescript-foundations/criteria",
          },
          image: {
            id: "https://example.edu/badges/typescript-foundations/image.png",
          },
        },
      },
    };

    mockedFindAssertionByPublicId.mockResolvedValue(sampleAssertion());
    mockedGetImmutableCredentialObject.mockResolvedValue(credential);

    const response = await app.request(
      "/badges/40a6dc92-85ec-4cb0-8a50-afb2ae700e22",
      undefined,
      env,
    );
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(body).toContain("Validate Assertion (IMS)");
    expect(body).toContain("Validate Badge Class (IMS)");
    expect(body).toContain("Validate Issuer (IMS)");
    expect(body).toContain("vc.1ed.tech/upload?validatorId=OB30Inspector");
    expect(body).toContain("&amp;uri=");
  });

  it("renders TrustEd-aligned metadata from the issued public credential", async () => {
    const env = createEnv();
    const seededDemo = getSeededDemoTrustEdCredentialFixture();

    mockedFindAssertionByPublicId.mockResolvedValue(seededDemo.assertion);
    mockedFindLearnerProfileById.mockResolvedValue(seededDemo.learnerProfile);
    mockedFindBadgeTemplateById.mockResolvedValue(seededDemo.badgeTemplate);
    mockedGetImmutableCredentialObject.mockResolvedValue(seededDemo.credential);

    const response = await app.request(seededDemo.routeFamily.publicCredential, undefined, env);
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(body).toContain("Trust metadata");
    expect(body).toContain("TrustEd-aligned");
    expect(body).toContain(
      "Structured credential data published inside this Open Badges 3.0 record.",
    );
    expect(body).toContain("Achievement type");
    expect(body).toContain("Project");
    expect(body).toContain("Complete the applied analytics project and faculty review.");
    expect(body).toContain("View criteria");
    expect(body).toContain("Pass on 2026-05-18");
    expect(body).toContain("Applied data analysis");
    expect(body).toContain("Example Skills Framework");
    expect(body).toContain("Middle States Commission on Higher Education");
    expect(body).toContain("accreditor");
    expect(body).toContain("Faculty-scored applied analytics capstone.");
    expect(body).toContain("Applied analytics rubric");
    expect(body).toContain("6 weeks");
    expect(body).toContain("Available: 3 credits; Earned: 3 credits");
    expect(body).toContain("Regional Workforce Council");
    expect(body).toContain("Analyze civic datasets");
    expect(body).toContain("Example CASE Framework");
    expect(body).toContain(
      "https://case.example.edu/frameworks/data-analysis/items/analyze-civic-data",
    );
    expect(body).toContain("Capstone analysis portfolio");
  });

  it("keeps public badge pages available after LMS course deletion", async () => {
    const env = createEnv();
    const credential: JsonObject = {
      id: "urn:credtrail:assertion:tenant_123%3Aassertion_456",
      credentialSubject: {
        achievement: {
          name: "TypeScript Foundations",
        },
      },
    };

    mockedFindAssertionByPublicId.mockResolvedValue(sampleAssertion());
    mockedGetImmutableCredentialObject.mockResolvedValue(credential);
    mockedListLtiIssuerRegistrations.mockResolvedValue([]);

    const response = await app.request(
      "/badges/40a6dc92-85ec-4cb0-8a50-afb2ae700e22",
      undefined,
      env,
    );
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(body).toContain("TypeScript Foundations");
    expect(body).toContain("Verified");
    expect(mockedListLtiIssuerRegistrations).not.toHaveBeenCalled();
  });

  it("rebuilds canonical and LinkedIn links for the current platform host after platform move", async () => {
    const env = createEnv();
    const credential: JsonObject = {
      id: "urn:credtrail:assertion:tenant_123%3Aassertion_456",
      issuer: {
        name: "Example University",
      },
      credentialSubject: {
        achievement: {
          name: "TypeScript Foundations",
        },
      },
    };

    mockedFindAssertionByPublicId.mockResolvedValue(sampleAssertion());
    mockedGetImmutableCredentialObject.mockResolvedValue(credential);

    const response = await app.request(
      "http://badges.newcredtrail.test/badges/40a6dc92-85ec-4cb0-8a50-afb2ae700e22",
      undefined,
      env,
    );
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(body).toContain(
      '<link rel="canonical" href="http://badges.newcredtrail.test/badges/40a6dc92-85ec-4cb0-8a50-afb2ae700e22"',
    );
    expect(body).toContain(
      '<meta property="og:url" content="http://badges.newcredtrail.test/badges/40a6dc92-85ec-4cb0-8a50-afb2ae700e22"',
    );
    expect(body).toContain(
      '<meta name="description" content="TypeScript Foundations credential issued by Example University."',
    );
    expect(body).toContain(
      'data-copy-value="http://badges.newcredtrail.test/badges/40a6dc92-85ec-4cb0-8a50-afb2ae700e22"',
    );
    expect(body).toContain(
      "credential_offer_uri=http%3A%2F%2Fbadges.newcredtrail.test%2Fcredentials%2Fv1%2Foffers%2F40a6dc92-85ec-4cb0-8a50-afb2ae700e22",
    );
  });

  it("redirects legacy tenant-scoped badge URLs to canonical public permalink", async () => {
    const env = createEnv();

    mockedFindAssertionByPublicId.mockResolvedValue(null);
    mockedFindAssertionById.mockResolvedValue(sampleAssertion());

    const response = await app.request("/badges/tenant_123%3Aassertion_456", undefined, env);

    expect(response.status).toBe(308);
    expect(response.headers.get("location")).toBe("/badges/40a6dc92-85ec-4cb0-8a50-afb2ae700e22");
    expect(mockedGetImmutableCredentialObject).not.toHaveBeenCalled();
  });

  it("redirects /public_url alias path to canonical public permalink", async () => {
    const env = createEnv();
    const response = await app.request(
      "/badges/40a6dc92-85ec-4cb0-8a50-afb2ae700e22/public_url",
      undefined,
      env,
    );

    expect(response.status).toBe(308);
    expect(response.headers.get("location")).toBe("/badges/40a6dc92-85ec-4cb0-8a50-afb2ae700e22");
  });

  it("redirects legacy tenant-scoped badge asset URLs to canonical public alias URLs", async () => {
    const env = createEnv();

    mockedFindAssertionByPublicId.mockResolvedValue(null);
    mockedFindAssertionById.mockResolvedValue(sampleAssertion());

    const response = await app.request("/badges/tenant_123%3Aassertion_456/jsonld", undefined, env);

    expect(response.status).toBe(308);
    expect(response.headers.get("location")).toBe(
      "/badges/40a6dc92-85ec-4cb0-8a50-afb2ae700e22/jsonld",
    );
    expect(mockedGetImmutableCredentialObject).not.toHaveBeenCalled();
  });

  it("returns verification JSON through the canonical public alias route", async () => {
    const env = createEnv();
    const credential: JsonObject = {
      "@context": ["https://www.w3.org/ns/credentials/v2"],
      id: "urn:credtrail:assertion:tenant_123%3Aassertion_456",
      type: ["VerifiableCredential", "OpenBadgeCredential"],
    };

    mockedFindAssertionByPublicId.mockResolvedValue(sampleAssertion());
    mockedGetImmutableCredentialObject.mockResolvedValue(credential);

    const response = await app.request(
      "/badges/40a6dc92-85ec-4cb0-8a50-afb2ae700e22/verification",
      undefined,
      env,
    );
    const body = await response.json<{
      verification: {
        status: string;
      };
    }>();

    expect(response.status).toBe(200);
    expect(response.headers.get("cache-control")).toBe("no-store");
    expect(body.verification.status).toBe("active");
  });

  it("routes supported share actions through CredTrail before redirecting outward", async () => {
    const env = createEnv();
    const credential: JsonObject = {
      id: "urn:credtrail:assertion:tenant_123%3Aassertion_456",
      issuer: {
        name: "Example University",
      },
      credentialSubject: {
        achievement: {
          name: "TypeScript Foundations",
        },
      },
    };

    mockedFindAssertionByPublicId.mockResolvedValue(sampleAssertion());
    mockedGetImmutableCredentialObject.mockResolvedValue(credential);

    const pageResponse = await app.request(
      "/badges/40a6dc92-85ec-4cb0-8a50-afb2ae700e22",
      undefined,
      env,
    );
    const pageBody = await pageResponse.text();

    expect(pageResponse.status).toBe(200);
    expect(pageBody).toContain("/badges/40a6dc92-85ec-4cb0-8a50-afb2ae700e22/share/linkedin-feed");
    expect(pageBody).toContain(
      "/badges/40a6dc92-85ec-4cb0-8a50-afb2ae700e22/share/linkedin-profile",
    );
    expect(pageBody).not.toContain('href="https://www.linkedin.com/sharing/share-offsite/');
    expect(pageBody).not.toContain('href="https://www.linkedin.com/profile/add');

    mockedRecordAssertionEngagementEvent.mockClear();

    const shareResponse = await app.request(
      "/badges/40a6dc92-85ec-4cb0-8a50-afb2ae700e22/share/linkedin-feed",
      undefined,
      env,
    );

    expect(shareResponse.status).toBe(302);
    expect(shareResponse.headers.get("location")).toContain(
      "https://www.linkedin.com/sharing/share-offsite/",
    );
    expect(mockedRecordAssertionEngagementEvent).toHaveBeenCalledWith(
      fakeDb,
      expect.objectContaining({
        tenantId: "tenant_123",
        assertionId: "tenant_123:assertion_456",
        eventType: "share_click",
        actorType: "anonymous",
        channel: "linkedin_feed",
        occurredAt: expect.stringMatching(/^20/),
      }),
    );
  });

  it("returns JSON-LD and PDF downloads through canonical public alias routes", async () => {
    const env = createEnv();
    const credential: JsonObject = {
      "@context": ["https://www.w3.org/ns/credentials/v2"],
      id: "urn:credtrail:assertion:tenant_123%3Aassertion_456",
      type: ["VerifiableCredential", "OpenBadgeCredential"],
    };

    mockedFindAssertionByPublicId.mockResolvedValue(sampleAssertion());
    mockedGetImmutableCredentialObject.mockResolvedValue(credential);

    const jsonldResponse = await app.request(
      "/badges/40a6dc92-85ec-4cb0-8a50-afb2ae700e22/jsonld",
      undefined,
      env,
    );
    const jsonldBody = await jsonldResponse.text();
    const pdfResponse = await app.request(
      "/badges/40a6dc92-85ec-4cb0-8a50-afb2ae700e22/download.pdf",
      undefined,
      env,
    );
    const pdfBody = await pdfResponse.arrayBuffer();

    expect(jsonldResponse.status).toBe(200);
    expect(jsonldResponse.headers.get("content-type")).toContain("application/vc+ld+json");
    expect(jsonldBody).toContain('"OpenBadgeCredential"');
    expect(pdfResponse.status).toBe(200);
    expect(pdfResponse.headers.get("content-type")).toContain("application/pdf");
    expect(new TextDecoder().decode(pdfBody.slice(0, 5))).toBe("%PDF-");
  });

  it("returns public summary JSON payload for canonical public badge identifier", async () => {
    const env = createEnv();
    const credential: JsonObject = {
      id: "urn:credtrail:assertion:tenant_123%3Aassertion_456",
      type: ["VerifiableCredential", "OpenBadgeCredential"],
      issuer: {
        id: "did:web:credtrail.test:tenant_123",
        name: "Example University",
        url: "https://example.edu",
      },
      credentialSubject: {
        id: "mailto:learner@example.edu",
        achievement: {
          id: "https://example.edu/badges/typescript-foundations",
          name: "TypeScript Foundations",
          description: "Awarded for completing TypeScript fundamentals.",
          criteria: {
            id: "https://example.edu/badges/typescript-foundations/criteria",
          },
          image: {
            id: "https://example.edu/badges/typescript-foundations/image.png",
          },
        },
      },
    };

    mockedFindAssertionByPublicId.mockResolvedValue(sampleAssertion());
    mockedFindLearnerProfileById.mockResolvedValue(
      sampleLearnerProfile({
        displayName: "Ada Lovelace",
      }),
    );
    mockedGetImmutableCredentialObject.mockResolvedValue(credential);

    const response = await app.request(
      "/badges/40a6dc92-85ec-4cb0-8a50-afb2ae700e22/summary",
      undefined,
      env,
    );
    const body = await response.json<{
      badge: {
        name: string;
        tenantId: string;
        badgeTemplateId: string;
        issuedAt: string;
      };
      recipient: {
        identity: string;
        displayName: string | null;
      };
      issuer: {
        name: string;
      };
      lifecycle: {
        state: string;
      };
      verification: {
        label: string;
        isValid: boolean;
      };
      links: {
        summaryPath: string;
        badgePagePath: string;
        criteriaRegistryPath: string;
      };
    }>();

    expect(response.status).toBe(200);
    expect(response.headers.get("cache-control")).toBe("no-store");
    expect(body.badge.name).toBe("TypeScript Foundations");
    expect(body.badge.tenantId).toBe("tenant_123");
    expect(body.badge.badgeTemplateId).toBe("badge_template_001");
    expect(body.badge.issuedAt).toBe("2026-02-10T22:00:00.000Z");
    expect(body.recipient.identity).toBe("learner@example.edu");
    expect(body.recipient.displayName).toBe("Ada Lovelace");
    expect(body.issuer.name).toBe("Example University");
    expect(body.lifecycle.state).toBe("active");
    expect(body.verification.label).toBe("verified");
    expect(body.verification.isValid).toBe(true);
    expect(body.links.summaryPath).toBe("/badges/40a6dc92-85ec-4cb0-8a50-afb2ae700e22/summary");
    expect(body.links.badgePagePath).toBe("/badges/40a6dc92-85ec-4cb0-8a50-afb2ae700e22");
    expect(body.links.criteriaRegistryPath).toBe(
      "/showcase/tenant_123/criteria?badgeTemplateId=badge_template_001",
    );
  });

  it("redirects legacy tenant-scoped summary URL to canonical summary URL", async () => {
    const env = createEnv();

    mockedFindAssertionByPublicId.mockResolvedValue(null);
    mockedFindAssertionById.mockResolvedValue(sampleAssertion());

    const response = await app.request(
      "/badges/tenant_123%3Aassertion_456/summary",
      undefined,
      env,
    );

    expect(response.status).toBe(308);
    expect(response.headers.get("location")).toBe(
      "/badges/40a6dc92-85ec-4cb0-8a50-afb2ae700e22/summary",
    );
    expect(mockedGetImmutableCredentialObject).not.toHaveBeenCalled();
  });

  it("returns OpenID4VCI credential offer payload for canonical public badge identifier", async () => {
    const env = createEnv();
    const credential: JsonObject = {
      id: "urn:credtrail:assertion:tenant_123%3Aassertion_456",
      credentialSubject: {
        achievement: {
          name: "TypeScript Foundations",
        },
      },
    };

    mockedFindAssertionByPublicId.mockResolvedValue(sampleAssertion());
    mockedGetImmutableCredentialObject.mockResolvedValue(credential);

    const response = await app.request(
      "/credentials/v1/offers/40a6dc92-85ec-4cb0-8a50-afb2ae700e22",
      undefined,
      env,
    );
    const body = await response.json<{
      credential_issuer: string;
      credential_configuration_ids: string[];
      grants: {
        "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
          "pre-authorized_code": string;
        };
      };
      x_credtrail: {
        token_endpoint: string;
        credential_endpoint: string;
        offer_expires_at: string;
        public_badge_url: string;
        verification_url: string;
        credential_jsonld_url: string;
        credential_download_url: string;
      };
    }>();

    expect(response.status).toBe(200);
    expect(body.credential_issuer).toBe("http://localhost");
    expect(body.credential_configuration_ids).toContain("OpenBadgeCredential");
    expect(
      body.grants["urn:ietf:params:oauth:grant-type:pre-authorized_code"]["pre-authorized_code"],
    ).toMatch(/^oid4vci_pc_/);
    expect(body.x_credtrail.token_endpoint).toBe("http://localhost/credentials/v1/token");
    expect(body.x_credtrail.credential_endpoint).toBe(
      "http://localhost/credentials/v1/credentials",
    );
    expect(body.x_credtrail.offer_expires_at).toMatch(/^20/);
    expect(body.x_credtrail.public_badge_url).toBe(
      "http://localhost/badges/40a6dc92-85ec-4cb0-8a50-afb2ae700e22",
    );
    expect(body.x_credtrail.verification_url).toBe(
      "http://localhost/badges/40a6dc92-85ec-4cb0-8a50-afb2ae700e22/verification",
    );
    expect(body.x_credtrail.credential_jsonld_url).toBe(
      "http://localhost/badges/40a6dc92-85ec-4cb0-8a50-afb2ae700e22/jsonld",
    );
    expect(body.x_credtrail.credential_download_url).toBe(
      "http://localhost/badges/40a6dc92-85ec-4cb0-8a50-afb2ae700e22/download",
    );
    expect(mockedCreateOid4vciPreAuthorizedCode).toHaveBeenCalledTimes(1);
  });

  it("resolves credential_offer_uri with Sphereon and the CredTrail contract parser", async () => {
    const env = createEnv();
    const credential: JsonObject = {
      id: "urn:credtrail:assertion:tenant_123%3Aassertion_456",
      credentialSubject: {
        achievement: {
          name: "TypeScript Foundations",
        },
      },
    };

    mockedFindAssertionByPublicId.mockResolvedValue(sampleAssertion());
    mockedGetImmutableCredentialObject.mockResolvedValue(credential);

    const offerResponse = await app.request(
      "https://credtrail.test/credentials/v1/offers/40a6dc92-85ec-4cb0-8a50-afb2ae700e22",
      undefined,
      env,
    );
    expect(offerResponse.status).toBe(200);
    const offerPayload = await offerResponse.text();

    let offerRequestCount = 0;
    const server = createServer((request, response) => {
      if (request.url === "/wallet-offer") {
        offerRequestCount += 1;
        response.writeHead(200, { "content-type": "application/json" });
        response.end(offerPayload);
        return;
      }
      response.writeHead(404);
      response.end();
    });

    server.listen(0, "127.0.0.1");
    await once(server, "listening");

    const address = server.address();
    if (address === null || typeof address === "string") {
      server.close();
      throw new Error("Failed to determine wallet offer server address");
    }

    const walletOfferUrl = `http://127.0.0.1:${String(address.port)}/wallet-offer`;
    const walletOfferUri = `openid-credential-offer://?credential_offer_uri=${encodeURIComponent(walletOfferUrl)}`;

    try {
      const sphereonOffer = await CredentialOfferClient.fromURI(walletOfferUri, { resolve: true });
      const credtrailOffer = await resolveCredentialOfferUriForTest(walletOfferUri);

      expect(offerRequestCount).toBe(2);
      expect(sphereonOffer.credential_offer.credential_configuration_ids).toContain(
        "OpenBadgeCredential",
      );
      expect(sphereonOffer.credential_offer.credential_issuer).toBe("https://credtrail.test");
      expect(sphereonOffer.preAuthorizedCode).toMatch(/^oid4vci_pc_/);
      expect(sphereonOffer.supportedFlows).toContain("Pre-Authorized Code Flow");
      expect(
        sphereonOffer.credential_offer.grants?.[
          "urn:ietf:params:oauth:grant-type:pre-authorized_code"
        ]?.["pre-authorized_code"],
      ).toBe(sphereonOffer.preAuthorizedCode);

      expect(credtrailOffer.credentialConfigurationIds).toContain("OpenBadgeCredential");
      expect(credtrailOffer.credentialIssuer).toBe("https://credtrail.test");
      expect(credtrailOffer.credentials).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            format: "ldp_vc",
          }),
        ]),
      );
      expect(credtrailOffer.preAuthorizedCode).toBe(sphereonOffer.preAuthorizedCode);
    } finally {
      server.close();
      await once(server, "close");
    }
  });

  it("redirects legacy tenant-scoped offer URL to canonical offer URL", async () => {
    const env = createEnv();
    const credential: JsonObject = {
      id: "urn:credtrail:assertion:tenant_123%3Aassertion_456",
    };

    mockedFindAssertionByPublicId.mockResolvedValue(null);
    mockedFindAssertionById.mockResolvedValue(sampleAssertion());
    mockedGetImmutableCredentialObject.mockResolvedValue(credential);

    const response = await app.request(
      "/credentials/v1/offers/tenant_123%3Aassertion_456",
      undefined,
      env,
    );

    expect(response.status).toBe(308);
    expect(response.headers.get("location")).toBe(
      "/credentials/v1/offers/40a6dc92-85ec-4cb0-8a50-afb2ae700e22",
    );
  });

  it("serves OpenID4VCI issuer metadata for wallet discovery", async () => {
    const response = await app.request(
      "/.well-known/openid-credential-issuer",
      undefined,
      createEnv(),
    );
    const body = await response.json<{
      credential_issuer: string;
      token_endpoint: string;
      credential_endpoint: string;
      credential_configurations_supported: {
        OpenBadgeCredential?: {
          format: string;
        };
      };
    }>();

    expect(response.status).toBe(200);
    expect(body.credential_issuer).toBe("http://localhost");
    expect(body.token_endpoint).toBe("http://localhost/credentials/v1/token");
    expect(body.credential_endpoint).toBe("http://localhost/credentials/v1/credentials");
    expect(body.credential_configurations_supported.OpenBadgeCredential?.format).toBe("ldp_vc");
  });

  it("creates offer URIs through POST /credentials/offer", async () => {
    const env = createEnv();
    const credential: JsonObject = {
      id: "urn:credtrail:assertion:tenant_123%3Aassertion_456",
      credentialSubject: {
        achievement: {
          name: "TypeScript Foundations",
        },
      },
    };

    mockedFindAssertionByPublicId.mockResolvedValue(sampleAssertion());
    mockedGetImmutableCredentialObject.mockResolvedValue(credential);

    const response = await app.request(
      "/credentials/offer",
      {
        method: "POST",
        headers: {
          "content-type": "application/json",
        },
        body: JSON.stringify({
          badgeIdentifier: "40a6dc92-85ec-4cb0-8a50-afb2ae700e22",
        }),
      },
      env,
    );
    const body = await response.json<{
      credential_offer_uri: string;
      credential_offer: {
        grants: {
          "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
            "pre-authorized_code": string;
          };
        };
      };
    }>();

    expect(response.status).toBe(201);
    expect(body.credential_offer_uri).toBe(
      "http://localhost/credentials/v1/offers/40a6dc92-85ec-4cb0-8a50-afb2ae700e22",
    );
    expect(
      body.credential_offer.grants["urn:ietf:params:oauth:grant-type:pre-authorized_code"][
        "pre-authorized_code"
      ],
    ).toMatch(/^oid4vci_pc_/);
  });

  it("returns DCC wallet request payload with vcapi exchange URL and deep-link aliases", async () => {
    const env = createEnv();
    const credential: JsonObject = {
      id: "urn:credtrail:assertion:tenant_123%3Aassertion_456",
      type: ["VerifiableCredential", "OpenBadgeCredential"],
    };

    mockedFindAssertionByPublicId.mockResolvedValue(sampleAssertion());
    mockedGetImmutableCredentialObject.mockResolvedValue(credential);

    const response = await app.request(
      "/credentials/v1/dcc/request/40a6dc92-85ec-4cb0-8a50-afb2ae700e22",
      undefined,
      env,
    );
    const body = await response.json<{
      credentialRequestOrigin: string;
      protocols: {
        vcapi: string;
      };
      app_link_deep_link_url: string;
      custom_protocol_deep_link_url: string;
    }>();

    expect(response.status).toBe(200);
    expect(body.credentialRequestOrigin).toBe("http://localhost");
    expect(body.protocols.vcapi).toBe(
      "http://localhost/credentials/v1/dcc/exchanges/40a6dc92-85ec-4cb0-8a50-afb2ae700e22",
    );
    expect(body.app_link_deep_link_url).toContain("https://lcw.app/request?request=");
    expect(body.custom_protocol_deep_link_url).toContain("dccrequest://");

    const deepLinkPayload = new URL(body.app_link_deep_link_url).searchParams.get("request");
    expect(deepLinkPayload).not.toBeNull();
    const parsedRequestPayload = JSON.parse(deepLinkPayload ?? "{}") as {
      protocols?: {
        vcapi?: string;
      };
      credentialRequestOrigin?: string;
    };
    expect(parsedRequestPayload.credentialRequestOrigin).toBe("http://localhost");
    expect(parsedRequestPayload.protocols?.vcapi).toBe(body.protocols.vcapi);
  });

  it("returns DCC VC-API exchange offer payload that wraps badge credential as a VP offer", async () => {
    const env = createEnv();
    const credential: JsonObject = {
      id: "urn:credtrail:assertion:tenant_123%3Aassertion_456",
      type: ["VerifiableCredential", "OpenBadgeCredential"],
      credentialSubject: {
        achievement: {
          name: "TypeScript Foundations",
        },
      },
    };

    mockedFindAssertionByPublicId.mockResolvedValue(sampleAssertion());
    mockedGetImmutableCredentialObject.mockResolvedValue(credential);

    const response = await app.request(
      "/credentials/v1/dcc/exchanges/40a6dc92-85ec-4cb0-8a50-afb2ae700e22",
      {
        method: "POST",
        headers: {
          "content-type": "application/json",
        },
        body: "{}",
      },
      env,
    );
    const body = await response.json<{
      credentialRequestOrigin: string;
      redirectUrl: string;
      verifiablePresentation: {
        "@context": string[];
        type: string[];
        verifiableCredential: JsonObject[];
      };
    }>();

    expect(response.status).toBe(200);
    expect(body.credentialRequestOrigin).toBe("http://localhost");
    expect(body.redirectUrl).toBe("http://localhost/badges/40a6dc92-85ec-4cb0-8a50-afb2ae700e22");
    expect(body.verifiablePresentation.type).toEqual(["VerifiablePresentation"]);
    expect(body.verifiablePresentation.verifiableCredential).toEqual([credential]);
  });

  it("exchanges pre-authorized code for access token and returns credential via OID4VCI endpoints", async () => {
    const env = createEnv();
    const credential: JsonObject = {
      id: "urn:credtrail:assertion:tenant_123%3Aassertion_456",
      type: ["VerifiableCredential", "OpenBadgeCredential"],
      credentialSubject: {
        achievement: {
          name: "TypeScript Foundations",
        },
      },
    };

    mockedConsumeOid4vciPreAuthorizedCode.mockResolvedValue(
      sampleOid4vciPreAuthorizedCodeRecord({
        usedAt: "2026-02-10T22:00:30.000Z",
      }),
    );
    mockedCreateOid4vciAccessToken.mockResolvedValue(sampleOid4vciAccessTokenRecord());
    mockedFindActiveOid4vciAccessTokenByHash.mockResolvedValue(sampleOid4vciAccessTokenRecord());
    mockedFindAssertionById.mockResolvedValue(sampleAssertion());
    mockedGetImmutableCredentialObject.mockResolvedValue(credential);

    const tokenResponse = await app.request(
      "/credentials/v1/token",
      {
        method: "POST",
        headers: {
          "content-type": "application/x-www-form-urlencoded",
        },
        body: new URLSearchParams({
          grant_type: "urn:ietf:params:oauth:grant-type:pre-authorized_code",
          "pre-authorized_code": "oid4vci_pc_example",
        }).toString(),
      },
      env,
    );
    const tokenBody = await tokenResponse.json<{
      access_token: string;
      token_type: string;
      expires_in: number;
    }>();

    expect(tokenResponse.status).toBe(200);
    expect(tokenBody.access_token).toMatch(/^oid4vci_at_/);
    expect(tokenBody.token_type).toBe("Bearer");
    expect(tokenBody.expires_in).toBe(600);
    expect(mockedConsumeOid4vciPreAuthorizedCode).toHaveBeenCalledTimes(1);
    expect(mockedCreateOid4vciAccessToken).toHaveBeenCalledTimes(1);

    const credentialResponse = await app.request(
      "/credentials/v1/credentials",
      {
        method: "POST",
        headers: {
          authorization: `Bearer ${tokenBody.access_token}`,
          "content-type": "application/json",
        },
        body: JSON.stringify({
          format: "ldp_vc",
        }),
      },
      env,
    );
    const credentialBody = await credentialResponse.json<{
      format: string;
      credential: JsonObject;
      credential_identifier: string;
    }>();

    expect(credentialResponse.status).toBe(200);
    expect(credentialBody.format).toBe("ldp_vc");
    expect(credentialBody.credential_identifier).toBe("tenant_123:assertion_456");
    expect(credentialBody.credential).toEqual(credential);
  });

  it("renders revoked state for revoked credentials", async () => {
    const env = createEnv();
    const credential: JsonObject = {
      id: "urn:credtrail:assertion:tenant_123%3Aassertion_456",
      credentialSubject: {
        achievement: {
          name: "TypeScript Foundations",
        },
      },
    };

    mockedFindAssertionByPublicId.mockResolvedValue(
      sampleAssertion({
        revokedAt: "2026-02-11T01:00:00.000Z",
      }),
    );
    mockedResolveAssertionLifecycleState.mockResolvedValue({
      state: "revoked",
      source: "lifecycle_event",
      reasonCode: "issuer_requested",
      reason: "Issuer requested revocation",
      transitionedAt: "2026-02-11T01:00:00.000Z",
      revokedAt: "2026-02-11T01:00:00.000Z",
    });
    mockedGetImmutableCredentialObject.mockResolvedValue(credential);

    const response = await app.request(
      "/badges/40a6dc92-85ec-4cb0-8a50-afb2ae700e22",
      undefined,
      env,
    );
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(body).toContain("Revoked");
    expect(body).toContain("Revoked at");
    expect(body).not.toContain("Evidence</h2>");
  });

  it("renders suspended lifecycle state with reason text", async () => {
    const env = createEnv();
    const credential: JsonObject = {
      id: "urn:credtrail:assertion:tenant_123%3Aassertion_456",
      credentialSubject: {
        achievement: {
          name: "TypeScript Foundations",
        },
      },
    };

    mockedFindAssertionByPublicId.mockResolvedValue(sampleAssertion());
    mockedResolveAssertionLifecycleState.mockResolvedValue({
      state: "suspended",
      source: "lifecycle_event",
      reasonCode: "administrative_hold",
      reason: "Suspended pending conduct review",
      transitionedAt: "2026-02-12T02:30:00.000Z",
      revokedAt: null,
    });
    mockedGetImmutableCredentialObject.mockResolvedValue(credential);

    const response = await app.request(
      "/badges/40a6dc92-85ec-4cb0-8a50-afb2ae700e22",
      undefined,
      env,
    );
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(body).toContain("Suspended");
    expect(body).toContain("Suspended pending conduct review");
    expect(body).toContain("since");
  });

  it("returns not found page when credential does not exist", async () => {
    const env = createEnv();
    mockedFindAssertionByPublicId.mockResolvedValue(null);
    mockedFindAssertionById.mockResolvedValue(null);

    const response = await app.request("/badges/tenant_123%3Aassertion_456", undefined, env);
    const body = await response.text();

    expect(response.status).toBe(404);
    expect(body).toContain("Badge not found");
    expect(body).toContain('<meta name="robots" content="noindex, nofollow"');
    expect(mockedGetImmutableCredentialObject).not.toHaveBeenCalled();
    expect(mockedRecordAssertionEngagementEvent).not.toHaveBeenCalled();
  });

  it("returns not found page for unknown public badge identifiers", async () => {
    const env = createEnv();
    mockedFindAssertionByPublicId.mockResolvedValue(null);

    const response = await app.request("/badges/assertion_456", undefined, env);
    const body = await response.text();

    expect(response.status).toBe(404);
    expect(body).toContain("Badge not found");
    expect(mockedFindAssertionById).not.toHaveBeenCalled();
    expect(mockedRecordAssertionEngagementEvent).not.toHaveBeenCalled();
  });

  it("returns not found page when public_url alias is empty", async () => {
    const env = createEnv();
    const response = await app.request("/badges/%20/public_url", undefined, env);
    const body = await response.text();

    expect(response.status).toBe(404);
    expect(body).toContain("Badge not found");
    expect(mockedFindAssertionById).not.toHaveBeenCalled();
  });
});

import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("@credtrail/db", async () => {
  const actual = await vi.importActual<typeof import("@credtrail/db")>("@credtrail/db");

  return {
    ...actual,
    findTenantSigningRegistrationByDid: vi.fn(),
    upsertBadgeTemplateById: vi.fn(),
    upsertTenant: vi.fn(),
    upsertTenantSigningRegistration: vi.fn(),
  };
});

vi.mock("@credtrail/db/postgres", () => {
  return {
    createPostgresDatabase: vi.fn(),
  };
});

import { generateTenantDidSigningMaterial, type JsonObject } from "@credtrail/core-domain";
import {
  upsertBadgeTemplateById,
  findTenantSigningRegistrationByDid,
  upsertTenant,
  upsertTenantSigningRegistration,
  type BadgeTemplateRecord,
  type SqlDatabase,
  type TenantRecord,
  type TenantSigningRegistrationRecord,
} from "@credtrail/db";
import { createPostgresDatabase } from "@credtrail/db/postgres";
import { app } from "./index";

const mockedCreatePostgresDatabase = vi.mocked(createPostgresDatabase);
const mockedFindTenantSigningRegistrationByDid = vi.mocked(findTenantSigningRegistrationByDid);
const mockedUpsertBadgeTemplateById = vi.mocked(upsertBadgeTemplateById);
const mockedUpsertTenant = vi.mocked(upsertTenant);
const mockedUpsertTenantSigningRegistration = vi.mocked(upsertTenantSigningRegistration);

const fakeDb = {
  prepare: vi.fn(),
} as unknown as SqlDatabase;

const createEnv = (): {
  APP_ENV: string;
  DATABASE_URL: string;
  BADGE_OBJECTS: R2Bucket;
  PLATFORM_DOMAIN: string;
  BOOTSTRAP_ADMIN_TOKEN?: string;
} => {
  return {
    APP_ENV: "test",
    DATABASE_URL: "postgres://credtrail-test.local/db",
    BADGE_OBJECTS: {} as R2Bucket,
    PLATFORM_DOMAIN: "credtrail.test",
    BOOTSTRAP_ADMIN_TOKEN: "bootstrap-secret",
  };
};

const sampleRegistration = (
  overrides?: Partial<TenantSigningRegistrationRecord>,
): TenantSigningRegistrationRecord => {
  return {
    tenantId: "platform",
    did: "did:web:credtrail.test",
    keyId: "key-1",
    publicJwkJson: JSON.stringify({
      kty: "OKP",
      crv: "Ed25519",
      x: "A".repeat(32),
    }),
    privateJwkJson: null,
    createdAt: "2026-06-04T12:00:00.000Z",
    updatedAt: "2026-06-04T12:00:00.000Z",
    ...overrides,
  };
};

const sampleTenant = (overrides?: Partial<TenantRecord>): TenantRecord => {
  return {
    id: "sakai",
    slug: "sakai",
    displayName: "Sakai Project",
    planTier: "team",
    issuerDomain: "sakai.credtrail.test",
    didWeb: "did:web:credtrail.test:sakai",
    isActive: true,
    createdAt: "2026-06-04T12:00:00.000Z",
    updatedAt: "2026-06-04T12:00:00.000Z",
    ...overrides,
  };
};

const sampleBadgeTemplate = (overrides?: Partial<BadgeTemplateRecord>): BadgeTemplateRecord => {
  return {
    id: "badge_template_sakai_1000",
    tenantId: "sakai",
    slug: "sakai-1000-commits-contributor",
    title: "Sakai 1000+ Commits Contributor",
    description: "Awarded for contributing at least 1000 commits.",
    criteriaUri: "https://github.com/sakaiproject/sakai",
    imageUri: "https://avatars.githubusercontent.com/u/429529?s=200&v=4",
    trustedCredentialMetadataJson: null,
    createdByUserId: null,
    ownerOrgUnitId: "sakai:org:institution",
    governanceMetadataJson: '{"stability":"institution_registry"}',
    isArchived: false,
    createdAt: "2026-06-04T12:00:00.000Z",
    updatedAt: "2026-06-04T12:00:00.000Z",
    ...overrides,
  };
};

const asJsonObject = (value: unknown): JsonObject => {
  expect(value).not.toBeNull();
  expect(typeof value).toBe("object");
  expect(Array.isArray(value)).toBe(false);
  return value as JsonObject;
};

describe("bootstrap admin signing registration routes", () => {
  beforeEach(() => {
    mockedCreatePostgresDatabase.mockReset();
    mockedCreatePostgresDatabase.mockReturnValue(fakeDb);
    mockedFindTenantSigningRegistrationByDid.mockReset();
    mockedFindTenantSigningRegistrationByDid.mockResolvedValue(null);
    mockedUpsertBadgeTemplateById.mockReset();
    mockedUpsertTenant.mockReset();
    mockedUpsertTenantSigningRegistration.mockReset();
  });

  it("upserts a tenant for existing bootstrap scripts", async () => {
    mockedUpsertTenant.mockResolvedValue(sampleTenant());

    const response = await app.request(
      "/v1/admin/tenants/sakai",
      {
        method: "PUT",
        headers: {
          authorization: "Bearer bootstrap-secret",
          "content-type": "application/json",
        },
        body: JSON.stringify({
          slug: "sakai",
          displayName: "Sakai Project",
          planTier: "team",
          issuerDomain: "sakai.credtrail.test",
          isActive: true,
        }),
      },
      createEnv(),
    );
    const body = await response.json<JsonObject>();

    expect(response.status).toBe(201);
    expect(body.tenantId).toBe("sakai");
    expect(body.didWeb).toBe("did:web:credtrail.test:sakai");
    expect(mockedUpsertTenant).toHaveBeenCalledWith(fakeDb, {
      id: "sakai",
      slug: "sakai",
      displayName: "Sakai Project",
      planTier: "team",
      issuerDomain: "sakai.credtrail.test",
      didWeb: "did:web:credtrail.test:sakai",
      isActive: true,
    });
  });

  it("registers the platform root did:web signing material", async () => {
    const signingMaterial = await generateTenantDidSigningMaterial({
      did: "did:web:credtrail.test",
      keyId: "key-root",
    });

    mockedUpsertTenantSigningRegistration.mockResolvedValue(
      sampleRegistration({
        tenantId: "platform",
        did: signingMaterial.did,
        keyId: signingMaterial.keyId,
        publicJwkJson: JSON.stringify(signingMaterial.publicJwk),
        privateJwkJson: JSON.stringify(signingMaterial.privateJwk),
      }),
    );

    const response = await app.request(
      "/v1/admin/platform/signing-registration",
      {
        method: "PUT",
        headers: {
          authorization: "Bearer bootstrap-secret",
          "content-type": "application/json",
        },
        body: JSON.stringify({
          keyId: signingMaterial.keyId,
          publicJwk: signingMaterial.publicJwk,
          privateJwk: signingMaterial.privateJwk,
        }),
      },
      createEnv(),
    );
    const body = await response.json<JsonObject>();
    const didDocument = asJsonObject(body.didDocument);

    expect(response.status).toBe(201);
    expect(body.did).toBe("did:web:credtrail.test");
    expect(body.tenantId).toBe("platform");
    expect(didDocument.id).toBe("did:web:credtrail.test");
    expect(mockedUpsertTenant).toHaveBeenCalledWith(fakeDb, {
      id: "platform",
      slug: "platform",
      displayName: "CredTrail Platform",
      planTier: "enterprise",
      issuerDomain: "credtrail.test",
      didWeb: "did:web:credtrail.test",
      isActive: true,
    });
    expect(mockedUpsertTenantSigningRegistration).toHaveBeenCalledWith(fakeDb, {
      tenantId: "platform",
      did: "did:web:credtrail.test",
      keyId: signingMaterial.keyId,
      publicJwkJson: JSON.stringify(signingMaterial.publicJwk),
      privateJwkJson: expect.any(String),
    });
    const upsertInput = mockedUpsertTenantSigningRegistration.mock.calls[0]?.[1];
    expect(upsertInput).toBeDefined();
    expect(JSON.parse(upsertInput?.privateJwkJson ?? "{}")).toEqual(signingMaterial.privateJwk);
  });

  it("registers tenant path did:web signing material for existing bootstrap scripts", async () => {
    const signingMaterial = await generateTenantDidSigningMaterial({
      did: "did:web:credtrail.test:sakai",
      keyId: "key-sakai",
    });

    mockedUpsertTenantSigningRegistration.mockResolvedValue(
      sampleRegistration({
        tenantId: "sakai",
        did: signingMaterial.did,
        keyId: signingMaterial.keyId,
        publicJwkJson: JSON.stringify(signingMaterial.publicJwk),
        privateJwkJson: JSON.stringify(signingMaterial.privateJwk),
      }),
    );

    const response = await app.request(
      "/v1/admin/tenants/sakai/signing-registration",
      {
        method: "PUT",
        headers: {
          authorization: "Bearer bootstrap-secret",
          "content-type": "application/json",
        },
        body: JSON.stringify({
          keyId: signingMaterial.keyId,
          publicJwk: signingMaterial.publicJwk,
          privateJwk: signingMaterial.privateJwk,
        }),
      },
      createEnv(),
    );

    expect(response.status).toBe(201);
    expect(mockedUpsertTenant).not.toHaveBeenCalled();
    expect(mockedUpsertTenantSigningRegistration).toHaveBeenCalledWith(fakeDb, {
      tenantId: "sakai",
      did: "did:web:credtrail.test:sakai",
      keyId: signingMaterial.keyId,
      publicJwkJson: JSON.stringify(signingMaterial.publicJwk),
      privateJwkJson: expect.any(String),
    });
    const upsertInput = mockedUpsertTenantSigningRegistration.mock.calls[0]?.[1];
    expect(upsertInput).toBeDefined();
    expect(JSON.parse(upsertInput?.privateJwkJson ?? "{}")).toEqual(signingMaterial.privateJwk);
  });

  it("upserts a badge template for existing bootstrap scripts", async () => {
    mockedUpsertBadgeTemplateById.mockResolvedValue(sampleBadgeTemplate());

    const response = await app.request(
      "/v1/admin/tenants/sakai/badge-templates/badge_template_sakai_1000",
      {
        method: "PUT",
        headers: {
          authorization: "Bearer bootstrap-secret",
          "content-type": "application/json",
        },
        body: JSON.stringify({
          slug: "sakai-1000-commits-contributor",
          title: "Sakai 1000+ Commits Contributor",
          description: "Awarded for contributing at least 1000 commits.",
          criteriaUri: "https://github.com/sakaiproject/sakai",
          imageUri: "https://avatars.githubusercontent.com/u/429529?s=200&v=4",
        }),
      },
      createEnv(),
    );
    const body = await response.json<JsonObject>();

    expect(response.status).toBe(201);
    expect(body.id).toBe("badge_template_sakai_1000");
    expect(mockedUpsertBadgeTemplateById).toHaveBeenCalledWith(fakeDb, {
      id: "badge_template_sakai_1000",
      tenantId: "sakai",
      slug: "sakai-1000-commits-contributor",
      title: "Sakai 1000+ Commits Contributor",
      description: "Awarded for contributing at least 1000 commits.",
      criteriaUri: "https://github.com/sakaiproject/sakai",
      imageUri: "https://avatars.githubusercontent.com/u/429529?s=200&v=4",
    });
  });

  it("hides bootstrap routes when the bootstrap token is not configured", async () => {
    const env = createEnv();
    delete env.BOOTSTRAP_ADMIN_TOKEN;

    const response = await app.request(
      "/v1/admin/platform/signing-registration",
      {
        method: "PUT",
        headers: {
          authorization: "Bearer bootstrap-secret",
          "content-type": "application/json",
        },
        body: JSON.stringify({
          keyId: "key-root",
          publicJwk: {
            kty: "OKP",
            crv: "Ed25519",
            x: "A".repeat(32),
          },
        }),
      },
      env,
    );

    expect(response.status).toBe(404);
    expect(mockedUpsertTenantSigningRegistration).not.toHaveBeenCalled();
  });

  it("rejects unauthorized bootstrap requests", async () => {
    const response = await app.request(
      "/v1/admin/platform/signing-registration",
      {
        method: "PUT",
        headers: {
          authorization: "Bearer wrong-secret",
          "content-type": "application/json",
        },
        body: JSON.stringify({
          keyId: "key-root",
          publicJwk: {
            kty: "OKP",
            crv: "Ed25519",
            x: "A".repeat(32),
          },
        }),
      },
      createEnv(),
    );

    expect(response.status).toBe(401);
    expect(mockedUpsertTenantSigningRegistration).not.toHaveBeenCalled();
  });

  it("rejects P-256 signing registrations because current signing is Ed25519-only", async () => {
    const response = await app.request(
      "/v1/admin/platform/signing-registration",
      {
        method: "PUT",
        headers: {
          authorization: "Bearer bootstrap-secret",
          "content-type": "application/json",
        },
        body: JSON.stringify({
          keyId: "key-p256",
          publicJwk: {
            kty: "EC",
            crv: "P-256",
            x: "x",
            y: "y",
          },
        }),
      },
      createEnv(),
    );

    expect(response.status).toBe(400);
    expect(mockedUpsertTenantSigningRegistration).not.toHaveBeenCalled();
  });
});

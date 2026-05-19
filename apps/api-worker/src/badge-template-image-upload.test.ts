import { beforeEach, describe, expect, it, vi } from "vitest";

const {
  mockedResolveBetterAuthPrincipal,
  mockedResolveBetterAuthRequestedTenant,
  mockedFindActiveSessionByHash,
  mockedTouchSession,
} = vi.hoisted(() => {
  return {
    mockedResolveBetterAuthPrincipal: vi.fn(),
    mockedResolveBetterAuthRequestedTenant: vi.fn(),
    mockedFindActiveSessionByHash: vi.fn(),
    mockedTouchSession: vi.fn(),
  };
});

vi.mock("@credtrail/db", async () => {
  const actual = await vi.importActual<typeof import("@credtrail/db")>("@credtrail/db");

  return {
    ...actual,
    createAuditLog: vi.fn(),
    createBadgeTemplateImageGeneration: vi.fn(),
    createBadgeTemplateImageRevision: vi.fn(),
    enqueueJobQueueMessage: vi.fn(),
    findActiveSessionByHash: mockedFindActiveSessionByHash,
    findBadgeTemplateById: vi.fn(),
    findBadgeTemplateImageGenerationById: vi.fn(),
    findBadgeTemplateImageRevisionById: vi.fn(),
    findTenantMembership: vi.fn(),
    hasTenantMembershipOrgUnitAccess: vi.fn(),
    hasTenantMembershipOrgUnitScopeAssignments: vi.fn(),
    listBadgeTemplateImageRevisions: vi.fn(),
    listBadgeTemplates: vi.fn(),
    touchSession: mockedTouchSession,
    updateBadgeTemplate: vi.fn(),
    updateBadgeTemplateImageGeneration: vi.fn(),
  };
});

vi.mock("@credtrail/db/postgres", () => {
  return {
    createPostgresDatabase: vi.fn(),
  };
});

vi.mock("./auth/better-auth-adapter", async () => {
  const actual = await vi.importActual<typeof import("./auth/better-auth-adapter")>(
    "./auth/better-auth-adapter",
  );

  return {
    ...actual,
    createBetterAuthProvider: vi.fn(() => ({
      requestMagicLink: vi.fn(),
      createMagicLinkSession: vi.fn(),
      createLtiSession: vi.fn(),
      resolveAuthenticatedPrincipal: mockedResolveBetterAuthPrincipal,
      resolveRequestedTenantContext: mockedResolveBetterAuthRequestedTenant,
      revokeCurrentSession: vi.fn(async () => {}),
    })),
  };
});

import {
  createAuditLog,
  createBadgeTemplateImageGeneration,
  createBadgeTemplateImageRevision,
  enqueueJobQueueMessage,
  findBadgeTemplateById,
  findBadgeTemplateImageGenerationById,
  findBadgeTemplateImageRevisionById,
  findTenantMembership,
  hasTenantMembershipOrgUnitAccess,
  hasTenantMembershipOrgUnitScopeAssignments,
  listBadgeTemplateImageRevisions,
  listBadgeTemplates,
  updateBadgeTemplate,
  updateBadgeTemplateImageGeneration,
  type BadgeTemplateRecord,
  type BadgeTemplateImageGenerationRecord,
  type BadgeTemplateImageRevisionRecord,
  type JobQueueMessageRecord,
  type SessionRecord,
  type SqlDatabase,
  type TenantMembershipRecord,
} from "@credtrail/db";
import { createPostgresDatabase } from "@credtrail/db/postgres";
import type { BadgeTemplateImageGenerationAiBinding } from "./badges/badge-template-image-generation";
import { BADGE_TEMPLATE_IMAGE_MAX_BYTES } from "./badges/template-image-storage";
import { app } from "./index";

const mockedCreateAuditLog = vi.mocked(createAuditLog);
const mockedCreateBadgeTemplateImageGeneration = vi.mocked(createBadgeTemplateImageGeneration);
const mockedCreateBadgeTemplateImageRevision = vi.mocked(createBadgeTemplateImageRevision);
const mockedEnqueueJobQueueMessage = vi.mocked(enqueueJobQueueMessage);
const mockedFindBadgeTemplateById = vi.mocked(findBadgeTemplateById);
const mockedFindBadgeTemplateImageGenerationById = vi.mocked(findBadgeTemplateImageGenerationById);
const mockedFindBadgeTemplateImageRevisionById = vi.mocked(findBadgeTemplateImageRevisionById);
const mockedFindTenantMembership = vi.mocked(findTenantMembership);
const mockedHasTenantMembershipOrgUnitAccess = vi.mocked(hasTenantMembershipOrgUnitAccess);
const mockedHasTenantMembershipOrgUnitScopeAssignments = vi.mocked(
  hasTenantMembershipOrgUnitScopeAssignments,
);
const mockedListBadgeTemplateImageRevisions = vi.mocked(listBadgeTemplateImageRevisions);
const mockedListBadgeTemplates = vi.mocked(listBadgeTemplates);
const mockedUpdateBadgeTemplate = vi.mocked(updateBadgeTemplate);
const mockedUpdateBadgeTemplateImageGeneration = vi.mocked(updateBadgeTemplateImageGeneration);
const mockedCreatePostgresDatabase = vi.mocked(createPostgresDatabase);

const fakeDb = {
  prepare: vi.fn(),
} as unknown as SqlDatabase;

const createEnv = (
  badgeObjects: R2Bucket,
): {
  APP_ENV: string;
  DATABASE_URL: string;
  BADGE_OBJECTS: R2Bucket;
  PLATFORM_DOMAIN: string;
} => {
  return {
    APP_ENV: "test",
    DATABASE_URL: "postgres://credtrail-test.local/db",
    BADGE_OBJECTS: badgeObjects,
    PLATFORM_DOMAIN: "credtrail.test",
  };
};

const sampleSession = (): SessionRecord => {
  return {
    id: "ses_123",
    tenantId: "tenant_123",
    userId: "usr_admin",
    sessionTokenHash: "session_hash",
    expiresAt: "2026-02-23T23:00:00.000Z",
    lastSeenAt: "2026-02-23T12:00:00.000Z",
    revokedAt: null,
    createdAt: "2026-02-23T12:00:00.000Z",
  };
};

const sampleSessionForTenant = (tenantId: string): SessionRecord => {
  return {
    ...sampleSession(),
    tenantId,
  };
};

const sampleMembership = (): TenantMembershipRecord => {
  return {
    tenantId: "tenant_123",
    userId: "usr_admin",
    role: "admin",
    createdAt: "2026-02-23T12:00:00.000Z",
    updatedAt: "2026-02-23T12:00:00.000Z",
  };
};

const sampleTemplate = (overrides?: Partial<BadgeTemplateRecord>): BadgeTemplateRecord => {
  return {
    id: "badge_template_001",
    tenantId: "tenant_123",
    slug: "typescript-foundations",
    title: "TypeScript Foundations",
    description: "Awarded for TypeScript basics.",
    criteriaUri: null,
    imageUri: null,
    createdByUserId: "usr_admin",
    ownerOrgUnitId: "tenant_123:org:institution",
    governanceMetadataJson: null,
    isArchived: false,
    createdAt: "2026-02-23T12:00:00.000Z",
    updatedAt: "2026-02-23T12:00:00.000Z",
    ...overrides,
  };
};

const sampleImageRevision = (
  overrides?: Partial<BadgeTemplateImageRevisionRecord>,
): BadgeTemplateImageRevisionRecord => {
  return {
    id: "btir_123",
    tenantId: "tenant_123",
    badgeTemplateId: "badge_template_001",
    previousImageUri: "https://credtrail.test/old.png",
    newImageUri: "https://credtrail.test/new.png",
    sourceType: "upload",
    promptText: null,
    provider: null,
    model: null,
    metadataJson: null,
    createdByUserId: "usr_admin",
    createdAt: "2026-02-23T12:30:00.000Z",
    ...overrides,
  };
};

const sampleImageGeneration = (
  overrides?: Partial<BadgeTemplateImageGenerationRecord>,
): BadgeTemplateImageGenerationRecord => {
  return {
    id: "btig_123",
    tenantId: "tenant_123",
    badgeTemplateId: "badge_template_001",
    status: "queued",
    promptText: "Create a badge image.",
    stylePreset: "institutional",
    promptNotes: null,
    accentColor: null,
    resultImageUri: null,
    errorMessage: null,
    requestedByUserId: "usr_admin",
    queuedJobId: null,
    createdAt: "2026-02-23T12:30:00.000Z",
    updatedAt: "2026-02-23T12:30:00.000Z",
    completedAt: null,
    ...overrides,
  };
};

const sampleQueuedJob = (overrides?: Partial<JobQueueMessageRecord>): JobQueueMessageRecord => {
  return {
    id: "job_123",
    tenantId: "tenant_123",
    jobType: "generate_badge_template_image",
    payloadJson: "{}",
    idempotencyKey: "btig_123",
    attemptCount: 0,
    maxAttempts: 3,
    availableAt: "2026-02-23T12:30:00.000Z",
    leasedUntil: null,
    leaseToken: null,
    lastError: null,
    completedAt: null,
    failedAt: null,
    status: "pending",
    createdAt: "2026-02-23T12:30:00.000Z",
    updatedAt: "2026-02-23T12:30:00.000Z",
    ...overrides,
  };
};

interface InMemoryImmutableStore {
  head: (key: string) => Promise<{ key: string } | null>;
  get: (key: string) => Promise<{ text: () => Promise<string> } | null>;
  put: (
    key: string,
    value: string,
    _options?: unknown,
  ) => Promise<{
    key: string;
    etag: string;
    version: string;
    size: number;
    uploaded: Date;
  } | null>;
}

const createBadgeObjectStore = (): {
  store: R2Bucket;
  entries: Map<string, string>;
} => {
  const entries = new Map<string, string>();
  const store: InMemoryImmutableStore = {
    head(key) {
      return Promise.resolve(entries.has(key) ? { key } : null);
    },
    get(key) {
      const value = entries.get(key);

      if (value === undefined) {
        return Promise.resolve(null);
      }

      return Promise.resolve({
        text: () => Promise.resolve(value),
      });
    },
    put(key, value) {
      entries.set(key, value);
      return Promise.resolve({
        key,
        etag: "etag_123",
        version: "v1",
        size: new TextEncoder().encode(value).length,
        uploaded: new Date("2026-02-23T12:30:00.000Z"),
      });
    },
  };

  return {
    store: store as unknown as R2Bucket,
    entries,
  };
};

const samplePngBytes = (): Uint8Array => {
  return new Uint8Array([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x01, 0x02]);
};

const bytesToArrayBuffer = (bytes: Uint8Array): ArrayBuffer => {
  const arrayBuffer = new ArrayBuffer(bytes.byteLength);
  new Uint8Array(arrayBuffer).set(bytes);
  return arrayBuffer;
};

beforeEach(() => {
  mockedCreatePostgresDatabase.mockReset();
  mockedCreatePostgresDatabase.mockReturnValue(fakeDb);
  mockedResolveBetterAuthPrincipal.mockReset();
  mockedResolveBetterAuthPrincipal.mockImplementation(
    async (context: { req: { header(name: string): string | undefined } }) => {
      const cookieHeader = context.req.header("cookie") ?? "";

      if (!cookieHeader.includes("better-auth.session_token=")) {
        return null;
      }

      return {
        userId: "usr_admin",
        authSessionId: "ba_ses_123",
        authMethod: "better_auth" as const,
        expiresAt: "2026-02-23T23:00:00.000Z",
      };
    },
  );
  mockedResolveBetterAuthRequestedTenant.mockReset();
  mockedResolveBetterAuthRequestedTenant.mockResolvedValue(null);
  mockedFindActiveSessionByHash.mockReset();
  mockedFindActiveSessionByHash.mockResolvedValue(sampleSession());
  mockedTouchSession.mockReset();
  mockedTouchSession.mockResolvedValue(undefined);
  mockedFindTenantMembership.mockReset();
  mockedFindTenantMembership.mockResolvedValue(sampleMembership());
  mockedFindBadgeTemplateById.mockReset();
  mockedFindBadgeTemplateById.mockResolvedValue(sampleTemplate());
  mockedHasTenantMembershipOrgUnitScopeAssignments.mockReset();
  mockedHasTenantMembershipOrgUnitScopeAssignments.mockResolvedValue(false);
  mockedHasTenantMembershipOrgUnitAccess.mockReset();
  mockedHasTenantMembershipOrgUnitAccess.mockResolvedValue(true);
  mockedListBadgeTemplates.mockReset();
  mockedListBadgeTemplates.mockResolvedValue([sampleTemplate()]);
  mockedListBadgeTemplateImageRevisions.mockReset();
  mockedListBadgeTemplateImageRevisions.mockResolvedValue([sampleImageRevision()]);
  mockedFindBadgeTemplateImageRevisionById.mockReset();
  mockedFindBadgeTemplateImageRevisionById.mockResolvedValue(sampleImageRevision());
  mockedCreateBadgeTemplateImageRevision.mockReset();
  mockedCreateBadgeTemplateImageRevision.mockResolvedValue(sampleImageRevision());
  mockedCreateBadgeTemplateImageGeneration.mockReset();
  mockedCreateBadgeTemplateImageGeneration.mockResolvedValue(sampleImageGeneration());
  mockedFindBadgeTemplateImageGenerationById.mockReset();
  mockedFindBadgeTemplateImageGenerationById.mockResolvedValue(sampleImageGeneration());
  mockedUpdateBadgeTemplateImageGeneration.mockReset();
  mockedUpdateBadgeTemplateImageGeneration.mockImplementation((_db, request) => {
    return Promise.resolve(
      sampleImageGeneration({
        id: request.id,
        status: request.status ?? "queued",
        queuedJobId: request.queuedJobId ?? null,
        resultImageUri: request.resultImageUri ?? null,
        errorMessage: request.errorMessage ?? null,
        completedAt: request.completedAt ?? null,
      }),
    );
  });
  mockedEnqueueJobQueueMessage.mockReset();
  mockedEnqueueJobQueueMessage.mockResolvedValue(sampleQueuedJob());
  mockedUpdateBadgeTemplate.mockReset();
  mockedUpdateBadgeTemplate.mockImplementation((_db, request) => {
    return Promise.resolve(
      sampleTemplate({
        imageUri: request.imageUri ?? null,
      }),
    );
  });
  mockedCreateAuditLog.mockReset();
  mockedCreateAuditLog.mockResolvedValue({
    id: "audit_123",
    tenantId: "tenant_123",
    actorUserId: "usr_admin",
    action: "badge_template.image_uploaded",
    targetType: "badge_template",
    targetId: "badge_template_001",
    metadataJson: null,
    occurredAt: "2026-02-23T12:30:00.000Z",
    createdAt: "2026-02-23T12:30:00.000Z",
  });
});

describe("badge template image upload routes", () => {
  it("lists badge templates from requested tenant membership even when session tenant differs", async () => {
    const { store } = createBadgeObjectStore();
    const env = createEnv(store);

    mockedFindActiveSessionByHash.mockResolvedValue(sampleSessionForTenant("tenant_other"));

    const response = await app.request(
      "/v1/tenants/tenant_123/badge-templates",
      {
        headers: {
          Cookie: "better-auth.session_token=session-token",
        },
      },
      env,
    );
    const body = await response.json<{
      tenantId: string;
      templates: Array<{
        id: string;
      }>;
    }>();

    expect(response.status).toBe(200);
    expect(body.tenantId).toBe("tenant_123");
    expect(body.templates).toHaveLength(1);
    expect(mockedFindTenantMembership).toHaveBeenCalledWith(fakeDb, "tenant_123", "usr_admin");
    expect(mockedListBadgeTemplates).toHaveBeenCalledWith(fakeDb, {
      tenantId: "tenant_123",
      includeArchived: false,
    });
  });

  it("uploads a PNG image, stores it in object storage, and serves it publicly", async () => {
    const { store, entries } = createBadgeObjectStore();
    const env = createEnv(store);
    const formData = new FormData();
    formData.set(
      "file",
      new File([bytesToArrayBuffer(samplePngBytes())], "typescript-badge.png", {
        type: "image/png",
      }),
    );

    const uploadResponse = await app.request(
      "/v1/tenants/tenant_123/badge-templates/badge_template_001/image-upload",
      {
        method: "POST",
        headers: {
          Cookie: "better-auth.session_token=session-token",
        },
        body: formData,
      },
      env,
    );
    const uploadBody = await uploadResponse.json<{
      tenantId: string;
      template: {
        imageUri: string | null;
      };
      image: {
        path: string;
        url: string;
        mimeType: string;
        byteSize: number;
      };
    }>();

    expect(uploadResponse.status).toBe(201);
    expect(uploadBody.tenantId).toBe("tenant_123");
    expect(uploadBody.image.mimeType).toBe("image/png");
    expect(uploadBody.image.byteSize).toBe(samplePngBytes().byteLength);
    expect(uploadBody.image.path).toContain("/badges/assets/tenant_123/badge_template_001/");
    expect(uploadBody.image.url).toContain("/badges/assets/tenant_123/badge_template_001/");
    expect(uploadBody.template.imageUri).toBe(uploadBody.image.url);
    expect(entries.size).toBe(1);
    expect(mockedUpdateBadgeTemplate).toHaveBeenCalledTimes(1);
    expect(mockedCreateBadgeTemplateImageRevision).toHaveBeenCalledWith(
      fakeDb,
      expect.objectContaining({
        tenantId: "tenant_123",
        badgeTemplateId: "badge_template_001",
        sourceType: "upload",
        newImageUri: uploadBody.image.url,
      }),
    );
    expect(mockedCreateAuditLog).toHaveBeenCalledTimes(1);

    const publicAssetPath = new URL(uploadBody.image.url).pathname;
    const publicResponse = await app.request(publicAssetPath, undefined, env);
    const publicBody = new Uint8Array(await publicResponse.arrayBuffer());

    expect(publicResponse.status).toBe(200);
    expect(publicResponse.headers.get("content-type")).toContain("image/png");
    expect(publicResponse.headers.get("cache-control")).toBe("public, max-age=31536000, immutable");
    expect(publicBody).toEqual(samplePngBytes());
  });

  it("returns 422 when file type is unsupported", async () => {
    const { store } = createBadgeObjectStore();
    const env = createEnv(store);
    const formData = new FormData();
    formData.set(
      "file",
      new File([bytesToArrayBuffer(new Uint8Array([0x47, 0x49, 0x46]))], "badge.gif", {
        type: "image/gif",
      }),
    );

    const response = await app.request(
      "/v1/tenants/tenant_123/badge-templates/badge_template_001/image-upload",
      {
        method: "POST",
        headers: {
          Cookie: "better-auth.session_token=session-token",
        },
        body: formData,
      },
      env,
    );
    const body = await response.json<{ error: string }>();

    expect(response.status).toBe(422);
    expect(body.error).toContain("Unsupported image type");
  });

  it("returns 422 when content bytes do not match declared mime type", async () => {
    const { store } = createBadgeObjectStore();
    const env = createEnv(store);
    const formData = new FormData();
    formData.set(
      "file",
      new File([bytesToArrayBuffer(new Uint8Array([0xff, 0xd8, 0xff, 0x00]))], "badge.png", {
        type: "image/png",
      }),
    );

    const response = await app.request(
      "/v1/tenants/tenant_123/badge-templates/badge_template_001/image-upload",
      {
        method: "POST",
        headers: {
          Cookie: "better-auth.session_token=session-token",
        },
        body: formData,
      },
      env,
    );
    const body = await response.json<{ error: string }>();

    expect(response.status).toBe(422);
    expect(body.error).toBe("Uploaded file content does not match declared image type");
  });

  it("returns 413 when upload exceeds byte limit", async () => {
    const { store } = createBadgeObjectStore();
    const env = createEnv(store);
    const oversizedBytes = new Uint8Array(BADGE_TEMPLATE_IMAGE_MAX_BYTES + 1);
    oversizedBytes.set(samplePngBytes(), 0);
    const formData = new FormData();
    formData.set(
      "file",
      new File([bytesToArrayBuffer(oversizedBytes)], "big-image.png", { type: "image/png" }),
    );

    const response = await app.request(
      "/v1/tenants/tenant_123/badge-templates/badge_template_001/image-upload",
      {
        method: "POST",
        headers: {
          Cookie: "better-auth.session_token=session-token",
        },
        body: formData,
      },
      env,
    );
    const body = await response.json<{ error: string }>();

    expect(response.status).toBe(413);
    expect(body.error).toContain("byte limit");
  });

  it("returns 404 for unknown public image asset path", async () => {
    const { store } = createBadgeObjectStore();
    const env = createEnv(store);
    const response = await app.request(
      "/badges/assets/tenant_123/badge_template_001/asset_missing",
      undefined,
      env,
    );

    expect(response.status).toBe(404);
  });

  it("queues a badge template image generation and returns a polling record", async () => {
    const { store, entries } = createBadgeObjectStore();
    const aiRun = vi.fn<BadgeTemplateImageGenerationAiBinding["run"]>(async () => {
      return {
        image: Buffer.from(samplePngBytes()).toString("base64"),
      };
    });
    const ai = { run: aiRun };
    const env = {
      ...createEnv(store),
      AI: ai,
      BADGE_IMAGE_GENERATION_MODEL: "@cf/black-forest-labs/flux-2-dev",
    };

    const response = await app.request(
      "/v1/tenants/tenant_123/badge-templates/badge_template_001/image-generations",
      {
        method: "POST",
        headers: {
          Cookie: "better-auth.session_token=session-token",
          "content-type": "application/json",
        },
        body: JSON.stringify({
          stylePreset: "institutional",
          promptNotes: "Use a shield motif.",
        }),
      },
      env,
    );
    const body = await response.json<{
      generation: {
        id: string;
        status: string;
        resultImageUri: string | null;
      };
    }>();

    expect(response.status).toBe(202);
    expect(body.generation.id).toBe("btig_123");
    expect(body.generation.status).toBe("queued");
    expect(body.generation.resultImageUri).toBeNull();
    expect(mockedCreateBadgeTemplateImageGeneration).toHaveBeenCalledTimes(1);
    expect(mockedEnqueueJobQueueMessage).toHaveBeenCalledWith(
      fakeDb,
      expect.objectContaining({
        tenantId: "tenant_123",
        jobType: "generate_badge_template_image",
        idempotencyKey: "btig_123",
        maxAttempts: 3,
        payload: expect.objectContaining({
          generationId: "btig_123",
          badgeTemplateId: "badge_template_001",
          stylePreset: "institutional",
          promptNotes: "Use a shield motif.",
          requestedByUserId: "usr_admin",
        }) as unknown,
      }),
    );
    expect(mockedUpdateBadgeTemplateImageGeneration).toHaveBeenCalledWith(
      fakeDb,
      expect.objectContaining({
        tenantId: "tenant_123",
        id: "btig_123",
        status: "queued",
        queuedJobId: "job_123",
      }),
    );
    expect(aiRun).not.toHaveBeenCalled();
    expect(entries.size).toBe(0);
  });

  it("applies a completed generated image through the admin route", async () => {
    const { store } = createBadgeObjectStore();
    const env = createEnv(store);

    mockedFindBadgeTemplateImageGenerationById.mockResolvedValue(
      sampleImageGeneration({
        status: "succeeded",
        resultImageUri:
          "https://credtrail.test/badges/assets/tenant_123/badge_template_001/asset_ai",
      }),
    );

    const response = await app.request(
      "/v1/tenants/tenant_123/badge-templates/badge_template_001/image-generations/btig_123/apply",
      {
        method: "POST",
        headers: {
          Cookie: "better-auth.session_token=session-token",
        },
      },
      env,
    );

    expect(response.status).toBe(200);
    expect(mockedUpdateBadgeTemplate).toHaveBeenCalledWith(
      fakeDb,
      expect.objectContaining({
        tenantId: "tenant_123",
        id: "badge_template_001",
        imageUri: "https://credtrail.test/badges/assets/tenant_123/badge_template_001/asset_ai",
      }),
    );
    expect(mockedCreateBadgeTemplateImageRevision).toHaveBeenCalledWith(
      fakeDb,
      expect.objectContaining({
        sourceType: "ai_generated",
        promptText: "Create a badge image.",
      }),
    );
  });
});

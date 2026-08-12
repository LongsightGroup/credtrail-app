import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("@credtrail/db", async () => {
  const actual = await vi.importActual<typeof import("@credtrail/db")>("@credtrail/db");

  return {
    ...actual,
    findTenantSigningRegistrationByDid: vi.fn(),
    listAssertionStatusListEntries: vi.fn(),
  };
});

vi.mock("@credtrail/db/postgres", () => {
  return {
    createPostgresDatabase: vi.fn(),
  };
});

import {
  type JsonObject,
  generateTenantDidSigningMaterial,
  signCredentialWithDataIntegrityProof,
} from "@credtrail/core-domain";
import {
  findTenantSigningRegistrationByDid,
  listAssertionStatusListEntries,
  type AssertionStatusListEntryRecord,
  type SqlDatabase,
  type TenantSigningRegistrationRecord,
} from "@credtrail/db";
import { createPostgresDatabase } from "@credtrail/db/postgres";

import { app } from "./index";
import { generateP256SigningMaterial } from "./test-support/p256-signing-material";

interface ErrorResponse {
  error: string;
}

const mockedFindTenantSigningRegistrationByDid = vi.mocked(findTenantSigningRegistrationByDid);
const mockedListAssertionStatusListEntries = vi.mocked(listAssertionStatusListEntries);
const mockedCreatePostgresDatabase = vi.mocked(createPostgresDatabase);
const fakeDb = {
  prepare: vi.fn(),
} as unknown as SqlDatabase;

const createEnv = (): {
  APP_ENV: string;
  DATABASE_URL: string;
  BADGE_OBJECTS: R2Bucket;
  PLATFORM_DOMAIN: string;
  PUBLIC_APP_ORIGIN: string;
  TENANT_SIGNING_REGISTRY_JSON?: string;
  TENANT_REMOTE_SIGNER_REGISTRY_JSON?: string;
} => {
  return {
    APP_ENV: "test",
    DATABASE_URL: "postgres://credtrail-test.local/db",
    BADGE_OBJECTS: {} as R2Bucket,
    PLATFORM_DOMAIN: "credtrail.test",
    PUBLIC_APP_ORIGIN: "https://credtrail.test",
  };
};

beforeEach(() => {
  mockedCreatePostgresDatabase.mockReset();
  mockedCreatePostgresDatabase.mockReturnValue(fakeDb);
  mockedFindTenantSigningRegistrationByDid.mockReset();
  mockedFindTenantSigningRegistrationByDid.mockResolvedValue(null);
  mockedListAssertionStatusListEntries.mockReset();
});

const asJsonObject = (value: unknown): JsonObject | null => {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    return null;
  }

  return value as JsonObject;
};

const asString = (value: unknown): string | null => {
  return typeof value === "string" ? value : null;
};

const jsonObjectFromRequestInitBody = (init: RequestInit | undefined): JsonObject => {
  if (typeof init?.body !== "string") {
    return {};
  }

  try {
    const parsed = JSON.parse(init.body) as unknown;
    return asJsonObject(parsed) ?? {};
  } catch {
    return {};
  }
};

const sampleTenantSigningRegistration = (
  overrides?: Partial<TenantSigningRegistrationRecord>,
): TenantSigningRegistrationRecord => {
  return {
    tenantId: "sakai",
    did: "did:web:credtrail.test:sakai",
    keyId: "key-1",
    publicJwkJson: JSON.stringify({
      kty: "OKP",
      crv: "Ed25519",
      x: "A".repeat(32),
    }),
    privateJwkJson: JSON.stringify({
      kty: "OKP",
      crv: "Ed25519",
      x: "A".repeat(32),
      d: "B".repeat(32),
    }),
    createdAt: "2026-02-10T22:00:00.000Z",
    updatedAt: "2026-02-10T22:00:00.000Z",
    ...overrides,
  };
};

const base64UrlToBytes = (value: string): Uint8Array => {
  const base64 = value.replace(/-/g, "+").replace(/_/g, "/");
  const padded = `${base64}${"=".repeat((4 - (base64.length % 4)) % 4)}`;
  const raw = atob(padded);
  const bytes = new Uint8Array(raw.length);

  for (let index = 0; index < raw.length; index += 1) {
    bytes[index] = raw.charCodeAt(index);
  }

  return bytes;
};

const gunzip = async (bytes: Uint8Array): Promise<Uint8Array> => {
  const normalizedBytes = Uint8Array.from(bytes);
  const sourceStream = new ReadableStream<BufferSource>({
    start(controller): void {
      controller.enqueue(normalizedBytes);
      controller.close();
    },
  });
  const decompressedStream = sourceStream.pipeThrough(new DecompressionStream("gzip"));
  const decompressedBuffer = await new Response(decompressedStream).arrayBuffer();
  return new Uint8Array(decompressedBuffer);
};

const isBitSet = (bytes: Uint8Array, bitIndex: number): boolean => {
  const byteIndex = Math.floor(bitIndex / 8);
  const bitOffset = bitIndex % 8;
  const byte = bytes[byteIndex];

  if (byte === undefined) {
    return false;
  }

  return (byte & (1 << bitOffset)) !== 0;
};
describe("GET /credentials/v1/status-lists/:tenantId/revocation", () => {
  beforeEach(() => {
    mockedFindTenantSigningRegistrationByDid.mockReset();
    mockedFindTenantSigningRegistrationByDid.mockResolvedValue(null);
    mockedListAssertionStatusListEntries.mockReset();
  });

  it("returns a signed bitstring status list credential for tenant revocations", async () => {
    const env = createEnv();
    const signingMaterial = await generateTenantDidSigningMaterial({
      did: "did:web:credtrail.test:tenant_123",
    });
    const assertionStatuses: AssertionStatusListEntryRecord[] = [
      {
        statusListIndex: 0,
        revokedAt: null,
      },
      {
        statusListIndex: 1,
        revokedAt: "2026-02-11T01:00:00.000Z",
      },
      {
        statusListIndex: 8,
        revokedAt: "2026-02-11T01:05:00.000Z",
      },
    ];

    mockedListAssertionStatusListEntries.mockResolvedValue(assertionStatuses);

    const response = await app.request(
      "/credentials/v1/status-lists/tenant_123/revocation",
      undefined,
      {
        ...env,
        TENANT_SIGNING_REGISTRY_JSON: JSON.stringify({
          "did:web:credtrail.test:tenant_123": {
            tenantId: "tenant_123",
            keyId: signingMaterial.keyId,
            publicJwk: signingMaterial.publicJwk,
            privateJwk: signingMaterial.privateJwk,
          },
        }),
      },
    );
    const body = await response.text();
    const credential = JSON.parse(body) as JsonObject;
    const credentialSubject = asJsonObject(credential.credentialSubject);
    const credentialContext = credential["@context"];
    const encodedList = asString(credentialSubject?.encodedList);

    expect(response.status).toBe(200);
    expect(response.headers.get("cache-control")).toBe("no-store");
    expect(response.headers.get("content-type")).toContain("application/vc+ld+json");
    expect(asString(credential.id)).toBe(
      "https://credtrail.test/credentials/v1/status-lists/tenant_123/revocation",
    );
    expect(credentialContext).toEqual(
      expect.arrayContaining([
        "https://www.w3.org/ns/credentials/v2",
        "https://www.w3.org/ns/credentials/status/v1",
      ]),
    );
    expect(credential.type).toEqual(["VerifiableCredential", "BitstringStatusListCredential"]);
    expect(credential.proof).toBeDefined();
    expect(asString(credentialSubject?.statusPurpose)).toBe("revocation");
    expect(encodedList?.startsWith("u")).toBe(true);

    if (encodedList?.startsWith("u") !== true) {
      throw new Error("Expected a multibase base64url-encoded bitstring list");
    }

    const compressedListBytes = base64UrlToBytes(encodedList.slice(1));
    const listBytes = await gunzip(compressedListBytes);

    expect(listBytes.length).toBeGreaterThanOrEqual(16_384);
    expect(isBitSet(listBytes, 0)).toBe(false);
    expect(isBitSet(listBytes, 1)).toBe(true);
    expect(isBitSet(listBytes, 8)).toBe(true);
  });

  it("returns 404 when tenant signing config is missing", async () => {
    const env = createEnv();
    const response = await app.request(
      "/credentials/v1/status-lists/tenant_123/revocation",
      undefined,
      env,
    );
    const body = await response.json<ErrorResponse>();

    expect(response.status).toBe(404);
    expect(body.error).toBe("No signing configuration for tenant DID");
    expect(mockedListAssertionStatusListEntries).not.toHaveBeenCalled();
  });

  it("builds status list credential from DB-backed signing registration", async () => {
    const env = createEnv();
    const signingMaterial = await generateTenantDidSigningMaterial({
      did: "did:web:credtrail.test:tenant_123",
      keyId: "key-db",
    });

    mockedFindTenantSigningRegistrationByDid.mockResolvedValue(
      sampleTenantSigningRegistration({
        tenantId: "tenant_123",
        did: signingMaterial.did,
        keyId: signingMaterial.keyId,
        publicJwkJson: JSON.stringify(signingMaterial.publicJwk),
        privateJwkJson: JSON.stringify(signingMaterial.privateJwk),
      }),
    );
    mockedListAssertionStatusListEntries.mockResolvedValue([]);

    const response = await app.request(
      "/credentials/v1/status-lists/tenant_123/revocation",
      undefined,
      env,
    );
    const body = await response.json<JsonObject>();

    expect(response.status).toBe(200);
    expect(asString(body.issuer)).toBe("did:web:credtrail.test:tenant_123");
    expect(mockedFindTenantSigningRegistrationByDid).toHaveBeenCalledWith(
      fakeDb,
      "did:web:credtrail.test:tenant_123",
    );
  });

  it("signs status list credentials through configured remote signers when private keys are externalized", async () => {
    const signingMaterial = await generateTenantDidSigningMaterial({
      did: "did:web:credtrail.test:tenant_123",
      keyId: "key-remote",
    });
    const env = {
      ...createEnv(),
      TENANT_REMOTE_SIGNER_REGISTRY_JSON: JSON.stringify({
        "did:web:credtrail.test:tenant_123": {
          url: "https://kms.credtrail.test/sign",
          authorizationHeader: "Bearer test-remote-signer-token",
        },
      }),
    };
    const fetchSpy = vi.spyOn(globalThis, "fetch").mockImplementation(async (_url, init) => {
      const request = jsonObjectFromRequestInitBody(init);
      const unsignedCredential = asJsonObject(request.credential);
      const verificationMethod = asString(request.verificationMethod);
      const createdAt = asString(request.createdAt);

      if (unsignedCredential === null || verificationMethod === null) {
        return new Response(
          JSON.stringify({
            error: "invalid signer request",
          }),
          {
            status: 400,
            headers: {
              "content-type": "application/json",
            },
          },
        );
      }

      const signedCredential = await signCredentialWithDataIntegrityProof({
        credential: unsignedCredential,
        privateJwk: signingMaterial.privateJwk,
        verificationMethod,
        ...(createdAt === null ? {} : { createdAt }),
      });

      return new Response(
        JSON.stringify({
          credential: signedCredential,
        }),
        {
          status: 200,
          headers: {
            "content-type": "application/json",
          },
        },
      );
    });

    mockedFindTenantSigningRegistrationByDid.mockResolvedValue(
      sampleTenantSigningRegistration({
        tenantId: "tenant_123",
        did: signingMaterial.did,
        keyId: signingMaterial.keyId,
        publicJwkJson: JSON.stringify(signingMaterial.publicJwk),
        privateJwkJson: null,
      }),
    );
    mockedListAssertionStatusListEntries.mockResolvedValue([]);

    const response = await app.request(
      "/credentials/v1/status-lists/tenant_123/revocation",
      undefined,
      env,
    );
    const body = await response.json<JsonObject>();

    expect(response.status).toBe(200);
    expect(asJsonObject(body.proof)).not.toBeNull();
    expect(fetchSpy).toHaveBeenCalledTimes(1);
    expect(fetchSpy.mock.calls[0]?.[0]).toBe("https://kms.credtrail.test/sign");
    const requestInit = fetchSpy.mock.calls[0]?.[1];
    const requestHeaders = new Headers(requestInit?.headers);
    expect(requestInit?.method).toBe("POST");
    expect(requestHeaders.get("authorization")).toBe("Bearer test-remote-signer-token");
    expect(requestHeaders.get("user-agent")).toBe("CredTrail/1.0 (+https://credtrail.org)");

    fetchSpy.mockRestore();
  });

  it("returns 422 when tenant signing key is not Ed25519", async () => {
    const env = createEnv();
    const signingMaterial = await generateP256SigningMaterial("key-p256");

    mockedFindTenantSigningRegistrationByDid.mockResolvedValue(
      sampleTenantSigningRegistration({
        tenantId: "tenant_123",
        did: "did:web:credtrail.test:tenant_123",
        keyId: "key-p256",
        publicJwkJson: JSON.stringify(signingMaterial.publicJwk),
        privateJwkJson: JSON.stringify(signingMaterial.privateJwk),
      }),
    );

    const response = await app.request(
      "/credentials/v1/status-lists/tenant_123/revocation",
      undefined,
      env,
    );
    const body = await response.json<ErrorResponse>();

    expect(response.status).toBe(422);
    expect(body.error).toBe("Revocation status list signing requires an Ed25519 private key");
    expect(mockedListAssertionStatusListEntries).not.toHaveBeenCalled();
  });
});

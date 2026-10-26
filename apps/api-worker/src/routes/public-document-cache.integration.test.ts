import { afterEach, expect, it } from "vitest";
import {
  generateTenantDidSigningMaterial,
  immutableCredentialObjectKey,
  type ImmutableCredentialStore,
} from "@credtrail/core-domain";
import {
  cleanupTestResources,
  createBadgeRuleIntegrationFixture,
  createTestPostgresDatabase,
  describeDbIntegration,
  seedAssertion,
} from "../../../../packages/db/src/postgres-test-support";
import { app } from "../app";
import type { AppBindings } from "../app/types";
import { decodedRevocationStatusBit } from "../badges/revocation-status";

const tenantIds: string[] = [];
const userIds: string[] = [];
afterEach(async () => {
  if (tenantIds.length === 0) return;
  await cleanupTestResources(createTestPostgresDatabase(), { tenantIds, userIds });
  tenantIds.length = 0;
  userIds.length = 0;
});

describeDbIntegration("public verification document caching", () => {
  it("caches public documents, aligns status refresh with HTTP freshness, and keeps errors and downloads private", async () => {
    const fixture = await createBadgeRuleIntegrationFixture();
    tenantIds.push(fixture.tenantId);
    userIds.push(fixture.userId);
    const tenantId = fixture.tenantId;
    const assertionId = `${tenantId}:assertion`;
    const publicId = crypto.randomUUID();
    await seedAssertion(fixture.db, {
      tenantId,
      badgeTemplateId: fixture.badgeTemplateId,
      id: assertionId,
      publicId,
      recipientIdentity: "learner@example.edu",
      issuedAt: "2026-10-26T12:00:00.000Z",
      statusListIndex: 0,
    });
    const credential = {
      "@context": ["https://www.w3.org/ns/credentials/v2"],
      type: ["VerifiableCredential", "OpenBadgeCredential"],
      id: `https://credtrail.org/credentials/v1/${encodeURIComponent(assertionId)}`,
      issuer: { id: `did:web:credtrail.org:${tenantId}`, name: "Example University" },
      credentialSubject: { id: "mailto:learner@example.edu", achievement: { name: "Foundations" } },
    };
    const objects = new Map([
      [immutableCredentialObjectKey({ tenantId, assertionId }), JSON.stringify(credential)],
    ]);
    const store: ImmutableCredentialStore = {
      head: async (key) => (objects.has(key) ? { key } : null),
      get: async (key) => {
        const text = objects.get(key);
        return text === undefined ? null : { size: text.length, text: async () => text };
      },
      put: async (key, value) => {
        if (objects.has(key)) return null;
        objects.set(key, value);
        return { key, etag: "test", version: "1", size: value.length, uploaded: new Date() };
      },
      delete: async (key) => {
        objects.delete(key);
      },
    };
    const signing = await generateTenantDidSigningMaterial({
      did: "did:web:credtrail.org",
      keyId: "cache-test",
    });
    const env: AppBindings = {
      APP_ENV: "test",
      DATABASE_URL: process.env.TEST_DATABASE_URL ?? "",
      PLATFORM_DOMAIN: "credtrail.org",
      PUBLIC_APP_ORIGIN: "https://credtrail.org",
      BADGE_OBJECTS: store,
      TENANT_SIGNING_REGISTRY_JSON: JSON.stringify({
        "did:web:credtrail.org": {
          keyId: signing.keyId,
          publicJwk: signing.publicJwk,
          privateJwk: signing.privateJwk,
          tenantId,
        },
        [`did:web:credtrail.org:${tenantId}`]: {
          keyId: signing.keyId,
          publicJwk: signing.publicJwk,
          privateJwk: signing.privateJwk,
          tenantId,
        },
      }),
    };
    const request = async (path: string): Promise<Response> =>
      app.request(`https://credtrail.org${path}`, undefined, env);
    for (const path of [
      "/.well-known/did.json",
      "/.well-known/jwks.json",
      `/${tenantId}/did.json`,
      `/${tenantId}/jwks.json`,
      "/.well-known/openid-credential-issuer",
      `/badges/${publicId}/jsonld`,
      `/credentials/v1/${encodeURIComponent(assertionId)}/jsonld`,
    ]) {
      const response = await request(path);
      expect(response.status).toBe(200);
      expect(response.headers.get("cache-control")).toBe("public, max-age=1800");
      expect(response.headers.has("set-cookie")).toBe(false);
    }
    for (const path of [
      `/badges/${publicId}/jsonld`,
      `/credentials/v1/${encodeURIComponent(assertionId)}/jsonld`,
    ]) {
      expect(await (await request(path)).json()).toEqual(credential);
    }
    for (const suffix of ["/download", "/download.pdf"]) {
      for (const base of [
        `/badges/${publicId}`,
        `/credentials/v1/${encodeURIComponent(assertionId)}`,
      ]) {
        const response = await request(`${base}${suffix}`);
        expect(response.status).toBe(200);
        expect(response.headers.get("cache-control")).toBe("no-store");
      }
    }
    for (const path of [
      "/missing/did.json",
      "/missing/jwks.json",
      "/badges/missing/jsonld",
      `/credentials/v1/${encodeURIComponent(`${tenantId}:missing`)}/jsonld`,
      "/credentials/v1/status-lists/missing/revocation",
    ]) {
      const response = await request(path);
      expect(response.status).toBe(404);
      expect(response.headers.get("cache-control")).toBe("no-store");
    }
    const statusPath = `/credentials/v1/status-lists/${tenantId}/revocation`;
    const statusList = await request(statusPath);
    const active = await statusList.json<{
      credentialSubject: { ttl: number; encodedList: string };
      proof: unknown;
    }>();
    expect(statusList.status).toBe(200);
    expect(statusList.headers.get("cache-control")).toBe("public, max-age=600");
    expect(active.credentialSubject.ttl).toBe(600_000);
    expect(active.proof).toBeDefined();
    expect(await decodedRevocationStatusBit(active.credentialSubject.encodedList, 0)).toBe(false);
    await fixture.db
      .prepare("UPDATE assertions SET revoked_at = ? WHERE tenant_id = ? AND id = ?")
      .bind("2026-10-26T13:00:00.000Z", tenantId, assertionId)
      .run();
    const updated = await request(statusPath);
    const revoked = await updated.json<{
      credentialSubject: { ttl: number; encodedList: string };
    }>();
    expect(updated.headers.get("cache-control")).toBe("public, max-age=600");
    expect(revoked.credentialSubject.ttl).toBe(600_000);
    expect(await decodedRevocationStatusBit(revoked.credentialSubject.encodedList, 0)).toBe(true);
  });
});

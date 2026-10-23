import { Hono } from "hono";
import { expect, it } from "vitest";
import type { AppBindings, AppEnv } from "../app/types";
import { registerCredentialRoutes } from "./credential-routes";

const unused = (): never => {
  throw new Error("Unexpected dependency");
};

it("checks current lifecycle and recipient on both routes before reusing a PDF", async () => {
  const app = new Hono<AppEnv>();
  const objects = new Map<string, string>();
  const env: AppBindings = {
    APP_ENV: "test",
    PLATFORM_DOMAIN: "credtrail.org",
    PUBLIC_APP_ORIGIN: "https://credtrail.org",
    BADGE_OBJECTS: {
      head: async (key) => (objects.has(key) ? { key } : null),
      get: async (key) => {
        const text = objects.get(key);
        return text === undefined ? null : { size: text.length, text: async () => text };
      },
      put: async (key, value) => {
        if (objects.has(key)) return null;
        objects.set(key, value);
        return { key, etag: "test", version: "1", size: value.length, uploaded: new Date(0) };
      },
      delete: async (key) => {
        objects.delete(key);
      },
    },
  };
  let recipientDisplayName = "Ada Lovelace";
  let state: "active" | "suspended" | "revoked" | "expired" = "active";
  let available = true;
  let renders = 0;
  const model = (): {
    assertion: {
      id: string;
      tenantId: string;
      issuedAt: string;
      revokedAt: string | null;
      statusListIndex: number | null;
    };
    credential: { id: string };
    recipientDisplayName: string;
    lifecycle: {
      state: typeof state;
      source: "lifecycle_event";
      reasonCode: null;
      reason: null;
      transitionedAt: null;
      revokedAt: string | null;
    };
  } => ({
    assertion: {
      id: "tenant:assertion",
      tenantId: "tenant",
      issuedAt: "2026-10-23T12:00:00.000Z",
      revokedAt: state === "revoked" ? "2026-10-23T13:00:00.000Z" : null,
      statusListIndex: null,
    },
    credential: { id: "urn:credential:1" },
    recipientDisplayName,
    lifecycle: {
      state,
      source: "lifecycle_event",
      reasonCode: null,
      reason: null,
      transitionedAt: null,
      revokedAt: state === "revoked" ? "2026-10-23T13:00:00.000Z" : null,
    },
  });
  registerCredentialRoutes({
    app,
    resolveDatabase: () => ({ prepare: unused }),
    loadVerificationViewModel: async () =>
      available ? { status: "ok", value: model() } : { status: "not_found" },
    loadPublicBadgeViewModel: async () =>
      available ? { status: "ok", value: model() } : { status: "not_found" },
    credentialStatusForAssertion: unused,
    revocationStatusListUrlForTenant: unused,
    summarizeCredentialVerificationChecks: unused,
    summarizeCredentialLifecycleVerification: (_credential, revokedAt, checkedAt) => ({
      state: revokedAt === null ? "active" : "revoked",
      reason: null,
      checkedAt,
      expiresAt: null,
      revokedAt,
    }),
    verifyCredentialProofSummary: unused,
    credentialDownloadFilename: unused,
    publicBadgePathForAssertion: () => "/badges/public-id",
    asString: (value) => (typeof value === "string" ? value : null),
    achievementDetailsFromCredential: () => ({ imageUri: null }),
    recipientDisplayNameFromAssertion: () => null,
    recipientFromCredential: () => "recipient@example.edu",
    badgeNameFromCredential: () => "Foundations",
    issuerNameFromCredential: () => "University",
    formatIsoTimestamp: (value) => value,
    renderBadgePdfDocument: async (input) => {
      renders += 1;
      return {
        bytes: new TextEncoder().encode(`%PDF-${JSON.stringify(input)}`),
        artwork: "absent",
      };
    },
    resolvePublicResourceNetwork: () => ({ resolveHostname: unused, request: unused }),
    credentialPdfDownloadFilename: () => "badge.pdf",
    resolveSigningEntryForDid: unused,
    resolveRemoteSignerRegistryEntryForDid: unused,
    buildRevocationStatusListCredential: unused,
    signCredentialForDid: unused,
  });
  const paths = [
    "/badges/public-id/download.pdf",
    "/credentials/v1/tenant%3Aassertion/download.pdf",
  ];
  for (const path of paths) {
    const response = await app.request(path, undefined, env);
    expect(response.status).toBe(200);
    expect(response.headers.get("cache-control")).toBe("no-store");
    expect(response.headers.get("content-type")).toBe("application/pdf");
    expect(await response.text()).toContain("Ada Lovelace");
  }
  expect(renders).toBe(1);
  recipientDisplayName = "Grace Hopper";
  expect(await (await app.request(paths[0] ?? "", undefined, env)).text()).toContain(
    "Grace Hopper",
  );
  expect(renders).toBe(2);
  for (const next of ["suspended", "revoked", "expired", "active"] as const) {
    state = next;
    const response = await app.request(paths[1] ?? "", undefined, env);
    expect(response.headers.get("x-credtrail-credential-state")).toBe(next);
    const text = await response.text();
    expect(text).toContain(
      `"status":"${next === "active" ? "Verified" : next[0]?.toUpperCase() + next.slice(1)}"`,
    );
  }
  expect(renders).toBe(6);
  expect(objects.size).toBe(1);
  available = false;
  for (const path of paths) expect((await app.request(path, undefined, env)).status).toBe(404);
  expect(renders).toBe(6);
});

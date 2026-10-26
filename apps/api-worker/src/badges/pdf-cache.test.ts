import type { ImmutableCredentialStore } from "@credtrail/core-domain";
import { describe, expect, it } from "vitest";
import { PDFArray, PDFDocument, PDFRawStream, decodePDFRawStream } from "pdf-lib";
import { createFetchPublicResourceNetwork } from "../http/public-resource-network";
import { renderBadgePdfDocument, type BadgePdfDocumentInput } from "./pdf";
import { loadOrRenderBadgePdf } from "./pdf-cache";

const pngBytes = Uint8Array.from(
  atob(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=",
  ),
  (character) => character.charCodeAt(0),
);
const input: BadgePdfDocumentInput = {
  badgeName: "Foundations",
  recipientName: "Ada Lovelace",
  recipientIdentifier: "ada@example.edu",
  issuerName: "Example University",
  issuedAt: "23 October 2026 UTC",
  status: "Verified",
  assertionId: "tenant:assertion",
  credentialId: "urn:credential:1",
  publicBadgeUrl: "https://credtrail.org/badges/1",
  verificationUrl: "https://credtrail.org/badges/1/verification",
  ob3JsonUrl: "https://credtrail.org/badges/1/jsonld",
  badgeImageUrl: "https://images.example.edu/badge.png",
};

const memoryStore = (): { store: ImmutableCredentialStore; objects: Map<string, string> } => {
  const objects = new Map<string, string>();
  return {
    objects,
    store: {
      head: async (key) => (objects.has(key) ? { key } : null),
      get: async (key) => {
        const value = objects.get(key);
        return value === undefined
          ? null
          : { size: new TextEncoder().encode(value).length, text: async () => value };
      },
      put: async (key, value) => {
        if (objects.has(key)) return null;
        objects.set(key, value);
        return { key, size: value.length, etag: "test", version: "1", uploaded: new Date(0) };
      },
      delete: async (key) => {
        objects.delete(key);
      },
    },
  };
};

const pdfText = async (bytes: Uint8Array): Promise<string> => {
  const document = await PDFDocument.load(bytes);
  const contents = document.context.lookup(document.getPage(0).node.Contents());
  if (!(contents instanceof PDFArray)) throw new Error("Missing PDF content");
  return contents
    .asArray()
    .map((reference) => {
      const stream = document.context.lookup(reference);
      if (!(stream instanceof PDFRawStream)) throw new Error("Missing PDF stream");
      const operations = new TextDecoder().decode(decodePDFRawStream(stream).decode());
      return Array.from(operations.matchAll(/<([A-Fa-f0-9]+)> Tj/gu), (match) =>
        Buffer.from(match[1] ?? "", "hex").toString("latin1"),
      ).join("\n");
    })
    .join("\n");
};

const setup = (): {
  store: ImmutableCredentialStore;
  objects: Map<string, string>;
  downloads: string[];
  load: (value?: BadgePdfDocumentInput, now?: number, tenantId?: string) => Promise<Uint8Array>;
  setImageAvailable: (available: boolean) => void;
} => {
  const { store, objects } = memoryStore();
  const downloads: string[] = [];
  let imageAvailable = true;
  const network = createFetchPublicResourceNetwork((url) => {
    downloads.push(url);
    return Promise.resolve(
      imageAvailable ? new Response(pngBytes) : new Response("unavailable", { status: 503 }),
    );
  });
  return {
    store,
    objects,
    downloads,
    load: (value = input, now = 1_000, tenantId = "tenant") =>
      loadOrRenderBadgePdf({
        store,
        tenantId,
        input: value,
        now,
        render: () => renderBadgePdfDocument(value, { publicResourceNetwork: network }),
      }),
    setImageAvailable: (available) => {
      imageAvailable = available;
    },
  };
};

describe("internal PDF reuse", () => {
  it("generates lazily and reuses stored bytes without fetching artwork again", async () => {
    const fixture = setup();
    expect(fixture.objects.size).toBe(0);
    const first = await fixture.load();
    expect(await fixture.load({ ...input }, 2_000)).toEqual(first);
    expect(fixture.downloads).toHaveLength(1);
    expect(fixture.objects.size).toBe(1);
    expect(await pdfText(first)).toContain("Ada Lovelace");
  });
  it("refreshes recipient details and URLs while keeping one stored object", async () => {
    const fixture = setup();
    await fixture.load();
    const renamed = {
      ...input,
      recipientName: "Grace Hopper",
      recipientIdentifier: "grace@example.edu",
      publicBadgeUrl: "https://credtrail.org/badges/new",
    };
    const bytes = await fixture.load(renamed);
    const text = await pdfText(bytes);
    expect(text).toContain("Grace Hopper");
    expect(text).toContain("grace@example.edu");
    expect(text).toContain("https://credtrail.org/badges/new");
    expect(text).not.toContain("Ada Lovelace");
    expect(fixture.objects.size).toBe(1);
    expect(await fixture.load(renamed)).toEqual(bytes);
    expect(fixture.downloads).toHaveLength(2);
  });
  it("replaces active PDFs when suspended, revoked, expired, or reinstated", async () => {
    const fixture = setup();
    await fixture.load();
    for (const status of ["Suspended", "Revoked", "Expired", "Verified"]) {
      const bytes = await fixture.load({
        ...input,
        status,
        validUntil: "24 October 2026 UTC",
        ...(status === "Revoked" ? { revokedAt: "23 October 2026 UTC" } : {}),
      });
      expect(await pdfText(bytes)).toContain(status);
      expect(fixture.objects.size).toBe(1);
    }
    expect(fixture.downloads).toHaveLength(5);
  });
  it("bounds artwork freshness to 24 hours", async () => {
    const fixture = setup();
    await fixture.load();
    await fixture.load(input, 1_000 + 24 * 60 * 60 * 1_000);
    expect(fixture.downloads).toHaveLength(2);
    expect(fixture.objects.size).toBe(1);
  });
  it("does not persist temporary artwork failures and retries on the next download", async () => {
    const fixture = setup();
    fixture.setImageAvailable(false);
    await fixture.load();
    expect(fixture.objects.size).toBe(0);
    fixture.setImageAvailable(true);
    await fixture.load();
    await fixture.load();
    expect(fixture.downloads).toHaveLength(2);
    expect(fixture.objects.size).toBe(1);
  });
  it("keeps tenants isolated", async () => {
    const fixture = setup();
    await fixture.load();
    await fixture.load(input, 1_000, "other-tenant");
    expect(fixture.objects.size).toBe(2);
    expect(fixture.downloads).toHaveLength(2);
  });
  it("replaces corrupt stored artifacts", async () => {
    const fixture = setup();
    await fixture.load();
    for (const key of fixture.objects.keys()) fixture.objects.set(key, "invalid JSON");
    expect(await pdfText(await fixture.load())).toContain("Ada Lovelace");
    await fixture.load();
    expect(fixture.downloads).toHaveLength(2);
  });
  it.each(["get", "put", "delete"] as const)(
    "returns a PDF when cache %s fails",
    async (operation) => {
      const fixture = setup();
      await fixture.load();
      const store = {
        ...fixture.store,
        [operation]: async () => {
          throw new Error("storage unavailable");
        },
      };
      const value = { ...input, recipientName: "Grace Hopper" };
      const bytes = await loadOrRenderBadgePdf({
        store,
        tenantId: "tenant",
        input: value,
        now: 1_000,
        render: () =>
          renderBadgePdfDocument(value, {
            publicResourceNetwork: createFetchPublicResourceNetwork(
              async () => new Response(pngBytes),
            ),
          }),
      });
      expect(await pdfText(bytes)).toContain("Grace Hopper");
    },
  );
});

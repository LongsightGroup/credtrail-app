import { describe, expect, it } from "vitest";
import { createFetchPublicResourceNetwork } from "../http/public-resource-network";
import { renderBadgePdfDocument, type BadgePdfDocumentInput } from "./pdf";

const PNG_BYTES = Uint8Array.from(
  atob(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=",
  ),
  (character) => character.charCodeAt(0),
);

const pdfInput = (badgeImageUrl: string): BadgePdfDocumentInput => ({
  badgeName: "Secure badge",
  recipientName: "Ada Lovelace",
  recipientIdentifier: "ada@example.edu",
  issuerName: "Example University",
  issuedAt: "17 August 2026 UTC",
  status: "Verified",
  assertionId: "assertion_123",
  credentialId: "credential_123",
  publicBadgeUrl: "https://credtrail.org/badges/badge_123",
  verificationUrl: "https://credtrail.org/badges/badge_123/verification",
  ob3JsonUrl: "https://credtrail.org/badges/badge_123/jsonld",
  badgeImageUrl,
});

describe("renderBadgePdfDocument badge images", () => {
  it("does not request private network image URLs", async () => {
    const requestedUrls: string[] = [];
    const network = createFetchPublicResourceNetwork((url) => {
      requestedUrls.push(url);
      return Promise.resolve(new Response(PNG_BYTES));
    });

    const pdf = await renderBadgePdfDocument(pdfInput("http://127.0.0.1/badge.png"), {
      publicResourceNetwork: network,
    });

    expect(requestedUrls).toEqual([]);
    expect(new TextDecoder().decode(pdf.slice(0, 5))).toBe("%PDF-");
  });

  it("loads a public image through the bounded public-resource network", async () => {
    const requestedUrls: string[] = [];
    const network = createFetchPublicResourceNetwork((url) => {
      requestedUrls.push(url);
      return Promise.resolve(
        new Response(PNG_BYTES, {
          headers: { "content-type": "application/octet-stream" },
        }),
      );
    });

    const pdf = await renderBadgePdfDocument(pdfInput("https://images.example.edu/badge"), {
      publicResourceNetwork: network,
    });

    expect(requestedUrls).toEqual(["https://images.example.edu/badge"]);
    expect(new TextDecoder().decode(pdf.slice(0, 5))).toBe("%PDF-");
  });

  it("rejects image bytes that do not match a supported image signature", async () => {
    const network = createFetchPublicResourceNetwork(() => {
      return Promise.resolve(new Response("not an image"));
    });

    const pdf = await renderBadgePdfDocument(pdfInput("https://images.example.edu/not-image"), {
      publicResourceNetwork: network,
    });

    expect(new TextDecoder().decode(pdf.slice(0, 5))).toBe("%PDF-");
  });

  it("propagates caller cancellation to the image request", async () => {
    const requestSignals: AbortSignal[] = [];
    const network = createFetchPublicResourceNetwork((_url, init) => {
      if (init.signal !== null && init.signal !== undefined) {
        requestSignals.push(init.signal);
      }

      return Promise.reject(init.signal?.reason);
    });
    const abortController = new AbortController();
    abortController.abort("request-disconnected");

    const pdf = await renderBadgePdfDocument(pdfInput("https://images.example.edu/badge"), {
      publicResourceNetwork: network,
      signal: abortController.signal,
    });

    expect(requestSignals).toHaveLength(1);
    expect(requestSignals[0]?.aborted).toBe(true);
    expect(new TextDecoder().decode(pdf.slice(0, 5))).toBe("%PDF-");
  });
});

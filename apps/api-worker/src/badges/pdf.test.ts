import { describe, expect, it } from "vitest";
import { createFetchPublicResourceNetwork } from "../http/public-resource-network";
import { renderBadgePdfDocument, type BadgePdfDocumentInput } from "./pdf";
import { PDFDocument, PDFArray, PDFRawStream, decodePDFRawStream } from "pdf-lib";

const PNG_BYTES = Uint8Array.from(
  atob(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=",
  ),
  (character) => character.charCodeAt(0),
);

const pdfInput = (badgeImageUrl: string | null): BadgePdfDocumentInput => ({
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
  it.each(["tenant_123", "institution_with_a_longer_tenant_identifier"])(
    "keeps expiry and revocation inside the record panel for %s",
    async (tenantId) => {
      const assertionId = `${tenantId}:40a6dc92-85ec-4cb0-8a50-afb2ae700e22`;
      const network = createFetchPublicResourceNetwork(() => Promise.resolve(new Response()));
      const bytes = await renderBadgePdfDocument(
        {
          ...pdfInput(null),
          assertionId,
          credentialId: `urn:credtrail:assertion:${encodeURIComponent(assertionId)}`,
          validUntil: "Jan 31, 2027, 11:59 PM UTC",
          revokedAt: "Oct 8, 2026, 12:00 PM UTC",
          status: "Revoked",
        },
        { publicResourceNetwork: network },
      );
      const document = await PDFDocument.load(bytes);
      const page = document.getPage(0);
      const contents = document.context.lookup(page.node.Contents());
      if (!(contents instanceof PDFArray)) throw new Error("Expected page drawing streams");
      const operations = contents
        .asArray()
        .map((reference) => {
          const stream = document.context.lookup(reference);
          if (!(stream instanceof PDFRawStream)) throw new Error("Expected encoded drawing stream");
          return new TextDecoder().decode(decodePDFRawStream(stream).decode());
        })
        .join("\n");
      const text = Array.from(operations.matchAll(/BT([\s\S]*?)ET/gu)).flatMap((block) => {
        const transform = block[1]?.match(/1 0 0 1 ([\d.-]+) ([\d.-]+) Tm/u);
        const encoded = block[1]?.match(/<([A-Fa-f0-9]+)> Tj/u);
        if (
          transform?.[1] === undefined ||
          transform[2] === undefined ||
          encoded?.[1] === undefined
        )
          return [];
        return [
          {
            x: Number(transform[1]),
            y: Number(transform[2]),
            value: Buffer.from(encoded[1], "hex").toString("latin1"),
          },
        ];
      });
      const title = text.find((row) => row.value === "Record details");
      if (title === undefined) throw new Error("Missing record panel");
      const rows = text.filter((row) => row.x === title.x && row.y < title.y);
      expect(rows.map((row) => row.value)).toEqual(
        expect.arrayContaining([
          "Valid until",
          "Jan 31, 2027, 11:59 PM UTC",
          "Revoked at",
          "Oct 8, 2026, 12:00 PM UTC",
        ]),
      );
      const rectangles = Array.from(operations.matchAll(/q\n([\s\S]*?)\nQ/gu)).flatMap((block) => {
        const transform = block[1]?.match(/1 0 0 1 ([\d.-]+) ([\d.-]+) cm/u);
        const edges = block[1]?.match(/0 0 m\n0 ([\d.-]+) l\n([\d.-]+) [\d.-]+ l/u);
        if (
          transform?.[1] === undefined ||
          transform[2] === undefined ||
          edges?.[1] === undefined ||
          edges[2] === undefined
        )
          return [];
        return [
          {
            x: Number(transform[1]),
            y: Number(transform[2]),
            height: Number(edges[1]),
            width: Number(edges[2]),
          },
        ];
      });
      const recordPanel = rectangles.find(
        (rectangle) =>
          rectangle.x < title.x &&
          rectangle.x > page.getWidth() / 2 &&
          rectangle.y < title.y &&
          rectangle.y + rectangle.height > title.y &&
          rectangle.width > 200,
      );
      if (recordPanel === undefined) throw new Error("Missing record panel frame");
      for (const row of rows) expect(row.y).toBeGreaterThan(recordPanel.y + 12);
    },
  );

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

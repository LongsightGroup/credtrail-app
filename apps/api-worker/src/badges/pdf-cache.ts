import type { ImmutableCredentialStore } from "@credtrail/core-domain";
import { z } from "zod";
import type { BadgePdfDocumentInput, BadgePdfDocumentResult } from "./pdf";

// Bump when PDF layout, fonts, wording, or rendering behavior changes.
const PDF_RENDERER_VERSION = 1;
const PDF_REUSE_MS = 24 * 60 * 60 * 1_000;
const MAX_PDF_BYTES = 8 * 1024 * 1024;
const MAX_STORED_BYTES = Math.ceil(MAX_PDF_BYTES / 3) * 4 + 1_024;
const storedPdfSchema = z.object({
  version: z.literal(1),
  fingerprint: z.string().regex(/^[a-f0-9]{64}$/u),
  expiresAt: z.number().int().nonnegative(),
  byteSize: z.number().int().positive().max(MAX_PDF_BYTES),
  base64Data: z
    .string()
    .max(MAX_STORED_BYTES)
    .regex(/^[A-Za-z0-9+/]*={0,2}$/u),
});

interface LoadOrRenderBadgePdfInput {
  readonly store: ImmutableCredentialStore;
  readonly tenantId: string;
  readonly input: BadgePdfDocumentInput;
  readonly now: number;
  readonly render: () => Promise<BadgePdfDocumentResult>;
}

const readStoredPdf = async (
  object: { readonly size: number; text(): Promise<string> },
  fingerprint: string,
  now: number,
): Promise<Uint8Array | null> => {
  if (object.size > MAX_STORED_BYTES) return null;
  const serialized = await object.text();
  if (new TextEncoder().encode(serialized).byteLength > MAX_STORED_BYTES) return null;
  let raw: unknown;
  try {
    raw = JSON.parse(serialized);
  } catch {
    return null;
  }
  const parsed = storedPdfSchema.safeParse(raw);
  if (!parsed.success) return null;
  const cached = parsed.data;
  if (cached.fingerprint !== fingerprint || cached.expiresAt <= now) return null;
  let binary: string;
  try {
    binary = atob(cached.base64Data);
  } catch {
    return null;
  }
  if (binary.length !== cached.byteSize || !binary.startsWith("%PDF-")) return null;
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
};

/** Reuses one private PDF per assertion, after the caller resolves current render inputs. */
export const loadOrRenderBadgePdf = async (
  options: LoadOrRenderBadgePdfInput,
): Promise<Uint8Array> => {
  // All render inputs are primitives. Sorting makes the fingerprint independent of property order.
  const serializedInput = JSON.stringify({
    rendererVersion: PDF_RENDERER_VERSION,
    input: Object.fromEntries(Object.entries(options.input).sort(([a], [b]) => a.localeCompare(b))),
  });
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(serializedInput));
  const fingerprint = Array.from(new Uint8Array(digest), (byte) =>
    byte.toString(16).padStart(2, "0"),
  ).join("");
  const key = `tenants/${encodeURIComponent(options.tenantId)}/pdf-cache/${encodeURIComponent(options.input.assertionId)}.json`;
  let existing = false;
  let storageAvailable = true;
  try {
    const object = await options.store.get(key);
    existing = object !== null;
    if (object !== null) {
      const bytes = await readStoredPdf(object, fingerprint, options.now);
      if (bytes !== null) return bytes;
    }
  } catch {
    // Derived artifacts are optional: a cache outage must not prevent rendering a download.
    storageAvailable = false;
  }

  const rendered = await options.render();
  if (
    !storageAvailable ||
    rendered.artwork === "unavailable" ||
    rendered.bytes.length > MAX_PDF_BYTES
  ) {
    return rendered.bytes;
  }
  let binary = "";
  for (const byte of rendered.bytes) binary += String.fromCharCode(byte);
  const payload = JSON.stringify({
    version: 1,
    fingerprint,
    expiresAt: options.now + PDF_REUSE_MS,
    byteSize: rendered.bytes.length,
    base64Data: btoa(binary),
  });
  try {
    // Both adapters use create-only writes. One replaceable slot bounds storage per assertion.
    // Concurrent misses may render twice; every read still checks the complete fingerprint.
    if (existing) await options.store.delete(key);
    await options.store.put(key, payload, {
      httpMetadata: { contentType: "application/json", cacheControl: "no-store" },
      customMetadata: { artifactType: "badge-pdf-cache-v1" },
    });
  } catch {
    // The freshly rendered PDF remains usable even when persistence fails.
  }
  return rendered.bytes;
};

import type { ImmutableCredentialStore } from "@credtrail/core-domain";
import { describe, expect, it } from "vitest";
import { ensureLocalDevBadgeTemplateArtwork } from "./local-dev-badge-artwork";

const createRecordingStore = (): {
  readonly store: ImmutableCredentialStore;
  readonly writtenKeys: readonly string[];
} => {
  const objects = new Map<string, string>();
  const writtenKeys: string[] = [];

  return {
    writtenKeys,
    store: {
      head: (key) => Promise.resolve(objects.has(key) ? { key } : null),
      get: (key) => {
        const value = objects.get(key);
        return Promise.resolve(
          value === undefined
            ? null
            : {
                size: new TextEncoder().encode(value).byteLength,
                text: () => Promise.resolve(value),
              },
        );
      },
      put: (key, value) => {
        if (objects.has(key)) {
          return Promise.resolve(null);
        }

        objects.set(key, value);
        writtenKeys.push(key);
        return Promise.resolve({
          key,
          etag: `etag-${String(writtenKeys.length)}`,
          version: `version-${String(writtenKeys.length)}`,
          size: new TextEncoder().encode(value).byteLength,
          uploaded: new Date("2026-08-12T12:00:00.000Z"),
        });
      },
      delete: (key) => {
        objects.delete(key);
        return Promise.resolve();
      },
    },
  };
};

const pngBytes = (suffix: number): Uint8Array => {
  return new Uint8Array([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, suffix]);
};

describe("ensureLocalDevBadgeTemplateArtwork", () => {
  it("reuses identical artwork and assigns changed bytes a new immutable URI", async () => {
    const recording = createRecordingStore();
    const base = {
      store: recording.store,
      publicAppOrigin: "http://localhost:8787",
      tenantId: "tenant_123",
      badgeTemplateId: "badge_template_123",
      mimeType: "image/png" as const,
      originalFilename: "badge.png",
    };
    const firstUri = await ensureLocalDevBadgeTemplateArtwork({ ...base, bytes: pngBytes(1) });
    const replayedUri = await ensureLocalDevBadgeTemplateArtwork({ ...base, bytes: pngBytes(1) });
    const changedUri = await ensureLocalDevBadgeTemplateArtwork({ ...base, bytes: pngBytes(2) });

    expect(replayedUri).toBe(firstUri);
    expect(changedUri).not.toBe(firstUri);
    expect(recording.writtenKeys).toHaveLength(2);
    expect(new Set(recording.writtenKeys).size).toBe(2);
  });
});

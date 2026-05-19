import { describe, expect, it, vi } from "vitest";
import {
  type BadgeTemplateImageGenerationAiBinding,
  badgeTemplateImageGenerationConfigFromEnv,
  buildBadgeTemplateImagePrompt,
  generateBadgeTemplateImageViaWorkersAi,
  isBadgeTemplateImageGenerationConfigured,
} from "./badge-template-image-generation";
import type { BadgeTemplateRecord } from "@credtrail/db";

const samplePngBase64 = (): string => {
  return Buffer.from(
    new Uint8Array([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x01, 0x02]),
  ).toString("base64");
};

const sampleTemplate = (): BadgeTemplateRecord => {
  return {
    id: "badge_template_001",
    tenantId: "tenant_123",
    slug: "intro-to-badging",
    title: "Intro to Badging",
    description:
      "Awarded for completing the Intro to Badging project and demonstrating public verification.",
    criteriaUri: null,
    imageUri: null,
    createdByUserId: "usr_admin",
    ownerOrgUnitId: "tenant_123:org:institution",
    governanceMetadataJson: null,
    isArchived: false,
    createdAt: "2026-02-23T12:00:00.000Z",
    updatedAt: "2026-02-23T12:00:00.000Z",
  };
};

describe("badge template image generation Workers AI client", () => {
  it("defaults to the fast Workers AI FLUX.2 Klein model", () => {
    const ai = {
      run: vi.fn<BadgeTemplateImageGenerationAiBinding["run"]>(async () => {
        return {};
      }),
    };
    const config = badgeTemplateImageGenerationConfigFromEnv({
      AI: ai,
      PLATFORM_DOMAIN: "credtrail.test",
    });

    expect(config.provider).toBe("workers-ai");
    expect(config.model).toBe("@cf/black-forest-labs/flux-2-klein-4b");
    expect(
      isBadgeTemplateImageGenerationConfigured({
        AI: ai,
        PLATFORM_DOMAIN: "credtrail.test",
      }),
    ).toBe(true);
  });

  it("is not configured without the Workers AI binding", () => {
    expect(
      isBadgeTemplateImageGenerationConfigured({
        PLATFORM_DOMAIN: "credtrail.test",
      }),
    ).toBe(false);
  });

  it("builds an icon-style prompt that rejects certificate and hero layouts", () => {
    const prompt = buildBadgeTemplateImagePrompt({
      template: sampleTemplate(),
      stylePreset: "minimal",
      promptNotes: "stars",
      accentColor: "Sakai blue",
    });

    expect(prompt).toContain("tiny, fun, simple square badge icon");
    expect(prompt).toContain("app icon, sticker, pin, patch, or achievement token");
    expect(prompt).toContain("one bold symbol");
    expect(prompt).toContain("not a certificate");
    expect(prompt).toContain("not a certificate, poster, hero image");
    expect(prompt).toContain("Do not typeset the title or description");
    expect(prompt).toContain("no text by default");
    expect(prompt).toContain("No paragraphs");
    expect(prompt).toContain("no CredTrail wordmark");
    expect(prompt).toContain("legible at 64x64 and 128x128 pixels");
    expect(prompt).toContain("Concept title: Intro to Badging");
    expect(prompt).not.toContain("Badge description:");
  });

  it("calls the direct Workers AI binding with multipart prompt fields", async () => {
    const run = vi.fn<BadgeTemplateImageGenerationAiBinding["run"]>(async () => {
      return { image: samplePngBase64() };
    });
    const ai = { run };

    const generated = await generateBadgeTemplateImageViaWorkersAi({
      env: {
        AI: ai,
        BADGE_IMAGE_GENERATION_MODEL: "@cf/black-forest-labs/flux-2-klein-4b",
        PLATFORM_DOMAIN: "credtrail.test",
      },
      promptText: "Create a badge.",
    });

    expect(generated.mimeType).toBe("image/png");
    expect(generated.provider).toBe("workers-ai");
    expect(run).toHaveBeenCalledTimes(1);

    const [model, input] = run.mock.calls[0] ?? [];
    const payload = input as {
      multipart?: {
        body?: unknown;
        contentType?: unknown;
      };
    };

    const multipart = payload.multipart;

    if (multipart === undefined || !(multipart.body instanceof ReadableStream)) {
      throw new Error("Expected Workers AI multipart body to be a ReadableStream");
    }

    const contentType = typeof multipart.contentType === "string" ? multipart.contentType : "";

    expect(model).toBe("@cf/black-forest-labs/flux-2-klein-4b");
    expect(contentType).toContain("multipart/form-data");

    const submittedForm = await new Response(multipart.body, {
      headers: {
        "content-type": contentType,
      },
    }).formData();

    expect(submittedForm.get("steps")).toBe("12");
    expect(submittedForm.get("width")).toBe("256");
    expect(submittedForm.get("height")).toBe("256");
  });
});

import { describe, expect, it } from "vitest";

import {
  parseCreateBadgeTemplateRequest,
  parseGenerateBadgeTemplateImageRequest,
  parseUpdateBadgeTemplateRequest,
} from "./badge-template.js";
import {
  parseBadgeTemplateImageGenerationPathParams,
  parseBadgeTemplateImageRevisionPathParams,
  parseBadgeTemplatePathParams,
} from "./path-params.js";

describe("badge template parsers", () => {
  it("accepts a valid create request", () => {
    const payload = parseCreateBadgeTemplateRequest({
      slug: "intro-to-ts",
      title: "Intro to TypeScript",
      description: "Awarded for completing TypeScript basics.",
      criteriaUri: "https://example.edu/badges/intro-to-ts/criteria",
      imageUri: "https://cdn.example.edu/badges/intro-to-ts.png",
    });

    expect(payload.slug).toBe("intro-to-ts");
  });

  it("rejects invalid slugs", () => {
    expect(() => {
      parseCreateBadgeTemplateRequest({
        slug: "Intro To TS",
        title: "Intro to TypeScript",
      });
    }).toThrow(/./);
  });

  it("accepts update requests with nullable optional fields", () => {
    const payload = parseUpdateBadgeTemplateRequest({
      description: null,
      imageUri: null,
    });

    expect(payload.description).toBeNull();
  });

  it("rejects empty update payloads", () => {
    expect(() => {
      parseUpdateBadgeTemplateRequest({});
    }).toThrow(/./);
  });

  it("parses path params for badge template routes", () => {
    const params = parseBadgeTemplatePathParams({
      tenantId: "tenant_123",
      badgeTemplateId: "tmpl_456",
    });

    expect(params.badgeTemplateId).toBe("tmpl_456");
  });

  it("parses badge template image generation requests and path params", () => {
    const request = parseGenerateBadgeTemplateImageRequest({
      stylePreset: "technical",
      promptNotes: "Use circuit lines.",
      accentColor: "blue",
    });
    const generationParams = parseBadgeTemplateImageGenerationPathParams({
      tenantId: "tenant_123",
      badgeTemplateId: "tmpl_456",
      generationId: "btig_789",
    });
    const revisionParams = parseBadgeTemplateImageRevisionPathParams({
      tenantId: "tenant_123",
      badgeTemplateId: "tmpl_456",
      revisionId: "btir_789",
    });

    expect(request.stylePreset).toBe("technical");
    expect(generationParams.generationId).toBe("btig_789");
    expect(revisionParams.revisionId).toBe("btir_789");
  });

  it("accepts create payloads that include owner org unit", () => {
    const payload = parseCreateBadgeTemplateRequest({
      slug: "intro-to-ts",
      title: "Intro to TypeScript",
      ownerOrgUnitId: "tenant_123:org:institution",
    });

    expect(payload.ownerOrgUnitId).toBe("tenant_123:org:institution");
  });
});

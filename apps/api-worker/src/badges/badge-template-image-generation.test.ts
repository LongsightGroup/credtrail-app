import { afterEach, describe, expect, it, vi } from "vitest";
import {
  badgeTemplateImageGenerationConfigFromEnv,
  generateBadgeTemplateImageViaCloudflareGateway,
  isBadgeTemplateImageGenerationConfigured,
} from "./badge-template-image-generation";

const samplePngBase64 = (): string => {
  return Buffer.from(
    new Uint8Array([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x01, 0x02]),
  ).toString("base64");
};

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("badge template image generation gateway client", () => {
  it("defaults to the fast Workers AI FLUX.2 klein model", () => {
    const config = badgeTemplateImageGenerationConfigFromEnv({
      AI_GATEWAY_ENABLED: "true",
      AI_GATEWAY_ACCOUNT_ID: "cf_account_123",
      AI_GATEWAY_ID: "credtrail",
      AI_GATEWAY_PROVIDER_API_KEY: "cf-workers-ai-token",
      PLATFORM_DOMAIN: "credtrail.test",
    });

    expect(config.provider).toBe("workers-ai");
    expect(config.model).toBe("@cf/black-forest-labs/flux-2-klein-4b");
    expect(
      isBadgeTemplateImageGenerationConfigured({
        AI_GATEWAY_ENABLED: "true",
        AI_GATEWAY_ACCOUNT_ID: "cf_account_123",
        AI_GATEWAY_ID: "credtrail",
        AI_GATEWAY_PROVIDER_API_KEY: "cf-workers-ai-token",
        PLATFORM_DOMAIN: "credtrail.test",
      }),
    ).toBe(true);
  });

  it("calls Workers AI through AI Gateway with multipart prompt fields", async () => {
    const mockedFetch = vi.fn<typeof fetch>(async () => {
      return new Response(JSON.stringify({ image: samplePngBase64() }), {
        status: 200,
        headers: {
          "content-type": "application/json",
        },
      });
    });
    vi.stubGlobal("fetch", mockedFetch);

    const generated = await generateBadgeTemplateImageViaCloudflareGateway({
      env: {
        AI_GATEWAY_ENABLED: "true",
        AI_GATEWAY_ACCOUNT_ID: "cf_account_123",
        AI_GATEWAY_ID: "credtrail",
        AI_GATEWAY_PROVIDER: "workers-ai",
        AI_GATEWAY_PROVIDER_API_KEY: "cf-workers-ai-token",
        BADGE_IMAGE_GENERATION_MODEL: "@cf/black-forest-labs/flux-2-klein-4b",
        PLATFORM_DOMAIN: "credtrail.test",
      },
      promptText: "Create a badge.",
    });

    expect(generated.mimeType).toBe("image/png");
    expect(generated.provider).toBe("workers-ai");
    expect(mockedFetch).toHaveBeenCalledTimes(1);

    const [url, init] = mockedFetch.mock.calls[0] ?? [];
    const requestInit = init as RequestInit;
    const headers = new Headers(requestInit.headers);
    const body = requestInit.body;

    if (typeof url !== "string") {
      throw new Error("Expected Workers AI request URL to be a string");
    }

    if (!(body instanceof FormData)) {
      throw new Error("Expected Workers AI request body to be FormData");
    }

    expect(url).toBe(
      "https://gateway.ai.cloudflare.com/v1/cf_account_123/credtrail/workers-ai/%40cf/black-forest-labs/flux-2-klein-4b",
    );
    expect(headers.get("authorization")).toBe("Bearer cf-workers-ai-token");
    expect(headers.has("content-type")).toBe(false);
    expect(headers.get("cf-aig-request-timeout")).toBe("120000");
    expect(headers.get("cf-aig-max-attempts")).toBe("2");
    expect(headers.get("cf-aig-retry-delay")).toBe("1000");
    expect(headers.get("cf-aig-backoff")).toBe("exponential");
    expect(body.get("prompt")).toBe("Create a badge.");
    expect(body.get("width")).toBe("1024");
    expect(body.get("height")).toBe("1024");
  });

  it("keeps the OpenAI provider-compatible path available", async () => {
    const mockedFetch = vi.fn<typeof fetch>(async () => {
      return new Response(JSON.stringify({ data: [{ b64_json: samplePngBase64() }] }), {
        status: 200,
        headers: {
          "content-type": "application/json",
        },
      });
    });
    vi.stubGlobal("fetch", mockedFetch);

    await generateBadgeTemplateImageViaCloudflareGateway({
      env: {
        AI_GATEWAY_ENABLED: "true",
        AI_GATEWAY_ACCOUNT_ID: "cf_account_123",
        AI_GATEWAY_ID: "credtrail",
        AI_GATEWAY_PROVIDER: "openai",
        AI_GATEWAY_PROVIDER_API_KEY: "openai-token",
        BADGE_IMAGE_GENERATION_MODEL: "gpt-image-1",
        PLATFORM_DOMAIN: "credtrail.test",
      },
      promptText: "Create a badge.",
    });

    const [url, init] = mockedFetch.mock.calls[0] ?? [];
    const requestInit = init as RequestInit;
    const requestBody = requestInit.body;
    const headers = new Headers(requestInit.headers);

    if (typeof url !== "string") {
      throw new Error("Expected OpenAI provider request URL to be a string");
    }

    if (typeof requestBody !== "string") {
      throw new Error("Expected OpenAI provider request body to be JSON text");
    }

    const body = JSON.parse(requestBody) as {
      model: string;
      prompt: string;
    };

    expect(url).toBe(
      "https://gateway.ai.cloudflare.com/v1/cf_account_123/credtrail/openai/images/generations",
    );
    expect(headers.get("content-type")).toBe("application/json");
    expect(headers.get("cf-aig-request-timeout")).toBe("120000");
    expect(body.model).toBe("gpt-image-1");
    expect(body.prompt).toBe("Create a badge.");
  });
});

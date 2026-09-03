import { z } from "zod";
import { generateBadgeTemplateImageViaWorkersAi } from "../badges/badge-template-image-generation";
import { badgeTemplateImageMimeTypeFromBytes } from "../badges/template-image-storage";
import {
  buildBadgeImageModelBenchmarkPrompt,
  findBadgeImageModelBenchmarkSample,
} from "./badge-image-model-benchmark-samples";

interface BenchmarkAiBinding {
  run(model: string, inputs: Record<string, unknown>): Promise<unknown>;
}

interface BenchmarkEnv {
  AI: BenchmarkAiBinding;
}

const CURRENT_IMAGE_MODEL = "@cf/black-forest-labs/flux-2-klein-9b";
const QWEN_IMAGE_MODEL = "alibaba/qwen-image-3.0-pro";
const CURRENT_IMAGE_SIZE_PX = 256;
const QWEN_IMAGE_SIZE_PX = 1024;
const BENCHMARK_IMAGE_MAX_BYTES = 10 * 1024 * 1024;

const benchmarkGenerationRequestSchema = z.strictObject({
  sampleId: z.string().trim().min(1).max(100),
  model: z.enum(["current", "qwen"]),
});

const qwenImageGenerationResponseSchema = z.object({
  state: z.literal("Completed"),
  result: z.object({
    images: z.array(z.url()).min(1),
  }),
});

type GeneratedBenchmarkImage = {
  readonly bytes: Uint8Array;
  readonly mimeType: "image/png" | "image/jpeg" | "image/webp";
  readonly modelId: string;
  readonly modelRunMs: number;
  readonly assetFetchMs: number;
  readonly outputSizePx: number;
};

const generatedCurrentImage = async (
  ai: BenchmarkAiBinding,
  prompt: string,
): Promise<GeneratedBenchmarkImage> => {
  const startedAt = performance.now();
  const image = await generateBadgeTemplateImageViaWorkersAi({
    env: {
      AI: ai,
      BADGE_IMAGE_GENERATION_MODEL: CURRENT_IMAGE_MODEL,
      PLATFORM_DOMAIN: "benchmark.invalid",
      PUBLIC_APP_ORIGIN: "https://benchmark.invalid",
    },
    promptText: prompt,
  });

  return {
    bytes: image.bytes,
    mimeType: image.mimeType,
    modelId: CURRENT_IMAGE_MODEL,
    modelRunMs: performance.now() - startedAt,
    assetFetchMs: 0,
    outputSizePx: CURRENT_IMAGE_SIZE_PX,
  };
};

const generatedQwenImage = async (
  ai: BenchmarkAiBinding,
  prompt: string,
  signal: AbortSignal,
): Promise<GeneratedBenchmarkImage> => {
  signal.throwIfAborted();
  const modelStartedAt = performance.now();
  const rawResponse = await ai.run(QWEN_IMAGE_MODEL, {
    prompt,
    size: `${String(QWEN_IMAGE_SIZE_PX)}x${String(QWEN_IMAGE_SIZE_PX)}`,
    n: 1,
    watermark: false,
    prompt_extend: false,
  });
  signal.throwIfAborted();
  const modelRunMs = performance.now() - modelStartedAt;
  const parsedResponse = qwenImageGenerationResponseSchema.safeParse(rawResponse);

  if (!parsedResponse.success) {
    throw new Error("Qwen image generation returned an unexpected response");
  }

  const imageUrlValue = parsedResponse.data.result.images[0];

  if (imageUrlValue === undefined) {
    throw new Error("Qwen image generation returned no image URL");
  }

  const imageUrl = new URL(imageUrlValue);

  if (imageUrl.protocol !== "https:") {
    throw new Error("Qwen image generation returned a non-HTTPS image URL");
  }

  const fetchStartedAt = performance.now();
  const imageResponse = await fetch(imageUrl, { signal });
  const assetFetchMs = performance.now() - fetchStartedAt;

  if (!imageResponse.ok) {
    throw new Error(`Qwen image download failed with HTTP ${String(imageResponse.status)}`);
  }

  const declaredLength = Number(imageResponse.headers.get("content-length"));

  if (Number.isFinite(declaredLength) && declaredLength > BENCHMARK_IMAGE_MAX_BYTES) {
    throw new Error("Qwen image download exceeded the benchmark size limit");
  }

  const bytes = new Uint8Array(await imageResponse.arrayBuffer());

  if (bytes.byteLength < 1 || bytes.byteLength > BENCHMARK_IMAGE_MAX_BYTES) {
    throw new Error("Qwen image download had an invalid byte length");
  }

  const mimeType = badgeTemplateImageMimeTypeFromBytes(bytes);

  if (mimeType === null) {
    throw new Error("Qwen image generation did not produce PNG, JPEG, or WebP bytes");
  }

  return {
    bytes,
    mimeType,
    modelId: QWEN_IMAGE_MODEL,
    modelRunMs,
    assetFetchMs,
    outputSizePx: QWEN_IMAGE_SIZE_PX,
  };
};

const generateBenchmarkImage = async (request: Request, env: BenchmarkEnv): Promise<Response> => {
  let requestBody: unknown;

  try {
    requestBody = await request.json();
  } catch (cause: unknown) {
    return Response.json(
      {
        error: "Request body must be valid JSON",
        detail: cause instanceof Error ? cause.message : "Unknown JSON parsing error",
      },
      { status: 400 },
    );
  }

  const parsedRequest = benchmarkGenerationRequestSchema.safeParse(requestBody);

  if (!parsedRequest.success) {
    return Response.json(
      {
        error: "Request body did not match the benchmark contract",
        issues: parsedRequest.error.issues.map((issue) => issue.message),
      },
      { status: 400 },
    );
  }

  const sample = findBadgeImageModelBenchmarkSample(parsedRequest.data.sampleId);

  if (sample === null) {
    return Response.json({ error: "Benchmark sample not found" }, { status: 404 });
  }

  const prompt = buildBadgeImageModelBenchmarkPrompt(sample);
  const image =
    parsedRequest.data.model === "current"
      ? await generatedCurrentImage(env.AI, prompt)
      : await generatedQwenImage(env.AI, prompt, request.signal);

  const responseBytes = new Uint8Array(image.bytes.byteLength);
  responseBytes.set(image.bytes);

  return new Response(responseBytes.buffer, {
    headers: {
      "content-type": image.mimeType,
      "cache-control": "no-store",
      "x-credtrail-model-id": image.modelId,
      "x-credtrail-model-run-ms": image.modelRunMs.toFixed(1),
      "x-credtrail-asset-fetch-ms": image.assetFetchMs.toFixed(1),
      "x-credtrail-output-size-px": String(image.outputSizePx),
    },
  });
};

/** Remote-development Worker used only by the local badge image benchmark runner. */
export default {
  async fetch(request: Request, env: BenchmarkEnv): Promise<Response> {
    const url = new URL(request.url);

    if (url.pathname === "/health" && request.method === "GET") {
      return Response.json({ status: "ready" });
    }

    if (url.pathname !== "/generate") {
      return Response.json({ error: "Not found" }, { status: 404 });
    }

    if (request.method !== "POST") {
      return Response.json(
        { error: "Method not allowed" },
        { status: 405, headers: { allow: "POST" } },
      );
    }

    try {
      return await generateBenchmarkImage(request, env);
    } catch (cause: unknown) {
      return Response.json(
        {
          error: "Badge image generation failed",
          detail: cause instanceof Error ? cause.message : "Unknown generation error",
        },
        { status: 502 },
      );
    }
  },
} satisfies ExportedHandler<BenchmarkEnv>;

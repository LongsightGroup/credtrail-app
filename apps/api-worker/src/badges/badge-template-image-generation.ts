import type { ImmutableCredentialStore } from "@credtrail/core-domain";
import {
  createAuditLog,
  findBadgeTemplateById,
  findBadgeTemplateImageGenerationById,
  updateBadgeTemplateImageGeneration,
  type BadgeTemplateImageGenerationRecord,
  type BadgeTemplateRecord,
  type SqlDatabase,
} from "@credtrail/db";
import type { GenerateBadgeTemplateImageQueueJob } from "@credtrail/validation";
import {
  BADGE_TEMPLATE_IMAGE_MAX_BYTES,
  badgeTemplateImageMimeTypeFromBytes,
  storeBadgeTemplateImage,
  type BadgeTemplateImageMimeType,
} from "./template-image-storage";

export interface BadgeTemplateImageGenerationConfig {
  provider: "workers-ai";
  model: string;
}

export interface BadgeTemplateImageGenerationAiBinding {
  run(model: string, inputs: Record<string, unknown>): Promise<unknown>;
}

export interface BadgeTemplateImageGenerationEnv {
  AI?: BadgeTemplateImageGenerationAiBinding;
  BADGE_IMAGE_GENERATION_MODEL?: string;
  PLATFORM_DOMAIN: string;
}

interface GeneratedBadgeTemplateImage {
  bytes: Uint8Array;
  mimeType: BadgeTemplateImageMimeType;
  provider: string;
  model: string;
  metadata: Record<string, string | number | boolean | null>;
}

const DEFAULT_WORKERS_AI_IMAGE_MODEL = "@cf/black-forest-labs/flux-2-klein-4b";
const WORKERS_AI_IMAGE_GENERATION_TIMEOUT_MS = 30_000;

const decodeBase64 = (value: string): Uint8Array => {
  const normalized = value.includes(",") ? (value.split(",").pop() ?? "") : value;
  const binary = atob(normalized);
  const bytes = new Uint8Array(binary.length);

  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }

  return bytes;
};

const asRecord = (value: unknown): Record<string, unknown> | null => {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    return null;
  }

  return value as Record<string, unknown>;
};

const requiredConfigValue = (value: string | undefined): string => {
  const trimmed = value?.trim() ?? "";
  return trimmed;
};

export const badgeTemplateImageGenerationConfigFromEnv = (
  env: BadgeTemplateImageGenerationEnv,
): BadgeTemplateImageGenerationConfig => {
  const configuredModel = requiredConfigValue(env.BADGE_IMAGE_GENERATION_MODEL);
  const model = configuredModel.length > 0 ? configuredModel : DEFAULT_WORKERS_AI_IMAGE_MODEL;

  return {
    provider: "workers-ai",
    model,
  };
};

export const isBadgeTemplateImageGenerationConfigured = (
  env: BadgeTemplateImageGenerationEnv,
): boolean => {
  const config = badgeTemplateImageGenerationConfigFromEnv(env);
  return env.AI !== undefined && config.model.length > 0;
};

export const buildBadgeTemplateImagePrompt = (input: {
  template: BadgeTemplateRecord;
  stylePreset: string;
  promptNotes?: string | undefined;
  accentColor?: string | undefined;
}): string => {
  const notes = input.promptNotes?.trim();
  const accentColor = input.accentColor?.trim();
  const description = input.template.description?.trim();

  return [
    "Create a tiny, fun, simple square badge icon for a digital credential. Think app icon, sticker, pin, patch, or achievement token.",
    "Keep it playful and minimal: one bold symbol, very few details, no layout sections, and no explanatory content.",
    "This must be a small icon-style badge mark, not a certificate, poster, hero image, web page, card, document, or screenshot.",
    "Use the badge title and description only as semantic guidance for symbols and mood. Do not typeset the title or description.",
    `Concept title: ${input.template.title}.`,
    description === undefined || description.length === 0 ? "" : `Concept meaning: ${description}.`,
    `Visual style preset: ${input.stylePreset}.`,
    accentColor === undefined || accentColor.length === 0
      ? ""
      : `Preferred accent color: ${accentColor}.`,
    notes === undefined || notes.length === 0 ? "" : `Visual hints from admin: ${notes}.`,
    "Composition: centered emblem, medallion, sticker, pin, patch, or simple geometric symbol with one clear focal idea. Make it legible at 64x64 and 128x128 pixels.",
    "Use clean vector-like geometry, strong contrast, friendly color blocking, and a transparent or simple solid background.",
    "Text rules: no text by default. No paragraphs, no sentences, no subtitle blocks, no brand headers, no CredTrail wordmark, no LMS wordmarks, no fake UI text, no tiny unreadable text. If text is unavoidable, use at most one to three large characters.",
    "Do not use protected LMS logos or product logos unless the prompt explicitly includes permission.",
  ]
    .filter((line) => line.length > 0)
    .join("\n");
};

const imageBytesFromGenerationResponse = (responsePayload: unknown): Uint8Array => {
  const payload = asRecord(responsePayload);
  const directImage = payload?.image;

  if (typeof directImage === "string" && directImage.length > 0) {
    return decodeBase64(directImage);
  }

  const result = asRecord(payload?.result);
  const resultImage = result?.image;

  if (typeof resultImage === "string" && resultImage.length > 0) {
    return decodeBase64(resultImage);
  }

  throw new Error("Workers AI image generation response did not include image data");
};

const withTimeout = async <T>(promise: Promise<T>, timeoutMs: number): Promise<T> => {
  let timeout: ReturnType<typeof setTimeout> | null = null;

  const timeoutPromise = new Promise<never>((_resolve, reject) => {
    timeout = setTimeout(() => {
      reject(new Error(`Workers AI image generation timed out after ${String(timeoutMs)}ms`));
    }, timeoutMs);
  });

  try {
    return await Promise.race([promise, timeoutPromise]);
  } finally {
    if (timeout !== null) {
      clearTimeout(timeout);
    }
  }
};

const requestWorkersAiImage = (input: {
  ai: BadgeTemplateImageGenerationAiBinding;
  config: BadgeTemplateImageGenerationConfig;
  promptText: string;
}): Promise<unknown> => {
  const form = new FormData();
  form.set("prompt", input.promptText);
  form.set("width", "1024");
  form.set("height", "1024");

  const serializedForm = new Response(form);
  const body = serializedForm.body;
  const contentType = serializedForm.headers.get("content-type");

  if (body === null || contentType === null) {
    throw new Error("Unable to serialize Workers AI multipart image request");
  }

  return input.ai.run(input.config.model, {
    multipart: {
      body,
      contentType,
    },
  });
};

export const generateBadgeTemplateImageViaWorkersAi = async (input: {
  env: BadgeTemplateImageGenerationEnv;
  promptText: string;
}): Promise<GeneratedBadgeTemplateImage> => {
  const config = badgeTemplateImageGenerationConfigFromEnv(input.env);

  if (!isBadgeTemplateImageGenerationConfigured(input.env)) {
    throw new Error("Badge image generation is not configured");
  }

  const ai = input.env.AI;

  if (ai === undefined) {
    throw new Error("Badge image generation is not configured");
  }

  const responsePayload = await withTimeout(
    requestWorkersAiImage({
      ai,
      config,
      promptText: input.promptText,
    }),
    WORKERS_AI_IMAGE_GENERATION_TIMEOUT_MS,
  );
  const bytes = imageBytesFromGenerationResponse(responsePayload);

  if (bytes.byteLength > BADGE_TEMPLATE_IMAGE_MAX_BYTES) {
    throw new Error(
      `Generated badge image exceeds ${String(BADGE_TEMPLATE_IMAGE_MAX_BYTES)} bytes`,
    );
  }

  const mimeType = badgeTemplateImageMimeTypeFromBytes(bytes);

  if (mimeType === null) {
    throw new Error("Generated badge image did not produce PNG, JPEG, or WebP bytes");
  }

  return {
    bytes,
    mimeType,
    provider: config.provider,
    model: config.model,
    metadata: {
      provider: config.provider,
      model: config.model,
      byteSize: bytes.byteLength,
      invocation: "workers-ai-binding",
    },
  };
};

const assetUrlForPlatform = (input: {
  platformDomain: string;
  tenantId: string;
  badgeTemplateId: string;
  assetId: string;
}): { path: string; url: string } => {
  const path = `/badges/assets/${encodeURIComponent(input.tenantId)}/${encodeURIComponent(
    input.badgeTemplateId,
  )}/${encodeURIComponent(input.assetId)}`;
  const trimmedDomain = input.platformDomain.trim();
  const baseUrl =
    trimmedDomain.startsWith("http://") || trimmedDomain.startsWith("https://")
      ? trimmedDomain
      : `https://${trimmedDomain}`;

  return {
    path,
    url: new URL(path, baseUrl).toString(),
  };
};

export const completeBadgeTemplateImageGeneration = async (input: {
  db: SqlDatabase;
  store: ImmutableCredentialStore;
  env: BadgeTemplateImageGenerationEnv;
  tenantId: string;
  badgeTemplateId: string;
  generationId: string;
  promptText: string;
  requestedByUserId?: string | null | undefined;
}): Promise<BadgeTemplateImageGenerationRecord> => {
  await updateBadgeTemplateImageGeneration(input.db, {
    tenantId: input.tenantId,
    id: input.generationId,
    status: "processing",
    errorMessage: null,
    completedAt: null,
  });

  try {
    const generated = await generateBadgeTemplateImageViaWorkersAi({
      env: input.env,
      promptText: input.promptText,
    });
    const assetId = crypto.randomUUID();

    await storeBadgeTemplateImage(input.store, {
      tenantId: input.tenantId,
      badgeTemplateId: input.badgeTemplateId,
      assetId,
      mimeType: generated.mimeType,
      bytes: generated.bytes,
      originalFilename: null,
    });

    const image = assetUrlForPlatform({
      platformDomain: input.env.PLATFORM_DOMAIN,
      tenantId: input.tenantId,
      badgeTemplateId: input.badgeTemplateId,
      assetId,
    });
    const completedAt = new Date().toISOString();
    const updatedGeneration = await updateBadgeTemplateImageGeneration(input.db, {
      tenantId: input.tenantId,
      id: input.generationId,
      status: "succeeded",
      resultImageUri: image.url,
      errorMessage: null,
      completedAt,
    });

    if (updatedGeneration === null) {
      throw new Error(`Badge template image generation ${input.generationId} not found`);
    }

    await createAuditLog(input.db, {
      tenantId: input.tenantId,
      ...(input.requestedByUserId === undefined || input.requestedByUserId === null
        ? {}
        : {
            actorUserId: input.requestedByUserId,
          }),
      action: "badge_template.image_generated",
      targetType: "badge_template",
      targetId: input.badgeTemplateId,
      metadata: {
        generationId: input.generationId,
        imagePath: image.path,
        imageMimeType: generated.mimeType,
        imageSizeBytes: generated.bytes.byteLength,
        provider: generated.provider,
        model: generated.model,
      },
    });

    return updatedGeneration;
  } catch (error: unknown) {
    const detail = error instanceof Error ? error.message : "Unknown badge image generation error";

    await updateBadgeTemplateImageGeneration(input.db, {
      tenantId: input.tenantId,
      id: input.generationId,
      status: "failed",
      errorMessage: detail,
      completedAt: new Date().toISOString(),
    });

    throw error;
  }
};

export const processBadgeTemplateImageGenerationJob = async (input: {
  db: SqlDatabase;
  store: ImmutableCredentialStore;
  env: BadgeTemplateImageGenerationEnv;
  tenantId: string;
  payload: GenerateBadgeTemplateImageQueueJob["payload"];
}): Promise<void> => {
  const existingGeneration = await findBadgeTemplateImageGenerationById(
    input.db,
    input.tenantId,
    input.payload.generationId,
  );

  if (existingGeneration === null) {
    throw new Error(`Badge template image generation ${input.payload.generationId} not found`);
  }

  if (existingGeneration.status === "succeeded") {
    return;
  }

  await updateBadgeTemplateImageGeneration(input.db, {
    tenantId: input.tenantId,
    id: input.payload.generationId,
    status: "processing",
    errorMessage: null,
    completedAt: null,
  });

  try {
    const template = await findBadgeTemplateById(
      input.db,
      input.tenantId,
      input.payload.badgeTemplateId,
    );

    if (template === null) {
      throw new Error(`Badge template ${input.payload.badgeTemplateId} not found`);
    }

    await completeBadgeTemplateImageGeneration({
      db: input.db,
      store: input.store,
      env: input.env,
      tenantId: input.tenantId,
      badgeTemplateId: input.payload.badgeTemplateId,
      generationId: input.payload.generationId,
      promptText: input.payload.promptText,
      requestedByUserId: input.payload.requestedByUserId,
    });
  } catch (error: unknown) {
    const detail = error instanceof Error ? error.message : "Unknown badge image generation error";

    await updateBadgeTemplateImageGeneration(input.db, {
      tenantId: input.tenantId,
      id: input.payload.generationId,
      status: "failed",
      errorMessage: detail,
      completedAt: new Date().toISOString(),
    });

    throw error;
  }
};

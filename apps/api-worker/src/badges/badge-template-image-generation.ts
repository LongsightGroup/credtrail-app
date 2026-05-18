import type { ImmutableCredentialStore } from "@credtrail/core-domain";
import {
  createAuditLog,
  findBadgeTemplateById,
  findBadgeTemplateImageGenerationById,
  updateBadgeTemplateImageGeneration,
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
  enabled: boolean;
  accountId: string;
  gatewayId: string;
  provider: string;
  model: string;
  gatewayAuthToken: string | null;
  providerApiKey: string | null;
}

export interface BadgeTemplateImageGenerationEnv {
  AI_GATEWAY_ENABLED?: string;
  AI_GATEWAY_ACCOUNT_ID?: string;
  AI_GATEWAY_ID?: string;
  AI_GATEWAY_PROVIDER?: string;
  AI_GATEWAY_AUTH_TOKEN?: string;
  AI_GATEWAY_PROVIDER_API_KEY?: string;
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
  const enabled = requiredConfigValue(env.AI_GATEWAY_ENABLED).toLowerCase() === "true";
  const accountId = requiredConfigValue(env.AI_GATEWAY_ACCOUNT_ID);
  const gatewayId = requiredConfigValue(env.AI_GATEWAY_ID);
  const provider = requiredConfigValue(env.AI_GATEWAY_PROVIDER) || "openai";
  const model = requiredConfigValue(env.BADGE_IMAGE_GENERATION_MODEL);
  const gatewayAuthToken = requiredConfigValue(env.AI_GATEWAY_AUTH_TOKEN);
  const providerApiKey = requiredConfigValue(env.AI_GATEWAY_PROVIDER_API_KEY);

  return {
    enabled,
    accountId,
    gatewayId,
    provider,
    model,
    gatewayAuthToken: gatewayAuthToken.length === 0 ? null : gatewayAuthToken,
    providerApiKey: providerApiKey.length === 0 ? null : providerApiKey,
  };
};

export const isBadgeTemplateImageGenerationConfigured = (
  env: BadgeTemplateImageGenerationEnv,
): boolean => {
  const config = badgeTemplateImageGenerationConfigFromEnv(env);
  return (
    config.enabled &&
    config.accountId.length > 0 &&
    config.gatewayId.length > 0 &&
    config.provider.length > 0 &&
    config.model.length > 0
  );
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
    "Create a square Open Badges 3.0 badge image for CredTrail.",
    `Badge title: ${input.template.title}.`,
    description === undefined || description.length === 0
      ? ""
      : `Badge description: ${description}.`,
    `Visual style preset: ${input.stylePreset}.`,
    accentColor === undefined || accentColor.length === 0
      ? ""
      : `Preferred accent color: ${accentColor}.`,
    notes === undefined || notes.length === 0 ? "" : `Admin notes: ${notes}.`,
    "Use clean vector-like geometry, strong contrast, no photo background, no watermark, no signature, and no tiny unreadable text.",
    "Do not use protected LMS logos unless the prompt explicitly includes permission.",
  ]
    .filter((line) => line.length > 0)
    .join("\n");
};

const buildCloudflareAiGatewayUrl = (config: BadgeTemplateImageGenerationConfig): string => {
  return `https://gateway.ai.cloudflare.com/v1/${encodeURIComponent(
    config.accountId,
  )}/${encodeURIComponent(config.gatewayId)}/${encodeURIComponent(config.provider)}/images/generations`;
};

const imageBytesFromGenerationResponse = async (responsePayload: unknown): Promise<Uint8Array> => {
  const payload = asRecord(responsePayload);
  const data = Array.isArray(payload?.data) ? payload.data : [];
  const first = asRecord(data[0]);

  if (first === null) {
    throw new Error("AI image generation response did not include image data");
  }

  if (typeof first.b64_json === "string" && first.b64_json.length > 0) {
    return decodeBase64(first.b64_json);
  }

  if (typeof first.url === "string" && first.url.length > 0) {
    const imageResponse = await fetch(first.url);

    if (!imageResponse.ok) {
      throw new Error(`Unable to fetch generated image URL: HTTP ${String(imageResponse.status)}`);
    }

    return new Uint8Array(await imageResponse.arrayBuffer());
  }

  throw new Error("AI image generation response did not include b64_json or url");
};

export const generateBadgeTemplateImageViaCloudflareGateway = async (input: {
  env: BadgeTemplateImageGenerationEnv;
  promptText: string;
}): Promise<GeneratedBadgeTemplateImage> => {
  const config = badgeTemplateImageGenerationConfigFromEnv(input.env);

  if (!isBadgeTemplateImageGenerationConfigured(input.env)) {
    throw new Error("Badge image generation is not configured");
  }

  const headers = new Headers({
    "content-type": "application/json",
  });

  if (config.providerApiKey !== null) {
    headers.set("authorization", `Bearer ${config.providerApiKey}`);
  }

  if (config.gatewayAuthToken !== null) {
    headers.set("cf-aig-authorization", `Bearer ${config.gatewayAuthToken}`);
  }

  const response = await fetch(buildCloudflareAiGatewayUrl(config), {
    method: "POST",
    headers,
    body: JSON.stringify({
      model: config.model,
      prompt: input.promptText,
      n: 1,
      size: "1024x1024",
      response_format: "b64_json",
    }),
  });

  const responseText = await response.text();
  const responsePayload = responseText.length === 0 ? null : (JSON.parse(responseText) as unknown);

  if (!response.ok) {
    const errorPayload = asRecord(responsePayload);
    const detail =
      typeof errorPayload?.error === "string"
        ? errorPayload.error
        : `AI Gateway image generation failed with HTTP ${String(response.status)}`;
    throw new Error(detail);
  }

  const bytes = await imageBytesFromGenerationResponse(responsePayload);

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
      gatewayProvider: config.provider,
      model: config.model,
      byteSize: bytes.byteLength,
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

    const generated = await generateBadgeTemplateImageViaCloudflareGateway({
      env: input.env,
      promptText: input.payload.promptText,
    });
    const assetId = crypto.randomUUID();

    await storeBadgeTemplateImage(input.store, {
      tenantId: input.tenantId,
      badgeTemplateId: input.payload.badgeTemplateId,
      assetId,
      mimeType: generated.mimeType,
      bytes: generated.bytes,
      originalFilename: null,
    });

    const image = assetUrlForPlatform({
      platformDomain: input.env.PLATFORM_DOMAIN,
      tenantId: input.tenantId,
      badgeTemplateId: input.payload.badgeTemplateId,
      assetId,
    });
    const completedAt = new Date().toISOString();

    await updateBadgeTemplateImageGeneration(input.db, {
      tenantId: input.tenantId,
      id: input.payload.generationId,
      status: "succeeded",
      resultImageUri: image.url,
      errorMessage: null,
      completedAt,
    });

    await createAuditLog(input.db, {
      tenantId: input.tenantId,
      ...(input.payload.requestedByUserId === undefined
        ? {}
        : {
            actorUserId: input.payload.requestedByUserId,
          }),
      action: "badge_template.image_generated",
      targetType: "badge_template",
      targetId: input.payload.badgeTemplateId,
      metadata: {
        generationId: input.payload.generationId,
        imagePath: image.path,
        imageMimeType: generated.mimeType,
        imageSizeBytes: generated.bytes.byteLength,
        provider: generated.provider,
        model: generated.model,
      },
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

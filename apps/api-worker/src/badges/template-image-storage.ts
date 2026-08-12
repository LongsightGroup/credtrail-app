import type { ImmutableCredentialStore } from "@credtrail/core-domain";
import { managedBadgeTemplateImagePath } from "@credtrail/validation";

export const BADGE_TEMPLATE_IMAGE_MAX_BYTES = 2 * 1024 * 1024;
export const BADGE_TEMPLATE_IMAGE_MAX_FILENAME_CHARACTERS = 255;
const BADGE_TEMPLATE_IMAGE_MAX_BASE64_CHARACTERS =
  Math.ceil(BADGE_TEMPLATE_IMAGE_MAX_BYTES / 3) * 4;
const BADGE_TEMPLATE_IMAGE_MAX_SERIALIZED_BYTES =
  BADGE_TEMPLATE_IMAGE_MAX_BASE64_CHARACTERS + 4_096;
const BADGE_TEMPLATE_IMAGE_CACHE_CONTROL = "public, max-age=31536000, immutable";
const BADGE_TEMPLATE_IMAGE_ARTIFACT_TYPE = "badge-template-image-v1";

export const BADGE_TEMPLATE_IMAGE_ALLOWED_MIME_TYPES = [
  "image/png",
  "image/jpeg",
  "image/webp",
] as const;

export type BadgeTemplateImageMimeType = (typeof BADGE_TEMPLATE_IMAGE_ALLOWED_MIME_TYPES)[number];

interface StoredBadgeTemplateImageObject {
  version: 1;
  mimeType: BadgeTemplateImageMimeType;
  byteSize: number;
  base64Data: string;
  uploadedAt: string;
  originalFilename: string | null;
}

interface BadgeTemplateImageObjectIds {
  tenantId: string;
  badgeTemplateId: string;
  assetId: string;
}

interface StoreBadgeTemplateImageInput extends BadgeTemplateImageObjectIds {
  mimeType: BadgeTemplateImageMimeType;
  bytes: Uint8Array;
  originalFilename: string | null;
}

export interface StoredBadgeTemplateImage {
  key: string;
  uploadedAt: string;
}

export interface LoadedBadgeTemplateImage {
  mimeType: BadgeTemplateImageMimeType;
  byteSize: number;
  bytes: Uint8Array;
  uploadedAt: string;
}

export type ReadBadgeTemplateImageResult =
  | {
      readonly status: "found";
      readonly image: LoadedBadgeTemplateImage;
    }
  | {
      readonly status: "missing";
    }
  | {
      readonly status: "invalid";
      readonly reason:
        | "invalid_json"
        | "invalid_payload"
        | "payload_too_large"
        | "invalid_base64"
        | "byte_size_mismatch"
        | "mime_type_mismatch";
    };

const encodePathSegment = (value: string): string => {
  const trimmed = value.trim();

  if (trimmed.length === 0) {
    throw new Error("Object storage path segments must not be empty");
  }

  return encodeURIComponent(trimmed);
};

export const badgeTemplateImageObjectKey = (ids: BadgeTemplateImageObjectIds): string => {
  return `tenants/${encodePathSegment(ids.tenantId)}/badge-template-images/${encodePathSegment(
    ids.badgeTemplateId,
  )}/${encodePathSegment(ids.assetId)}.json`;
};

/** Builds the public route path for one stored immutable badge image. */
export const badgeTemplateImagePublicPath = (ids: BadgeTemplateImageObjectIds): string => {
  return managedBadgeTemplateImagePath(ids);
};

const asciiSlice = (bytes: Uint8Array, start: number, length: number): string => {
  if (start < 0 || length < 0 || start + length > bytes.length) {
    return "";
  }

  let output = "";

  for (let index = start; index < start + length; index += 1) {
    output += String.fromCharCode(bytes[index] ?? 0);
  }

  return output;
};

const bytesToBase64 = (bytes: Uint8Array): string => {
  let binary = "";

  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }

  return btoa(binary);
};

const base64ToBytes = (value: string): Uint8Array => {
  const binary = atob(value);
  const bytes = new Uint8Array(binary.length);

  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }

  return bytes;
};

const isPng = (bytes: Uint8Array): boolean => {
  return (
    bytes.length >= 8 &&
    bytes[0] === 0x89 &&
    bytes[1] === 0x50 &&
    bytes[2] === 0x4e &&
    bytes[3] === 0x47 &&
    bytes[4] === 0x0d &&
    bytes[5] === 0x0a &&
    bytes[6] === 0x1a &&
    bytes[7] === 0x0a
  );
};

const isJpeg = (bytes: Uint8Array): boolean => {
  return bytes.length >= 3 && bytes[0] === 0xff && bytes[1] === 0xd8 && bytes[2] === 0xff;
};

const isWebp = (bytes: Uint8Array): boolean => {
  return (
    bytes.length >= 12 && asciiSlice(bytes, 0, 4) === "RIFF" && asciiSlice(bytes, 8, 4) === "WEBP"
  );
};

export const badgeTemplateImageMimeTypeFromBytes = (
  bytes: Uint8Array,
): BadgeTemplateImageMimeType | null => {
  if (isPng(bytes)) {
    return "image/png";
  }

  if (isJpeg(bytes)) {
    return "image/jpeg";
  }

  if (isWebp(bytes)) {
    return "image/webp";
  }

  return null;
};

export const badgeTemplateImageMimeTypeFromValue = (
  value: string,
): BadgeTemplateImageMimeType | null => {
  const normalized = value.trim().toLowerCase();

  switch (normalized) {
    case "image/png":
      return "image/png";
    case "image/jpeg":
      return "image/jpeg";
    case "image/webp":
      return "image/webp";
    default:
      return null;
  }
};

type ParseStoredBadgeTemplateImageObjectResult =
  | {
      readonly status: "parsed";
      readonly payload: StoredBadgeTemplateImageObject;
    }
  | {
      readonly status: "invalid";
      readonly reason: "invalid_payload" | "payload_too_large";
    };

const parseStoredBadgeTemplateImageObject = (
  value: unknown,
): ParseStoredBadgeTemplateImageObjectResult => {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    return { status: "invalid", reason: "invalid_payload" };
  }

  const candidate = value as Record<string, unknown>;

  if (candidate.version !== 1) {
    return { status: "invalid", reason: "invalid_payload" };
  }

  if (
    candidate.mimeType !== "image/png" &&
    candidate.mimeType !== "image/jpeg" &&
    candidate.mimeType !== "image/webp"
  ) {
    return { status: "invalid", reason: "invalid_payload" };
  }

  if (
    typeof candidate.base64Data !== "string" ||
    typeof candidate.byteSize !== "number" ||
    !Number.isInteger(candidate.byteSize) ||
    candidate.byteSize < 1 ||
    typeof candidate.uploadedAt !== "string"
  ) {
    return { status: "invalid", reason: "invalid_payload" };
  }

  if (
    candidate.byteSize > BADGE_TEMPLATE_IMAGE_MAX_BYTES ||
    candidate.base64Data.length > BADGE_TEMPLATE_IMAGE_MAX_BASE64_CHARACTERS
  ) {
    return { status: "invalid", reason: "payload_too_large" };
  }

  if (candidate.originalFilename !== null && typeof candidate.originalFilename !== "string") {
    return { status: "invalid", reason: "invalid_payload" };
  }

  return {
    status: "parsed",
    payload: {
      version: 1,
      mimeType: candidate.mimeType,
      base64Data: candidate.base64Data,
      byteSize: candidate.byteSize,
      uploadedAt: candidate.uploadedAt,
      originalFilename: candidate.originalFilename,
    },
  };
};

export const storeBadgeTemplateImage = async (
  store: ImmutableCredentialStore,
  input: StoreBadgeTemplateImageInput,
): Promise<StoredBadgeTemplateImage> => {
  if (input.bytes.byteLength < 1 || input.bytes.byteLength > BADGE_TEMPLATE_IMAGE_MAX_BYTES) {
    throw new Error(
      `Badge template image must contain between 1 and ${String(BADGE_TEMPLATE_IMAGE_MAX_BYTES)} bytes`,
    );
  }

  if (
    input.originalFilename !== null &&
    input.originalFilename.length > BADGE_TEMPLATE_IMAGE_MAX_FILENAME_CHARACTERS
  ) {
    throw new Error(
      `Badge template image filename must not exceed ${String(BADGE_TEMPLATE_IMAGE_MAX_FILENAME_CHARACTERS)} characters`,
    );
  }

  const key = badgeTemplateImageObjectKey(input);
  const payload: StoredBadgeTemplateImageObject = {
    version: 1,
    mimeType: input.mimeType,
    byteSize: input.bytes.byteLength,
    base64Data: bytesToBase64(input.bytes),
    uploadedAt: new Date().toISOString(),
    originalFilename: input.originalFilename,
  };
  const serialized = JSON.stringify(payload);

  if (new TextEncoder().encode(serialized).byteLength > BADGE_TEMPLATE_IMAGE_MAX_SERIALIZED_BYTES) {
    throw new Error("Badge template image payload exceeds the stored-object size limit");
  }

  const putResult = await store.put(key, serialized, {
    httpMetadata: {
      contentType: "application/json; charset=utf-8",
      cacheControl: BADGE_TEMPLATE_IMAGE_CACHE_CONTROL,
    },
    customMetadata: {
      tenantId: input.tenantId,
      badgeTemplateId: input.badgeTemplateId,
      assetId: input.assetId,
      artifactType: BADGE_TEMPLATE_IMAGE_ARTIFACT_TYPE,
      mimeType: input.mimeType,
    },
  });

  if (putResult === null) {
    throw new Error(`Badge template image already exists for key "${key}"`);
  }

  return {
    key,
    uploadedAt: payload.uploadedAt,
  };
};

/** Reads one image object without turning corrupt stored data into an untyped rejection. */
export const readBadgeTemplateImage = async (
  store: ImmutableCredentialStore,
  ids: BadgeTemplateImageObjectIds,
): Promise<ReadBadgeTemplateImageResult> => {
  const key = badgeTemplateImageObjectKey(ids);
  const storedObject = await store.get(key);

  if (storedObject === null) {
    return { status: "missing" };
  }

  if (storedObject.size > BADGE_TEMPLATE_IMAGE_MAX_SERIALIZED_BYTES) {
    return { status: "invalid", reason: "payload_too_large" };
  }

  const serialized = await storedObject.text();

  if (new TextEncoder().encode(serialized).byteLength > BADGE_TEMPLATE_IMAGE_MAX_SERIALIZED_BYTES) {
    return { status: "invalid", reason: "payload_too_large" };
  }

  let parsed: unknown;

  try {
    parsed = JSON.parse(serialized) as unknown;
  } catch {
    return { status: "invalid", reason: "invalid_json" };
  }

  const parsedPayload = parseStoredBadgeTemplateImageObject(parsed);

  if (parsedPayload.status === "invalid") {
    return parsedPayload;
  }

  const payload = parsedPayload.payload;
  let bytes: Uint8Array;

  try {
    bytes = base64ToBytes(payload.base64Data);
  } catch {
    return { status: "invalid", reason: "invalid_base64" };
  }

  if (bytes.byteLength !== payload.byteSize) {
    return { status: "invalid", reason: "byte_size_mismatch" };
  }

  const detectedMimeType = badgeTemplateImageMimeTypeFromBytes(bytes);

  if (detectedMimeType === null || detectedMimeType !== payload.mimeType) {
    return { status: "invalid", reason: "mime_type_mismatch" };
  }

  return {
    status: "found",
    image: {
      mimeType: payload.mimeType,
      byteSize: payload.byteSize,
      bytes,
      uploadedAt: payload.uploadedAt,
    },
  };
};

/** Loads an image for serving, treating corrupt persisted data as an invariant violation. */
export const loadBadgeTemplateImage = async (
  store: ImmutableCredentialStore,
  ids: BadgeTemplateImageObjectIds,
): Promise<LoadedBadgeTemplateImage | null> => {
  const result = await readBadgeTemplateImage(store, ids);

  if (result.status === "missing") {
    return null;
  }

  if (result.status === "invalid") {
    throw new Error(
      `Stored badge template image is invalid for key "${badgeTemplateImageObjectKey(ids)}" (${result.reason})`,
    );
  }

  return result.image;
};

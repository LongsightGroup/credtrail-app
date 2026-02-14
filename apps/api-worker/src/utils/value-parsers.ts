import type { JsonObject } from '@credtrail/core-domain';

export const asJsonObject = (value: unknown): JsonObject | null => {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    return null;
  }

  return value as JsonObject;
};

export const asString = (value: unknown): string | null => {
  if (typeof value !== 'string') {
    return null;
  }

  return value;
};

export const asNonEmptyString = (value: unknown): string | null => {
  const candidate = asString(value);

  if (candidate === null) {
    return null;
  }

  const trimmed = candidate.trim();
  return trimmed.length === 0 ? null : trimmed;
};

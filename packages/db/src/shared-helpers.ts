export const createPrefixedId = (prefix: string): string => {
  return `${prefix}_${crypto.randomUUID()}`;
};

export const addSecondsToIso = (fromIso: string, seconds: number): string => {
  const fromMs = Date.parse(fromIso);

  if (!Number.isFinite(fromMs)) {
    throw new Error("Invalid ISO timestamp");
  }

  return new Date(fromMs + seconds * 1000).toISOString();
};

export const addDaysToIso = (fromIso: string, days: number): string => {
  return addSecondsToIso(fromIso, days * 24 * 60 * 60);
};

export const addMonthsToIso = (fromIso: string, months: number): string => {
  const fromMs = assertValidIsoTimestamp(fromIso, "fromIso");
  const date = new Date(fromMs);
  date.setUTCMonth(date.getUTCMonth() + months);
  return date.toISOString();
};

export const parseOptionalDateTimeInputToIso = (value: string | undefined): string | undefined => {
  if (value === undefined) {
    return undefined;
  }

  const trimmed = value.trim();

  if (trimmed.length === 0) {
    return undefined;
  }

  const parsedMs = Date.parse(trimmed);

  if (!Number.isFinite(parsedMs)) {
    return undefined;
  }

  return new Date(parsedMs).toISOString();
};

export const assertValidIsoTimestamp = (timestamp: string, fieldName: string): number => {
  const parsedMs = Date.parse(timestamp);

  if (!Number.isFinite(parsedMs)) {
    throw new Error(`${fieldName} must be a valid ISO timestamp`);
  }

  return parsedMs;
};

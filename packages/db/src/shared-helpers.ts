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

export const assertValidIsoTimestamp = (timestamp: string, fieldName: string): number => {
  const parsedMs = Date.parse(timestamp);

  if (!Number.isFinite(parsedMs)) {
    throw new Error(`${fieldName} must be a valid ISO timestamp`);
  }

  return parsedMs;
};

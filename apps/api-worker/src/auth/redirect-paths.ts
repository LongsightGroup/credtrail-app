export const isSafeRedirectPath = (path: string | undefined | null): path is string => {
  const trimmed = path?.trim() ?? "";

  return trimmed.startsWith("/") && !trimmed.startsWith("//");
};

export const normalizeSafeRedirectPath = (
  path: string | undefined | null,
  fallbackPath: string,
): string => {
  const trimmed = path?.trim() ?? "";

  return isSafeRedirectPath(trimmed) ? trimmed : fallbackPath;
};

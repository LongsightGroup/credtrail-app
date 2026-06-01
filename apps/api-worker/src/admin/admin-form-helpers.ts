export const deriveSlugFromDisplayName = (value: string): string => {
  return value
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .replace(/-{2,}/g, "-");
};

export const readOptionalFormField = (formData: FormData, name: string): string | undefined => {
  const raw = formData.get(name);

  if (typeof raw !== "string") {
    return undefined;
  }

  const trimmed = raw.trim();

  return trimmed.length > 0 ? trimmed : undefined;
};

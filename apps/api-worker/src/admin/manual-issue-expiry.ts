/** YYYY-MM-DD from the form -> ISO end of that day (UTC); null when it is not a real calendar date. */
export const expiryTimestampFromFormDate = (value: string): string | null => {
  const trimmed = value.trim();
  if (!/^\d{4}-\d{2}-\d{2}$/u.test(trimmed)) return null;
  const timestamp = Date.parse(`${trimmed}T23:59:59.000Z`);
  if (Number.isNaN(timestamp) || !new Date(timestamp).toISOString().startsWith(trimmed))
    return null;
  return new Date(timestamp).toISOString();
};

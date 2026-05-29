export const ADMIN_STATUS_PILL_BASE_CLASS = "ct-admin__status-pill";

export const adminStatusPillClass = (tone: string | null | undefined): string => {
  const normalizedTone = tone?.trim();

  return normalizedTone === undefined || normalizedTone.length === 0
    ? ADMIN_STATUS_PILL_BASE_CLASS
    : `${ADMIN_STATUS_PILL_BASE_CLASS} ${ADMIN_STATUS_PILL_BASE_CLASS}--${normalizedTone}`;
};

/** Injected into feature-local admin JavaScript asset strings. */
export const ADMIN_STATUS_PILL_CLASS_HELPER_JS = `
  const adminStatusPillClass = (tone) => {
    const normalizedTone = typeof tone === 'string' ? tone.trim() : '';
    return normalizedTone.length === 0
      ? 'ct-admin__status-pill'
      : 'ct-admin__status-pill ct-admin__status-pill--' + normalizedTone;
  };
`;

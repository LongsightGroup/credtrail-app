export const ADMIN_STATUS_PILL_BASE_CLASS = "ct-admin__status-pill";

export const adminStatusPillClass = (tone: string | null | undefined): string => {
  const normalizedTone = tone?.trim();

  return normalizedTone === undefined || normalizedTone.length === 0
    ? ADMIN_STATUS_PILL_BASE_CLASS
    : `${ADMIN_STATUS_PILL_BASE_CLASS} ${ADMIN_STATUS_PILL_BASE_CLASS}--${normalizedTone}`;
};

/** Browser helper source generated into page assets at build time. */
export const renderAdminStatusPillClassBrowserHelper = (): string => {
  const baseClass = ADMIN_STATUS_PILL_BASE_CLASS;

  return `var adminStatusPillClass = function adminStatusPillClass(tone) {
  const normalizedTone = typeof tone === "string" ? tone.trim() : "";
  return normalizedTone.length === 0
    ? "${baseClass}"
    : "${baseClass} ${baseClass}--" + normalizedTone;
};
`;
};

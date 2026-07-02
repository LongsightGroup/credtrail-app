export const ADMIN_STATUS_PILL_BASE_CLASS = "ct-admin__status-pill";

export const adminStatusPillClass = (tone: string | null | undefined): string => {
  const normalizedTone = tone?.trim();

  return normalizedTone === undefined || normalizedTone.length === 0
    ? ADMIN_STATUS_PILL_BASE_CLASS
    : `${ADMIN_STATUS_PILL_BASE_CLASS} ${ADMIN_STATUS_PILL_BASE_CLASS}--${normalizedTone}`;
};

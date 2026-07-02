const adminStatusPillClass = (tone) => {
  const normalizedTone = typeof tone === "string" ? tone.trim() : "";
  return normalizedTone.length === 0
    ? "ct-admin__status-pill"
    : "ct-admin__status-pill ct-admin__status-pill--" + normalizedTone;
};

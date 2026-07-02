const badgeTemplateShowcasePath = (badgeTemplateId) => {
  if (showcasePath.length === 0) {
    return "";
  }

  const url = new URL(showcasePath, window.location.origin);
  url.searchParams.set("badgeTemplateId", badgeTemplateId);
  return url.pathname + url.search;
};
const badgeTemplateCriteriaRegistryPath = (badgeTemplateId) => {
  if (showcasePath.length === 0) {
    return "";
  }

  const url = new URL(showcasePath, window.location.origin);
  url.pathname = url.pathname.replace(/\/$/, "") + "/criteria";
  url.searchParams.set("badgeTemplateId", badgeTemplateId);
  return url.pathname + url.search;
};
const updateBadgeTemplateEditorActivitySummary = (badgeTemplateId, revisionCount) => {
  if (!(badgeTemplateEditorActivitySummary instanceof HTMLElement)) {
    return;
  }

  const record = badgeTemplateRecordsById.get(badgeTemplateId);
  const updatedAt =
    record && typeof record.updatedAt === "string" && record.updatedAt.length > 0
      ? formatTimestamp(record.updatedAt)
      : "n/a";
  const revisionLabel =
    revisionCount === 1 ? "1 image version" : String(revisionCount) + " image versions";
  badgeTemplateEditorActivitySummary.textContent =
    revisionLabel + ". Last updated " + updatedAt + ".";
};
const updateBadgeTemplateImageRevisionHint = (badgeTemplateId, revisionCount) => {
  if (typeof badgeTemplateId !== "string" || badgeTemplateId.length === 0) {
    return;
  }

  if (badgeTemplateEditorHistoryLink instanceof HTMLElement) {
    badgeTemplateEditorHistoryLink.dataset.templateHistoryImageRevisionCount =
      String(revisionCount);
  }

  updateBadgeTemplateEditorActivitySummary(badgeTemplateId, revisionCount);
};
const readBadgeTemplateImageRevisionCount = (badgeTemplateId) => {
  if (badgeTemplateEditorHistoryLink instanceof HTMLElement) {
    const parsed = Number.parseInt(
      badgeTemplateEditorHistoryLink.dataset.templateHistoryImageRevisionCount || "0",
      10,
    );

    if (Number.isFinite(parsed)) {
      return Math.max(0, Math.trunc(parsed));
    }
  }

  return 0;
};
const syncBadgeTemplateEditorLinks = (badgeTemplateId) => {
  const showcasePath = badgeTemplateShowcasePath(badgeTemplateId);
  const criteriaPath = badgeTemplateCriteriaRegistryPath(badgeTemplateId);

  if (badgeTemplateEditorPublicLink instanceof HTMLAnchorElement && showcasePath.length > 0) {
    badgeTemplateEditorPublicLink.href = showcasePath;
  }

  if (badgeTemplateEditorCriteriaLink instanceof HTMLAnchorElement && criteriaPath.length > 0) {
    badgeTemplateEditorCriteriaLink.href = criteriaPath;
  }

  updateBadgeTemplateEditorActivitySummary(
    badgeTemplateId,
    readBadgeTemplateImageRevisionCount(badgeTemplateId),
  );
};
const updateBadgeTemplateEditorDetails = (badgeTemplateId, template) => {
  if (typeof badgeTemplateId !== "string" || badgeTemplateId.length === 0) {
    return;
  }

  if (template && typeof template.id === "string") {
    syncBadgeTemplateEditorLinks(template.id);
  }
};

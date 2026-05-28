export const INSTITUTION_ADMIN_BADGE_TEMPLATE_EDITOR_RECORDS_JS = `
  const setBadgeTemplateHistoryTimelineHtml = (html) => {
    if (!(badgeTemplateHistoryAuditList instanceof HTMLElement)) {
      return;
    }

    badgeTemplateHistoryAuditList.innerHTML =
      typeof html === 'string' && html.length > 0
        ? html
        : '<p class="ct-admin__empty">No edit history is recorded for this badge template yet.</p>';
  };
  const parseBadgeTemplateHistoryImageRevisionCount = (response) => {
    const countHeader = response.headers.get('X-CredTrail-Badge-Template-Image-Revision-Count');
    const parsed = countHeader === null ? 0 : Number.parseInt(countHeader, 10);

    return Number.isFinite(parsed) ? Math.max(0, Math.trunc(parsed)) : 0;
  };
  const parseBadgeTemplateHistoryEventCount = (response) => {
    const countHeader = response.headers.get('X-CredTrail-Badge-Template-History-Event-Count');
    const parsed = countHeader === null ? 0 : Number.parseInt(countHeader, 10);

    return Number.isFinite(parsed) ? Math.max(0, Math.trunc(parsed)) : 0;
  };
  const badgeTemplateShowcasePath = (badgeTemplateId) => {
    if (showcasePath.length === 0) {
      return '';
    }

    const url = new URL(showcasePath, window.location.origin);
    url.searchParams.set('badgeTemplateId', badgeTemplateId);
    return url.pathname + url.search;
  };
  const badgeTemplateCriteriaRegistryPath = (badgeTemplateId) => {
    if (showcasePath.length === 0) {
      return '';
    }

    const url = new URL(showcasePath, window.location.origin);
    url.pathname = url.pathname.replace(/\\/$/, '') + '/criteria';
    url.searchParams.set('badgeTemplateId', badgeTemplateId);
    return url.pathname + url.search;
  };
  const updateBadgeTemplateEditorActivitySummary = (badgeTemplateId, revisionCount) => {
    if (!(badgeTemplateEditorActivitySummary instanceof HTMLElement)) {
      return;
    }

    const record = badgeTemplateRecordsById.get(badgeTemplateId);
    const updatedAt =
      record && typeof record.updatedAt === 'string' && record.updatedAt.length > 0
        ? formatTimestamp(record.updatedAt)
        : 'n/a';
    const revisionLabel =
      revisionCount === 1 ? '1 image version' : String(revisionCount) + ' image versions';
    badgeTemplateEditorActivitySummary.textContent =
      revisionLabel + '. Last updated ' + updatedAt + '.';
  };
  const updateBadgeTemplateImageRevisionHint = (badgeTemplateId, revisionCount) => {
    if (typeof badgeTemplateId !== 'string' || badgeTemplateId.length === 0) {
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
        badgeTemplateEditorHistoryLink.dataset.templateHistoryImageRevisionCount || '0',
        10,
      );

      if (Number.isFinite(parsed)) {
        return Math.max(0, Math.trunc(parsed));
      }
    }

    return 0;
  };
  const bumpBadgeTemplateImageRevisionHint = (badgeTemplateId) => {
    updateBadgeTemplateImageRevisionHint(
      badgeTemplateId,
      readBadgeTemplateImageRevisionCount(badgeTemplateId) + 1,
    );
  };
  const syncBadgeTemplateEditorLinks = (badgeTemplateId) => {
    const record = badgeTemplateRecordsById.get(badgeTemplateId);

    if (record === undefined) {
      return;
    }

    const publicPath = badgeTemplateShowcasePath(badgeTemplateId);
    const criteriaPath = badgeTemplateCriteriaRegistryPath(badgeTemplateId);

    if (badgeTemplateEditorPublicLink instanceof HTMLAnchorElement && publicPath.length > 0) {
      badgeTemplateEditorPublicLink.href = publicPath;
    }

    if (badgeTemplateEditorCriteriaLink instanceof HTMLAnchorElement && criteriaPath.length > 0) {
      badgeTemplateEditorCriteriaLink.href = criteriaPath;
    }

    if (badgeTemplateEditorHistoryLink instanceof HTMLAnchorElement) {
      badgeTemplateEditorHistoryLink.dataset.templateHistoryTemplateId = badgeTemplateId;
      badgeTemplateEditorHistoryLink.dataset.templateHistoryTemplateTitle =
        typeof record.title === 'string' ? record.title : '';
    }

    updateBadgeTemplateEditorActivitySummary(
      badgeTemplateId,
      readBadgeTemplateImageRevisionCount(badgeTemplateId),
    );
  };
  const updateBadgeTemplatePreviewImage = (badgeTemplateId, imageUri) => {
    if (typeof badgeTemplateId !== 'string' || badgeTemplateId.length === 0) {
      return;
    }

    const record = badgeTemplateRecordsById.get(badgeTemplateId);
    const title =
      record && typeof record.title === 'string' && record.title.length > 0
        ? record.title
        : 'Badge template';

    const imageLinkHtml =
      '<a href="' +
      escapeHtml(imageUri) +
      '" target="_blank" rel="noopener noreferrer" aria-label="Open full size image for ' +
      escapeHtml(title) +
      '">' +
      '<img src="' +
      escapeHtml(imageUri) +
      '" alt="' +
      escapeHtml(title) +
      ' artwork">' +
      '</a>';
    const previewFrame = document.getElementById('badge-template-editor-preview-frame');

    if (previewFrame instanceof HTMLElement) {
      previewFrame.innerHTML =
        typeof imageUri !== 'string' || imageUri.length === 0
          ? '<span class="ct-admin__template-editor-preview-empty">No artwork</span>'
          : imageLinkHtml;
    }

    const currentArtwork = document.getElementById('badge-template-editor-current-artwork');

    if (currentArtwork instanceof HTMLElement) {
      const detail =
        typeof imageUri !== 'string' || imageUri.length === 0
          ? 'Add artwork before using this template in rules.'
          : 'This image appears on issued badges and public badge pages.';
      currentArtwork.innerHTML =
        (typeof imageUri !== 'string' || imageUri.length === 0
          ? '<span class="ct-admin__template-editor-current-artwork-empty">No artwork</span>'
          : imageLinkHtml) +
        '<div><strong>Current artwork</strong><p>' +
        escapeHtml(detail) +
        '</p></div>';
    }
  };
  const updateBadgeTemplateEditorDetails = (badgeTemplateId, template) => {
    if (typeof badgeTemplateId !== 'string' || badgeTemplateId.length === 0) {
      return;
    }

    if (
      activeBadgeTemplateHistoryId === badgeTemplateId &&
      template &&
      typeof template.title === 'string' &&
      badgeTemplateHistoryDialogSubtitle instanceof HTMLElement
    ) {
      activeBadgeTemplateHistoryTitle = template.title;
      badgeTemplateHistoryDialogSubtitle.textContent = template.title;
    }

    if (template && typeof template.id === 'string') {
      syncBadgeTemplateEditorLinks(template.id);
    }
  };
`;

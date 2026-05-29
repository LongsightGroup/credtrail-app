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
    const hasImage = typeof imageUri === 'string' && imageUri.length > 0;

    if (record && typeof record === 'object') {
      record.imageUri = hasImage ? imageUri : null;
    }

    const imageLinkHtml = hasImage
      ? '<a href="' +
        escapeHtml(imageUri) +
        '" target="_blank" rel="noopener noreferrer" aria-label="Open full size image for ' +
        escapeHtml(title) +
        '">' +
        '<img src="' +
        escapeHtml(imageUri) +
        '" alt="' +
        escapeHtml(title) +
        ' artwork">' +
        '</a>'
      : '';
    const previewFrame = document.getElementById('badge-template-editor-preview-frame');

    if (previewFrame instanceof HTMLElement) {
      previewFrame.innerHTML =
        hasImage
          ? imageLinkHtml
          : '<span class="ct-admin__template-editor-preview-empty">No artwork</span>';
    }

    const currentArtworkMedia = document.getElementById(
      'badge-template-editor-current-artwork-media',
    );

    if (currentArtworkMedia instanceof HTMLElement) {
      currentArtworkMedia.innerHTML = hasImage
        ? imageLinkHtml
        : '<span class="ct-admin__template-editor-current-artwork-empty">No artwork</span>';
    }

    const currentArtworkStatus = document.getElementById(
      'badge-template-editor-current-artwork-status',
    );

    if (currentArtworkStatus instanceof HTMLElement) {
      currentArtworkStatus.className =
        'ct-admin__status-pill ct-admin__status-pill--' + (hasImage ? 'active' : 'warning');
      currentArtworkStatus.textContent = hasImage ? 'Approved image' : 'No approved image';
    }

    const currentArtworkDetail = document.getElementById(
      'badge-template-editor-current-artwork-detail',
    );

    if (currentArtworkDetail instanceof HTMLElement) {
      currentArtworkDetail.textContent = hasImage
        ? 'Approved artwork is set. This template is ready for rules.'
        : 'Add an approved image before using this template in rules.';
    }

    const readyStatus = document.getElementById('badge-template-editor-ready-status');

    if (readyStatus instanceof HTMLElement) {
      const isArchived = record && record.isArchived === true;
      const readyTone = isArchived ? 'revoked' : hasImage ? 'active' : 'warning';
      readyStatus.className = 'ct-admin__status-pill ct-admin__status-pill--' + readyTone;
      readyStatus.textContent = isArchived
        ? 'Archived'
        : hasImage
          ? 'Ready for rules'
          : 'Needs image';
    }

    const artworkActions = document.getElementById('badge-template-editor-artwork-actions');

    if (artworkActions instanceof HTMLDetailsElement) {
      artworkActions.open = !hasImage;
    }

    const artworkActionsTitle = document.getElementById(
      'badge-template-editor-artwork-actions-title',
    );

    if (artworkActionsTitle instanceof HTMLElement) {
      artworkActionsTitle.textContent = hasImage ? 'Replace artwork' : 'Add artwork';
    }

    const artworkActionsDetail = document.getElementById(
      'badge-template-editor-artwork-actions-detail',
    );

    if (artworkActionsDetail instanceof HTMLElement) {
      artworkActionsDetail.textContent = hasImage
        ? 'Upload a new image to replace the current artwork.'
        : 'Upload an approved image or generate a draft to review.';
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

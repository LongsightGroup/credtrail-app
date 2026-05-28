export const INSTITUTION_ADMIN_BADGE_TEMPLATE_HISTORY_CORE_JS = `
  let activeBadgeTemplateHistoryId = '';
  let activeBadgeTemplateHistoryTitle = '';
  const loadBadgeTemplateHistory = async (badgeTemplateId) => {
    if (!(badgeTemplateHistoryStatus instanceof HTMLElement)) {
      return false;
    }

    setStatus(badgeTemplateHistoryStatus, 'Loading template history...', false);

    try {
      const [historyResponse, revisionsResponse] = await Promise.all([
        fetch(
          badgeTemplateApiPathPrefix +
            '/' +
            encodeURIComponent(badgeTemplateId) +
            '/history-timeline?limit=100',
          {
            headers: {
              accept: 'text/html',
            },
          },
        ),
        fetch(
          badgeTemplateApiPathPrefix +
            '/' +
            encodeURIComponent(badgeTemplateId) +
            '/image-revisions',
        ),
      ]);
      const [historyHtml, revisionsPayload] = await Promise.all([
        historyResponse.text(),
        parseJsonBody(revisionsResponse),
      ]);

      if (!historyResponse.ok) {
        let historyPayload = null;
        try {
          historyPayload = JSON.parse(historyHtml);
        } catch {
          historyPayload = null;
        }
        setStatus(badgeTemplateHistoryStatus, errorDetailFromPayload(historyPayload), true);
        return false;
      }

      const imageRevisionCount = parseBadgeTemplateHistoryImageRevisionCount(historyResponse);
      const timelineEventCount = parseBadgeTemplateHistoryEventCount(historyResponse);

      setBadgeTemplateHistoryTimelineHtml(historyHtml);
      updateBadgeTemplateImageRevisionHint(badgeTemplateId, imageRevisionCount);

      if (badgeTemplateImageHistorySection instanceof HTMLDetailsElement) {
        if (imageRevisionCount > 0) {
          badgeTemplateImageHistorySection.hidden = false;
        } else {
          badgeTemplateImageHistorySection.hidden = true;
          badgeTemplateImageHistorySection.open = false;
        }
      }

      if (badgeTemplateImageRevisionList instanceof HTMLElement) {
        badgeTemplateImageRevisionList.textContent = '';
      }

      if (revisionsResponse.ok) {
        const revisions =
          revisionsPayload && Array.isArray(revisionsPayload.revisions)
            ? revisionsPayload.revisions
            : [];

        if (revisions.length > 0) {
          if (badgeTemplateImageHistorySection instanceof HTMLDetailsElement) {
            badgeTemplateImageHistorySection.hidden = false;
          }

          renderBadgeTemplateImageRevisions(badgeTemplateId, revisions);
        }
      }

      const restoredTemplate =
        revisionsPayload &&
        revisionsPayload.template &&
        typeof revisionsPayload.template === 'object'
          ? revisionsPayload.template
          : null;
      const restoredImageUri =
        restoredTemplate && typeof restoredTemplate.imageUri === 'string'
          ? restoredTemplate.imageUri
          : null;

      if (restoredImageUri !== null) {
        updateBadgeTemplatePreviewImage(badgeTemplateId, restoredImageUri);
      }

      const eventLabel = timelineEventCount === 1 ? 'event' : 'events';
      setStatus(
        badgeTemplateHistoryStatus,
        String(timelineEventCount) + ' history ' + eventLabel + ' loaded.',
        false,
        'success',
      );
      return true;
    } catch {
      setStatus(
        badgeTemplateHistoryStatus,
        'Unable to load template history from this browser session.',
        true,
      );
      return false;
    }
  };
  const openBadgeTemplateHistory = async (badgeTemplateId, badgeTemplateTitle) => {
    if (
      !(badgeTemplateHistoryDialog instanceof HTMLDialogElement) ||
      !(badgeTemplateHistoryStatus instanceof HTMLElement)
    ) {
      return;
    }

    activeBadgeTemplateHistoryId = badgeTemplateId;
    activeBadgeTemplateHistoryTitle = badgeTemplateTitle;

    if (badgeTemplateHistoryDialogTitle instanceof HTMLElement) {
      badgeTemplateHistoryDialogTitle.textContent = 'Template history';
    }

    if (badgeTemplateHistoryDialogSubtitle instanceof HTMLElement) {
      badgeTemplateHistoryDialogSubtitle.textContent =
        badgeTemplateTitle.length > 0 ? badgeTemplateTitle : badgeTemplateId;
    }

    if (badgeTemplateImageHistorySection instanceof HTMLDetailsElement) {
      badgeTemplateImageHistorySection.hidden = true;
      badgeTemplateImageHistorySection.open = false;
    }

    setBadgeTemplateHistoryTimelineHtml('');

    if (badgeTemplateImageRevisionList instanceof HTMLElement) {
      badgeTemplateImageRevisionList.textContent = '';
    }

    badgeTemplateHistoryDialog.showModal();
    await loadBadgeTemplateHistory(badgeTemplateId);
  };
  const refreshBadgeTemplateHistoryIfOpen = async (badgeTemplateId) => {
    if (
      activeBadgeTemplateHistoryId.length === 0 ||
      activeBadgeTemplateHistoryId !== badgeTemplateId ||
      !(badgeTemplateHistoryDialog instanceof HTMLDialogElement) ||
      !badgeTemplateHistoryDialog.open
    ) {
      return;
    }

    await loadBadgeTemplateHistory(badgeTemplateId);
  };
`;

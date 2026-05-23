export const INSTITUTION_ADMIN_BADGE_TEMPLATE_HISTORY_JS = `
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
        updateBadgeTemplateRowImage(badgeTemplateId, restoredImageUri);
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
  const badgeTemplateTableBody = document.getElementById('badge-template-table-body');

  if (badgeTemplateTableBody instanceof HTMLElement) {
    badgeTemplateTableBody.addEventListener('click', async (event) => {
      const target = event.target;

      if (!(target instanceof Element)) {
        return;
      }

      const editButton = target.closest('[data-template-edit-template-id]');

      if (editButton instanceof HTMLButtonElement) {
        openTemplateEditPanel(editButton.dataset.templateEditTemplateId || '');
        return;
      }

      const imageButton = target.closest('[data-template-manage-image-template-id]');

      if (imageButton instanceof HTMLButtonElement) {
        openTemplateImagePanel(imageButton.dataset.templateManageImageTemplateId || '');
        return;
      }

      const historyTrigger = target.closest('[data-template-history-template-id]');

      if (
        historyTrigger instanceof HTMLButtonElement ||
        historyTrigger instanceof HTMLAnchorElement
      ) {
        event.preventDefault();
        await openBadgeTemplateHistory(
          historyTrigger.dataset.templateHistoryTemplateId || '',
          historyTrigger.dataset.templateHistoryTemplateTitle || '',
        );
      }
    });
  }

  if (badgeTemplateCreateArtworkButton instanceof HTMLButtonElement) {
    badgeTemplateCreateArtworkButton.addEventListener('click', () => {
      openTemplateImagePanel(
        badgeTemplateCreateArtworkButton.dataset.templateCreateArtworkTemplateId || '',
      );
    });
  }
`;

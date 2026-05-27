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
  const closeActionMenuPopover = (element) => {
    window.CredTrailAdminActionMenus?.close(element);
  };
  const setBadgeTemplateArchivedStateFromRow = async (badgeTemplateId, action, statusElement) => {
    if (badgeTemplateId.length === 0 || (action !== 'archive' && action !== 'unarchive')) {
      setStatus(statusElement, 'Invalid template archive action.', true);
      return;
    }

    setStatus(
      statusElement,
      action === 'archive' ? 'Archiving badge template...' : 'Restoring badge template...',
      false,
    );

    try {
      const response = await fetch(
        badgeTemplateApiPathPrefix +
          '/' +
          encodeURIComponent(badgeTemplateId) +
          '/' +
          action,
        {
          method: 'POST',
        },
      );
      const payload = await parseJsonBody(response);

      if (!response.ok) {
        setStatus(statusElement, errorDetailFromPayload(payload), true);
        return;
      }

      const template =
        payload && payload.template && typeof payload.template === 'object'
          ? payload.template
          : null;

      if (template !== null && typeof template.id === 'string') {
        const existingRecord = badgeTemplateRecordsById.get(template.id) || {};
        badgeTemplateRecordsById.set(template.id, {
          ...existingRecord,
          ...template,
        });
        await upsertBadgeTemplateTableRow(template.id);
        syncBadgeTemplateEditForm(template.id);
      }

      setStatus(
        statusElement,
        action === 'archive' ? 'Badge template archived.' : 'Badge template restored.',
        false,
        'success',
      );
    } catch {
      setStatus(
        statusElement,
        'Unable to update badge template archive state from this browser session.',
        true,
      );
    }
  };

  if (badgeTemplateTableBody instanceof HTMLElement) {
    badgeTemplateTableBody.addEventListener('click', async (event) => {
      const target = event.target;

      if (!(target instanceof Element)) {
        return;
      }

      const editButton = target.closest('[data-template-edit-template-id]');

      if (editButton instanceof HTMLButtonElement) {
        openTemplateEditor(editButton.dataset.templateEditTemplateId || '');
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
        closeActionMenuPopover(historyTrigger);
        return;
      }

      const archiveButton = target.closest('[data-template-archive-template-id]');

      if (archiveButton instanceof HTMLButtonElement) {
        closeActionMenuPopover(archiveButton);
        await setBadgeTemplateArchivedStateFromRow(
          archiveButton.dataset.templateArchiveTemplateId || '',
          archiveButton.dataset.templateArchiveAction || '',
          badgeTemplateEditStatus,
        );
      }
    });
  }

  if (badgeTemplateCreateArtworkButton instanceof HTMLButtonElement) {
    badgeTemplateCreateArtworkButton.addEventListener('click', () => {
      openTemplateEditor(
        badgeTemplateCreateArtworkButton.dataset.templateCreateArtworkTemplateId || '',
        'artwork',
      );
    });
  }

  if (badgeTemplateEditorHistoryLink instanceof HTMLAnchorElement) {
    badgeTemplateEditorHistoryLink.addEventListener('click', async (event) => {
      event.preventDefault();
      await openBadgeTemplateHistory(
        badgeTemplateEditorHistoryLink.dataset.templateHistoryTemplateId || '',
        badgeTemplateEditorHistoryLink.dataset.templateHistoryTemplateTitle || '',
      );
    });
  }
`;

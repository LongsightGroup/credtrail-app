export const INSTITUTION_ADMIN_BADGE_TEMPLATE_LIST_HISTORY_JS = `
  const badgeTemplateTableBody = document.getElementById('badge-template-table-body');
  const closeActionMenuPopover = (element) => {
    window.CredTrailAdminActionMenus.close(element);
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
          badgeTemplateTableStatus,
        );
      }
    });
  }

  const autoOpenTemplateAuditTemplateId =
    parsedContext &&
    typeof parsedContext.autoOpenTemplateAuditTemplateId === 'string'
      ? parsedContext.autoOpenTemplateAuditTemplateId.trim()
      : '';

  if (autoOpenTemplateAuditTemplateId.length > 0) {
    const record = badgeTemplateRecordsById.get(autoOpenTemplateAuditTemplateId);
    const badgeTemplateTitle =
      record && typeof record.title === 'string' && record.title.length > 0
        ? record.title
        : autoOpenTemplateAuditTemplateId;
    void openBadgeTemplateHistory(autoOpenTemplateAuditTemplateId, badgeTemplateTitle);
  }
`;

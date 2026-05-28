export const INSTITUTION_ADMIN_BADGE_TEMPLATE_EDITOR_HISTORY_JS = `
  if (
    badgeTemplateImageRevisionList instanceof HTMLElement &&
    badgeTemplateHistoryStatus instanceof HTMLElement
  ) {
    badgeTemplateImageRevisionList.addEventListener('click', async (event) => {
      const target = event.target;

      if (!(target instanceof HTMLButtonElement)) {
        return;
      }

      const badgeTemplateId = target.dataset.badgeTemplateId || '';
      const revisionId = target.dataset.revisionId || '';

      if (badgeTemplateId.length === 0 || revisionId.length === 0) {
        setStatus(badgeTemplateHistoryStatus, 'Invalid image revision action.', true);
        return;
      }

      target.disabled = true;
      setStatus(badgeTemplateHistoryStatus, 'Restoring badge image...', false);

      try {
        const response = await fetch(
          badgeTemplateApiPathPrefix +
            '/' +
            encodeURIComponent(badgeTemplateId) +
            '/image-revisions/' +
            encodeURIComponent(revisionId) +
            '/restore',
          {
            method: 'POST',
          },
        );
        const payload = await parseJsonBody(response);

        if (!response.ok) {
          setStatus(badgeTemplateHistoryStatus, errorDetailFromPayload(payload), true);
          target.disabled = false;
          return;
        }

        const restoredTemplate =
          payload && payload.template && typeof payload.template === 'object'
            ? payload.template
            : null;
        const restoredImageUri =
          restoredTemplate && typeof restoredTemplate.imageUri === 'string'
            ? restoredTemplate.imageUri
            : null;

        if (restoredImageUri !== null) {
          updateBadgeTemplatePreviewImage(badgeTemplateId, restoredImageUri);
        }

        setStatus(badgeTemplateHistoryStatus, 'Badge image restored.', false, 'success');
        await loadBadgeTemplateHistory(badgeTemplateId);
        target.disabled = false;
      } catch {
        setStatus(
          badgeTemplateHistoryStatus,
          'Unable to restore badge image from this browser session.',
          true,
        );
        target.disabled = false;
      }
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

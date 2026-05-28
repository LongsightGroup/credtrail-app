export const INSTITUTION_ADMIN_BADGE_TEMPLATE_EDITOR_EDIT_JS = `
  const isBadgeTemplateUrlKeyConflict = (response, payload) => {
    const detail = errorDetailFromPayload(payload).toLowerCase();

    return (
      response.status === 409 &&
      (detail.includes('url key') ||
        detail.includes('already exists') ||
        detail.includes('slug'))
    );
  };

  if (badgeTemplateEditForm instanceof HTMLFormElement && badgeTemplateEditStatus instanceof HTMLElement) {
    badgeTemplateEditForm.addEventListener('submit', async (event) => {
      event.preventDefault();
      setStatus(badgeTemplateEditStatus, 'Saving template...', false);

      const data = new FormData(badgeTemplateEditForm);
      const badgeTemplateIdRaw = data.get('badgeTemplateId');
      const titleRaw = data.get('title');
      const slugRaw = data.get('slug');
      const descriptionRaw = data.get('description');
      const criteriaUriRaw = data.get('criteriaUri');
      const badgeTemplateId =
        typeof badgeTemplateIdRaw === 'string' ? badgeTemplateIdRaw.trim() : '';
      const title = typeof titleRaw === 'string' ? titleRaw.trim() : '';
      const slug = typeof slugRaw === 'string' ? slugRaw.trim() : '';
      const description =
        typeof descriptionRaw === 'string' ? descriptionRaw.trim() : '';
      const criteriaUri = typeof criteriaUriRaw === 'string' ? criteriaUriRaw.trim() : '';

      if (badgeTemplateId.length === 0) {
        setStatus(badgeTemplateEditStatus, 'Badge template is required.', true);
        return;
      }

      if (title.length === 0 || slug.length === 0) {
        setStatus(badgeTemplateEditStatus, 'Badge name and URL key are required.', true);
        return;
      }

      try {
        const response = await fetch(
          badgeTemplateApiPathPrefix + '/' + encodeURIComponent(badgeTemplateId),
          {
            method: 'PATCH',
            headers: {
              'content-type': 'application/json',
            },
            body: JSON.stringify({
              title,
              slug,
              description: description.length === 0 ? null : description,
              criteriaUri: criteriaUri.length === 0 ? null : criteriaUri,
            }),
          },
        );
        const payload = await parseJsonBody(response);

        if (!response.ok) {
          setStatus(
            badgeTemplateEditStatus,
            isBadgeTemplateUrlKeyConflict(response, payload)
              ? 'A template with this URL key already exists. Change the URL key or edit the existing template.'
              : errorDetailFromPayload(payload),
            true,
          );
          return;
        }

        const updatedTemplate =
          payload && payload.template && typeof payload.template === 'object'
            ? payload.template
            : null;

        if (updatedTemplate !== null && typeof updatedTemplate.id === 'string') {
          const existingRecord = badgeTemplateRecordsById.get(updatedTemplate.id) || {};
          badgeTemplateRecordsById.set(updatedTemplate.id, {
            ...existingRecord,
            id: updatedTemplate.id,
            slug: typeof updatedTemplate.slug === 'string' ? updatedTemplate.slug : slug,
            title: typeof updatedTemplate.title === 'string' ? updatedTemplate.title : title,
            description:
              typeof updatedTemplate.description === 'string' ||
              updatedTemplate.description === null
                ? updatedTemplate.description
                : description.length === 0
                  ? null
                  : description,
            criteriaUri:
              typeof updatedTemplate.criteriaUri === 'string' ||
              updatedTemplate.criteriaUri === null
                ? updatedTemplate.criteriaUri
                : criteriaUri.length === 0
                  ? null
                  : criteriaUri,
            updatedAt:
              typeof updatedTemplate.updatedAt === 'string'
                ? updatedTemplate.updatedAt
                : existingRecord.updatedAt ?? '',
          });
          updateBadgeTemplateEditorDetails(updatedTemplate.id, updatedTemplate);
        }

        setStatus(badgeTemplateEditStatus, 'Template saved.', false, 'success');

        if (
          activeBadgeTemplateHistoryId.length > 0 &&
          activeBadgeTemplateHistoryId === badgeTemplateId
        ) {
          void refreshBadgeTemplateHistoryIfOpen(badgeTemplateId);
        }
      } catch {
        setStatus(
          badgeTemplateEditStatus,
          'Unable to save badge template from this browser session.',
          true,
        );
      }
    });

    const badgeTemplateIdField = badgeTemplateEditForm.elements.namedItem('badgeTemplateId');

    if (badgeTemplateIdField instanceof HTMLInputElement && badgeTemplateIdField.value.length > 0) {
      syncBadgeTemplateEditorLinks(badgeTemplateIdField.value.trim());
    }
  }

  if (window.location.hash.length > 1) {
    scrollToBadgeTemplateEditorSection(window.location.hash.slice(1));
  }
`;

export const INSTITUTION_ADMIN_BADGE_TEMPLATE_CREATE_EDIT_JS = `
  if (
    badgeTemplateCreateForm instanceof HTMLFormElement &&
    badgeTemplateCreateStatus instanceof HTMLElement
  ) {
    const syncCreateFormAriaInvalid = () => {
      Array.from(badgeTemplateCreateForm.elements).forEach((control) => {
        if (
          !(control instanceof HTMLInputElement) &&
          !(control instanceof HTMLTextAreaElement) &&
          !(control instanceof HTMLSelectElement)
        ) {
          return;
        }

        let isUserInvalid = false;
        let supportsUserInvalid = true;

        try {
          isUserInvalid = control.matches(':user-invalid');
        } catch {
          supportsUserInvalid = false;
          isUserInvalid = !control.checkValidity();
        }

        if (!supportsUserInvalid) {
          control.classList.toggle('user-invalid-fallback', isUserInvalid);
        }

        if (isUserInvalid) {
          control.setAttribute('aria-invalid', 'true');
        } else {
          control.removeAttribute('aria-invalid');
        }
      });
    };

    badgeTemplateCreateForm.addEventListener(
      'blur',
      () => {
        syncCreateFormAriaInvalid();
      },
      true,
    );
    badgeTemplateCreateForm.addEventListener('input', () => {
      syncCreateFormAriaInvalid();
    });
    badgeTemplateCreateForm.addEventListener('submit', async (event) => {
      event.preventDefault();
      hideBadgeTemplateCreateNextActions();
      syncCreateFormAriaInvalid();

      if (!badgeTemplateCreateForm.checkValidity()) {
        badgeTemplateCreateForm.reportValidity();
        setStatus(
          badgeTemplateCreateStatus,
          'Complete the required template fields before creating it.',
          true,
        );
        return;
      }

      const data = new FormData(badgeTemplateCreateForm);
      const titleRaw = data.get('title');
      const descriptionRaw = data.get('description');
      const title = typeof titleRaw === 'string' ? titleRaw.trim() : '';
      const slug = deriveBadgeTemplateSlugFromTitle(title);
      const description =
        typeof descriptionRaw === 'string' ? descriptionRaw.trim() : '';

      if (slug.length === 0) {
        setStatus(
          badgeTemplateCreateStatus,
          'Badge name needs at least one letter or number so CredTrail can create the URL key.',
          true,
        );
        return;
      }

      setStatus(badgeTemplateCreateStatus, 'Creating template...', false);

      try {
        const response = await fetch(badgeTemplateApiPathPrefix, {
          method: 'POST',
          headers: {
            'content-type': 'application/json',
          },
          body: JSON.stringify({
            title,
            slug,
            ...(description.length === 0 ? {} : { description }),
          }),
        });
        const payload = await parseJsonBody(response);

        if (!response.ok) {
          const detail = errorDetailFromPayload(payload);
          setStatus(
            badgeTemplateCreateStatus,
            response.status === 409 && detail.toLowerCase().includes('slug')
              ? 'A template with this badge name already exists. Use a more specific badge name or edit the existing template.'
              : detail,
            true,
          );
          return;
        }

        const createdTemplate = normalizeBadgeTemplateRecord(
          payload && payload.template ? payload.template : null,
          {
            slug,
            title,
            description: description.length === 0 ? null : description,
            criteriaUri: null,
          },
        );

        if (createdTemplate === null) {
          setStatus(badgeTemplateCreateStatus, 'Template created without a generated id.', true);
          return;
        }

        badgeTemplateRecordsById.set(createdTemplate.id, createdTemplate);
        upsertBadgeTemplateSelectOptions(createdTemplate);
        const tableRowUpdated = await upsertBadgeTemplateTableRow(createdTemplate.id);
        syncBadgeTemplateEditForm(createdTemplate.id);
        setBadgeTemplateImageFormSelection(createdTemplate.id);
        badgeTemplateCreateForm.reset();
        syncCreateFormAriaInvalid();
        showBadgeTemplateCreateNextActions(createdTemplate.id);
        openTemplateImagePanel(createdTemplate.id, false);

        if (templateCreatePanel instanceof HTMLDetailsElement) {
          templateCreatePanel.open = true;
        }

        const successMessage =
          'Template created. URL key: ' +
          createdTemplate.slug +
          '. Generated template ID: ' +
          createdTemplate.id +
          '. Next: add artwork below.';
        setStatus(
          badgeTemplateCreateStatus,
          tableRowUpdated ? successMessage : successMessage + ' Refresh to see it in the table.',
          false,
          'success',
        );
      } catch {
        setStatus(
          badgeTemplateCreateStatus,
          'Unable to create badge template from this browser session.',
          true,
        );
      }
    });
  }

  if (badgeTemplateEditForm instanceof HTMLFormElement && badgeTemplateEditStatus instanceof HTMLElement) {
    const templateSelect = badgeTemplateEditForm.elements.namedItem('badgeTemplateId');

    if (templateSelect instanceof HTMLSelectElement) {
      templateSelect.addEventListener('change', () => {
        syncBadgeTemplateEditForm(templateSelect.value.trim());
      });

      if (templateSelect.value.length > 0) {
        syncBadgeTemplateEditForm(templateSelect.value.trim());
      }
    }

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
          setStatus(badgeTemplateEditStatus, errorDetailFromPayload(payload), true);
          return;
        }

        const updatedTemplate =
          payload && payload.template && typeof payload.template === 'object'
            ? payload.template
            : null;

        if (updatedTemplate !== null && typeof updatedTemplate.id === 'string') {
          badgeTemplateRecordsById.set(updatedTemplate.id, {
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
          });
          updateBadgeTemplateRowDetails(updatedTemplate.id, updatedTemplate);
        }

        if (templateEditPanel instanceof HTMLDetailsElement) {
          templateEditPanel.open = false;
          templateEditPanel.hidden = true;
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
  }

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
          updateBadgeTemplateRowImage(badgeTemplateId, restoredImageUri);
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
  }
  };

  if (document.getElementById('badge-template-edit-form')) {
    initInstitutionAdminBadgeTemplates();
  }
})();
`;

export const INSTITUTION_ADMIN_BADGE_TEMPLATE_LIST_CREATE_JS = `
  const isBadgeTemplateUrlKeyConflict = (response, payload) => {
    const detail = errorDetailFromPayload(payload).toLowerCase();

    return (
      response.status === 409 &&
      (detail.includes('url key') ||
        detail.includes('already exists') ||
        detail.includes('slug'))
    );
  };

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
            isBadgeTemplateUrlKeyConflict(response, payload)
              ? 'That badge name creates a URL key already used by another template. Use a more specific badge name or edit the existing template.'
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
            imageUri: null,
            isArchived: false,
            updatedAt: '',
          },
        );

        if (createdTemplate === null) {
          setStatus(badgeTemplateCreateStatus, 'Template created without a generated id.', true);
          return;
        }

        badgeTemplateRecordsById.set(createdTemplate.id, createdTemplate);
        const editorPath = badgeTemplateEditorPath(createdTemplate.id, 'artwork');

        if (editorPath.length > 0) {
          window.location.assign(editorPath);
          return;
        }

        badgeTemplateCreateForm.reset();
        syncCreateFormAriaInvalid();

        setStatus(
          badgeTemplateCreateStatus,
          'Template created. URL key: ' +
            createdTemplate.slug +
            '. Opening the editor to add artwork.',
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
`;

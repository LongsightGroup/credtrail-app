export const INSTITUTION_ADMIN_BADGE_TEMPLATE_JS = `
  const initInstitutionAdminBadgeTemplates = () => {
  const badgeTemplateImageGenerationPath = (badgeTemplateId, generationId) => {
    return (
      badgeTemplateApiPathPrefix +
      '/' +
      encodeURIComponent(badgeTemplateId) +
      '/image-generations/' +
      encodeURIComponent(generationId)
    );
  };
  const clearBadgeTemplateImageGenerationPoll = () => {
    if (badgeTemplateImageGenerationPollTimer !== null) {
      window.clearTimeout(badgeTemplateImageGenerationPollTimer);
      badgeTemplateImageGenerationPollTimer = null;
    }
  };
  const showBadgeTemplateImageGenerationPreview = (generation) => {
    if (
      !(badgeTemplateImageGenerationPreview instanceof HTMLElement) ||
      !(badgeTemplateImageGenerationPreviewImg instanceof HTMLImageElement) ||
      !(badgeTemplateImageGenerationApplyButton instanceof HTMLButtonElement) ||
      !(badgeTemplateImageGenerationOpenLink instanceof HTMLAnchorElement)
    ) {
      return;
    }

    if (
      !generation ||
      generation.status !== 'succeeded' ||
      typeof generation.resultImageUri !== 'string' ||
      generation.resultImageUri.length === 0
    ) {
      badgeTemplateImageGenerationPreview.hidden = true;
      badgeTemplateImageGenerationPreviewImg.removeAttribute('src');
      badgeTemplateImageGenerationApplyButton.disabled = true;
      badgeTemplateImageGenerationOpenLink.hidden = true;
      badgeTemplateImageGenerationOpenLink.removeAttribute('href');
      return;
    }

    badgeTemplateImageGenerationPreview.hidden = false;
    badgeTemplateImageGenerationPreviewImg.src = generation.resultImageUri;
    badgeTemplateImageGenerationApplyButton.disabled = false;
    badgeTemplateImageGenerationOpenLink.href = generation.resultImageUri;
    badgeTemplateImageGenerationOpenLink.hidden = false;
  };
  const pollBadgeTemplateImageGeneration = async (badgeTemplateId, generationId) => {
    if (!(badgeTemplateImageGenerationStatus instanceof HTMLElement)) {
      return;
    }

    try {
      const response = await fetch(badgeTemplateImageGenerationPath(badgeTemplateId, generationId));
      const payload = await parseJsonBody(response);

      if (!response.ok) {
        setStatus(badgeTemplateImageGenerationStatus, errorDetailFromPayload(payload), true);
        clearBadgeTemplateImageGenerationPoll();
        return;
      }

      const generation = payload && payload.generation ? payload.generation : null;
      activeBadgeTemplateImageGeneration = {
        badgeTemplateId,
        generationId,
      };

      if (generation && generation.status === 'succeeded') {
        setStatus(badgeTemplateImageGenerationStatus, 'Generated draft ready.', false, 'success');
        showBadgeTemplateImageGenerationPreview(generation);
        clearBadgeTemplateImageGenerationPoll();
        return;
      }

      if (generation && generation.status === 'failed') {
        const detail =
          typeof generation.errorMessage === 'string' && generation.errorMessage.length > 0
            ? generation.errorMessage
            : 'Badge image generation failed.';
        setStatus(badgeTemplateImageGenerationStatus, detail, true);
        showBadgeTemplateImageGenerationPreview(null);
        clearBadgeTemplateImageGenerationPoll();
        return;
      }

      const status = generation && typeof generation.status === 'string' ? generation.status : '';
      const statusText =
        status === 'queued'
          ? 'Draft queued. Waiting for the background image worker...'
          : 'Generating badge image draft. Checking again shortly...';
      const nextPollDelayMs =
        status === 'processing'
          ? badgeTemplateImageProcessingPollDelayMs
          : badgeTemplateImageQueuedPollDelayMs;

      setStatus(badgeTemplateImageGenerationStatus, statusText, false);
      badgeTemplateImageGenerationPollTimer = window.setTimeout(() => {
        void pollBadgeTemplateImageGeneration(badgeTemplateId, generationId);
      }, nextPollDelayMs);
    } catch {
      setStatus(
        badgeTemplateImageGenerationStatus,
        'Unable to check badge image generation status from this browser session.',
        true,
      );
      clearBadgeTemplateImageGenerationPoll();
    }
  };
  const renderBadgeTemplateImageRevisions = (badgeTemplateId, revisions) => {
    if (!(badgeTemplateImageRevisionList instanceof HTMLElement)) {
      return;
    }

    badgeTemplateImageRevisionList.textContent = '';

    if (!Array.isArray(revisions) || revisions.length === 0) {
      const empty = document.createElement('p');
      empty.className = 'ct-admin__empty';
      empty.textContent = 'No image history is available for this badge template.';
      badgeTemplateImageRevisionList.append(empty);
      return;
    }

    revisions.forEach((revision) => {
      const item = document.createElement('div');
      item.className = 'ct-admin__image-revision-item';
      const previousImageUri =
        typeof revision.previousImageUri === 'string' && revision.previousImageUri.length > 0
          ? revision.previousImageUri
          : '';

      const preview =
        previousImageUri.length > 0
          ? document.createElement('a')
          : document.createElement('span');
      preview.className = 'ct-admin__image-revision-thumbnail-link';

      if (preview instanceof HTMLAnchorElement) {
        preview.href = previousImageUri;
        preview.target = '_blank';
        preview.rel = 'noopener noreferrer';
        preview.setAttribute('aria-label', 'Open full size previous badge image');
        const thumbnail = document.createElement('img');
        thumbnail.className = 'ct-admin__image-revision-thumbnail';
        thumbnail.src = previousImageUri;
        thumbnail.alt = '';
        thumbnail.loading = 'lazy';
        preview.append(thumbnail);
      } else {
        preview.classList.add('ct-admin__image-revision-thumbnail-link--empty');
        preview.textContent = 'No image';
      }

      const meta = document.createElement('div');
      meta.className = 'ct-admin__image-revision-meta';
      const title = document.createElement('strong');
      title.textContent =
        String(revision.sourceType || 'image change') + ' · ' + formatTimestamp(revision.createdAt);
      const detail = document.createElement('span');
      detail.textContent =
        previousImageUri.length > 0 ? 'Restore the previous image' : 'Restore to no image';
      meta.append(title, detail);

      const actions = document.createElement('div');
      actions.className = 'ct-admin__image-revision-actions';

      if (previousImageUri.length > 0) {
        const openLink = document.createElement('a');
        openLink.className = 'ct-admin__text-action';
        openLink.href = previousImageUri;
        openLink.target = '_blank';
        openLink.rel = 'noopener noreferrer';
        openLink.textContent = 'Open full size';
        actions.append(openLink);
      }

      const button = createAdminButtonElement(adminButtonTinySecondaryClass, 'Restore', {
        'data-badge-template-id': badgeTemplateId,
        'data-revision-id': String(revision.id || ''),
      });

      actions.append(button);
      item.append(preview, meta, actions);
      badgeTemplateImageRevisionList.append(item);
    });
  };
const setBadgeTemplateImageFormSelection = (badgeTemplateId) => {
    ['badge-template-image-upload-form', 'badge-template-image-generation-form'].forEach(
      (formId) => {
        const form = document.getElementById(formId);

        if (!(form instanceof HTMLFormElement)) {
          return;
        }

        const templateSelect = form.elements.namedItem('badgeTemplateId');

        if (templateSelect instanceof HTMLSelectElement) {
          templateSelect.value = badgeTemplateId;
        }
      },
    );
  };
  const syncBadgeTemplateEditForm = (badgeTemplateId) => {
    if (!(badgeTemplateEditForm instanceof HTMLFormElement)) {
      return;
    }

    const record = badgeTemplateRecordsById.get(badgeTemplateId);

    if (record === undefined) {
      return;
    }

    const templateSelect = badgeTemplateEditForm.elements.namedItem('badgeTemplateId');
    const titleInput = badgeTemplateEditForm.elements.namedItem('title');
    const slugInput = badgeTemplateEditForm.elements.namedItem('slug');
    const descriptionInput = badgeTemplateEditForm.elements.namedItem('description');
    const criteriaUriInput = badgeTemplateEditForm.elements.namedItem('criteriaUri');

    if (templateSelect instanceof HTMLSelectElement) {
      templateSelect.value = badgeTemplateId;
    }

    if (titleInput instanceof HTMLInputElement) {
      titleInput.value = typeof record.title === 'string' ? record.title : '';
    }

    if (slugInput instanceof HTMLInputElement) {
      slugInput.value = typeof record.slug === 'string' ? record.slug : '';
    }

    if (descriptionInput instanceof HTMLTextAreaElement) {
      descriptionInput.value =
        typeof record.description === 'string' && record.description !== null
          ? record.description
          : '';
    }

    if (criteriaUriInput instanceof HTMLInputElement) {
      criteriaUriInput.value =
        typeof record.criteriaUri === 'string' && record.criteriaUri !== null
          ? record.criteriaUri
          : '';
    }
  };
  const openTemplateEditPanel = (badgeTemplateId) => {
    syncBadgeTemplateEditForm(badgeTemplateId);

    if (templateEditPanel instanceof HTMLDetailsElement) {
      templateEditPanel.open = true;
      templateEditPanel.scrollIntoView({ block: 'start', behavior: 'smooth' });
    }
  };
  const openTemplateImagePanel = (badgeTemplateId) => {
    setBadgeTemplateImageFormSelection(badgeTemplateId);

    if (templateImagePanel instanceof HTMLDetailsElement) {
      templateImagePanel.open = true;
      templateImagePanel.scrollIntoView({ block: 'start', behavior: 'smooth' });
    }
  };
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
  const updateBadgeTemplateRowImage = (badgeTemplateId, imageUri) => {
    if (typeof badgeTemplateId !== 'string' || badgeTemplateId.length === 0) {
      return;
    }

    const row = document.querySelector('[data-template-row-id="' + badgeTemplateId + '"]');

    if (!(row instanceof HTMLTableRowElement)) {
      return;
    }

    const imageCell = row.cells.item(0);

    if (imageCell === null) {
      return;
    }

    if (typeof imageUri !== 'string' || imageUri.length === 0) {
      imageCell.innerHTML = '<span class="ct-admin__template-placeholder">No image</span>';
      return;
    }

    const link = document.createElement('a');
    link.className = 'ct-admin__template-image-link';
    link.href = imageUri;
    link.target = '_blank';
    link.rel = 'noopener noreferrer';
    link.setAttribute('aria-label', 'Open full size badge template image');
    const thumbnail = document.createElement('img');
    thumbnail.className = 'ct-admin__template-image';
    thumbnail.src = imageUri;
    thumbnail.alt = '';
    thumbnail.loading = 'lazy';
    link.append(thumbnail);
    imageCell.textContent = '';
    imageCell.append(link);
  };
  const updateBadgeTemplateImageRevisionHint = (badgeTemplateId, revisionCount) => {
    if (typeof badgeTemplateId !== 'string' || badgeTemplateId.length === 0) {
      return;
    }

    const historyButton = document.querySelector(
      '[data-template-history-template-id="' + badgeTemplateId + '"]',
    );

    if (historyButton instanceof HTMLElement) {
      historyButton.dataset.templateHistoryImageRevisionCount = String(revisionCount);
    }

    const row = document.querySelector('[data-template-row-id="' + badgeTemplateId + '"]');

    if (!(row instanceof HTMLTableRowElement)) {
      return;
    }

    const titleCell = row.cells.item(1);

    if (titleCell === null) {
      return;
    }

    let hint = titleCell.querySelector('[data-template-image-revision-hint]');

    if (revisionCount < 1) {
      hint?.remove();
      return;
    }

    const hintText =
      revisionCount === 1 ? '1 image version' : String(revisionCount) + ' image versions';

    if (!(hint instanceof HTMLElement)) {
      hint = document.createElement('span');
      hint.className = 'ct-admin__meta';
      hint.dataset.templateImageRevisionHint = 'true';
      const title = titleCell.querySelector('strong');

      if (title instanceof HTMLElement) {
        title.insertAdjacentElement('afterend', hint);
      } else {
        titleCell.append(hint);
      }
    }

    hint.textContent = hintText;
  };
  const readBadgeTemplateImageRevisionCount = (badgeTemplateId) => {
    const historyButton = document.querySelector(
      '[data-template-history-template-id="' + badgeTemplateId + '"]',
    );

    if (!(historyButton instanceof HTMLElement)) {
      return 0;
    }

    const parsed = Number.parseInt(
      historyButton.dataset.templateHistoryImageRevisionCount || '0',
      10,
    );

    return Number.isFinite(parsed) ? Math.max(0, Math.trunc(parsed)) : 0;
  };
  const bumpBadgeTemplateImageRevisionHint = (badgeTemplateId) => {
    updateBadgeTemplateImageRevisionHint(
      badgeTemplateId,
      readBadgeTemplateImageRevisionCount(badgeTemplateId) + 1,
    );
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
  const updateBadgeTemplateRowDetails = (badgeTemplateId, template) => {
    if (typeof badgeTemplateId !== 'string' || badgeTemplateId.length === 0) {
      return;
    }

    const row = document.querySelector('[data-template-row-id="' + badgeTemplateId + '"]');

    if (!(row instanceof HTMLTableRowElement)) {
      return;
    }

    const titleCell = row.cells.item(1);

    if (titleCell !== null && template && typeof template.title === 'string') {
      const title = titleCell.querySelector('strong');

      if (title instanceof HTMLElement) {
        title.textContent = template.title;
      }
    }

    const updatedAtCell = row.cells.item(4);

    if (updatedAtCell !== null && template && typeof template.updatedAt === 'string') {
      updatedAtCell.textContent = formatTimestamp(template.updatedAt);
    }

    document
      .querySelectorAll('[data-template-history-template-id="' + badgeTemplateId + '"]')
      .forEach((candidate) => {
        if (candidate instanceof HTMLElement && template && typeof template.title === 'string') {
          candidate.dataset.templateHistoryTemplateTitle = template.title;
        }
      });

    if (
      activeBadgeTemplateHistoryId === badgeTemplateId &&
      template &&
      typeof template.title === 'string' &&
      badgeTemplateHistoryDialogSubtitle instanceof HTMLElement
    ) {
      activeBadgeTemplateHistoryTitle = template.title;
      badgeTemplateHistoryDialogSubtitle.textContent = template.title;
    }
  };
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
  if (
    badgeTemplateImageUploadForm instanceof HTMLFormElement &&
    badgeTemplateImageUploadStatus instanceof HTMLElement
  ) {
    badgeTemplateImageUploadForm.addEventListener('submit', async (event) => {
      event.preventDefault();
      setStatus(badgeTemplateImageUploadStatus, 'Uploading template image...', false);
      const data = new FormData(badgeTemplateImageUploadForm);
      const badgeTemplateIdRaw = data.get('badgeTemplateId');
      const upload = data.get('file');
      const badgeTemplateId =
        typeof badgeTemplateIdRaw === 'string' ? badgeTemplateIdRaw.trim() : '';

      if (badgeTemplateId.length === 0 || !(upload instanceof File)) {
        setStatus(
          badgeTemplateImageUploadStatus,
          'Badge template and image file are required.',
          true,
        );
        return;
      }

      if (upload.size > 2 * 1024 * 1024) {
        setStatus(
          badgeTemplateImageUploadStatus,
          'Image file exceeds 2 MB limit.',
          true,
        );
        return;
      }

      const normalizedMimeType = upload.type.trim().toLowerCase();
      const allowedMimeTypes = new Set(['image/png', 'image/jpeg', 'image/webp']);

      if (!allowedMimeTypes.has(normalizedMimeType)) {
        setStatus(
          badgeTemplateImageUploadStatus,
          'Unsupported image type. Use PNG, JPEG, or WebP.',
          true,
        );
        return;
      }

      const uploadBody = new FormData();
      uploadBody.set('file', upload);

      try {
        const response = await fetch(
          badgeTemplateApiPathPrefix +
            '/' +
            encodeURIComponent(badgeTemplateId) +
            '/image-upload',
          {
            method: 'POST',
            body: uploadBody,
          },
        );
        const payload = await parseJsonBody(response);

        if (!response.ok) {
          setStatus(badgeTemplateImageUploadStatus, errorDetailFromPayload(payload), true);
          return;
        }

        const uploadedTemplate =
          payload && payload.template && typeof payload.template === 'object'
            ? payload.template
            : null;
        const imageUrl =
          uploadedTemplate && typeof uploadedTemplate.imageUri === 'string'
            ? uploadedTemplate.imageUri
            : payload &&
                payload.image &&
                typeof payload.image.url === 'string'
              ? payload.image.url
              : null;

        if (imageUrl !== null) {
          updateBadgeTemplateRowImage(badgeTemplateId, imageUrl);
          bumpBadgeTemplateImageRevisionHint(badgeTemplateId);
          void refreshBadgeTemplateHistoryIfOpen(badgeTemplateId);
        }

        setStatus(badgeTemplateImageUploadStatus, 'Template image uploaded.', false, 'success');
      } catch {
        setStatus(
          badgeTemplateImageUploadStatus,
          'Unable to upload template image from this browser session.',
          true,
        );
      }
    });
  }

  if (
    badgeTemplateImageGenerationForm instanceof HTMLFormElement &&
    badgeTemplateImageGenerationStatus instanceof HTMLElement
  ) {
    badgeTemplateImageGenerationForm.addEventListener('submit', async (event) => {
      event.preventDefault();
      clearBadgeTemplateImageGenerationPoll();
      showBadgeTemplateImageGenerationPreview(null);
      setStatus(
        badgeTemplateImageGenerationStatus,
        'Generating badge image draft...',
        false,
      );
      const data = new FormData(badgeTemplateImageGenerationForm);
      const badgeTemplateIdRaw = data.get('badgeTemplateId');
      const stylePresetRaw = data.get('stylePreset');
      const promptNotesRaw = data.get('promptNotes');
      const accentColorRaw = data.get('accentColor');
      const badgeTemplateId =
        typeof badgeTemplateIdRaw === 'string' ? badgeTemplateIdRaw.trim() : '';
      const stylePreset = typeof stylePresetRaw === 'string' ? stylePresetRaw.trim() : '';
      const promptNotes = typeof promptNotesRaw === 'string' ? promptNotesRaw.trim() : '';
      const accentColor = typeof accentColorRaw === 'string' ? accentColorRaw.trim() : '';

      if (badgeTemplateId.length === 0 || stylePreset.length === 0) {
        setStatus(badgeTemplateImageGenerationStatus, 'Badge template and style are required.', true);
        return;
      }

      try {
        const response = await fetch(
          badgeTemplateApiPathPrefix +
            '/' +
            encodeURIComponent(badgeTemplateId) +
            '/image-generations',
          {
            method: 'POST',
            headers: {
              'content-type': 'application/json',
            },
            body: JSON.stringify({
              stylePreset,
              ...(promptNotes.length === 0 ? {} : { promptNotes }),
              ...(accentColor.length === 0 ? {} : { accentColor }),
            }),
          },
        );
        const payload = await parseJsonBody(response);

        if (!response.ok) {
          setStatus(badgeTemplateImageGenerationStatus, errorDetailFromPayload(payload), true);
          return;
        }

        const generationId =
          payload &&
          payload.generation &&
          typeof payload.generation.id === 'string'
            ? payload.generation.id
            : '';

        if (generationId.length === 0) {
          setStatus(badgeTemplateImageGenerationStatus, 'Generation completed without an id.', true);
          return;
        }

        activeBadgeTemplateImageGeneration = {
          badgeTemplateId,
          generationId,
        };
        const generation = payload && payload.generation ? payload.generation : null;

        if (
          generation &&
          generation.status === 'succeeded' &&
          typeof generation.resultImageUri === 'string' &&
          generation.resultImageUri.length > 0
        ) {
          showBadgeTemplateImageGenerationPreview(generation);
          setStatus(badgeTemplateImageGenerationStatus, 'Generated draft ready.', false, 'success');
          return;
        }

        setStatus(
          badgeTemplateImageGenerationStatus,
          generation && generation.status === 'processing'
            ? 'Generating badge image draft. Checking again shortly...'
            : 'Draft queued. Waiting for the image worker...',
          false,
        );
        const nextPollDelayMs =
          generation && generation.status === 'processing'
            ? badgeTemplateImageProcessingPollDelayMs
            : badgeTemplateImageQueuedPollDelayMs;
        badgeTemplateImageGenerationPollTimer = window.setTimeout(() => {
          void pollBadgeTemplateImageGeneration(badgeTemplateId, generationId);
        }, nextPollDelayMs);
      } catch {
        setStatus(
          badgeTemplateImageGenerationStatus,
          'Unable to generate badge image from this browser session.',
          true,
        );
      }
    });
  }

  if (
    badgeTemplateImageGenerationApplyButton instanceof HTMLButtonElement &&
    badgeTemplateImageGenerationStatus instanceof HTMLElement
  ) {
    badgeTemplateImageGenerationApplyButton.addEventListener('click', async () => {
      if (
        !activeBadgeTemplateImageGeneration ||
        typeof activeBadgeTemplateImageGeneration.badgeTemplateId !== 'string' ||
        typeof activeBadgeTemplateImageGeneration.generationId !== 'string'
      ) {
        setStatus(badgeTemplateImageGenerationStatus, 'No generated draft is selected.', true);
        return;
      }

      badgeTemplateImageGenerationApplyButton.disabled = true;
      setStatus(badgeTemplateImageGenerationStatus, 'Applying generated badge image...', false);

      try {
        const response = await fetch(
          badgeTemplateImageGenerationPath(
            activeBadgeTemplateImageGeneration.badgeTemplateId,
            activeBadgeTemplateImageGeneration.generationId,
          ) + '/apply',
          {
            method: 'POST',
          },
        );
        const payload = await parseJsonBody(response);

        if (!response.ok) {
          setStatus(badgeTemplateImageGenerationStatus, errorDetailFromPayload(payload), true);
          badgeTemplateImageGenerationApplyButton.disabled = false;
          return;
        }

        const appliedTemplate =
          payload && payload.template && typeof payload.template === 'object'
            ? payload.template
            : null;
        const appliedImageUri =
          appliedTemplate && typeof appliedTemplate.imageUri === 'string'
            ? appliedTemplate.imageUri
            : null;

        if (appliedImageUri !== null) {
          const appliedBadgeTemplateId = activeBadgeTemplateImageGeneration.badgeTemplateId;
          updateBadgeTemplateRowImage(appliedBadgeTemplateId, appliedImageUri);
          bumpBadgeTemplateImageRevisionHint(appliedBadgeTemplateId);
          void refreshBadgeTemplateHistoryIfOpen(appliedBadgeTemplateId);
        }

        setStatus(badgeTemplateImageGenerationStatus, 'Generated image applied.', false, 'success');
        badgeTemplateImageGenerationApplyButton.disabled = false;
      } catch {
        setStatus(
          badgeTemplateImageGenerationStatus,
          'Unable to apply generated badge image from this browser session.',
          true,
        );
        badgeTemplateImageGenerationApplyButton.disabled = false;
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
        setStatus(badgeTemplateEditStatus, 'Title and slug are required.', true);
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

  document.querySelectorAll('[data-template-edit-template-id]').forEach((candidate) => {
    if (!(candidate instanceof HTMLButtonElement)) {
      return;
    }

    candidate.addEventListener('click', () => {
      const badgeTemplateId = candidate.dataset.templateEditTemplateId || '';
      openTemplateEditPanel(badgeTemplateId);
    });
  });

  document.querySelectorAll('[data-template-manage-image-template-id]').forEach((candidate) => {
    if (!(candidate instanceof HTMLButtonElement)) {
      return;
    }

    candidate.addEventListener('click', () => {
      const badgeTemplateId = candidate.dataset.templateManageImageTemplateId || '';
      openTemplateImagePanel(badgeTemplateId);
    });
  });

  document.querySelectorAll('[data-template-history-template-id]').forEach((candidate) => {
    if (
      !(candidate instanceof HTMLButtonElement) &&
      !(candidate instanceof HTMLAnchorElement)
    ) {
      return;
    }

    candidate.addEventListener('click', async (event) => {
      event.preventDefault();
      const badgeTemplateId = candidate.dataset.templateHistoryTemplateId || '';
      const badgeTemplateTitle = candidate.dataset.templateHistoryTemplateTitle || '';
      await openBadgeTemplateHistory(badgeTemplateId, badgeTemplateTitle);
    });
  });

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
`;

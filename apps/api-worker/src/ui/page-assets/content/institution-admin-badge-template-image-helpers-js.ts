export const INSTITUTION_ADMIN_BADGE_TEMPLATE_IMAGE_HELPERS_JS = `
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

        const templateField = form.elements.namedItem('badgeTemplateId');

        if (
          templateField instanceof HTMLSelectElement ||
          templateField instanceof HTMLInputElement
        ) {
          templateField.value = badgeTemplateId;
        }
      },
    );
  };
`;

export const INSTITUTION_ADMIN_BADGE_TEMPLATE_IMAGE_WORKFLOW_JS = `
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
          updateBadgeTemplatePreviewImage(badgeTemplateId, imageUrl);
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
          updateBadgeTemplatePreviewImage(appliedBadgeTemplateId, appliedImageUri);
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
`;

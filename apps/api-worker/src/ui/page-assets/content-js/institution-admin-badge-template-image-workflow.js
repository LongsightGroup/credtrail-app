if (
  badgeTemplateImageGenerationForm instanceof HTMLFormElement &&
  badgeTemplateImageGenerationStatus instanceof HTMLElement
) {
  badgeTemplateImageGenerationForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    clearBadgeTemplateImageGenerationPoll();
    showBadgeTemplateImageGenerationPreview(null);
    setStatus(badgeTemplateImageGenerationStatus, "Generating badge image draft...", false);
    const data = new FormData(badgeTemplateImageGenerationForm);
    const badgeTemplateIdRaw = data.get("badgeTemplateId");
    const stylePresetRaw = data.get("stylePreset");
    const promptNotesRaw = data.get("promptNotes");
    const accentColorRaw = data.get("accentColor");
    const badgeTemplateId = typeof badgeTemplateIdRaw === "string" ? badgeTemplateIdRaw.trim() : "";
    const stylePreset = typeof stylePresetRaw === "string" ? stylePresetRaw.trim() : "";
    const promptNotes = typeof promptNotesRaw === "string" ? promptNotesRaw.trim() : "";
    const accentColor = typeof accentColorRaw === "string" ? accentColorRaw.trim() : "";

    if (badgeTemplateId.length === 0 || stylePreset.length === 0) {
      setStatus(badgeTemplateImageGenerationStatus, "Badge template and style are required.", true);
      return;
    }

    try {
      const response = await fetch(
        badgeTemplateApiPathPrefix +
          "/" +
          encodeURIComponent(badgeTemplateId) +
          "/image-generations",
        {
          method: "POST",
          headers: {
            "content-type": "application/json",
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
        payload && payload.generation && typeof payload.generation.id === "string"
          ? payload.generation.id
          : "";

      if (generationId.length === 0) {
        setStatus(badgeTemplateImageGenerationStatus, "Generation completed without an id.", true);
        return;
      }

      activeBadgeTemplateImageGeneration = {
        badgeTemplateId,
        generationId,
      };
      const generation = payload && payload.generation ? payload.generation : null;

      if (
        generation &&
        generation.status === "succeeded" &&
        typeof generation.resultImageUri === "string" &&
        generation.resultImageUri.length > 0
      ) {
        showBadgeTemplateImageGenerationPreview(generation);
        setStatus(badgeTemplateImageGenerationStatus, "Generated draft ready.", false, "success");
        return;
      }

      setStatus(
        badgeTemplateImageGenerationStatus,
        generation && generation.status === "processing"
          ? "Generating badge image draft. Checking again shortly..."
          : "Draft queued. Waiting for the image worker...",
        false,
      );
      const nextPollDelayMs =
        generation && generation.status === "processing"
          ? badgeTemplateImageProcessingPollDelayMs
          : badgeTemplateImageQueuedPollDelayMs;
      badgeTemplateImageGenerationPollTimer = window.setTimeout(() => {
        void pollBadgeTemplateImageGeneration(badgeTemplateId, generationId);
      }, nextPollDelayMs);
    } catch {
      setStatus(
        badgeTemplateImageGenerationStatus,
        "Unable to generate badge image from this browser session.",
        true,
      );
    }
  });
}

if (
  badgeTemplateImageGenerationApplyButton instanceof HTMLButtonElement &&
  badgeTemplateImageGenerationApplyForm instanceof HTMLFormElement &&
  badgeTemplateImageGenerationApplyGenerationId instanceof HTMLInputElement &&
  badgeTemplateImageGenerationStatus instanceof HTMLElement
) {
  badgeTemplateImageGenerationApplyButton.addEventListener("click", (event) => {
    if (
      !activeBadgeTemplateImageGeneration ||
      typeof activeBadgeTemplateImageGeneration.badgeTemplateId !== "string" ||
      typeof activeBadgeTemplateImageGeneration.generationId !== "string"
    ) {
      event.preventDefault();
      setStatus(badgeTemplateImageGenerationStatus, "No generated draft is selected.", true);
      return;
    }

    badgeTemplateImageGenerationApplyGenerationId.value =
      activeBadgeTemplateImageGeneration.generationId;
  });
}

if (badgeTemplateImageGenerationOpenLink instanceof HTMLButtonElement) {
  badgeTemplateImageGenerationOpenLink.addEventListener("click", () => {
    const openUri = badgeTemplateImageGenerationOpenLink.dataset.openUri;
    if (typeof openUri !== "string" || openUri.length === 0) {
      return;
    }

    window.open(openUri, "_blank", "noopener,noreferrer");
  });
}

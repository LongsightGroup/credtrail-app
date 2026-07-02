const badgeTemplateImageGenerationPath = (badgeTemplateId, generationId) => {
  return (
    badgeTemplateApiPathPrefix +
    "/" +
    encodeURIComponent(badgeTemplateId) +
    "/image-generations/" +
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
    !(badgeTemplateImageGenerationOpenLink instanceof HTMLButtonElement)
  ) {
    return;
  }

  if (
    !generation ||
    generation.status !== "succeeded" ||
    typeof generation.resultImageUri !== "string" ||
    generation.resultImageUri.length === 0
  ) {
    badgeTemplateImageGenerationPreview.hidden = true;
    badgeTemplateImageGenerationPreviewImg.removeAttribute("src");
    badgeTemplateImageGenerationApplyButton.disabled = true;
    badgeTemplateImageGenerationOpenLink.hidden = true;
    badgeTemplateImageGenerationOpenLink.disabled = true;
    delete badgeTemplateImageGenerationOpenLink.dataset.openUri;
    return;
  }

  badgeTemplateImageGenerationPreview.hidden = false;
  badgeTemplateImageGenerationPreviewImg.src = generation.resultImageUri;
  badgeTemplateImageGenerationApplyButton.disabled = false;
  badgeTemplateImageGenerationOpenLink.dataset.openUri = generation.resultImageUri;
  badgeTemplateImageGenerationOpenLink.hidden = false;
  badgeTemplateImageGenerationOpenLink.disabled = false;
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

    if (generation && generation.status === "succeeded") {
      setStatus(badgeTemplateImageGenerationStatus, "Generated draft ready.", false, "success");
      showBadgeTemplateImageGenerationPreview(generation);
      clearBadgeTemplateImageGenerationPoll();
      return;
    }

    if (generation && generation.status === "failed") {
      const detail =
        typeof generation.errorMessage === "string" && generation.errorMessage.length > 0
          ? generation.errorMessage
          : "Badge image generation failed.";
      setStatus(badgeTemplateImageGenerationStatus, detail, true);
      showBadgeTemplateImageGenerationPreview(null);
      clearBadgeTemplateImageGenerationPoll();
      return;
    }

    const status = generation && typeof generation.status === "string" ? generation.status : "";
    const statusText =
      status === "queued"
        ? "Draft queued. Waiting for the background image worker..."
        : "Generating badge image draft. Checking again shortly...";
    const nextPollDelayMs =
      status === "processing"
        ? badgeTemplateImageProcessingPollDelayMs
        : badgeTemplateImageQueuedPollDelayMs;

    setStatus(badgeTemplateImageGenerationStatus, statusText, false);
    badgeTemplateImageGenerationPollTimer = window.setTimeout(() => {
      void pollBadgeTemplateImageGeneration(badgeTemplateId, generationId);
    }, nextPollDelayMs);
  } catch {
    setStatus(
      badgeTemplateImageGenerationStatus,
      "Unable to check badge image generation status from this browser session.",
      true,
    );
    clearBadgeTemplateImageGenerationPoll();
  }
};

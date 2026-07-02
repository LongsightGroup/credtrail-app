(() => {
  const contextElement = document.getElementById('ct-admin-context');

  if (!(contextElement instanceof HTMLElement)) {
    return;
  }

  let parsedContext;

  try {
    parsedContext = JSON.parse(contextElement.dataset.contextJson ?? '{}');
  } catch {
    return;
  }

  const badgeTemplateApiPathPrefix =
    parsedContext && typeof parsedContext.badgeTemplateApiPathPrefix === 'string'
      ? parsedContext.badgeTemplateApiPathPrefix
      : '';
  const showcasePath =
    parsedContext && typeof parsedContext.showcasePath === 'string'
      ? parsedContext.showcasePath
      : '';
  const badgeTemplateRecordsById = new Map();
  const badgeTemplateRecordsContext =
    parsedContext && Array.isArray(parsedContext.badgeTemplateRecords)
      ? parsedContext.badgeTemplateRecords
      : [];

  badgeTemplateRecordsContext.forEach((entry) => {
    if (entry && typeof entry.id === 'string' && entry.id.length > 0) {
      badgeTemplateRecordsById.set(entry.id, entry);
    }
  });

  const badgeTemplateImageQueuedPollDelayMs = 15000;
  const badgeTemplateImageProcessingPollDelayMs = 10000;
  const badgeTemplateEditorCriteriaLink = document.getElementById(
    'badge-template-editor-criteria-link',
  );
  const badgeTemplateEditorPublicLink = document.getElementById(
    'badge-template-editor-public-link',
  );
  const badgeTemplateEditorActivitySummary = document.getElementById(
    'badge-template-editor-activity-summary',
  );
  const badgeTemplateEditorHistoryLink = document.getElementById(
    'badge-template-editor-history-link',
  );
  const badgeTemplateImageGenerationForm = document.getElementById(
    'badge-template-image-generation-form',
  );
  const badgeTemplateImageGenerationStatus = document.getElementById(
    'badge-template-image-generation-status',
  );
  const badgeTemplateImageGenerationPreview = document.getElementById(
    'badge-template-image-generation-preview',
  );
  const badgeTemplateImageGenerationPreviewImg = document.getElementById(
    'badge-template-image-generation-preview-img',
  );
  const badgeTemplateImageGenerationApplyForm = document.getElementById(
    'badge-template-image-generation-apply-form',
  );
  const badgeTemplateImageGenerationApplyGenerationId = document.getElementById(
    'badge-template-image-generation-apply-generation-id',
  );
  const badgeTemplateImageGenerationApplyButton = document.getElementById(
    'badge-template-image-generation-apply',
  );
  const badgeTemplateImageGenerationOpenLink = document.getElementById(
    'badge-template-image-generation-open',
  );
  const badgeTemplateHistoryDialog = document.getElementById('badge-template-history-dialog');
  const badgeTemplateHistoryDialogTitle = document.getElementById(
    'badge-template-history-dialog-title',
  );
  const badgeTemplateHistoryDialogSubtitle = document.getElementById(
    'badge-template-history-dialog-subtitle',
  );
  const badgeTemplateHistoryStatus = document.getElementById('badge-template-history-status');
  const badgeTemplateHistoryAuditList = document.getElementById('badge-template-history-audit-list');
  const badgeTemplateImageHistorySection = document.getElementById(
    'badge-template-image-history-section',
  );
  let activeBadgeTemplateImageGeneration = null;
  let badgeTemplateImageGenerationPollTimer = null;

  const setStatus = (el, text, isError, tone = 'info') => {
    if (!(el instanceof HTMLElement)) {
      return;
    }

    el.textContent = text;
    el.dataset.tone = isError ? 'error' : tone;
  };
  const parseJsonBody = async (response) => {
    try {
      return await response.json();
    } catch {
      return null;
    }
  };
  const errorDetailFromPayload = (payload) => {
    return payload && typeof payload.error === 'string' ? payload.error : 'Request failed';
  };
  const formatTimestamp = (value) => {
    if (typeof value !== 'string' || value.length === 0) {
      return 'n/a';
    }

    const parsed = Date.parse(value);

    if (!Number.isFinite(parsed)) {
      return value;
    }

    return new Date(parsed).toLocaleString();
  };

const initBadgeTemplateHistoryDialogFromPage = () => {
  if (!(badgeTemplateHistoryDialog instanceof HTMLDialogElement)) {
    return;
  }

  const closeButton = document.getElementById("badge-template-history-dialog-close");

  if (closeButton instanceof HTMLButtonElement) {
    closeButton.addEventListener("click", () => {
      badgeTemplateHistoryDialog.close();
    });
  }

  const autoOpenTemplateId = badgeTemplateHistoryDialog.dataset.autoOpenHistoryTemplateId || "";

  if (autoOpenTemplateId.length === 0) {
    return;
  }

  if (!badgeTemplateHistoryDialog.open) {
    badgeTemplateHistoryDialog.showModal();
  }
};

initBadgeTemplateHistoryDialogFromPage();

const initAdminImageFallbacks = () => {
  document.querySelectorAll("[data-admin-image-fallback]").forEach((frame) => {
    if (!(frame instanceof HTMLElement)) {
      return;
    }

    const link = frame.querySelector("[data-admin-image-link]");
    const image = frame.querySelector("[data-admin-image]");
    const placeholder = frame.querySelector("[data-admin-image-placeholder]");

    if (
      !(link instanceof HTMLElement) ||
      !(image instanceof HTMLImageElement) ||
      !(placeholder instanceof HTMLElement)
    ) {
      return;
    }

    const showPlaceholder = () => {
      link.hidden = true;
      placeholder.hidden = false;
      frame.dataset.adminImageFallback = "unavailable";
    };

    if (image.complete && image.naturalWidth === 0) {
      showPlaceholder();
      return;
    }

    image.addEventListener("error", showPlaceholder, { once: true });
  });
};

initAdminImageFallbacks();

const badgeTemplateTableBody = document.getElementById("badge-template-table-body");
const closeActionMenuPopover = (element) => {
  window.CredTrailAdminActionMenus.close(element);
};

if (badgeTemplateTableBody instanceof HTMLElement) {
  badgeTemplateTableBody.addEventListener("click", (event) => {
    const target = event.target;

    if (!(target instanceof Element)) {
      return;
    }

    const historyTrigger = target.closest("[data-template-history-template-id]");

    if (
      historyTrigger instanceof HTMLButtonElement ||
      historyTrigger instanceof HTMLAnchorElement
    ) {
      closeActionMenuPopover(historyTrigger);
    }
  });
}

})();
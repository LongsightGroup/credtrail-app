(() => {
const readAdminContext = () => {
  const contextElement = document.getElementById("ct-admin-context");

  if (!(contextElement instanceof HTMLElement)) {
    return null;
  }

  const contextJson =
    contextElement.dataset.contextJson ??
    (contextElement instanceof HTMLScriptElement ? contextElement.textContent : null) ??
    "{}";

  try {
    const parsedContext = JSON.parse(contextJson);

    return parsedContext && typeof parsedContext === "object" ? parsedContext : null;
  } catch {
    return null;
  }
};

const setStatus = (el, text, isError, tone = "info") => {
  if (!(el instanceof HTMLElement)) {
    return;
  }

  el.textContent = text;
  el.dataset.tone = isError ? "error" : tone;
};

const parseJsonBody = async (response) => {
  try {
    return await response.json();
  } catch {
    return null;
  }
};

const errorDetailFromPayload = (payload) => {
  return payload && typeof payload.error === "string" ? payload.error : "Request failed";
};

const setCodeOutput = (el, value) => {
  if (!(el instanceof HTMLElement)) {
    return;
  }

  if (typeof value !== "string" || value.length === 0) {
    el.hidden = true;
    el.textContent = "";
    return;
  }

  el.hidden = false;
  el.textContent = value;
};

const parsedContext = readAdminContext();

if (!parsedContext) {
  return;
}

const badgeTemplateApiPathPrefix =
  typeof parsedContext.badgeTemplateApiPathPrefix === "string"
    ? parsedContext.badgeTemplateApiPathPrefix
    : "";
const showcasePath =
  typeof parsedContext.showcasePath === "string" ? parsedContext.showcasePath : "";
const badgeTemplateRecordsById = new Map();
const badgeTemplateRecordsContext = Array.isArray(parsedContext.badgeTemplateRecords)
  ? parsedContext.badgeTemplateRecords
  : [];

badgeTemplateRecordsContext.forEach((entry) => {
  if (entry && typeof entry.id === "string" && entry.id.length > 0) {
    badgeTemplateRecordsById.set(entry.id, entry);
  }
});

const badgeTemplateImageQueuedPollDelayMs = 15000;
const badgeTemplateImageProcessingPollDelayMs = 10000;
const badgeTemplateEditorCriteriaLink = document.getElementById(
  "badge-template-editor-criteria-link",
);
const badgeTemplateEditorPublicLink = document.getElementById("badge-template-editor-public-link");
const badgeTemplateEditorActivitySummary = document.getElementById(
  "badge-template-editor-activity-summary",
);
const badgeTemplateEditorHistoryLink = document.getElementById(
  "badge-template-editor-history-link",
);
const badgeTemplateImageGenerationForm = document.getElementById(
  "badge-template-image-generation-form",
);
const badgeTemplateImageGenerationStatus = document.getElementById(
  "badge-template-image-generation-status",
);
const badgeTemplateImageGenerationPreview = document.getElementById(
  "badge-template-image-generation-preview",
);
const badgeTemplateImageGenerationPreviewImg = document.getElementById(
  "badge-template-image-generation-preview-img",
);
const badgeTemplateImageGenerationApplyForm = document.getElementById(
  "badge-template-image-generation-apply-form",
);
const badgeTemplateImageGenerationApplyGenerationId = document.getElementById(
  "badge-template-image-generation-apply-generation-id",
);
const badgeTemplateImageGenerationApplyButton = document.getElementById(
  "badge-template-image-generation-apply",
);
const badgeTemplateImageGenerationOpenLink = document.getElementById(
  "badge-template-image-generation-open",
);
const badgeTemplateHistoryDialog = document.getElementById("badge-template-history-dialog");
const badgeTemplateHistoryDialogTitle = document.getElementById(
  "badge-template-history-dialog-title",
);
const badgeTemplateHistoryDialogSubtitle = document.getElementById(
  "badge-template-history-dialog-subtitle",
);
const badgeTemplateHistoryStatus = document.getElementById("badge-template-history-status");
const badgeTemplateHistoryAuditList = document.getElementById("badge-template-history-audit-list");
const badgeTemplateImageHistorySection = document.getElementById(
  "badge-template-image-history-section",
);
let activeBadgeTemplateImageGeneration = null;
let badgeTemplateImageGenerationPollTimer = null;

const formatTimestamp = (value) => {
  if (typeof value !== "string" || value.length === 0) {
    return "n/a";
  }

  const parsed = Date.parse(value);

  if (!Number.isFinite(parsed)) {
    return value;
  }

  return new Date(parsed).toLocaleString();
};

const badgeTemplateShowcasePath = (badgeTemplateId) => {
  if (showcasePath.length === 0) {
    return "";
  }

  const url = new URL(showcasePath, window.location.origin);
  url.searchParams.set("badgeTemplateId", badgeTemplateId);
  return url.pathname + url.search;
};
const badgeTemplateCriteriaRegistryPath = (badgeTemplateId) => {
  if (showcasePath.length === 0) {
    return "";
  }

  const url = new URL(showcasePath, window.location.origin);
  url.pathname = url.pathname.replace(/\/$/, "") + "/criteria";
  url.searchParams.set("badgeTemplateId", badgeTemplateId);
  return url.pathname + url.search;
};
const updateBadgeTemplateEditorActivitySummary = (badgeTemplateId, revisionCount) => {
  if (!(badgeTemplateEditorActivitySummary instanceof HTMLElement)) {
    return;
  }

  const record = badgeTemplateRecordsById.get(badgeTemplateId);
  const updatedAt =
    record && typeof record.updatedAt === "string" && record.updatedAt.length > 0
      ? formatTimestamp(record.updatedAt)
      : "n/a";
  const revisionLabel =
    revisionCount === 1 ? "1 image version" : String(revisionCount) + " image versions";
  badgeTemplateEditorActivitySummary.textContent =
    revisionLabel + ". Last updated " + updatedAt + ".";
};
const updateBadgeTemplateImageRevisionHint = (badgeTemplateId, revisionCount) => {
  if (typeof badgeTemplateId !== "string" || badgeTemplateId.length === 0) {
    return;
  }

  if (badgeTemplateEditorHistoryLink instanceof HTMLElement) {
    badgeTemplateEditorHistoryLink.dataset.templateHistoryImageRevisionCount =
      String(revisionCount);
  }

  updateBadgeTemplateEditorActivitySummary(badgeTemplateId, revisionCount);
};
const readBadgeTemplateImageRevisionCount = (badgeTemplateId) => {
  if (badgeTemplateEditorHistoryLink instanceof HTMLElement) {
    const parsed = Number.parseInt(
      badgeTemplateEditorHistoryLink.dataset.templateHistoryImageRevisionCount || "0",
      10,
    );

    if (Number.isFinite(parsed)) {
      return Math.max(0, Math.trunc(parsed));
    }
  }

  return 0;
};
const syncBadgeTemplateEditorLinks = (badgeTemplateId) => {
  const showcasePath = badgeTemplateShowcasePath(badgeTemplateId);
  const criteriaPath = badgeTemplateCriteriaRegistryPath(badgeTemplateId);

  if (badgeTemplateEditorPublicLink instanceof HTMLAnchorElement && showcasePath.length > 0) {
    badgeTemplateEditorPublicLink.href = showcasePath;
  }

  if (badgeTemplateEditorCriteriaLink instanceof HTMLAnchorElement && criteriaPath.length > 0) {
    badgeTemplateEditorCriteriaLink.href = criteriaPath;
  }

  updateBadgeTemplateEditorActivitySummary(
    badgeTemplateId,
    readBadgeTemplateImageRevisionCount(badgeTemplateId),
  );
};
const updateBadgeTemplateEditorDetails = (badgeTemplateId, template) => {
  if (typeof badgeTemplateId !== "string" || badgeTemplateId.length === 0) {
    return;
  }

  if (template && typeof template.id === "string") {
    syncBadgeTemplateEditorLinks(template.id);
  }
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

const updateTrustEdRepeatableTemplateTokens = (root, rowIndex) => {
  const rowNumber = String(rowIndex + 1);
  const index = String(rowIndex);
  const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT);
  let textNode = walker.nextNode();

  while (textNode !== null) {
    textNode.textContent = (textNode.textContent || "")
      .replaceAll("__INDEX__", index)
      .replaceAll("__ROW_NUMBER__", rowNumber);
    textNode = walker.nextNode();
  }

  root.querySelectorAll("*").forEach((element) => {
    for (const attribute of Array.from(element.attributes)) {
      if (attribute.value.includes("__INDEX__") || attribute.value.includes("__ROW_NUMBER__")) {
        element.setAttribute(
          attribute.name,
          attribute.value.replaceAll("__INDEX__", index).replaceAll("__ROW_NUMBER__", rowNumber),
        );
      }
    }
  });
};
const renumberTrustEdRepeatableRows = (group) => {
  group.querySelectorAll("[data-trusted-repeatable-row]").forEach((row, index) => {
    if (!(row instanceof HTMLElement)) {
      return;
    }

    const label = row.querySelector(
      ".ct-admin__template-editor-trusted-repeatable-row-header span",
    );

    row.dataset.trustedRepeatableIndex = String(index);

    if (label instanceof HTMLElement) {
      const groupTitle =
        group.dataset.trustedRepeatableTitle ??
        group
          .querySelector(".ct-admin__template-editor-trusted-repeatable-summary strong")
          ?.textContent?.trim() ??
        "Entry";
      label.textContent = groupTitle + " " + String(index + 1);
    }

    row.querySelectorAll("input, textarea").forEach((control) => {
      if (!(control instanceof HTMLInputElement) && !(control instanceof HTMLTextAreaElement)) {
        return;
      }

      control.name = control.name.replace(/\[\d+\]/, "[" + String(index) + "]");
    });
  });
};
document.addEventListener("click", (event) => {
  const target = event.target;

  if (!(target instanceof Element)) {
    return;
  }

  const addButton = target.closest("[data-trusted-repeatable-add]");

  if (addButton instanceof HTMLElement) {
    const groupName = addButton.dataset.trustedRepeatableAdd;
    const group =
      typeof groupName === "string"
        ? document.querySelector('[data-trusted-repeatable="' + groupName + '"]')
        : null;

    if (!(group instanceof HTMLElement)) {
      return;
    }

    const template = group.querySelector("template[data-trusted-repeatable-template]");
    const rows = group.querySelector(".ct-admin__template-editor-trusted-repeatable-rows");

    if (!(template instanceof HTMLTemplateElement) || !(rows instanceof HTMLElement)) {
      return;
    }

    const nextIndex = Number.parseInt(group.dataset.trustedRepeatableNextIndex || "0", 10);
    const safeNextIndex = Number.isFinite(nextIndex) ? nextIndex : rows.children.length;
    const fragment = template.content.cloneNode(true);

    updateTrustEdRepeatableTemplateTokens(fragment, safeNextIndex);
    rows.appendChild(fragment);
    group.dataset.trustedRepeatableNextIndex = String(safeNextIndex + 1);

    const addedRows = rows.querySelectorAll("[data-trusted-repeatable-row]");
    const addedRow = addedRows[addedRows.length - 1];
    const firstControl =
      addedRow instanceof HTMLElement ? addedRow.querySelector("input, textarea") : null;

    if (firstControl instanceof HTMLElement) {
      firstControl.focus();
    }
    return;
  }

  const removeButton = target.closest("[data-trusted-repeatable-remove]");

  if (removeButton instanceof HTMLElement) {
    const row = removeButton.closest("[data-trusted-repeatable-row]");
    const group = removeButton.closest("[data-trusted-repeatable]");

    if (row instanceof HTMLElement && group instanceof HTMLElement) {
      row.remove();
      renumberTrustEdRepeatableRows(group);
    }
  }
});

})();